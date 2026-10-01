"""Bounded, payload-free evidence for streaming stalls and transport failures.

The httpcore trace extension describes request phases; a network-stream delegate
measures socket I/O and observes HTTP/2 frame headers and numeric control fields.
It skips body/header payloads and GOAWAY debug text. Neither hook changes timeouts,
protocol selection, retries, cancellation, or the bytes passing through it.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import re
import time
from collections import OrderedDict, deque
from contextvars import ContextVar
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Any
from uuid import UUID

import httpcore

logger = logging.getLogger("headroom.proxy")
current_stream: ContextVar[StreamRecord | None] = ContextVar("current_stream", default=None)
_LIMIT = 64
_SLOW_SECONDS = 30
_PHASES = frozenset(
    {
        "connect_tcp",
        "connect_unix_socket",
        "start_tls",
        "send_connection_init",
        "send_request_headers",
        "send_request_body",
        "receive_response_headers",
        "receive_response_body",
        "response_closed",
        "receive_remote_settings",
        "retry",
        "upstream_read",
        "downstream_yield",
        "downstream_send",
        "socket_read",
        "socket_write",
    }
)
_ID = re.compile(r"[A-Za-z0-9_.:/-]{1,160}\Z")
_H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
_H2_SETTINGS = {
    1: "header_table_size",
    2: "enable_push",
    3: "max_concurrent_streams",
    4: "initial_window_size",
    5: "max_frame_size",
    6: "max_header_list_size",
    8: "enable_connect_protocol",
    9: "no_rfc7540_priorities",
}
_H2_FRAME_NAMES = (
    "DATA",
    "HEADERS",
    "PRIORITY",
    "RST_STREAM",
    "SETTINGS",
    "PUSH_PROMISE",
    "PING",
    "GOAWAY",
    "WINDOW_UPDATE",
    "CONTINUATION",
)


def _identifier(value: Any) -> str | None:
    return value if isinstance(value, str) and _ID.fullmatch(value) else None


def _number(value: Any) -> int | float | None:
    if type(value) in (int, float) and 0 <= value <= 10**12 and math.isfinite(value):
        return value
    return None


def exception_details(error: BaseException | None) -> list[dict]:
    """Keep types/codes, never str(error), URLs, headers, or GOAWAY debug data."""
    result = []
    seen = set()
    while isinstance(error, BaseException) and id(error) not in seen and len(result) < 4:
        seen.add(id(error))
        item: dict[str, Any] = {"type": type(error).__name__[:64]}
        errno = getattr(error, "errno", None)
        if type(errno) is int:
            item["errno"] = errno
        # httpx maps errors with `raise mapped(message) from httpcore_error`.
        # The cause retains the h2 event object; its repr can contain peer data.
        for event in error.args[:2]:
            if type(event).__module__ != "h2.events":
                continue
            if type(event).__name__ not in {"StreamReset", "ConnectionTerminated"}:
                continue
            item["h2_event"] = type(event).__name__
            for key in ("stream_id", "error_code", "last_stream_id"):
                value = getattr(event, key, None)
                if isinstance(value, int) and not isinstance(value, bool):
                    item[key] = int(value)
            value = getattr(event, "remote_reset", None)
            if type(value) is bool:
                item["remote_reset"] = value
        result.append(item)
        error = error.__cause__ or error.__context__
    return result


def _emit(kind: str, fields: dict) -> None:
    # Diagnostics must never turn a logging/serialization failure into a failed API call.
    try:
        logger.info(
            "event=stream_diagnostic %s",
            json.dumps(
                {"kind": kind, **fields},
                separators=(",", ":"),
                allow_nan=False,
            ),
        )
    except Exception:
        pass


@dataclass
class Wait:
    started: float | None = None
    completed: float | None = None
    total: float = 0
    maximum: float = 0
    count: int = 0
    size: int = 0
    reported: bool = False

    def end(self, now: float, size: int = 0) -> None:
        if self.started is None:
            return
        elapsed = max(0, now - self.started)
        self.total += elapsed
        self.maximum = max(self.maximum, elapsed)
        self.count += 1
        self.size += size
        self.started = None
        self.completed = now

    def snapshot(self, now: float) -> dict:
        return {
            "count": self.count,
            "bytes": self.size,
            "total_ms": round(self.total * 1000),
            "max_ms": round(self.maximum * 1000),
            "active_ms": round(max(0, now - self.started) * 1000)
            if self.started is not None
            else 0,
            "last_completed_ms_ago": round(max(0, now - self.completed) * 1000)
            if self.completed is not None
            else None,
        }


class StreamRecord:
    def __init__(
        self,
        owner: StreamDiagnostics,
        key: int,
        route: str,
        client_port: int | None,
        http_version: str | None,
    ):
        self.owner, self.key, self.route = owner, key, route
        self.started = owner.clock()
        self.ended: float | None = None
        self.request_id: str | None = None
        self.client_request_id: str | None = None
        self.client_port = client_port if type(client_port) is int else None
        self.client_http_version = (
            http_version if http_version in {"1.0", "1.1", "2", "3"} else None
        )
        self.waits: dict[str, Wait] = {}
        self.events: deque = deque(maxlen=16)
        self.attempts: deque = deque(maxlen=4)
        self.attempt = 0
        self.timeouts: dict = {}
        self.stream_id: int | None = None
        self.connection_id: str | None = None
        self.upstream_http_version: str | None = None
        self.upstream_ids: dict = {}
        self.http_status: int | None = None
        self.error: list = []
        self.errors: deque = deque(maxlen=4)
        self.http2_settings: dict = {}
        self.disconnected = False
        self.reason: str | None = None

    def bind_request(self, request_id: str) -> None:
        self.request_id = _identifier(request_id)

    def bind_client_request_id(self, value: str) -> None:
        if isinstance(value, str) and len(value) <= 64:
            try:
                self.client_request_id = str(UUID(value))
            except ValueError:
                pass

    def wait_start(self, name: str) -> None:
        if name in _PHASES:
            self.waits.setdefault(name, Wait()).started = self.owner.clock()

    def wait_end(self, name: str, size: int = 0, exception: BaseException | None = None) -> None:
        wait = self.waits.get(name)
        if wait is not None:
            wait.end(self.owner.clock(), size if type(size) is int and size >= 0 else 0)
            self._slow(name, wait)
        if exception is not None:
            self.observe_exception(exception)

    def _slow(self, name: str, wait: Wait) -> None:
        now = self.owner.clock()
        duration = max(wait.maximum, now - wait.started if wait.started is not None else 0)
        if duration >= _SLOW_SECONDS and not wait.reported:
            wait.reported = True
            _emit(
                "slow",
                {
                    "record_id": self.key,
                    "request_id": self.request_id,
                    "connection_id": self.connection_id,
                    "stream_id": self.stream_id,
                    "phase": name,
                    "duration_ms": round(duration * 1000),
                },
            )

    def mark_disconnected(self) -> None:
        self.disconnected = True

    def observe_exception(self, exception: BaseException) -> None:
        details = exception_details(exception)
        if not self.errors or self.errors[-1]["error"] != details:
            self.errors.append(
                {"at_ms": self._elapsed(), "attempt": self.attempt, "error": details}
            )
        # A disconnect can cancel cleanup after the useful transport failure.
        # Keep both in history without replacing the actual failure with teardown.
        if self.error and isinstance(exception, (GeneratorExit, asyncio.CancelledError)):
            return
        self.error = details
        if self.attempts:
            self.attempts[-1]["error"] = self.error

    def start_attempt(self, attempt: int, timeouts: dict) -> None:
        self.attempt = attempt
        self.error = []
        self.stream_id = None
        self.connection_id = None
        self.upstream_ids = {}
        self.http2_settings = {}
        self.timeouts = {
            key: value
            for key, value in timeouts.items()
            if key in {"connect", "read", "write", "pool"}
            and (value is None or _number(value) is not None)
        }
        self.attempts.append({"attempt": attempt, "at_ms": self._elapsed()})

    def retry(self, delay_ms: float) -> None:
        if self.attempts and _number(delay_ms) is not None:
            self.attempts[-1]["retry_delay_ms"] = round(delay_ms)

    def _elapsed(self) -> int:
        return round(max(0, self.owner.clock() - self.started) * 1000)

    async def trace(self, name: str, info: dict) -> None:
        # Trace info includes complete requests/headers. Select scalar fields only.
        parts = name.split(".")
        if len(parts) != 3 or parts[0] not in {"connection", "http11", "http2"}:
            return
        _, phase, outcome = parts
        if phase not in _PHASES or outcome not in {"started", "complete", "failed"}:
            return
        stream_id = info.get("stream_id")
        if type(stream_id) is int:
            self.stream_id = stream_id
            if self.attempts:
                self.attempts[-1]["stream_id"] = stream_id
        event = {
            "phase": phase,
            "outcome": outcome,
            "at_ms": self._elapsed(),
            "attempt": self.attempt,
        }
        if outcome == "started":
            self.wait_start(phase)
        else:
            error = info.get("exception")
            self.wait_end(phase, exception=error if isinstance(error, BaseException) else None)
            if isinstance(error, BaseException):
                event["error_type"] = type(error).__name__[:64]
            if phase in {"connect_tcp", "start_tls"}:
                self._bind_connection(info.get("return_value"))
            if phase == "receive_response_headers" and outcome == "complete":
                value = info.get("return_value")
                if isinstance(value, tuple) and value and type(value[0]) is int and self.attempts:
                    self.attempts[-1]["status"] = value[0]
            if phase == "receive_remote_settings" and outcome == "complete":
                settings = getattr(info.get("return_value"), "changed_settings", {})
                if isinstance(settings, dict):
                    values = {}
                    for key, setting in settings.items():
                        value = getattr(setting, "new_value", None)
                        if key in _H2_SETTINGS and type(value) is int and 0 <= value <= 2**32 - 1:
                            values[_H2_SETTINGS[key]] = value
                    self.http2_settings.update(values)
                    connection = self.owner.connections.get(self.connection_id)
                    if connection is not None:
                        connection.http2_settings.update(values)
                    event["remote_settings"] = dict(self.http2_settings)
        self.events.append(event)

    def _bind_connection(self, stream: Any) -> None:
        if stream is None:
            return
        try:
            value = stream.get_extra_info("headroom_connection_id")
        except Exception:
            value = None
        self.connection_id = _identifier(value) or f"{os.getpid()}-network-{id(stream):x}"
        connection = self.owner.connections.get(self.connection_id)
        if connection is not None:
            self.http2_settings.update(connection.http2_settings)
        if self.attempts:
            self.attempts[-1]["connection_id"] = self.connection_id

    def response(self, response: Any) -> None:
        extensions = getattr(response, "extensions", {})
        if not isinstance(extensions, dict):
            extensions = {}
        version = extensions.get("http_version")
        if isinstance(version, bytes):
            version = version.decode("ascii", errors="replace")
        if version in {"HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/3"}:
            self.upstream_http_version = version
        if type(extensions.get("stream_id")) is int:
            self.stream_id = extensions["stream_id"]
        self._bind_connection(extensions.get("network_stream"))
        self.http_status = response.status_code if type(response.status_code) is int else None
        for key in ("request-id", "x-request-id", "anthropic-request-id", "cf-ray"):
            value = _identifier(response.headers.get(key))
            if value is not None:
                self.upstream_ids[key] = value
        if self.attempts:
            self.attempts[-1].update(
                status=self.http_status, connection_id=self.connection_id, stream_id=self.stream_id
            )
        _emit(
            "headers",
            {
                "record_id": self.key,
                "request_id": self.request_id,
                "attempt": self.attempt,
                "connection_id": self.connection_id,
                "stream_id": self.stream_id,
                "http_version": self.upstream_http_version,
                "status": self.http_status,
                "upstream_ids": self.upstream_ids,
            },
        )

    async def iter_chunks(self, chunks):
        source = chunks.__aiter__()
        while True:
            self.wait_start("upstream_read")
            try:
                chunk = await anext(source)
            except StopAsyncIteration:
                self.wait_end("upstream_read")
                return
            except BaseException as error:
                self.wait_end("upstream_read", exception=error)
                raise
            self.wait_end("upstream_read", size=len(chunk))
            yield chunk

    def snapshot(self) -> dict:
        now = self.ended if self.ended is not None else self.owner.clock()
        for name, wait in self.waits.items():
            self._slow(name, wait)
        connection = self.owner.connections.get(self.connection_id)
        if connection is not None:
            self.http2_settings.update(connection.http2_settings)
        return {
            "record_id": self.key,
            "pid": os.getpid(),
            "route": self.route,
            "request_id": self.request_id,
            "client_request_id": self.client_request_id,
            "client_port": self.client_port,
            "client_http_version": self.client_http_version,
            "age_ms": round(max(0, now - self.started) * 1000),
            "connection_id": self.connection_id,
            "stream_id": self.stream_id,
            "upstream_http_version": self.upstream_http_version,
            "status": self.http_status,
            "upstream_ids": dict(self.upstream_ids),
            "attempt": self.attempt,
            "attempts": list(self.attempts),
            "timeouts": dict(self.timeouts),
            "disconnected": self.disconnected,
            "reason": self.reason,
            "error": list(self.error),
            "errors": list(self.errors),
            "http2_settings": dict(self.http2_settings),
            "waits": {name: wait.snapshot(now) for name, wait in self.waits.items()},
            "events": list(self.events),
        }


class ConnectionRecord:
    def __init__(self, owner: StreamDiagnostics, key: str):
        self.owner, self.key = owner, key
        self.started = owner.clock()
        self.waits: dict[str, Wait] = {}
        self.closed = False
        self.error: list = []
        self.addresses: dict = {}
        self.timeouts: dict = {}
        self.last_read_at: float | None = None
        self.last_write_at: float | None = None
        self.http2_settings: dict = {}
        self.http2_local_settings: dict = {}
        self.http2_observers: dict = {}
        self.http2_events: deque = deque(maxlen=32)
        self.http2_frame_counts = {"inbound": {}, "outbound": {}}
        self.http2_data_bytes = {"inbound": 0, "outbound": 0}
        self.http2_window_increments = {
            "inbound": {"connection": 0, "streams": 0},
            "outbound": {"connection": 0, "streams": 0},
        }
        self.http2_metadata_omitted = 0
        self.http2_observer_errors = 0

    def observe_http2(self, direction: str, data: bytes) -> None:
        observer = self.http2_observers.get(direction)
        if observer is None:
            observer = self.http2_observers[direction] = H2FrameObserver(self, direction)
        try:
            observer.feed(data)
        except Exception:
            # Observation must never interfere with the underlying transport.
            observer.disabled = True
            observer.header.clear()
            observer.payload.clear()
            self.http2_observer_errors += 1

    def start(self, name: str, timeout=None) -> None:
        self.waits.setdefault(name, Wait()).started = self.owner.clock()
        self.timeouts[name] = _number(timeout)

    def end(self, name: str, size: int = 0, error: BaseException | None = None) -> None:
        self.waits[name].end(self.owner.clock(), size)
        if size and name == "socket_read":
            self.last_read_at = self.owner.clock()
        if size and name == "socket_write":
            self.last_write_at = self.owner.clock()
        if error is not None:
            self.error = exception_details(error)

    def snapshot(self) -> dict:
        now = self.owner.clock()
        waits = {name: wait.snapshot(now) for name, wait in self.waits.items()}
        for name, wait in self.waits.items():
            duration = max(waits[name]["active_ms"], waits[name]["max_ms"])
            if duration >= _SLOW_SECONDS * 1000 and not wait.reported:
                wait.reported = True
                _emit(
                    "socket_slow",
                    {"connection_id": self.key, "phase": name, "duration_ms": duration},
                )
        return {
            "connection_id": self.key,
            "age_ms": round((now - self.started) * 1000),
            "closed": self.closed,
            "error": self.error,
            **self.addresses,
            "timeouts": dict(self.timeouts),
            "last_read_ms_ago": round((now - self.last_read_at) * 1000)
            if self.last_read_at is not None
            else None,
            "last_write_ms_ago": round((now - self.last_write_at) * 1000)
            if self.last_write_at is not None
            else None,
            "read_bytes": waits.get("socket_read", {}).get("bytes", 0),
            "write_bytes": waits.get("socket_write", {}).get("bytes", 0),
            "waits": waits,
            "http2": {
                "remote_settings": dict(self.http2_settings),
                "local_settings": dict(self.http2_local_settings),
                "frame_counts": {
                    key: dict(value) for key, value in self.http2_frame_counts.items()
                },
                "data_payload_bytes": dict(self.http2_data_bytes),
                "window_update_increments": {
                    key: dict(value) for key, value in self.http2_window_increments.items()
                },
                "recent_frames": list(self.http2_events),
                "metadata_omitted_frames": self.http2_metadata_omitted,
                "observer_errors": self.http2_observer_errors,
                "buffered_bytes": sum(
                    len(item.header) + len(item.payload) for item in self.http2_observers.values()
                ),
                "pending_frames": [
                    {**item.frame, "remaining_payload_bytes": item.remaining}
                    for item in self.http2_observers.values()
                    if item.frame is not None
                ],
            },
        }


class H2FrameObserver:
    """Read framing metadata only; payloads are skipped without retaining bytes."""

    def __init__(self, state: ConnectionRecord, direction: str):
        self.state, self.direction = state, direction
        self.preface_position = 0 if direction == "outbound" else len(_H2_PREFACE)
        self.header = bytearray()
        self.payload = bytearray()
        self.frame: dict | None = None
        self.remaining = 0
        self.capture = 0
        self.disabled = False

    def feed(self, data: bytes) -> None:
        if self.disabled:
            return
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            if self.preface_position < len(_H2_PREFACE):
                size = min(len(view) - offset, len(_H2_PREFACE) - self.preface_position)
                if (
                    view[offset : offset + size]
                    != _H2_PREFACE[self.preface_position : self.preface_position + size]
                ):
                    self.disabled = True
                    self.state.http2_observer_errors += 1
                    return
                self.preface_position += size
                offset += size
                continue
            if self.frame is None:
                size = min(9 - len(self.header), len(view) - offset)
                self.header.extend(view[offset : offset + size])
                offset += size
                if len(self.header) < 9:
                    continue
                length = int.from_bytes(self.header[:3], "big")
                kind, flags = self.header[3:5]
                self.frame = {
                    "direction": self.direction,
                    "at_ms": round((self.state.owner.clock() - self.state.started) * 1000),
                    "type": kind,
                    "flags": flags,
                    "stream_id": int.from_bytes(self.header[5:9], "big") & 0x7FFFFFFF,
                    "length": length,
                }
                self.header.clear()
                self.remaining = length
                self.capture = 0
                if kind in {3, 8} and length == 4:
                    self.capture = 4
                elif kind == 7 and length >= 8:
                    self.capture = 8
                elif kind == 4 and not flags & 1 and length % 6 == 0:
                    # ponytail: skip SETTINGS over 256 bytes; incremental tuple parsing if a peer needs more.
                    if length <= 256:
                        self.capture = length
                    else:
                        self.frame["metadata_omitted"] = True
                        self.state.http2_metadata_omitted += 1
                if not self.remaining:
                    self._finish()
                    continue
            size = min(self.remaining, len(view) - offset)
            capture_size = min(size, self.capture - len(self.payload))
            if capture_size:
                self.payload.extend(view[offset : offset + capture_size])
            offset += size
            self.remaining -= size
            if not self.remaining:
                self._finish()

    def _finish(self) -> None:
        event = self.frame
        assert event is not None
        kind = event["type"]
        name = _H2_FRAME_NAMES[kind] if kind < len(_H2_FRAME_NAMES) else "UNKNOWN"
        counts = self.state.http2_frame_counts[self.direction]
        counts[name] = counts.get(name, 0) + 1
        if kind == 0:
            self.state.http2_data_bytes[self.direction] += event["length"]
        elif kind == 3 and len(self.payload) == 4:
            event["error_code"] = int.from_bytes(self.payload, "big")
        elif kind == 7 and len(self.payload) == 8:
            event["last_stream_id"] = int.from_bytes(self.payload[:4], "big") & 0x7FFFFFFF
            event["error_code"] = int.from_bytes(self.payload[4:], "big")
            event["debug_data_length"] = event["length"] - 8
        elif kind == 8 and len(self.payload) == 4:
            increment = int.from_bytes(self.payload, "big") & 0x7FFFFFFF
            event["increment"] = increment
            key = "streams" if event["stream_id"] else "connection"
            self.state.http2_window_increments[self.direction][key] += increment
        elif kind == 4 and self.payload:
            values = {}
            for offset in range(0, len(self.payload), 6):
                key = int.from_bytes(self.payload[offset : offset + 2], "big")
                if key in _H2_SETTINGS:
                    values[_H2_SETTINGS[key]] = int.from_bytes(
                        self.payload[offset + 2 : offset + 6], "big"
                    )
            settings = (
                self.state.http2_settings
                if self.direction == "inbound"
                else self.state.http2_local_settings
            )
            settings.update(values)
            event["settings"] = values
        self.state.http2_events.append(event)
        if kind in {3, 7}:
            _emit("h2_control", {"connection_id": self.state.key, **event})
        self.payload.clear()
        self.frame = None


class StreamDiagnostics:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.sequence = 0
        self.connection_sequence = 0
        self.active: dict[int, StreamRecord] = {}
        self.recent: deque = deque(maxlen=_LIMIT)
        self.connections: OrderedDict[str, ConnectionRecord] = OrderedDict()
        self.omitted_records = 0
        self.omitted_connections = 0

    def begin(self, route, *, client_port=None, http_version=None) -> StreamRecord:
        self.sequence += 1
        record = StreamRecord(
            self,
            self.sequence,
            route if route in {"codex", "claude"} else "other",
            client_port,
            http_version,
        )
        if len(self.active) < _LIMIT:
            self.active[record.key] = record
        else:
            self.omitted_records += 1
        return record

    def end(self, record, reason, exception=None) -> None:
        if record.ended is not None:
            return
        if exception is not None:
            record.observe_exception(exception)
        record.ended = self.clock()
        record.reason = _identifier(reason)
        for wait in record.waits.values():
            wait.end(record.ended)
        self.active.pop(record.key, None)
        item = record.snapshot()
        self.recent.append(item)
        _emit("terminal", item)

    def connection(self) -> ConnectionRecord:
        self.connection_sequence += 1
        key = f"{os.getpid()}-c{self.connection_sequence}"
        result = ConnectionRecord(self, key)
        self.track_connection(result)
        return result

    def track_connection(self, record: ConnectionRecord) -> None:
        if record.key in self.connections:
            self.connections.move_to_end(record.key)
            return
        if len(self.connections) >= _LIMIT:
            referenced = {item.connection_id for item in self.active.values()}
            victim = next((key for key, item in self.connections.items() if item.closed), None)
            if victim is None:
                victim = next((key for key in self.connections if key not in referenced), None)
            self.omitted_connections += 1
            if victim is None:
                return  # Keep active evidence; never reject traffic at the diagnostic ceiling.
            del self.connections[victim]
        self.connections[record.key] = record

    def snapshot(self) -> dict:
        return {
            "active": [record.snapshot() for record in self.active.values()],
            "recent": list(self.recent),
            "connections": [record.snapshot() for record in self.connections.values()],
            "omitted_records": self.omitted_records,
            "omitted_connections": self.omitted_connections,
        }


diagnostics = StreamDiagnostics()


class InstrumentedStream(httpcore.AsyncNetworkStream):
    """Transparent delegate: retain lengths, timings and numeric HTTP/2 metadata."""

    def __init__(self, inner, owner=diagnostics, state=None):
        self.inner = inner
        self.state = state or owner.connection()
        for name in ("client_addr", "server_addr"):
            try:
                address = inner.get_extra_info(name)
                if isinstance(address, tuple) and len(address) >= 2:
                    host = str(ip_address(address[0]))
                    if type(address[1]) is int:
                        self.state.addresses[name] = [host, address[1]]
            except Exception:
                pass
        try:
            ssl = inner.get_extra_info("ssl_object")
            if ssl is not None:
                alpn, version = ssl.selected_alpn_protocol(), ssl.version()
                if alpn in {"h2", "http/1.1"}:
                    self.state.addresses["alpn"] = alpn
                if version in {"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"}:
                    self.state.addresses["tls_version"] = version
        except Exception:
            pass
        self.http2 = self.state.addresses.get("alpn") == "h2"

    async def read(self, max_bytes, timeout=None):
        self.state.start("socket_read", timeout)
        try:
            data = await self.inner.read(max_bytes, timeout=timeout)
        except BaseException as error:
            self.state.end("socket_read", error=error)
            raise
        self.state.end("socket_read", size=len(data))
        if self.http2:
            self.state.observe_http2("inbound", data)
        return data

    async def write(self, buffer, timeout=None):
        self.state.start("socket_write", timeout)
        try:
            result = await self.inner.write(buffer, timeout=timeout)
        except BaseException as error:
            self.state.end("socket_write", error=error)
            raise
        self.state.end("socket_write", size=len(buffer))
        if self.http2:
            self.state.observe_http2("outbound", buffer)
        return result

    async def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        self.state.start("start_tls", timeout)
        try:
            stream = await self.inner.start_tls(
                ssl_context,
                server_hostname=server_hostname,
                timeout=timeout,
            )
        except BaseException as error:
            self.state.end("start_tls", error=error)
            raise
        self.state.end("start_tls")
        return InstrumentedStream(stream, state=self.state)

    async def aclose(self):
        try:
            result = await self.inner.aclose()
        except BaseException as error:
            self.state.error = exception_details(error)
            _emit("socket_close_failed", self.state.snapshot())
            raise
        if not self.state.closed:
            self.state.closed = True
            _emit("socket_closed", self.state.snapshot())
        return result

    def get_extra_info(self, info):
        if info == "headroom_connection_id":
            self.state.owner.track_connection(self.state)
            return self.state.key
        return self.inner.get_extra_info(info)


def instrument_stream(stream):
    return stream if isinstance(stream, InstrumentedStream) else InstrumentedStream(stream)
