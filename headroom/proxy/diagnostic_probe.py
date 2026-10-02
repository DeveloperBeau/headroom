"""Explicit, bounded HTTP transport comparisons; emit metadata only."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import ipaddress
import json
import math
import os
import re
import ssl
import stat
import time
from datetime import datetime, timezone
from uuid import uuid4

import httpx

_MAX_BODY = 1024 * 1024
_MAX_LINE = 64 * 1024
_TERMINALS = {"message_stop", "response.completed"}
_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9_.:/-]{1,160}\Z")
_PROVIDER_IDS = ("request-id", "x-request-id", "anthropic-request-id", "cf-ray")


class ProbeInputError(ValueError):
    """Input rejected without echoing supplied values."""


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ProbeInputError()


def _read(path: str, limit: int, *, private: bool = False) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as file:
        info = os.fstat(file.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ProbeInputError()
        if private and os.name == "posix" and info.st_mode & 0o077:
            raise ProbeInputError()
        result = file.read(limit + 1)
        if len(result) > limit:
            raise ProbeInputError()
        return result


def _endpoint(path: str, allow_http: bool) -> httpx.URL:
    text = _read(path, 8192).decode("utf-8").strip()
    if not text or any(ord(char) < 33 or ord(char) == 127 for char in text) or "#" in text:
        raise ProbeInputError()
    url = httpx.URL(text)
    if url.scheme not in {"https", "http"} or not url.host or url.userinfo:
        raise ProbeInputError()
    if url.port is not None and not 1 <= url.port <= 65535:
        raise ProbeInputError()
    if url.scheme == "http":
        if not allow_http:
            raise ProbeInputError()
        try:
            if not ipaddress.ip_address(url.host).is_loopback:
                raise ProbeInputError()
        except ValueError:
            raise ProbeInputError() from None
    return url


def _headers(path: str | None) -> dict[str, str]:
    if path is None:
        return {}
    result = json.loads(_read(path, 16 * 1024, private=True))
    if not isinstance(result, dict) or len(result) > 64:
        raise ProbeInputError()
    names = set()
    for name, value in result.items():
        if not isinstance(name, str) or not _HEADER_NAME.fullmatch(name):
            raise ProbeInputError()
        lower = name.lower()
        if lower in names or lower in {"host", "content-length", "transfer-encoding", "connection"}:
            raise ProbeInputError()
        names.add(lower)
        if not isinstance(value, str) or any(ord(char) < 32 or ord(char) > 126 for char in value):
            raise ProbeInputError()
    return result


def load_options(argv: list[str] | None = None) -> dict:
    parser = _Parser(prog="headroom-diagnostic-probe", description=__doc__)
    parser.add_argument("--endpoint-file", required=True)
    parser.add_argument("--request-file", required=True)
    parser.add_argument("--headers-file")
    parser.add_argument("--proxy-endpoint-file")
    parser.add_argument("--proxy-headers-file")
    parser.add_argument("--ca-file")
    parser.add_argument("--method", choices=("POST", "GET"), default="POST")
    parser.add_argument("--count", type=int, default=2, help="requests per matrix cell, 1..5")
    parser.add_argument("--timeout", type=float, default=30, help="seconds per request, 1..60")
    parser.add_argument("--max-seconds", type=float, default=120, help="whole-run budget, 1..300")
    parser.add_argument("--max-response-bytes", type=int, default=_MAX_BODY)
    parser.add_argument("--allow-loopback-http", action="store_true")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--execute", action="store_true")
    args = vars(parser.parse_args(argv))
    if not 1 <= args["count"] <= 5 or not 1 <= args["max_response_bytes"] <= 32 * _MAX_BODY:
        raise ProbeInputError()
    for name, maximum in (("timeout", 60), ("max_seconds", 300)):
        if not math.isfinite(args[name]) or not 1 <= args[name] <= maximum:
            raise ProbeInputError()
    if args["proxy_headers_file"] and not args["proxy_endpoint_file"]:
        raise ProbeInputError()
    try:
        routes = [
            (
                "direct",
                _endpoint(args["endpoint_file"], args["allow_loopback_http"]),
                _headers(args["headers_file"]),
            )
        ]
        if args["proxy_endpoint_file"]:
            routes.append(
                (
                    "proxy",
                    _endpoint(args["proxy_endpoint_file"], args["allow_loopback_http"]),
                    _headers(args["proxy_headers_file"]),
                )
            )
        args["body"] = _read(args["request_file"], _MAX_BODY, private=True)
        args["routes"] = routes
        args["verify"] = ssl.create_default_context(cafile=args["ca_file"])
    except (OSError, ValueError, httpx.InvalidURL):
        raise ProbeInputError() from None
    return args


class _SSE:
    """Bound lines/events in memory and only recognize dispatched terminal events."""

    def __init__(self):
        self.line = bytearray()
        self.data = bytearray()
        self.event = None
        self.discard_line = False
        self.discard_event = False
        self.terminal = False
        self.limited = False
        self.skip_lf = False

    def feed(self, chunk: bytes) -> None:
        if self.skip_lf and chunk:
            if chunk.startswith(b"\n"):
                chunk = chunk[1:]
            self.skip_lf = False
        for piece in chunk.splitlines(keepends=True):
            # A bare CR is accepted as a line terminator by SSE, as is LF/CRLF.
            ended = piece.endswith((b"\n", b"\r"))
            if len(self.line) + len(piece) > _MAX_LINE:
                self.discard_line = self.discard_event = self.limited = True
                self.line.clear()
            if not self.discard_line:
                self.line.extend(piece)
            if ended:
                if not self.discard_line:
                    self._line(bytes(self.line).rstrip(b"\r\n"))
                self.line.clear()
                self.discard_line = False
        if chunk.endswith(b"\r"):
            self.skip_lf = True

    def _line(self, line: bytes) -> None:
        if not line:
            if not self.discard_event and self.data:
                terminal = self.event in _TERMINALS or self.data.strip() == b"[DONE]"
                if not terminal and self.data:
                    try:
                        value = json.loads(self.data)
                        kind = value.get("type") if isinstance(value, dict) else None
                        terminal = isinstance(kind, str) and kind in _TERMINALS
                    except (ValueError, RecursionError):
                        pass
                self.terminal |= terminal
            self.data.clear()
            self.event = None
            self.discard_event = False
        elif line.startswith(b"event:"):
            value = line[6:]
            if value.startswith(b" "):
                value = value[1:]
            self.event = (
                value.decode("ascii") if value in {b"message_stop", b"response.completed"} else None
            )
        elif line.startswith(b"data:") and not self.discard_event:
            value = line[5:]
            if value.startswith(b" "):
                value = value[1:]
            if len(self.data) + len(value) + 1 > _MAX_LINE:
                self.discard_event = self.limited = True
                self.data.clear()
            else:
                self.data.extend(value + b"\n")


def _error_type(error: BaseException) -> str:
    for cls in (
        httpx.ConnectTimeout,
        httpx.ReadTimeout,
        httpx.WriteTimeout,
        httpx.PoolTimeout,
        httpx.ConnectError,
        httpx.ReadError,
        httpx.WriteError,
        httpx.RemoteProtocolError,
        httpx.LocalProtocolError,
        httpx.DecodingError,
        asyncio.TimeoutError,
        asyncio.CancelledError,
    ):
        if isinstance(error, cls):
            return cls.__name__
    return "unexpected_error"


async def _request(client, options, url, headers, row, connections) -> None:
    started = time.monotonic()
    request_headers = httpx.Headers(headers)
    request_headers["x-client-request-id"] = row["request_id"]
    request_headers["accept-encoding"] = "identity"
    request = client.build_request(
        options["method"], url, content=options["body"], headers=request_headers
    )
    response = await client.send(request, stream=True)
    failed = False
    try:
        row["headers_ms"] = round((time.monotonic() - started) * 1000)
        row["status"] = response.status_code
        version = response.extensions.get("http_version")
        if version in {b"HTTP/1.0", b"HTTP/1.1", b"HTTP/2", b"HTTP/3"}:
            row["negotiated_protocol"] = version.decode("ascii")
            row["protocol_matched"] = row["requested_protocol"] == row["negotiated_protocol"]
        stream = response.extensions.get("network_stream")
        if stream is not None:
            existing = next((i for i, item in enumerate(connections) if item is stream), None)
            row["connection_reused"] = existing is not None
            if existing is None:
                existing = len(connections)
                connections.append(
                    stream
                )  # At most 40 strong references; avoid recycled object IDs.
            row["connection_id"] = f"c{existing + 1}"
            row["connection_evidence"] = "network_stream_identity"
            try:
                tls = stream.get_extra_info("ssl_object")
                if tls is not None:
                    alpn, version = tls.selected_alpn_protocol(), tls.version()
                    if alpn in {"h2", "http/1.1"}:
                        row["alpn"] = alpn
                    if version in {"TLSv1.2", "TLSv1.3"}:
                        row["tls_version"] = version
            except Exception:
                pass
        stream_id = response.extensions.get("stream_id")
        if type(stream_id) is int and 0 <= stream_id <= 2**31 - 1:
            row["stream_id"] = stream_id
        row["provider_request_ids"] = {
            name: hashlib.sha256(value.encode("ascii")).hexdigest()[:24]
            for name in _PROVIDER_IDS
            if (value := response.headers.get(name)) is not None and _IDENTIFIER.fullmatch(value)
        }
        is_sse = (
            response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            == "text/event-stream"
        )
        can_parse = (
            is_sse and response.headers.get("content-encoding", "identity").lower() == "identity"
        )
        row["is_sse"] = is_sse
        row["sse_available"] = can_parse
        row["sse_terminal"] = False if can_parse else None
        parser = _SSE()
        async for chunk in response.aiter_raw():
            if row["first_byte_ms"] is None and chunk:
                row["first_byte_ms"] = round((time.monotonic() - started) * 1000)
            row["response_bytes"] += len(chunk)
            if row["response_bytes"] > options["max_response_bytes"]:
                row["outcome"] = "response_limit"
                return
            if can_parse:
                parser.feed(chunk)
                row["sse_terminal"] = parser.terminal
                row["sse_parser_limited"] = parser.limited
        row["outcome"] = (
            "redirect_blocked"
            if 300 <= response.status_code < 400
            else "http_error"
            if response.status_code >= 400
            else "sse_unavailable"
            if is_sse and not can_parse
            else "missing_terminal"
            if can_parse and not parser.terminal
            else "complete"
        )
    except BaseException:
        failed = True
        raise
    finally:
        try:
            await asyncio.wait_for(response.aclose(), timeout=1)
        except BaseException as error:
            row["response_cleanup_error_type"] = _error_type(error)
            if not failed:
                raise


async def compare(options: dict) -> dict:
    run_id = uuid4().hex
    result = {
        "run_id": run_id,
        "pid": os.getpid(),
        "started_at": datetime.now(timezone.utc).isoformat(),
        "dry_run": options["dry_run"],
        "planned_requests": len(options["routes"]) * 4 * options["count"],
        "count_per_cell": options["count"],
        "request_timeout_seconds": options["timeout"],
        "run_budget_seconds": options["max_seconds"],
        "max_response_bytes": options["max_response_bytes"],
        "routes": [name for name, _, _ in options["routes"]],
        "results": [],
        "completed": True,
    }
    if options["dry_run"]:
        return result
    deadline = time.monotonic() + options["max_seconds"]
    connections = []
    for route, url, headers in options["routes"]:
        for protocol in ("HTTP/1.1", "HTTP/2"):
            for mode in ("fresh", "reused"):
                client = None
                client_id = None
                for attempt in range(1, options["count"] + 1):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        result["completed"] = False
                        if client is not None:
                            try:
                                await asyncio.wait_for(client.aclose(), timeout=1)
                            except Exception:
                                pass
                        return result
                    started = time.monotonic()
                    row = {
                        "request_id": str(uuid4()),
                        "sequence": len(result["results"]) + 1,
                        "started_at": datetime.now(timezone.utc).isoformat(),
                        "route": route,
                        "requested_protocol": protocol,
                        "negotiated_protocol": None,
                        "protocol_matched": None,
                        "client_mode": mode,
                        "attempt": attempt,
                        "connection_id": None,
                        "connection_reused": None,
                        "connection_evidence": "unavailable",
                        "status": None,
                        "stream_id": None,
                        "alpn": None,
                        "tls_version": None,
                        "headers_ms": None,
                        "first_byte_ms": None,
                        "response_bytes": 0,
                        "sse_terminal": None,
                        "sse_parser_limited": False,
                    }
                    try:
                        if client is None:
                            client = httpx.AsyncClient(
                                http1=True,
                                http2=protocol == "HTTP/2",
                                verify=options["verify"],
                                trust_env=False,
                                follow_redirects=False,
                                timeout=options["timeout"],
                                limits=httpx.Limits(max_connections=1, max_keepalive_connections=1),
                            )
                            client_id = uuid4().hex
                        row["client_id"] = client_id
                        await asyncio.wait_for(
                            _request(client, options, url, headers, row, connections),
                            timeout=min(remaining, options["timeout"]),
                        )
                    except asyncio.TimeoutError:
                        row["outcome"] = (
                            "deadline" if remaining <= options["timeout"] else "timeout"
                        )
                        row["error_type"] = "TimeoutError"
                    except ImportError:
                        row["outcome"] = "dependency_unavailable"
                        row["error_type"] = "ImportError"
                    except asyncio.CancelledError:
                        row["outcome"] = "cancelled"
                        raise
                    except Exception as error:
                        row["outcome"] = "transport_error"
                        row["error_type"] = _error_type(error)
                    finally:
                        row["duration_ms"] = round((time.monotonic() - started) * 1000)
                        result["results"].append(row)
                        if client is not None and (
                            mode == "fresh"
                            or attempt == options["count"]
                            or row.get("outcome") in {"deadline", "cancelled"}
                        ):
                            try:
                                await asyncio.wait_for(client.aclose(), timeout=1)
                            except Exception as error:
                                row["cleanup_error_type"] = _error_type(error)
                            client = None
                    if row["outcome"] == "deadline":
                        result["completed"] = False
                        return result
    return result


def main(argv: list[str] | None = None) -> int:
    try:
        result = asyncio.run(compare(load_options(argv)))
    except ProbeInputError:
        print(json.dumps({"error": "invalid_input"}))
        return 2
    except KeyboardInterrupt:
        print(json.dumps({"error": "interrupted"}))
        return 130
    except Exception:
        print(json.dumps({"error": "probe_unavailable"}))
        return 1
    print(json.dumps(result, allow_nan=False))
    return (
        0
        if result["completed"] and all(row["outcome"] == "complete" for row in result["results"])
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
