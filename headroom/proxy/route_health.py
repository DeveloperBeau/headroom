"""Observed Claude and Codex API health, without synthetic billable requests."""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from headroom.providers.openai_responses import OPENAI_RESPONSES_ROOT_PATHS
from headroom.proxy.upstream_diagnostics import current_stream, diagnostics

logger = logging.getLogger("headroom.proxy")
_WINDOW_SECONDS = 300
_FAILURES_TO_UNHEALTHY = 3
_TERMINAL_EVENTS = (b"event: response.completed", b"event: message_stop")


class LoopLagMonitor:
    """Bounded, payload-free event-loop scheduling diagnostics."""

    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self.clock = clock
        self._samples: deque[tuple[float, int]] = deque(maxlen=60)
        self._last_warning_at: float | None = None

    def tick(self, expected_at: float) -> None:
        now = self.clock()
        lag_ms = round(max(0, now - expected_at) * 1000)
        self._samples.append((now, lag_ms))
        if lag_ms >= 1000 and (self._last_warning_at is None or now - self._last_warning_at >= 60):
            self._last_warning_at = now
            logger.warning("event=proxy_loop_lag lag_ms=%s", lag_ms)

    def snapshot(self) -> dict[str, int | None]:
        now = self.clock()
        recent = [lag for observed_at, lag in self._samples if now - observed_at <= 60]
        return {
            "interval_ms": 1000,
            "window_seconds": 60,
            "samples": len(recent),
            "last_lag_ms": self._samples[-1][1] if self._samples else None,
            "max_lag_ms": max(recent) if recent else None,
            "heartbeat_age_ms": round((now - self._samples[-1][0]) * 1000)
            if self._samples
            else None,
        }

    async def run(self) -> None:
        while True:
            expected_at = self.clock() + 1
            await asyncio.sleep(1)
            self.tick(expected_at)


class ChunkTiming:
    """Payload-free timing for an upstream or downstream byte stream."""

    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self.clock = clock
        self.started = clock()
        self.first_at: float | None = None
        self.last_at: float | None = None
        self.chunks = 0
        self.bytes = 0
        self.max_gap_ms = 0

    def chunk(self, size: int) -> None:
        now = self.clock()
        if self.first_at is None:
            self.first_at = now
        if self.last_at is not None:
            self.max_gap_ms = max(self.max_gap_ms, round((now - self.last_at) * 1000))
        self.last_at = now
        self.chunks += 1
        self.bytes += size

    def summary(self) -> dict[str, int | None]:
        now = self.clock()
        return {
            "chunks": self.chunks,
            "bytes": self.bytes,
            "first_byte_ms": round((self.first_at - self.started) * 1000)
            if self.first_at is not None
            else None,
            "max_gap_ms": self.max_gap_ms,
            "idle_at_end_ms": round((now - self.last_at) * 1000)
            if self.last_at is not None
            else None,
            "duration_ms": round((now - self.started) * 1000),
        }


def _route(path: str) -> str | None:
    if path in ("/v1/messages", "/anthropic/v1/messages"):
        return "claude"
    if path in OPENAI_RESPONSES_ROOT_PATHS:
        return "codex"
    return None


class RouteHealth:
    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self.clock = clock
        self._outcomes: dict[str, deque[tuple[float, bool, str]]] = {
            "claude": deque(maxlen=4096),
            "codex": deque(maxlen=4096),
        }
        self._last_stream: dict[str, dict[str, Any] | None] = {"claude": None, "codex": None}
        self._last_reason: dict[str, str | None] = {"claude": None, "codex": None}
        self._last_observed_at: dict[str, str | None] = {"claude": None, "codex": None}
        self._last_observed_monotonic: dict[str, float | None] = {"claude": None, "codex": None}
        self._active: dict[str, dict[object, tuple[float, float]]] = {"claude": {}, "codex": {}}

    def begin(self, route: str) -> object:
        token = object()
        now = self.clock()
        self._active[route][token] = (now, now)
        return token

    def touch(self, route: str, token: object) -> None:
        started, _ = self._active[route][token]
        self._active[route][token] = (started, self.clock())

    def end(self, route: str, token: object) -> None:
        self._active[route].pop(token, None)

    def record(self, route: str, success: bool, reason: str, stream: dict[str, Any]) -> None:
        now = self.clock()
        outcomes = self._outcomes[route]
        outcomes.append((now, success, reason))
        self._last_stream[route] = stream
        self._last_reason[route] = reason
        self._last_observed_at[route] = datetime.now(timezone.utc).isoformat()
        self._last_observed_monotonic[route] = now
        self._prune(outcomes, now)

    def _prune(self, outcomes: deque[tuple[float, bool, str]], now: float) -> None:
        while outcomes and now - outcomes[0][0] > _WINDOW_SECONDS:
            outcomes.popleft()

    def snapshot(self) -> dict[str, dict[str, Any]]:
        now = self.clock()
        result = {}
        for route, outcomes in self._outcomes.items():
            self._prune(outcomes, now)
            failures = 0
            for _, success, _ in reversed(outcomes):
                if success:
                    break
                failures += 1
            state = (
                "unknown"
                if not outcomes
                else "healthy"
                if outcomes[-1][1]
                else "unhealthy"
                if failures >= _FAILURES_TO_UNHEALTHY
                else "degraded"
            )
            result[route] = {
                "state": state,
                "observations": len(outcomes),
                "consecutive_failures": failures,
                "last_reason": self._last_reason[route],
                "last_observed_at": self._last_observed_at[route],
                "last_observed_seconds_ago": round(now - self._last_observed_monotonic[route], 3)
                if self._last_observed_monotonic[route] is not None
                else None,
                "last_stream": self._last_stream[route],
                "active_requests": len(self._active[route]),
                "oldest_active_seconds": round(
                    max((now - started for started, _ in self._active[route].values()), default=0),
                    3,
                ),
                "longest_active_idle_seconds": round(
                    max((now - last for _, last in self._active[route].values()), default=0),
                    3,
                ),
            }
        return result


class RouteHealthMiddleware:
    def __init__(self, app: Any, health: RouteHealth):
        self.app = app
        self.health = health

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        route = _route(scope.get("path", "")) if scope.get("type") == "http" else None
        if route is None or scope.get("method") != "POST":
            await self.app(scope, receive, send)
            return

        started = self.health.clock()
        active_token = self.health.begin(route)
        diagnostic = diagnostics.begin(
            route,
            client_port=(scope.get("client") or (None, None))[1],
            http_version=scope.get("http_version"),
        )
        for name, value in scope.get("headers", ()):
            if name.lower() == b"x-client-request-id":
                if len(value) <= 64:
                    diagnostic.bind_client_request_id(value.decode("ascii", errors="replace"))
                break
        context_token = current_stream.set(diagnostic)
        status = 500
        is_sse = False
        complete = False
        terminal = False
        error_event = False
        chunks = 0
        byte_count = 0
        first_byte_at = None
        last_byte_at = None
        max_gap_ms = 0
        event_tail = b""
        raised: BaseException | None = None
        client_disconnected = False

        async def observe_receive() -> dict:
            nonlocal client_disconnected
            message = await receive()
            if message["type"] == "http.disconnect":
                client_disconnected = True
                diagnostic.mark_disconnected()
            return message

        async def observe_send(message: dict) -> None:
            nonlocal status, is_sse, complete, terminal, error_event
            nonlocal chunks, byte_count, first_byte_at, last_byte_at, max_gap_ms, event_tail
            if message["type"] == "http.response.start":
                status = message["status"]
                is_sse = any(
                    name.lower() == b"content-type"
                    and value.lower().startswith(b"text/event-stream")
                    for name, value in message.get("headers", ())
                )
            elif message["type"] == "http.response.body":
                body = message.get("body", b"")
                if body:
                    self.health.touch(route, active_token)
                    now = self.health.clock()
                    if first_byte_at is None:
                        first_byte_at = now
                    if last_byte_at is not None:
                        max_gap_ms = max(max_gap_ms, round((now - last_byte_at) * 1000))
                    last_byte_at = now
                    chunks += 1
                    byte_count += len(body)
                    if is_sse:
                        window = event_tail + body
                        lines = window.splitlines()
                        terminal |= any(line.strip() in _TERMINAL_EVENTS for line in lines)
                        error_event |= any(line.strip() == b"event: error" for line in lines)
                        event_tail = window[-64:]
                complete = not message.get("more_body", False)
            diagnostic.wait_start("downstream_send")
            try:
                await send(message)
            except BaseException as exc:
                diagnostic.wait_end("downstream_send", exception=exc)
                raise
            else:
                diagnostic.wait_end("downstream_send", size=len(message.get("body", b"")))

        try:
            await self.app(scope, observe_receive, observe_send)
        except BaseException as exc:
            raised = exc
            raise
        finally:
            current_stream.reset(context_token)
            self.health.end(route, active_token)
            ended = self.health.clock()
            idle_ms = round((ended - last_byte_at) * 1000) if last_byte_at is not None else None
            if raised is not None:
                reason = "interrupted"
            elif status >= 400:
                reason = f"http_{status}"
            elif error_event:
                reason = "sse_error"
            elif client_disconnected and not terminal:
                reason = "interrupted"
            elif not complete or (is_sse and not terminal):
                reason = "missing_terminal_event"
            else:
                reason = "completed"
            success = reason == "completed"
            stream = {
                "http_status": status,
                "sse": is_sse,
                "chunks": chunks,
                "bytes": byte_count,
                "first_byte_ms": round((first_byte_at - started) * 1000)
                if first_byte_at is not None
                else None,
                "max_gap_ms": max_gap_ms,
                "idle_at_end_ms": idle_ms,
                "duration_ms": round((ended - started) * 1000),
            }
            # Short client cancellations are routine. Keep metrics, but do not
            # declare the provider unhealthy unless the stream stalled first.
            quiet_ms = idle_ms if idle_ms is not None else round((ended - started) * 1000)
            if reason != "interrupted" or quiet_ms >= 60_000:
                self.health.record(route, success, reason, stream)
            diagnostics.end(diagnostic, reason, exception=raised)
            log = logger.info if success else logger.warning
            log(
                "event=route_stream_outcome route=%s reason=%s status=%s "
                "chunks=%s bytes=%s first_byte_ms=%s max_gap_ms=%s "
                "idle_at_end_ms=%s duration_ms=%s client_port=%s record_id=%s request_id=%s",
                route,
                reason,
                status,
                chunks,
                byte_count,
                stream["first_byte_ms"],
                max_gap_ms,
                idle_ms,
                stream["duration_ms"],
                (scope.get("client") or (None, None))[1],
                diagnostic.key,
                diagnostic.request_id,
            )
