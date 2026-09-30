"""Observed Claude and Codex API health, without synthetic billable requests."""

from __future__ import annotations

import logging
import time
from collections import deque
from collections.abc import Callable
from typing import Any

from headroom.providers.openai_responses import OPENAI_RESPONSES_ROOT_PATHS

logger = logging.getLogger("headroom.proxy")
_WINDOW_SECONDS = 300
_FAILURES_TO_UNHEALTHY = 3
_TERMINAL_EVENTS = (b"response.completed", b"message_stop")


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

    def record(self, route: str, success: bool, reason: str, stream: dict[str, Any]) -> None:
        now = self.clock()
        outcomes = self._outcomes[route]
        outcomes.append((now, success, reason))
        self._last_stream[route] = stream
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
                "last_reason": outcomes[-1][2] if outcomes else None,
                "last_observed_seconds_ago": round(now - outcomes[-1][0], 3) if outcomes else None,
                "last_stream": self._last_stream[route] if outcomes else None,
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
                        terminal |= any(marker in window for marker in _TERMINAL_EVENTS)
                        error_event |= b"event: error" in window
                        event_tail = window[-32:]
                complete = not message.get("more_body", False)
            await send(message)

        try:
            await self.app(scope, receive, observe_send)
        except BaseException as exc:
            raised = exc
            raise
        finally:
            ended = self.health.clock()
            idle_ms = round((ended - last_byte_at) * 1000) if last_byte_at is not None else None
            if raised is not None:
                reason = "interrupted"
            elif status >= 400:
                reason = f"http_{status}"
            elif error_event:
                reason = "sse_error"
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
            if reason != "interrupted" or (idle_ms is not None and idle_ms >= 60_000):
                self.health.record(route, success, reason, stream)
            log = logger.info if success else logger.warning
            log(
                "event=route_stream_outcome route=%s reason=%s status=%s "
                "chunks=%s bytes=%s first_byte_ms=%s max_gap_ms=%s "
                "idle_at_end_ms=%s duration_ms=%s client_port=%s",
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
            )
