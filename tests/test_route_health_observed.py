import importlib.metadata
import importlib.util
import os
import unittest
from unittest.mock import patch

from headroom.proxy.route_health import ChunkTiming, RouteHealth, RouteHealthMiddleware


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


async def deliver(health, path, chunks, *, status=200, content_type=b"text/event-stream"):
    async def app(scope, receive, send):
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [(b"content-type", content_type)],
            }
        )
        for index, chunk in enumerate(chunks):
            await send(
                {
                    "type": "http.response.body",
                    "body": chunk,
                    "more_body": index < len(chunks) - 1,
                }
            )

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        pass

    middleware = RouteHealthMiddleware(app, health)
    await middleware({"type": "http", "method": "POST", "path": path}, receive, send)


class RouteHealthTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        # Source checkout lacks the compiled extension; use the installed copy
        # when running this focused test against the local source tree.
        if importlib.util.find_spec("headroom._core") is None:
            import headroom

            installed = importlib.metadata.distribution("headroom-ai").locate_file("headroom")
            headroom.__path__.append(str(installed))

    async def test_upstream_timing_distinguishes_silence_after_chunks(self):
        clock = Clock()
        timing = ChunkTiming(clock=clock)
        clock.now = 1.5
        timing.chunk(100)
        clock.now = 2.0
        timing.chunk(20)
        clock.now = 302.0

        self.assertEqual(
            timing.summary(),
            {
                "chunks": 2,
                "bytes": 120,
                "first_byte_ms": 1500,
                "max_gap_ms": 500,
                "idle_at_end_ms": 300000,
                "duration_ms": 302000,
            },
        )

    async def test_server_exposes_provider_specific_health(self):
        from headroom.proxy.models import ProxyConfig
        from headroom.proxy.server import create_app

        app = create_app(ProxyConfig(optimize=False, cache_enabled=False))
        self.assertIsInstance(app.state.route_health, RouteHealth)
        self.assertIn("/health/routes", {route.path for route in app.routes})

    async def test_readyz_reports_failed_codex_route(self):
        from fastapi.testclient import TestClient
        from headroom.proxy.models import ProxyConfig
        from headroom.proxy.server import create_app

        with patch.dict(os.environ, {"HEADROOM_SKIP_UPSTREAM_CHECK": "1"}):
            app = create_app(ProxyConfig(optimize=False, cache_enabled=False))
            app.state.ready = True
            app.state.proxy.http_client = object()
            for _ in range(3):
                app.state.route_health.record("codex", False, "sse_error", {})
            response = TestClient(app).get("/readyz")

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["routes"]["codex"]["state"], "unhealthy")
        self.assertEqual(response.json()["routes"]["claude"]["state"], "unknown")

    async def test_incomplete_http_200_codex_stream_is_unhealthy(self):
        clock = Clock()
        health = RouteHealth(clock=clock)
        await deliver(health, "/responses", [b"event: response.created\n\n"])

        codex = health.snapshot()["codex"]
        self.assertEqual(codex["state"], "degraded")
        self.assertEqual(codex["last_reason"], "missing_terminal_event")
        self.assertEqual(health.snapshot()["claude"]["state"], "unknown")

    async def test_provider_health_uses_own_completed_streams(self):
        health = RouteHealth(clock=Clock())
        await deliver(health, "/responses", [b"event: response.completed\n\n"])
        await deliver(health, "/v1/messages", [b"event: error\ndata: {}\n\n"])

        self.assertEqual(health.snapshot()["codex"]["state"], "healthy")
        self.assertEqual(health.snapshot()["claude"]["state"], "degraded")

    async def test_terminal_words_in_generated_text_do_not_mark_success(self):
        health = RouteHealth(clock=Clock())
        await deliver(health, "/responses", [b'data: {"text":"response.completed message_stop"}\n\n'])
        self.assertEqual(health.snapshot()["codex"]["last_reason"], "missing_terminal_event")

    async def test_repeated_failures_trigger_unhealthy_then_expire(self):
        clock = Clock()
        health = RouteHealth(clock=clock)
        for _ in range(3):
            await deliver(health, "/responses", [b"event: error\n\n"])
        self.assertEqual(health.snapshot()["codex"]["state"], "unhealthy")

        clock.now += 301
        expired = health.snapshot()["codex"]
        self.assertEqual(expired["state"], "unknown")
        self.assertEqual(expired["last_reason"], "sse_error")
        self.assertEqual(expired["last_observed_seconds_ago"], 301)
        self.assertIsNotNone(expired["last_observed_at"])

    async def test_high_request_volume_keeps_health_history_bounded(self):
        health = RouteHealth(clock=Clock())
        for _ in range(5000):
            health.record("codex", True, "completed", {})
        self.assertLessEqual(health.snapshot()["codex"]["observations"], 4096)

    async def test_active_request_silence_is_visible_without_claiming_success(self):
        clock = Clock()
        health = RouteHealth(clock=clock)
        token = health.begin("codex")
        clock.now = 10
        health.touch("codex", token)
        clock.now = 310
        snapshot = health.snapshot()["codex"]
        self.assertEqual(snapshot["state"], "unknown")
        self.assertEqual(snapshot["active_requests"], 1)
        self.assertEqual(snapshot["oldest_active_seconds"], 310)
        self.assertEqual(snapshot["longest_active_idle_seconds"], 300)
        health.end("codex", token)
        self.assertEqual(health.snapshot()["codex"]["active_requests"], 0)

    async def test_chunk_gap_is_recorded_without_payload(self):
        clock = Clock()
        health = RouteHealth(clock=clock)

        async def app(scope, receive, send):
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [(b"content-type", b"text/event-stream")],
                }
            )
            await send(
                {
                    "type": "http.response.body",
                    "body": b"event: response.created\n\n",
                    "more_body": True,
                }
            )
            clock.now += 31
            await send(
                {
                    "type": "http.response.body",
                    "body": b"event: response.completed\n\n",
                    "more_body": False,
                }
            )

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            pass

        await RouteHealthMiddleware(app, health)(
            {"type": "http", "method": "POST", "path": "/responses"}, receive, send
        )
        self.assertEqual(health.snapshot()["codex"]["last_stream"]["max_gap_ms"], 31000)


if __name__ == "__main__":
    unittest.main()
