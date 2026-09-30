import asyncio
import importlib.metadata
import importlib.util
import unittest
from unittest.mock import AsyncMock, patch

from headroom.proxy import route_health


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class LoopLagTests(unittest.IsolatedAsyncioTestCase):
    def monitor(self, clock):
        self.assertTrue(hasattr(route_health, "LoopLagMonitor"), "loop lag is not recorded")
        return route_health.LoopLagMonitor(clock=clock)

    async def test_lag_and_stale_heartbeat_are_distinct(self):
        clock = Clock()
        monitor = self.monitor(clock)
        self.assertIsNone(monitor.snapshot()["heartbeat_age_ms"])
        clock.now = 2.5
        monitor.tick(expected_at=1.0)
        clock.now = 5.0
        snapshot = monitor.snapshot()
        self.assertEqual(snapshot["last_lag_ms"], 1500)
        self.assertEqual(snapshot["max_lag_ms"], 1500)
        self.assertEqual(snapshot["heartbeat_age_ms"], 2500)

    async def test_recent_lag_history_is_bounded_and_expires(self):
        clock = Clock()
        monitor = self.monitor(clock)
        for tick in range(100):
            clock.now = float(tick)
            monitor.tick(expected_at=clock.now - 0.25)
        self.assertLessEqual(monitor.snapshot()["samples"], 60)
        self.assertEqual(monitor.snapshot()["max_lag_ms"], 250)
        clock.now += 61
        self.assertEqual(monitor.snapshot()["samples"], 0)
        self.assertIsNone(monitor.snapshot()["max_lag_ms"])

    async def test_lag_warning_is_rate_limited(self):
        clock = Clock()
        monitor = self.monitor(clock)
        with patch.object(route_health.logger, "warning") as warning:
            for tick in (2.0, 4.0, 6.0, 63.0):
                clock.now = tick
                monitor.tick(expected_at=tick - 1.5)
        self.assertEqual(warning.call_count, 2)
        self.assertEqual(warning.call_args.args[0], "event=proxy_loop_lag lag_ms=%s")

    async def test_monitor_stops_on_cancellation(self):
        clock = Clock()
        monitor = self.monitor(clock)
        task = asyncio.create_task(monitor.run())
        await asyncio.sleep(0)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertTrue(task.done())


class StreamRuntimeEndpointTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        if importlib.util.find_spec("headroom._core") is None:
            import headroom

            installed = importlib.metadata.distribution("headroom-ai").locate_file("headroom")
            headroom.__path__.append(str(installed))

    def make_app(self):
        from headroom.proxy.models import ProxyConfig
        from headroom.proxy.server import create_app

        return create_app(ProxyConfig(optimize=False, cache_enabled=False))

    async def test_debug_snapshot_is_loopback_only_and_settings_are_allowlisted(self):
        from fastapi.testclient import TestClient

        app = self.make_app()
        self.assertIn("/debug/streams", {route.path for route in app.routes})
        client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 12345))
        app.state.proxy.config.http_proxy = "http://private_user:secret_password@example.test"
        response = client.get("/debug/streams")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("active", payload)
        self.assertIn("recent", payload)
        self.assertIn("event_loop", payload)
        self.assertIn("httpx", payload["runtime"]["libraries"])
        self.assertIn("http_client", payload["runtime"])
        self.assertNotIn("secret_password", response.text)
        self.assertNotIn("example.test", response.text)
        self.assertEqual(TestClient(app).get("/debug/streams").status_code, 404)

    async def test_failed_startup_cancels_heartbeat_task(self):
        app = self.make_app()
        with (
            patch("headroom.proxy.server._check_rust_core", return_value=("loaded", None)),
            patch.object(
                app.state.proxy, "startup", AsyncMock(side_effect=RuntimeError("startup failed"))
            ),
            patch.object(app.state.proxy, "shutdown", AsyncMock()),
        ):
            with self.assertRaisesRegex(RuntimeError, "startup failed"):
                async with app.router.lifespan_context(app):
                    self.fail("startup unexpectedly succeeded")
        self.assertTrue(hasattr(app.state, "loop_lag_task"), "heartbeat lifecycle is missing")
        self.assertIsNone(app.state.loop_lag_task)
        self.assertFalse(
            any(task.get_name() == "headroom-event-loop-lag" for task in asyncio.all_tasks())
        )


if __name__ == "__main__":
    unittest.main()
