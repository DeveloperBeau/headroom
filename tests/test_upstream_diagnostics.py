"""Payload-free streaming diagnostics preserve transport behavior."""

import asyncio
import json
import unittest

import httpcore
import httpx
from h2.events import StreamReset

from headroom.proxy.upstream_diagnostics import (
    InstrumentedStream,
    StreamDiagnostics,
    exception_details,
)


class Clock:
    now = 0.0

    def __call__(self):
        return self.now


class FakeStream(httpcore.AsyncNetworkStream):
    def __init__(self, clock):
        self.clock = clock
        self.calls = []
        self.failure = None

    async def read(self, max_bytes, timeout=None):
        self.calls.append(("read", max_bytes, timeout))
        self.clock.now += 4
        if self.failure:
            raise self.failure
        return b"private response"

    async def write(self, buffer, timeout=None):
        self.calls.append(("write", buffer, timeout))
        self.clock.now += 2

    async def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        self.calls.append(("tls", ssl_context, server_hostname, timeout))
        self.clock.now += 1
        return self

    async def aclose(self):
        self.calls.append(("close",))

    def get_extra_info(self, name):
        return {"client_addr": ("127.0.0.1", 4321), "server_addr": ("192.0.2.1", 443)}.get(name)


class DiagnosticsTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.clock = Clock()
        self.registry = StreamDiagnostics(clock=self.clock)
        self.record = self.registry.begin("codex", client_port=1234, http_version="1.1")

    async def test_read_wait_and_downstream_suspension_are_separate(self):
        async def source():
            self.clock.now += 4
            yield b"secret prompt"
            self.clock.now += 2
            yield b"secret output"

        iterator = self.record.iter_chunks(source())
        self.assertEqual(await anext(iterator), b"secret prompt")
        self.record.wait_start("downstream_yield")
        self.clock.now += 7
        self.record.wait_end("downstream_yield")
        self.assertEqual(await anext(iterator), b"secret output")
        await iterator.aclose()
        waits = self.registry.snapshot()["active"][0]["waits"]
        self.assertEqual(waits["upstream_read"]["total_ms"], 6000)
        self.assertEqual(waits["downstream_yield"]["total_ms"], 7000)
        self.assertNotIn("secret", json.dumps(self.registry.snapshot()))

    async def test_trace_and_response_keep_only_allowlisted_metadata(self):
        self.record.bind_request("hr_123_000001")
        self.record.start_attempt(1, {"read": 300, "connect": 10, "secret": "token"})
        await self.record.trace(
            "http2.send_request_headers.started",
            {
                "stream_id": 7,
                "request": {"Authorization": "SECRET"},
            },
        )
        self.clock.now += 0.25
        await self.record.trace("http2.send_request_headers.complete", {"return_value": None})
        stream = InstrumentedStream(FakeStream(self.clock), self.registry)
        response = httpx.Response(
            200,
            headers={
                "x-request-id": "req-123",
                "cf-ray": "123abc-MEL",
                "authorization": "SECRET",
                "set-cookie": "SECRET",
                "anthropic-request-id": "bad secret value",
            },
            extensions={"http_version": b"HTTP/2", "stream_id": 7, "network_stream": stream},
        )
        self.record.response(response)
        self.registry.end(self.record, "completed")
        item = self.registry.snapshot()["recent"][0]
        self.assertEqual(item["stream_id"], 7)
        self.assertEqual(item["upstream_ids"], {"x-request-id": "req-123", "cf-ray": "123abc-MEL"})
        self.assertEqual(item["timeouts"], {"read": 300, "connect": 10})
        self.assertNotIn("SECRET", json.dumps(item))
        self.assertNotIn("bad secret", json.dumps(item))

    async def test_typed_reset_chain_has_codes_but_no_exception_messages(self):
        reset = StreamReset(stream_id=19, error_code=1, remote_reset=True)
        cause = httpcore.RemoteProtocolError(reset)
        outer = httpx.RemoteProtocolError("Authorization=SECRET https://private/path")
        outer.__cause__ = cause
        data = exception_details(outer)
        encoded = json.dumps(data)
        self.assertIn('"stream_id": 19', encoded)
        self.assertIn('"error_code": 1', encoded)
        self.assertIn('"remote_reset": true', encoded)
        self.assertNotIn("SECRET", encoded)
        self.assertNotIn("private", encoded)

    async def test_socket_preserves_bytes_arguments_identity_and_cancellation(self):
        inner = FakeStream(self.clock)
        stream = InstrumentedStream(inner, self.registry)
        connection_id = stream.get_extra_info("headroom_connection_id")
        tls = await stream.start_tls("context", "host.example", 10)
        self.assertEqual(tls.get_extra_info("headroom_connection_id"), connection_id)
        self.assertEqual(await tls.read(4096, 300), b"private response")
        await tls.write(b"private prompt", 150)
        self.assertEqual(
            inner.calls[:3],
            [
                ("tls", "context", "host.example", 10),
                ("read", 4096, 300),
                ("write", b"private prompt", 150),
            ],
        )
        cancelled = asyncio.CancelledError()
        inner.failure = cancelled
        with self.assertRaises(asyncio.CancelledError) as caught:
            await tls.read(128, 2)
        self.assertIs(caught.exception, cancelled)
        await tls.aclose()
        snapshot = self.registry.snapshot()
        connection = snapshot["connections"][0]
        self.assertEqual(connection["read_bytes"], len(b"private response"))
        self.assertEqual(connection["write_bytes"], len(b"private prompt"))
        self.assertTrue(connection["closed"])
        self.assertNotIn("private", json.dumps(snapshot))

    async def test_overflow_retains_traffic_and_bounds_snapshots(self):
        records = [self.registry.begin("codex") for _ in range(400)]
        for record in records:
            record.wait_start("upstream_read")
            record.wait_end("upstream_read", size=3)
            self.registry.end(record, "completed")
        for _ in range(400):
            InstrumentedStream(FakeStream(self.clock), self.registry)
        snapshot = self.registry.snapshot()
        self.assertLessEqual(len(snapshot["active"]), 128)
        self.assertLessEqual(len(snapshot["recent"]), 128)
        self.assertLessEqual(len(snapshot["connections"]), 128)
        self.assertGreater(snapshot["omitted_records"], 0)
        self.assertGreater(snapshot["omitted_connections"], 0)

    async def test_inflight_wait_visible_and_cancelled_iterator_unwinds(self):
        started = asyncio.Event()

        async def source():
            started.set()
            await asyncio.sleep(100)
            yield b"never"

        iterator = self.record.iter_chunks(source())
        task = asyncio.create_task(anext(iterator))
        await started.wait()
        self.clock.now = 35
        state = self.registry.snapshot()["active"][0]
        self.assertEqual(state["waits"]["upstream_read"]["active_ms"], 35000)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(
            self.registry.snapshot()["active"][0]["waits"]["upstream_read"]["active_ms"], 0
        )

    async def test_reset_evidence_survives_cancelled_cleanup_and_settings_are_numeric(self):
        from h2.events import RemoteSettingsChanged
        from h2.settings import ChangedSetting, SettingCodes

        self.record.start_attempt(1, {})
        reset = httpcore.RemoteProtocolError(
            StreamReset(stream_id=19, error_code=1, remote_reset=True)
        )
        self.record.observe_exception(reset)
        self.record.observe_exception(asyncio.CancelledError("PRIVATE"))
        settings = RemoteSettingsChanged()
        settings.changed_settings[SettingCodes.INITIAL_WINDOW_SIZE] = ChangedSetting(
            SettingCodes.INITIAL_WINDOW_SIZE,
            65535,
            1048576,
        )
        await self.record.trace(
            "http2.receive_remote_settings.complete", {"return_value": settings}
        )
        self.registry.end(self.record, "cancelled", asyncio.CancelledError())
        record = self.registry.snapshot()["recent"][0]
        self.assertEqual(record["error"][0]["stream_id"], 19)
        self.assertEqual(record["errors"][-1]["error"][0]["type"], "CancelledError")
        self.assertEqual(record["http2_settings"], {"initial_window_size": 1048576})
        self.assertNotIn("PRIVATE", json.dumps(record))

    async def test_metadata_probe_failures_do_not_change_socket_traffic(self):
        stream = FakeStream(self.clock)

        def broken_metadata(name):
            raise OSError("private socket metadata")

        stream.get_extra_info = broken_metadata
        wrapped = InstrumentedStream(stream, self.registry)
        self.assertEqual(await wrapped.read(4096), b"private response")

    async def test_client_correlation_accepts_only_uuid(self):
        self.record.bind_client_request_id("Authorization: SECRET")
        self.assertIsNone(self.record.snapshot()["client_request_id"])
        self.record.bind_client_request_id("a" * 1000)
        self.assertIsNone(self.record.snapshot()["client_request_id"])
        self.record.bind_client_request_id("99b8ad3f-46f4-4ea9-9f52-dcd8ab9e74e7")
        self.assertEqual(
            self.record.snapshot()["client_request_id"], "99b8ad3f-46f4-4ea9-9f52-dcd8ab9e74e7"
        )

    async def test_full_snapshot_fits_watchdog_budget(self):
        # Saturate each bounded collection with maximum-length safe metadata.
        error = httpcore.RemoteProtocolError(
            StreamReset(stream_id=2**31 - 1, error_code=1, remote_reset=True)
        )
        for _ in range(3):
            parent = type("E" * 64, (Exception,), {})("NEVER_LOG_THIS")
            parent.__cause__ = error
            error = parent
        self.registry.end(self.record, "completed")
        for batch in range(2):
            records = [self.registry.begin("codex") for _ in range(64)]
            for record in records:
                record.bind_request("r" * 160)
                for attempt in range(4):
                    record.start_attempt(attempt + 1, {"read": 10**12})
                    record.observe_exception(error)
                    for _ in range(16):
                        await record.trace(
                            "http2.receive_response_headers.failed", {"exception": error}
                        )
                if batch == 0:
                    self.registry.end(record, "sse_error")
        for _ in range(64):
            InstrumentedStream(FakeStream(self.clock), self.registry)
        data = json.dumps(self.registry.snapshot()).encode()
        self.assertLess(len(data), 2 * 1024 * 1024)
        self.assertNotIn(b"NEVER_LOG_THIS", data)

    async def test_connection_churn_keeps_active_evidence_and_saturation_keeps_traffic(self):
        protected = InstrumentedStream(FakeStream(self.clock), self.registry)
        self.record.response(httpx.Response(200, extensions={"network_stream": protected}))
        for _ in range(200):
            InstrumentedStream(FakeStream(self.clock), self.registry)
        self.assertIn(self.record.connection_id, self.registry.connections)
        # Protect every retained connection, then demonstrate overflow is observational only.
        for state in list(self.registry.connections.values()):
            if state.key != self.record.connection_id:
                record = self.registry.begin("codex")
                record.connection_id = state.key
        before = set(self.registry.connections)
        extra = InstrumentedStream(FakeStream(self.clock), self.registry)
        self.assertEqual(await extra.read(4096), b"private response")
        self.assertEqual(set(self.registry.connections), before)

    async def test_cancelled_close_does_not_claim_socket_closed(self):
        inner = FakeStream(self.clock)
        cancelled = asyncio.CancelledError("PRIVATE")

        async def cancelled_close():
            raise cancelled

        inner.aclose = cancelled_close
        stream = InstrumentedStream(inner, self.registry)
        with self.assertRaises(asyncio.CancelledError) as caught:
            await stream.aclose()
        self.assertIs(caught.exception, cancelled)
        state = self.registry.snapshot()["connections"][0]
        self.assertFalse(state["closed"])
        self.assertEqual(state["error"][0]["type"], "CancelledError")
        self.assertNotIn("PRIVATE", json.dumps(state))

    async def test_opening_attempt_keeps_connection_and_stream_ids_across_retry(self):
        stream = InstrumentedStream(FakeStream(self.clock), self.registry)
        self.record.start_attempt(1, {})
        await self.record.trace("connection.connect_tcp.complete", {"return_value": stream})
        await self.record.trace("http2.send_request_headers.started", {"stream_id": 11})
        failure = httpcore.RemoteProtocolError(
            StreamReset(stream_id=11, error_code=1, remote_reset=True)
        )
        await self.record.trace("http2.send_request_headers.failed", {"exception": failure})
        self.record.start_attempt(2, {})
        failed = self.record.snapshot()["attempts"][0]
        self.assertEqual(failed["connection_id"], stream.get_extra_info("headroom_connection_id"))
        self.assertEqual(failed["stream_id"], 11)
        self.assertEqual(failed["error"][0]["stream_id"], 11)


if __name__ == "__main__":
    unittest.main()
