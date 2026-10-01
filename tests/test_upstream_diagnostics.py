"""Payload-free streaming diagnostics preserve transport behavior."""

import asyncio
import json
import unittest
from collections import deque
from types import SimpleNamespace

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


def h2_frame(kind, payload=b"", *, stream_id=0, flags=0):
    return (
        len(payload).to_bytes(3, "big")
        + bytes((kind, flags))
        + stream_id.to_bytes(4, "big")
        + payload
    )


class FakeH2Stream(FakeStream):
    def __init__(self, clock, chunks=(), alpn="h2"):
        super().__init__(clock)
        self.chunks = deque(chunks)
        self.alpn = alpn

    async def read(self, max_bytes, timeout=None):
        await super().read(max_bytes, timeout)
        return self.chunks.popleft() if self.chunks else b""

    def get_extra_info(self, name):
        if name == "ssl_object":
            return SimpleNamespace(
                selected_alpn_protocol=lambda: self.alpn, version=lambda: "TLSv1.3"
            )
        return super().get_extra_info(name)


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
        settings = b"".join(
            key.to_bytes(2, "big") + (2**32 - 1).to_bytes(4, "big")
            for key in (1, 2, 3, 4, 5, 6, 8, 9)
        )
        wire = h2_frame(4, settings) * 32
        for _ in range(64):
            stream = InstrumentedStream(FakeH2Stream(self.clock, [wire]), self.registry)
            await stream.read(len(wire))
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

    async def test_h2_controls_are_numeric_and_fragmented_frames_keep_boundaries(self):
        settings = (
            b"\x00\x03" + (100).to_bytes(4, "big") + b"\x00\x04" + (1048576).to_bytes(4, "big")
        )
        wire = (
            h2_frame(4, settings)
            + h2_frame(3, (1).to_bytes(4, "big"), stream_id=19)
            + h2_frame(8, (1024).to_bytes(4, "big"))
            + h2_frame(
                7, (19).to_bytes(4, "big") + (1).to_bytes(4, "big") + b"PRIVATE GOAWAY reason"
            )
        )
        chunks = [wire[:2], wire[2:11], wire[11:23], wire[23:]]
        stream = InstrumentedStream(FakeH2Stream(self.clock, chunks), self.registry)
        for chunk in chunks:
            self.assertEqual(await stream.read(4096, 300), chunk)
        connection = self.registry.snapshot()["connections"][0]
        h2 = connection["http2"]
        self.assertEqual(
            h2["remote_settings"], {"max_concurrent_streams": 100, "initial_window_size": 1048576}
        )
        self.assertEqual(
            h2["frame_counts"]["inbound"],
            {"SETTINGS": 1, "RST_STREAM": 1, "WINDOW_UPDATE": 1, "GOAWAY": 1},
        )
        self.assertEqual(
            h2["window_update_increments"]["inbound"], {"connection": 1024, "streams": 0}
        )
        reset = next(event for event in h2["recent_frames"] if event["type"] == 3)
        self.assertEqual(
            (reset["stream_id"], reset["error_code"], reset["direction"]), (19, 1, "inbound")
        )
        goaway = h2["recent_frames"][-1]
        self.assertEqual(
            (goaway["last_stream_id"], goaway["error_code"], goaway["debug_data_length"]),
            (19, 1, len(b"PRIVATE GOAWAY reason")),
        )
        self.assertEqual(h2["buffered_bytes"], 0)
        self.assertNotIn("PRIVATE", json.dumps(connection))

    async def test_h2_outbound_preface_fragments_and_coalesced_frames_are_not_rewritten(self):
        wire = (
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
            + h2_frame(4, b"\x00\x02\x00\x00\x00\x00")
            + h2_frame(1, b"PRIVATE authorization header", stream_id=1, flags=4)
            + h2_frame(0, b"PRIVATE request body", stream_id=1, flags=1)
            + h2_frame(8, (500).to_bytes(4, "big"), stream_id=1)
            + h2_frame(99, b"PRIVATE extension")
        )
        chunks = [wire[:1], wire[1:12], wire[12:29], wire[29:]]
        inner = FakeH2Stream(self.clock)
        stream = InstrumentedStream(inner, self.registry)
        for chunk in chunks:
            await stream.write(chunk, 150)
        self.assertEqual(inner.calls, [("write", chunk, 150) for chunk in chunks])
        h2 = self.registry.snapshot()["connections"][0]["http2"]
        self.assertEqual(h2["local_settings"], {"enable_push": 0})
        self.assertEqual(
            h2["frame_counts"]["outbound"],
            {"SETTINGS": 1, "HEADERS": 1, "DATA": 1, "WINDOW_UPDATE": 1, "UNKNOWN": 1},
        )
        self.assertEqual(h2["data_payload_bytes"]["outbound"], len(b"PRIVATE request body"))
        self.assertEqual(
            h2["window_update_increments"]["outbound"], {"connection": 0, "streams": 500}
        )
        self.assertNotIn("PRIVATE", json.dumps(h2))

    async def test_h2_large_sensitive_payloads_and_control_metadata_stay_bounded(self):
        payload = b"PRIVATE_TOKEN_HEADER_BODY" * 50000
        settings = b"\x00\x04\x00\x00\x10\x00" * 10000
        wire = (
            h2_frame(0, payload, stream_id=1)
            + h2_frame(1, payload, stream_id=1)
            + h2_frame(99, payload)
            + h2_frame(4, settings)
            + h2_frame(7, (1).to_bytes(4, "big") + (0).to_bytes(4, "big") + payload)
        )
        chunks = [wire[i : i + 32768] for i in range(0, len(wire), 32768)]
        stream = InstrumentedStream(FakeH2Stream(self.clock, chunks), self.registry)
        for chunk in chunks:
            self.assertEqual(await stream.read(32768), chunk)
            self.assertLessEqual(
                self.registry.snapshot()["connections"][0]["http2"]["buffered_bytes"], 256
            )
        h2 = self.registry.snapshot()["connections"][0]["http2"]
        self.assertEqual(h2["data_payload_bytes"]["inbound"], len(payload))
        self.assertEqual(h2["metadata_omitted_frames"], 1)
        self.assertEqual(h2["remote_settings"], {})
        self.assertEqual(h2["recent_frames"][-1]["debug_data_length"], len(payload))
        self.assertNotIn("PRIVATE", json.dumps(h2))
        self.assertLess(len(json.dumps(h2)), 4096)

    async def test_h2_event_ring_and_unknown_type_counters_are_bounded(self):
        wire = b"".join(h2_frame(kind, b"PRIVATE") for kind in range(256))
        stream = InstrumentedStream(FakeH2Stream(self.clock, [wire]), self.registry)
        await stream.read(len(wire))
        h2 = self.registry.snapshot()["connections"][0]["http2"]
        self.assertLessEqual(len(h2["recent_frames"]), 32)
        self.assertLessEqual(len(h2["frame_counts"]["inbound"]), 11)
        self.assertEqual(h2["frame_counts"]["inbound"]["UNKNOWN"], 246)
        self.assertNotIn("PRIVATE", json.dumps(h2))

    async def test_h2_partial_frame_reports_metadata_without_retaining_payload(self):
        wire = h2_frame(0, b"PRIVATE BODY", stream_id=7, flags=1)
        stream = InstrumentedStream(FakeH2Stream(self.clock, [wire[:12]]), self.registry)
        await stream.read(4096)
        h2 = stream.state.snapshot()["http2"]
        self.assertEqual(h2["buffered_bytes"], 0)
        self.assertEqual(
            h2["pending_frames"][0]["remaining_payload_bytes"], len(b"PRIVATE BODY") - 3
        )
        self.assertEqual(h2["pending_frames"][0]["stream_id"], 7)
        self.assertNotIn("PRIVATE", json.dumps(h2))

    async def test_h2_observer_failure_disables_only_observation(self):
        wire = h2_frame(4)
        stream = InstrumentedStream(FakeH2Stream(self.clock, [wire, wire]), self.registry)
        await stream.read(4096)

        def broken_observer(data):
            raise ValueError("PRIVATE observer bug")

        observer = stream.state.http2_observers["inbound"]
        observer.feed = broken_observer
        self.assertEqual(await stream.read(4096), wire)
        h2 = stream.state.snapshot()["http2"]
        self.assertEqual(h2["observer_errors"], 1)
        self.assertTrue(observer.disabled)
        self.assertNotIn("PRIVATE", json.dumps(h2))

    async def test_settings_cache_follows_connection_across_requests_and_retries(self):
        from h2.events import RemoteSettingsChanged
        from h2.settings import ChangedSetting, SettingCodes

        stream = InstrumentedStream(FakeH2Stream(self.clock), self.registry)
        self.record.start_attempt(1, {})
        await self.record.trace("connection.start_tls.complete", {"return_value": stream})
        settings = RemoteSettingsChanged()
        settings.changed_settings[SettingCodes.INITIAL_WINDOW_SIZE] = ChangedSetting(
            SettingCodes.INITIAL_WINDOW_SIZE, 65535, 1048576
        )
        await self.record.trace(
            "http2.receive_remote_settings.complete", {"return_value": settings}
        )
        reused = self.registry.begin("codex")
        reused.response(httpx.Response(200, extensions={"network_stream": stream}))
        self.assertEqual(reused.snapshot()["http2_settings"], {"initial_window_size": 1048576})
        self.assertEqual(
            self.registry.snapshot()["connections"][0]["http2"]["remote_settings"],
            {"initial_window_size": 1048576},
        )
        reused.start_attempt(2, {})
        fresh = InstrumentedStream(FakeH2Stream(self.clock), self.registry)
        reused.response(httpx.Response(200, extensions={"network_stream": fresh}))
        self.assertEqual(reused.snapshot()["http2_settings"], {})

    async def test_wire_settings_are_inherited_without_a_trace_on_reused_stream(self):
        wire = h2_frame(4, b"\x00\x04" + (1048576).to_bytes(4, "big"))
        stream = InstrumentedStream(FakeH2Stream(self.clock, [wire]), self.registry)
        await stream.read(4096)
        self.record.response(httpx.Response(200, extensions={"network_stream": stream}))
        self.assertEqual(self.record.snapshot()["http2_settings"], {"initial_window_size": 1048576})

    async def test_settings_trace_does_not_overwrite_newer_connection_settings(self):
        from h2.events import RemoteSettingsChanged
        from h2.settings import ChangedSetting, SettingCodes

        first = h2_frame(
            4, b"\x00\x03" + (100).to_bytes(4, "big") + b"\x00\x04" + (65535).to_bytes(4, "big")
        )
        update = h2_frame(4, b"\x00\x04" + (1048576).to_bytes(4, "big"))
        stream = InstrumentedStream(FakeH2Stream(self.clock, [first, update]), self.registry)
        await stream.read(4096)
        self.record.response(httpx.Response(200, extensions={"network_stream": stream}))
        await stream.read(4096)
        settings = RemoteSettingsChanged()
        settings.changed_settings[SettingCodes.MAX_CONCURRENT_STREAMS] = ChangedSetting(
            SettingCodes.MAX_CONCURRENT_STREAMS, 100, 200
        )
        await self.record.trace(
            "http2.receive_remote_settings.complete", {"return_value": settings}
        )
        self.assertEqual(
            self.record.snapshot()["http2_settings"],
            {"max_concurrent_streams": 200, "initial_window_size": 1048576},
        )

    async def test_http1_and_unknown_alpn_ignore_h2_shaped_bytes(self):
        for alpn in ("http/1.1", None):
            wire = h2_frame(3, (1).to_bytes(4, "big"), stream_id=1)
            inner = FakeH2Stream(self.clock, [wire], alpn=alpn)
            stream = InstrumentedStream(inner, self.registry)
            self.assertEqual(await stream.read(4096), wire)
            await stream.write(wire)
            h2 = stream.state.snapshot()["http2"]
            self.assertEqual(h2["frame_counts"], {"inbound": {}, "outbound": {}})
            self.assertEqual(h2["recent_frames"], [])

    async def test_h2_observation_preserves_transport_failure_and_cancellation(self):
        inner = FakeH2Stream(self.clock)
        stream = InstrumentedStream(inner, self.registry)
        failure = httpcore.ReadError("PRIVATE socket error")
        inner.failure = failure
        with self.assertRaises(httpcore.ReadError) as caught:
            await stream.read(4096, 2)
        self.assertIs(caught.exception, failure)
        cancelled = asyncio.CancelledError("PRIVATE cancellation")
        inner.failure = cancelled
        with self.assertRaises(asyncio.CancelledError) as caught:
            await stream.read(4096, 3)
        self.assertIs(caught.exception, cancelled)

        async def cancelled_write(buffer, timeout=None):
            raise cancelled

        inner.write = cancelled_write
        with self.assertRaises(asyncio.CancelledError) as caught:
            await stream.write(b"PRIVATE", 4)
        self.assertIs(caught.exception, cancelled)
        self.assertNotIn("PRIVATE", json.dumps(stream.state.snapshot()))


if __name__ == "__main__":
    unittest.main()
