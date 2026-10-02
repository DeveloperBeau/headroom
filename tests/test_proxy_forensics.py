"""First transport evidence survives retries and teardown without retaining payloads."""

import asyncio
import json
import ssl
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import httpcore
import httpx

from headroom.proxy import upstream_diagnostics as module


class Socket(httpcore.AsyncNetworkStream):
    error = None

    async def read(self, max_bytes, timeout=None):
        if self.error:
            raise self.error
        return b""

    async def write(self, buffer, timeout=None):
        if self.error:
            raise self.error

    async def aclose(self):
        if self.error:
            raise self.error

    def get_extra_info(self, name):
        return None


class ForensicsTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.owner = module.StreamDiagnostics()
        self.record = self.owner.begin("codex")
        self.record.bind_request("hr_123_000001")
        self.record.start_attempt(1, {"read": 2})
        self.inner = Socket()
        self.stream = module.InstrumentedStream(self.inner, self.owner)

    async def test_first_fault_is_frozen_before_cleanup_retry_and_eviction(self):
        token = module.current_stream.set(self.record)
        try:
            self.inner.error = httpcore.ReadError("PRIVATE secret body and URL")
            with patch.object(module.logger, "info") as logged:
                with self.assertRaises(httpcore.ReadError):
                    await self.stream.read(10)
            snapshot = self.owner.snapshot()
            self.assertIn("first_faults", snapshot)
            frozen = json.dumps(snapshot["first_faults"][0], sort_keys=True)
            fault = snapshot["first_faults"][0]
            self.assertEqual(fault["request_id"], "hr_123_000001")
            self.assertEqual(fault["connection_id"], self.stream.state.key)
            self.assertEqual(fault["phase"], "socket_read")
            self.assertIn('"kind":"first_fault"', str(logged.call_args_list))
            self.inner.error = asyncio.CancelledError("PRIVATE cancellation")
            with self.assertRaises(asyncio.CancelledError):
                await self.stream.aclose()
            self.record.start_attempt(2, {})
            for _ in range(100):
                self.owner.connection()
            self.assertEqual(
                json.dumps(self.owner.snapshot()["first_faults"][0], sort_keys=True), frozen
            )
            self.assertEqual(self.stream.state.snapshot()["first_error"][0]["type"], "ReadError")
            self.assertNotIn("PRIVATE", json.dumps(self.owner.snapshot()))
        finally:
            module.current_stream.reset(token)

    async def test_cancellation_context_does_not_become_transport_root_cause(self):
        error = asyncio.CancelledError("PRIVATE")
        error.__context__ = ssl.SSLWantReadError("PRIVATE TLS wants read")
        self.record.observe_exception(error)
        snapshot = self.record.snapshot()
        self.assertIn("cancellations", snapshot)
        self.assertEqual(snapshot["cancellations"][-1]["origin"], "unknown")
        self.assertEqual(self.owner.snapshot()["first_faults"], [])
        self.record.mark_disconnected()
        self.record.observe_exception(error)
        self.assertEqual(
            self.record.snapshot()["cancellations"][-1]["origin"], "downstream_disconnect"
        )
        self.assertNotIn("PRIVATE", json.dumps(self.record.snapshot()))

    async def test_eof_close_lifecycle_is_bounded_and_does_not_infer_fin_rst(self):
        for _ in range(100):
            await self.stream.read(1)
        await self.stream.aclose()
        state = self.stream.state.snapshot()
        self.assertIn("lifecycle", state)
        self.assertLessEqual(len(state["lifecycle"]), 24)
        self.assertEqual(
            [item["event"] for item in state["lifecycle"][-3:]],
            ["read_eof", "close_started", "close_complete"],
        )
        self.assertEqual(state["close_evidence"]["fin_rst_direction"], "unknown")
        self.assertEqual(state["close_evidence"]["tls_close_notify"], "unknown")
        self.assertEqual(state["tcp"]["availability"], "unavailable")

    async def test_session_ids_are_hashed_validated_and_bounded(self):
        self.assertTrue(hasattr(self.record, "bind_client_headers"))
        self.record.bind_client_headers(
            [
                (b"session_id", b"native-session-123"),
                (b"conversation_id", b"native-conversation-123"),
                (b"authorization", b"PRIVATE"),
            ]
        )
        second = self.owner.begin("codex")
        second.bind_client_headers(
            [
                (b"session_id", b"native-session-123"),
                (b"conversation_id", b"native-conversation-123"),
            ]
        )
        self.assertEqual(self.record.snapshot()["session_ids"], second.snapshot()["session_ids"])
        self.assertNotIn("native-session", json.dumps(self.record.snapshot()))
        self.assertIn("conversation_id", self.record.snapshot()["session_ids"])
        self.assertNotIn("native-conversation", json.dumps(self.record.snapshot()))
        second.bind_client_headers(
            [(b"session_id", b"PRIVATE unsafe?token"), (b"x-client-request-id", b"PRIVATE")]
        )
        self.assertIsNone(second.client_request_id)
        self.assertNotIn("PRIVATE", json.dumps(second.snapshot()))

    async def test_pool_unknown_and_limits_are_honest_and_metadata_only(self):
        self.assertTrue(hasattr(self.owner, "register_pool"))
        pool = httpcore.AsyncConnectionPool(max_connections=7, max_keepalive_connections=3)
        self.owner.register_pool(pool)
        pools = self.owner.snapshot()["pools"]
        self.assertEqual(pools[0]["max_connections"], 7)
        self.assertEqual(pools[0]["max_keepalive_connections"], 3)
        self.assertEqual(pools[0]["queued_requests"], 0)
        self.assertEqual(pools[0]["connections"], [])
        origin = httpcore.Origin(b"https", b"private.example", 443)
        pool._connections.append(pool.create_connection(origin))
        pending = module.pool_snapshot(pool)
        self.assertIsNone(pending["connections"][0]["active_streams"])
        self.assertFalse(pending["origins"][0]["active_streams_available"])
        self.assertNotIn("private.example", json.dumps(pending))
        unknown = SimpleNamespace()
        self.assertEqual(module.pool_snapshot(unknown)["availability"], "unavailable")
        await pool.aclose()

    async def test_first_fault_retention_and_snapshot_copies_are_bounded(self):
        for _ in range(100):
            stream = module.InstrumentedStream(Socket(), self.owner)
            stream.inner.error = BrokenPipeError(32, "PRIVATE")
            with self.assertRaises(BrokenPipeError):
                await stream.write(b"PRIVATE")
        snapshot = self.owner.snapshot()
        self.assertIn("first_faults", snapshot)
        self.assertEqual(len(snapshot["first_faults"]), 16)
        self.assertLess(len(json.dumps(snapshot)), 2 * 1024 * 1024)
        self.assertLess(max(len(json.dumps(item)) for item in snapshot["first_faults"]), 24 * 1024)
        fault_id = snapshot["first_faults"][0]["fault_id"]
        snapshot["first_faults"][0]["fault_id"] = "mutated"
        self.assertEqual(self.owner.snapshot()["first_faults"][0]["fault_id"], fault_id)
        self.assertNotIn("PRIVATE", json.dumps(self.owner.snapshot()))

    async def test_concurrent_requests_keep_separate_connection_identity(self):
        async def fail(record):
            token = module.current_stream.set(record)
            try:
                stream = module.InstrumentedStream(Socket(), self.owner)
                stream.inner.error = httpcore.ReadError("PRIVATE")
                await asyncio.sleep(0)
                with self.assertRaises(httpcore.ReadError):
                    await stream.read(4)
            finally:
                module.current_stream.reset(token)

        other = self.owner.begin("claude")
        other.bind_request("hr_other")
        await asyncio.gather(fail(self.record), fail(other))
        self.assertIn("first_faults", self.owner.snapshot())
        faults = self.owner.snapshot()["first_faults"]
        self.assertEqual({item["request_id"] for item in faults}, {"hr_123_000001", "hr_other"})
        self.assertEqual(len({item["connection_id"] for item in faults}), 2)

    async def test_inbound_reset_freezes_matching_stream_before_transport_exception(self):
        self.record.stream_id = 7
        self.stream.state.bind(self.record)
        other = self.owner.begin("claude")
        other.stream_id = 9
        self.stream.state.bind(other)
        wire = b"\x00\x00\x04\x03\x00\x00\x00\x00\x07\x00\x00\x00\x01"
        self.stream.state.observe_http2("inbound", wire)
        faults = self.owner.snapshot()["first_faults"]
        self.assertEqual(len(faults), 1)
        self.assertEqual(faults[0]["stream_id"], 7)
        self.assertEqual(faults[0]["record_id"], self.record.key)
        self.assertEqual(faults[0]["connection"]["http2"]["recent_frames"][-1]["error_code"], 1)
        self.assertEqual(faults[0]["connection"]["close_evidence"]["fin_rst_direction"], "unknown")
        second_wire = wire[:8] + b"\x09" + wire[9:]
        self.stream.state.observe_http2("inbound", second_wire)
        faults = self.owner.snapshot()["first_faults"]
        self.assertEqual(len(faults), 2)
        self.assertEqual(faults[1]["stream_id"], 9)
        self.assertEqual(self.stream.state.first_fault_id, faults[0]["fault_id"])

    async def test_multiplexed_io_switches_do_not_inflate_reuse_count(self):
        other = self.owner.begin("claude")
        for _ in range(10):
            self.stream.state.bind(self.record)
            self.stream.state.bind(other)
        self.assertEqual(self.stream.state.snapshot()["reuse_count"], 1)

    async def test_darwin_kernel_counters_and_unsupported_layout(self):
        info = bytearray(112)
        info[0] = 4
        struct.pack_into("=I", info, 44, 12)
        struct.pack_into("=Q", info, 72, 123)
        sock = SimpleNamespace(getsockopt=lambda *args: bytes(info))
        self.inner.get_extra_info = lambda name: sock if name == "socket" else None
        with patch.object(module.sys, "platform", "darwin"):
            self.stream.sample_tcp()
            tcp = self.stream.state.snapshot()["tcp"]
            self.assertEqual(tcp["availability"], "available")
            self.assertEqual(tcp["rtt_ms"], 12)
            self.assertEqual(tcp["tx_retransmit_bytes"], 123)
            sock.getsockopt = lambda *args: b"short"
            self.stream.sample_tcp()
            self.assertEqual(self.stream.state.snapshot()["tcp"]["reason"], "unsupported_layout")

    async def test_timeout_and_shutdown_are_observations_not_inferred_initiators(self):
        self.record.observe_exception(httpcore.ReadTimeout("PRIVATE"), phase="socket_read")
        self.assertEqual(self.record.snapshot()["cancellations"][-1]["origin"], "operation_timeout")
        self.owner.shutdown()
        self.record.observe_exception(asyncio.CancelledError("PRIVATE"))
        events = self.record.snapshot()["cancellations"]
        self.assertIn("shutdown", [item["origin"] for item in events])
        self.assertEqual(events[-1]["origin"], "unknown")

    async def test_broken_observers_do_not_replace_transport_error(self):
        self.inner.get_extra_info = lambda name: (_ for _ in ()).throw(ValueError("PRIVATE"))
        error = BrokenPipeError(32, "PRIVATE")
        self.inner.error = error
        with patch.object(module.logger, "info", side_effect=RuntimeError("PRIVATE logger")):
            with self.assertRaises(BrokenPipeError) as caught:
                await self.stream.write(b"PRIVATE")
        self.assertIs(caught.exception, error)
        self.assertEqual(self.stream.state.snapshot()["tcp"]["reason"], "probe_failed")
        self.assertNotIn("PRIVATE", json.dumps(self.owner.snapshot()))

    async def test_pool_removal_and_expiry_are_observed_at_close(self):
        core = SimpleNamespace(has_expired=lambda: True)
        pool = SimpleNamespace(_connections=[])
        self.stream.state.pool_connection = lambda: core
        self.stream.state.pool = lambda: pool
        await self.stream.aclose()
        self.assertIn(
            "pool_expired", [item["event"] for item in self.stream.state.snapshot()["lifecycle"]]
        )
        self.assertIn(
            "pool_removed", [item["event"] for item in self.stream.state.snapshot()["lifecycle"]]
        )

    async def test_registration_header_binding_and_shutdown_observer_faults_are_isolated(self):
        class InvalidHeaders:
            def __iter__(self):
                raise ValueError("PRIVATE")

        self.record.bind_client_headers(InvalidHeaders())
        self.owner.register_pool(object())
        with patch.object(self.record, "cancellation", side_effect=ValueError("PRIVATE")):
            self.owner.shutdown()
        self.assertNotIn("PRIVATE", json.dumps(self.owner.snapshot()))

    async def test_failed_optional_snapshot_does_not_lose_first_fault(self):
        token = module.current_stream.set(self.record)
        try:
            self.inner.error = httpcore.ReadError("PRIVATE")
            with patch.object(self.record, "snapshot", side_effect=ValueError("PRIVATE")):
                with self.assertRaises(httpcore.ReadError):
                    await self.stream.read(1)
            faults = self.owner.snapshot()["first_faults"]
            self.assertEqual(len(faults), 1)
            self.assertEqual(faults[0]["request_id"], self.record.request_id)
            self.assertEqual(faults[0]["request"]["availability"], "unavailable")
        finally:
            module.current_stream.reset(token)

    async def test_snapshot_byte_budget_preserves_faults_and_reports_omissions(self):
        # Simulate the largest allowed histories without repeating network traffic.
        for _ in range(64):
            record = self.owner.begin("codex")
            record.cancellations.extend(
                {"stack": [{"function": "f" * 64, "line": 10}] * 8} for _ in range(8)
            )
            self.owner.end(record, "completed")
            connection = self.owner.connection()
            connection.lifecycle.extend(
                {
                    "event": "socket_read_failed",
                    "error": [{"type": "E" * 64}] * 4,
                    "stack": [{"function": "f" * 64, "line": 10}] * 8,
                }
                for _ in range(24)
            )
            connection.http2_events.extend(
                {"type": 4, "settings": {str(i): 2**32 - 1 for i in range(9)}} for _ in range(32)
            )
        # Active and recently completed requests have independent retention rings.
        for _ in range(63):
            record = self.owner.begin("claude")
            record.cancellations.extend(
                {"stack": [{"function": "f" * 64, "line": 10}] * 8} for _ in range(8)
            )
        snapshot = self.owner.snapshot()
        self.assertLess(len(json.dumps(snapshot)), 2 * 1024 * 1024)
        self.assertGreater(sum(snapshot["omitted_snapshot_records"].values()), 0)
        connection.bind(record)
        self.owner.freeze_fault(connection, record, "socket_read", httpcore.ReadError("PRIVATE"))
        fault = self.owner.snapshot()["first_faults"][0]
        self.assertLess(len(json.dumps(fault)), 24 * 1024)

    async def test_real_pool_reuse_and_first_failure_include_request_and_pool(self):
        from headroom.proxy import upstream_pinning

        class Peer(Socket):
            requests = 0

            async def write(self, buffer, timeout=None):
                if buffer.startswith(b"GET"):
                    self.requests += 1

            async def read(self, max_bytes, timeout=None):
                if self.requests < 3:
                    return b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
                return b""

        class Backend(httpcore.AsyncNetworkBackend):
            async def connect_tcp(self, *args, **kwargs):
                return Peer()

        with (
            patch.object(upstream_pinning, "diagnostics", self.owner),
            patch.object(
                upstream_pinning,
                "instrument_stream",
                lambda inner: module.InstrumentedStream(inner, self.owner),
            ),
        ):
            async with httpx.AsyncClient(trust_env=False) as client:
                client._transport._pool._network_backend = Backend()
                upstream_pinning.install_upstream_pinning(client)
                ids = []
                for number in range(3):
                    record = self.owner.begin("codex")
                    record.bind_request(f"hr_{number}")
                    record.start_attempt(1, {})
                    token = module.current_stream.set(record)
                    try:
                        request = client.build_request("GET", "http://example.test")
                        request.extensions["trace"] = record.trace
                        if number == 2:
                            with self.assertRaises(httpx.RemoteProtocolError):
                                await client.send(request)
                        else:
                            response = await client.send(request)
                            record.response(response)
                            ids.append(record.connection_id)
                    finally:
                        module.current_stream.reset(token)
                        self.owner.end(record, "completed")
                self.assertEqual(ids[0], ids[1])
                fault = self.owner.snapshot()["first_faults"][0]
                self.assertEqual(fault["request_id"], "hr_2")
                self.assertEqual(fault["connection_id"], ids[0])
                self.assertEqual(fault["pool"]["availability"], "available")
                self.assertEqual(fault["connection"]["reuse_count"], 2)


if __name__ == "__main__":
    unittest.main()
