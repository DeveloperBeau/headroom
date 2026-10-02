"""Local-only checks for the opt-in comparison CLI."""

import asyncio
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpcore
import httpx
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import StreamEnded

from headroom.proxy.upstream_diagnostics import StreamDiagnostics

try:
    from headroom.proxy import diagnostic_probe as probe
except ImportError:
    probe = None


class ProbeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.assertIsNotNone(probe, "controlled comparison module must exist")
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.endpoint = self.write("endpoint", "https://example.invalid/private?secret=query")
        self.request = self.write("request", "private request body")
        self.headers = self.write("headers", json.dumps({"Authorization": "secret credential"}))

    def write(self, name, content):
        path = self.root / name
        path.write_text(content)
        path.chmod(0o600)
        return path

    def options(self, *extra):
        return probe.load_options(
            [
                "--endpoint-file",
                str(self.endpoint),
                "--request-file",
                str(self.request),
                "--headers-file",
                str(self.headers),
                *extra,
            ]
        )

    def test_dry_run_redacts_every_input_and_opens_no_client(self):
        output = io.StringIO()
        with patch.object(httpx, "AsyncClient", side_effect=AssertionError("network forbidden")):
            with contextlib.redirect_stdout(output):
                self.assertEqual(
                    probe.main(
                        [
                            "--endpoint-file",
                            str(self.endpoint),
                            "--request-file",
                            str(self.request),
                            "--headers-file",
                            str(self.headers),
                            "--dry-run",
                        ]
                    ),
                    0,
                )
        result = json.loads(output.getvalue())
        self.assertEqual(result["planned_requests"], 8)
        for secret in ("secret", "private", "example.invalid", str(self.root)):
            self.assertNotIn(secret, output.getvalue())

    def test_execution_requires_explicit_switch(self):
        with self.assertRaises(probe.ProbeInputError):
            self.options()

    def test_invalid_ca_file_is_rejected_without_disabling_tls(self):
        ca = self.write("ca.pem", "not a certificate")
        with self.assertRaises(probe.ProbeInputError):
            self.options("--dry-run", "--ca-file", str(ca))

    def test_urls_and_bounds_fail_closed(self):
        for url in (
            "https://user:secret@example.invalid",
            "https://example.invalid/#secret",
            "ftp://example.invalid",
            "http://example.invalid",
            "http://localhost",
            "https://example.invalid:0",
            "https://example.invalid\nheader",
        ):
            self.endpoint.write_text(url)
            with self.subTest(url=url), self.assertRaises(probe.ProbeInputError):
                self.options("--dry-run", "--allow-loopback-http")
        self.endpoint.write_text("https://example.invalid")
        for flag, value in (
            ("--count", "0"),
            ("--count", "6"),
            ("--timeout", "nan"),
            ("--timeout", "61"),
            ("--max-seconds", "301"),
            ("--max-response-bytes", "0"),
        ):
            with self.subTest(flag=flag, value=value), self.assertRaises(probe.ProbeInputError):
                self.options("--dry-run", flag, value)

    def test_private_bounded_files_and_headers(self):
        for contents in (
            '{"Host":"other.invalid"}',
            '{"X-Test":"a\\r\\nb"}',
            '{"X-Test":4}',
            '["secret"]',
            '{"Bad Name":"secret"}',
            '{"Authorization":"a", "authorization":"b"}',
        ):
            self.headers.write_text(contents)
            with self.subTest(contents=contents), self.assertRaises(probe.ProbeInputError):
                self.options("--dry-run")
        self.headers.write_text("{}")
        if os.name == "posix":
            self.headers.chmod(0o644)
            with self.assertRaises(probe.ProbeInputError):
                self.options("--dry-run")
            self.headers.chmod(0o600)
        self.request.write_bytes(b"x" * (1024 * 1024 + 1))
        with self.assertRaises(probe.ProbeInputError):
            self.options("--dry-run")

    def test_cli_errors_never_echo_arguments_or_paths(self):
        for args in (
            ["--unknown-secret", "credential"],
            ["--endpoint-file", "secret-file"],
            ["--count", "secret-credential"],
        ):
            output = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                self.assertEqual(probe.main(args), 2)
            self.assertEqual(json.loads(output.getvalue())["error"], "invalid_input")
            self.assertNotIn("secret", output.getvalue())

    async def test_local_matrix_measures_actual_reuse_and_h2_fallback(self):
        streams = []

        class WireStream(httpcore.AsyncNetworkStream):
            closed = False

            async def write(self, buffer, timeout=None):
                pass

            async def read(self, max_bytes, timeout=None):
                payload = b"data: private answer\n\ndata: [DONE]\n\n"
                return (
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                    b"x-request-id: provider-123\r\nContent-Length: "
                    + str(len(payload)).encode()
                    + b"\r\n\r\n"
                    + payload
                )

            async def aclose(self):
                self.closed = True

            def get_extra_info(self, name):
                return False if name == "is_readable" else None

        class Backend(httpcore.AsyncNetworkBackend):
            async def connect_tcp(self, *args, **kwargs):
                stream = WireStream()
                streams.append(stream)
                return stream

        real_client = httpx.AsyncClient

        def factory(**kwargs):
            transport = httpx.AsyncHTTPTransport(http2=kwargs["http2"], limits=kwargs["limits"])
            transport._pool._network_backend = Backend()
            return real_client(**kwargs, transport=transport)

        self.endpoint.write_text("http://127.0.0.1:8000/private?secret=query")
        options = self.options("--execute", "--allow-loopback-http")
        with patch.object(httpx, "AsyncClient", side_effect=factory):
            result = await probe.compare(options)
        self.assertEqual(len(result["results"]), 8)
        self.assertTrue(result["completed"])
        for row in result["results"]:
            self.assertEqual(row["negotiated_protocol"], "HTTP/1.1")
            self.assertTrue(row["sse_terminal"])
            self.assertEqual(row["status"], 200)
            self.assertIsNotNone(row["connection_id"])
            self.assertEqual(
                row["connection_reused"], row["client_mode"] == "reused" and row["attempt"] == 2
            )
            self.assertEqual(row["protocol_matched"], row["requested_protocol"] == "HTTP/1.1")
        self.assertEqual(len(streams), 6)
        self.assertTrue(all(stream.closed for stream in streams))
        serialized = json.dumps(result)
        for secret in ("private", "secret", "provider-123", "127.0.0.1"):
            self.assertNotIn(secret, serialized)

    async def fake_comparison(self, handler, **overrides):
        options = self.options("--execute", "--count", "1")
        options.update(overrides)
        real_client = httpx.AsyncClient

        def factory(**kwargs):
            self.assertFalse(kwargs["trust_env"])
            self.assertFalse(kwargs["follow_redirects"])
            self.assertTrue(kwargs["verify"].check_hostname)
            self.assertEqual(kwargs["verify"].verify_mode, 2)
            return real_client(**kwargs, transport=httpx.MockTransport(handler))

        with patch.object(httpx, "AsyncClient", side_effect=factory):
            return await probe.compare(options)

    async def test_redirects_are_not_followed_and_absent_reuse_is_unknown(self):
        requests = []

        def handler(request):
            requests.append(request)
            return httpx.Response(
                302,
                headers={"location": "https://secret.invalid/query?token=private"},
                stream=httpx.ByteStream(b""),
            )

        result = await self.fake_comparison(handler)
        self.assertEqual(len(requests), 4)
        for row in result["results"]:
            self.assertEqual(row["status"], 302)
            self.assertEqual(row["outcome"], "redirect_blocked")
            self.assertIsNone(row["connection_reused"])
        self.assertNotIn("secret", json.dumps(result))

    async def test_transport_errors_are_category_only(self):
        def handler(request):
            raise httpx.ConnectError("Authorization secret credential and private URL")

        result = await self.fake_comparison(handler)
        self.assertEqual({row["outcome"] for row in result["results"]}, {"transport_error"})
        self.assertEqual({row["error_type"] for row in result["results"]}, {"ConnectError"})
        self.assertNotIn("secret", json.dumps(result))

    async def test_read_failure_survives_response_cleanup_failure_and_redacts_both(self):
        class BrokenBody(httpx.AsyncByteStream):
            async def __aiter__(self):
                raise httpx.ReadError("secret read credential and private upstream URL")
                yield b""  # Keep the failing iterator an async generator.

            async def aclose(self):
                raise httpx.WriteError("secret close credential and private upstream URL")

        result = await self.fake_comparison(
            lambda request: httpx.Response(200, stream=BrokenBody())
        )
        self.assertEqual(len(result["results"]), 4)
        for row in result["results"]:
            self.assertEqual(row["outcome"], "transport_error")
            self.assertEqual(row["error_type"], "ReadError")
            self.assertEqual(row["response_cleanup_error_type"], "WriteError")
        for secret in ("secret", "credential", "private", "upstream URL"):
            self.assertNotIn(secret, json.dumps(result))

    async def test_h2_wire_negotiation_and_stream_reuse_with_fake_tls(self):
        streams = []

        class TLS:
            def selected_alpn_protocol(self):
                return "h2"

            def version(self):
                return "TLSv1.3"

        class Wire(httpcore.AsyncNetworkStream):
            def __init__(self):
                self.h2 = H2Connection(H2Configuration(client_side=False))
                self.h2.initiate_connection()
                self.closed = False

            async def start_tls(self, ssl_context, **kwargs):
                self_test.assertTrue(ssl_context.check_hostname)
                return self

            def get_extra_info(self, name):
                return TLS() if name == "ssl_object" else None

            async def write(self, buffer, timeout=None):
                for event in self.h2.receive_data(buffer):
                    if isinstance(event, StreamEnded):
                        self.h2.send_headers(
                            event.stream_id,
                            [(":status", "200"), ("content-type", "text/event-stream")],
                        )
                        self.h2.send_data(event.stream_id, b"data: [DONE]\n\n", end_stream=True)

            async def read(self, max_bytes, timeout=None):
                return self.h2.data_to_send()

            async def aclose(self):
                self.closed = True

        class Backend(httpcore.AsyncNetworkBackend):
            async def connect_tcp(self, *args, **kwargs):
                stream = Wire()
                streams.append(stream)
                return stream

        self_test = self
        real_client = httpx.AsyncClient

        def factory(**kwargs):
            if not kwargs["http2"]:
                return real_client(
                    **kwargs,
                    transport=httpx.MockTransport(
                        lambda request: httpx.Response(200, stream=httpx.ByteStream(b""))
                    ),
                )
            transport = httpx.AsyncHTTPTransport(
                http2=True, verify=kwargs["verify"], limits=kwargs["limits"]
            )
            transport._pool._network_backend = Backend()
            return real_client(**kwargs, transport=transport)

        with patch.object(httpx, "AsyncClient", side_effect=factory):
            result = await probe.compare(self.options("--execute"))
        rows = [row for row in result["results"] if row["requested_protocol"] == "HTTP/2"]
        self.assertEqual(len(rows), 4)
        for row in rows:
            self.assertEqual(row["negotiated_protocol"], "HTTP/2")
            self.assertTrue(row["protocol_matched"])
            self.assertEqual(row["alpn"], "h2")
            self.assertEqual(row["tls_version"], "TLSv1.3")
            self.assertTrue(row["sse_terminal"])
            self.assertEqual(
                row["connection_reused"], row["client_mode"] == "reused" and row["attempt"] == 2
            )
        self.assertEqual([row["stream_id"] for row in rows], [1, 1, 1, 3])
        self.assertTrue(all(stream.closed for stream in streams))

    async def test_missing_h2_dependency_is_reported_without_its_message(self):
        options = self.options("--execute", "--count", "1")
        real_client = httpx.AsyncClient

        def factory(**kwargs):
            if kwargs["http2"]:
                raise ImportError("secret package path")
            return real_client(
                **kwargs,
                transport=httpx.MockTransport(
                    lambda request: httpx.Response(200, stream=httpx.ByteStream(b""))
                ),
            )

        with patch.object(httpx, "AsyncClient", side_effect=factory):
            result = await probe.compare(options)
        self.assertEqual(
            [row["outcome"] for row in result["results"]],
            ["complete", "complete", "dependency_unavailable", "dependency_unavailable"],
        )
        self.assertNotIn("secret", json.dumps(result))

    def test_sse_crlf_split_and_invalid_type_never_create_false_terminal(self):
        parser = probe._SSE()
        parser.feed(b"event: message_stop\r")
        parser.feed(b'\ndata: {"type":[]}\r')
        self.assertFalse(parser.terminal)
        parser.feed(b"\n\r\n")
        self.assertTrue(parser.terminal)
        parser = probe._SSE()
        parser.feed(b'data: {"type":[]}\n\n')
        self.assertFalse(parser.terminal)

    async def test_encoded_sse_availability_is_explicit(self):
        result = await self.fake_comparison(
            lambda request: httpx.Response(
                200,
                headers={"content-type": "text/event-stream", "content-encoding": "gzip"},
                stream=httpx.ByteStream(b"private encoded content"),
            )
        )
        self.assertTrue(all(row["sse_terminal"] is None for row in result["results"]))
        self.assertTrue(all(row["outcome"] == "sse_unavailable" for row in result["results"]))

    def test_sse_event_name_alone_and_extra_spaces_do_not_dispatch_terminal(self):
        for payload in (
            b"event: message_stop\n\n",
            b"event:  message_stop\ndata: {}\n\n",
            b"event: message_stop \ndata: {}\n\n",
        ):
            with self.subTest(payload=payload):
                parser = probe._SSE()
                parser.feed(payload)
                self.assertFalse(parser.terminal)

    async def test_cancellation_closes_reused_client(self):
        options = self.options("--execute")
        requests = 0
        clients = []
        blocked = asyncio.Event()

        async def handler(request):
            nonlocal requests
            requests += 1
            if requests == 3:
                blocked.set()
                await asyncio.sleep(60)
            return httpx.Response(200, stream=httpx.ByteStream(b""))

        real_client = httpx.AsyncClient

        def factory(**kwargs):
            client = real_client(**kwargs, transport=httpx.MockTransport(handler))
            clients.append(client)
            return client

        with patch.object(httpx, "AsyncClient", side_effect=factory):
            task = asyncio.create_task(probe.compare(options))
            await asyncio.wait_for(blocked.wait(), timeout=1)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertTrue(all(client.is_closed for client in clients))

    async def test_chunked_sse_terminals_require_dispatched_events(self):
        class Body(httpx.AsyncByteStream):
            async def __aiter__(self):
                for chunk in (b"event: mes", b"sage_stop\r\n", b"data: {}\r\n\r\n"):
                    yield chunk

        result = await self.fake_comparison(
            lambda request: httpx.Response(
                200, headers={"content-type": "text/event-stream"}, stream=Body()
            )
        )
        self.assertTrue(all(row["sse_terminal"] for row in result["results"]))
        result = await self.fake_comparison(
            lambda request: httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                stream=httpx.ByteStream(b"event: message_stop\n"),
            )
        )
        self.assertTrue(all(row["sse_terminal"] is False for row in result["results"]))

    async def test_response_and_line_bounds_prevent_unbounded_retention(self):
        result = await self.fake_comparison(
            lambda request: httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                stream=httpx.ByteStream(b"x" * 200),
            ),
            max_response_bytes=100,
        )
        self.assertTrue(all(row["outcome"] == "response_limit" for row in result["results"]))
        result = await self.fake_comparison(
            lambda request: httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                stream=httpx.ByteStream(
                    b"data: " + b"x" * 70000 + b"\n\nevent: message_stop\ndata: {}\n\n"
                ),
            )
        )
        self.assertTrue(all(row["sse_parser_limited"] for row in result["results"]))
        self.assertTrue(all(row["sse_terminal"] for row in result["results"]))

    async def test_total_deadline_stops_stream_and_remaining_matrix(self):
        async def handler(request):
            await asyncio.sleep(1)
            return httpx.Response(200)

        result = await self.fake_comparison(handler, max_seconds=0.03)
        self.assertFalse(result["completed"])
        self.assertEqual(len(result["results"]), 1)
        self.assertEqual(result["results"][0]["outcome"], "deadline")

    async def test_request_timeout_is_distinct_from_run_deadline(self):
        async def handler(request):
            await asyncio.sleep(1)
            return httpx.Response(200, stream=httpx.ByteStream(b""))

        result = await self.fake_comparison(handler, timeout=0.01, max_seconds=1)
        self.assertTrue(result["completed"])
        self.assertEqual(len(result["results"]), 4)
        self.assertTrue(all(row["outcome"] == "timeout" for row in result["results"]))

    async def test_proxy_has_separate_headers_and_payload_is_identical(self):
        proxy_endpoint = self.write("proxy-endpoint", "https://proxy.invalid/v1/messages")
        proxy_headers = self.write("proxy-headers", '{"Authorization":"proxy credential"}')
        options = self.options(
            "--execute",
            "--count",
            "1",
            "--proxy-endpoint-file",
            str(proxy_endpoint),
            "--proxy-headers-file",
            str(proxy_headers),
        )
        requests = []

        def handler(request):
            requests.append(request)
            return httpx.Response(200, stream=httpx.ByteStream(b""))

        real_client = httpx.AsyncClient
        with patch.object(
            httpx,
            "AsyncClient",
            side_effect=lambda **kw: real_client(**kw, transport=httpx.MockTransport(handler)),
        ):
            result = await probe.compare(options)
        self.assertEqual(len(requests), 8)
        self.assertTrue(all(row["outcome"] == "complete" for row in result["results"]))
        self.assertEqual({row["route"] for row in result["results"]}, {"direct", "proxy"})
        self.assertTrue(all(request.content == b"private request body" for request in requests))
        self.assertTrue(
            all(request.headers["Authorization"] == "secret credential" for request in requests[:4])
        )
        self.assertTrue(
            all(request.headers["Authorization"] == "proxy credential" for request in requests[4:])
        )
        self.assertEqual(len({request.headers["x-client-request-id"] for request in requests}), 8)
        self.assertEqual([row["sequence"] for row in result["results"]], list(range(1, 9)))
        owner = StreamDiagnostics()
        for row, request in zip(result["results"], requests, strict=True):
            record = owner.begin("codex")
            record.bind_client_headers(request.headers.raw)
            self.assertEqual(record.client_request_id, row["request_id"])
        self.assertNotIn("credential", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
