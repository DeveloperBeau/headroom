import asyncio
import gzip
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi import HTTPException, Request

from headroom.proxy.raw_forwarding import forward_raw
from headroom.proxy.upstream_diagnostics import StreamDiagnostics, current_stream


class WireStream(httpx.AsyncByteStream):
    def __init__(self, chunks):
        self.chunks = chunks
        self.closed = False

    async def __aiter__(self):
        for chunk in self.chunks:
            yield chunk

    async def aclose(self):
        self.closed = True


def request(path="/v1/responses", headers=None):
    return Request(
        {
            "type": "http",
            "method": "POST",
            "scheme": "http",
            "path": path,
            "query_string": b"beta=true",
            "headers": [
                (key.lower().encode(), value.encode()) for key, value in (headers or {}).items()
            ],
            "client": ("127.0.0.1", 4567),
            "server": ("127.0.0.1", 8788),
        }
    )


def proxy(client, **config):
    return SimpleNamespace(
        http_client=client,
        OPENAI_API_URL="https://api.openai.com",
        ANTHROPIC_API_URL="https://api.anthropic.com",
        rate_limiter=None,
        cost_tracker=None,
        metrics=SimpleNamespace(record_rate_limited=AsyncMock()),
        config=SimpleNamespace(openai_extra_headers={}, anthropic_extra_headers={}, **config),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("policy", ["tokens", "budget", "security", "translated_backend"])
async def test_raw_upload_cannot_bypass_body_dependent_policy(policy):
    client = httpx.AsyncClient()
    client.send = AsyncMock(side_effect=AssertionError("policy bypass reached upstream"))
    server = proxy(client)
    route = "responses"
    if policy == "tokens":
        server.rate_limiter = SimpleNamespace(
            tokens_per_minute=100, check_request=AsyncMock(return_value=(True, 0))
        )
    elif policy == "budget":
        server.cost_tracker = SimpleNamespace(budget_limit_usd=5, check_budget=lambda: (True, 5))
    elif policy == "security":
        server.security = object()
        route = "messages"
    else:
        server.anthropic_backend = object()
        route = "messages"

    async def unread():
        raise AssertionError("policy bypass consumed upload")
        yield b""

    try:
        response = await forward_raw(
            server,
            request(),
            route=route,
            body=unread(),
            content_length=None,
            request_id="policy",
            reason="request_size",
        )
        assert response.status_code == 413
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_raw_media_and_encoded_response_preserve_bytes_headers_and_no_retry():
    payload = b"\xff\x00not-json\x80"
    response_bytes = gzip.compress(b"upstream error remains encoded")
    wire = WireStream([response_bytes[:5], response_bytes[5:]])
    calls = []

    async def send(upstream, **kwargs):
        calls.append(upstream)
        assert await upstream.aread() == payload
        assert kwargs == {"stream": True}
        return httpx.Response(
            413,
            headers={
                "content-encoding": "gzip",
                "content-length": str(len(response_bytes)),
                "x-request-id": "req-upstream",
                "connection": "x-hop",
                "x-hop": "drop",
            },
            stream=wire,
        )

    client = httpx.AsyncClient()
    client.send = AsyncMock(side_effect=send)
    req = request(
        headers={
            "Authorization": "Bearer sk-test",
            "Content-Encoding": "zstd",
            "Content-Length": str(len(payload)),
            "x-headroom-bypass": "true",
            "Connection": "x-hop",
            "x-hop": "drop",
        }
    )
    try:
        response = await forward_raw(
            proxy(client),
            req,
            route="responses",
            body=payload,
            content_length=len(payload),
            request_id="hr_raw",
            reason="request_size",
        )
        assert b"".join([chunk async for chunk in response.body_iterator]) == response_bytes
    finally:
        await client.aclose()
    assert len(calls) == 1
    assert calls[0].url == "https://api.openai.com/v1/responses?beta=true"
    assert calls[0].headers["authorization"] == "Bearer sk-test"
    assert calls[0].headers["content-encoding"] == "zstd"
    assert calls[0].headers["content-length"] == str(len(payload))
    assert "x-headroom-bypass" not in calls[0].headers
    assert "x-hop" not in calls[0].headers
    assert response.status_code == 413
    assert response.headers["content-encoding"] == "gzip"
    assert response.headers["content-length"] == str(len(response_bytes))
    assert "x-hop" not in response.headers
    assert wire.closed


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "route,path,headers,url",
    [
        (
            "responses",
            "/responses",
            {"authorization": "Bearer oauth", "chatgpt-account-id": "account"},
            "https://chatgpt.com/backend-api/codex/responses?beta=true",
        ),
        (
            "messages",
            "/v1/messages",
            {"x-api-key": "anthropic-key", "anthropic-version": "2023-06-01"},
            "https://api.anthropic.com/v1/messages?beta=true",
        ),
    ],
)
async def test_raw_route_and_credentials_follow_provider_decision(route, path, headers, url):
    client = httpx.AsyncClient()
    captured = []

    async def send(upstream, **kwargs):
        captured.append(upstream)
        return httpx.Response(200, stream=WireStream([b"opaque"]))

    client.send = AsyncMock(side_effect=send)
    try:
        response = await forward_raw(
            proxy(client),
            request(path, headers),
            route=route,
            body=b"opaque",
            content_length=6,
            request_id="hr_raw",
            reason="bypass_header",
        )
        assert b"".join([part async for part in response.body_iterator]) == b"opaque"
    finally:
        await client.aclose()
    assert str(captured[0].url) == url
    for key, value in headers.items():
        assert captured[0].headers[key] == value


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "configured_oauth,trusted_chatgpt", [(True, True), (True, False), (False, False)]
)
async def test_oauth_routing_considers_config_but_gates_extras_on_actual_host(
    configured_oauth, trusted_chatgpt, monkeypatch
):
    monkeypatch.delenv("HEADROOM_UPSTREAM_ALLOWED_HOSTS", raising=False)
    client = httpx.AsyncClient()
    client.send = AsyncMock(return_value=httpx.Response(200, stream=WireStream([b"ok"])))
    app = proxy(client)
    oauth = {"Authorization": "Bearer configured-oauth", "ChatGPT-Account-ID": "account"}
    app.config.openai_extra_headers = {"x-gateway-secret": "CONFIGURED_SECRET"}
    if configured_oauth:
        app.config.openai_extra_headers.update(oauth)
    if trusted_chatgpt:
        app.config.openai_api_url = "https://chatgpt.com"
        app.OPENAI_API_URL = "https://chatgpt.com"
    try:
        response = await forward_raw(
            app,
            request(headers={} if configured_oauth else oauth),
            route="responses",
            body=b"raw",
            content_length=3,
            request_id="hr_raw",
            reason="request_size",
        )
        assert b"".join([part async for part in response.body_iterator]) == b"ok"
    finally:
        await client.aclose()
    upstream = client.send.call_args.args[0]
    assert str(upstream.url) == "https://chatgpt.com/backend-api/codex/responses?beta=true"
    if trusted_chatgpt or not configured_oauth:
        assert upstream.headers["authorization"] == oauth["Authorization"]
        assert upstream.headers["chatgpt-account-id"] == oauth["ChatGPT-Account-ID"]
    else:
        assert "authorization" not in upstream.headers
        assert "chatgpt-account-id" not in upstream.headers
    assert ("x-gateway-secret" in upstream.headers) is trusted_chatgpt


@pytest.mark.asyncio
async def test_raw_upload_stays_lazy_and_cancelled_response_closes():
    consumed = []
    wire = WireStream([b"one", b"two"])

    async def upload():
        consumed.append(1)
        yield b"\xffone"
        consumed.append(2)
        yield b"two"

    client = httpx.AsyncClient()

    async def send(upstream, **kwargs):
        assert consumed == []
        assert await upstream.aread() == b"\xffonetwo"
        return httpx.Response(200, stream=wire)

    client.send = AsyncMock(side_effect=send)
    registry = StreamDiagnostics()
    record = registry.begin("codex")
    token = current_stream.set(record)
    try:
        response = await forward_raw(
            proxy(client),
            request(),
            route="responses",
            body=upload(),
            content_length=None,
            request_id="hr_raw",
            reason="request_size",
        )
        assert await anext(response.body_iterator) == b"one"
        await response.body_iterator.aclose()
        assert wire.closed
        assert record.snapshot()["attempt"] == 1
    finally:
        current_stream.reset(token)
        await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("gate", ["rate", "budget"])
async def test_raw_rate_and_budget_denials_do_not_consume_body(gate):
    client = httpx.AsyncClient()
    client.send = AsyncMock()
    app = proxy(client)
    if gate == "rate":
        app.rate_limiter = SimpleNamespace(check_request=AsyncMock(return_value=(False, 4.0)))
    else:
        app.cost_tracker = SimpleNamespace(
            check_budget=lambda: (False, 0), budget_denial_detail=lambda: "Budget exhausted"
        )

    async def unread():
        pytest.fail("denied request consumed its upload")
        yield b""

    try:
        with pytest.raises(HTTPException) as caught:
            await forward_raw(
                app,
                request(),
                route="responses",
                body=unread(),
                content_length=None,
                request_id="hr_raw",
                reason="request_size",
            )
        assert caught.value.status_code == 429
        client.send.assert_not_called()
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_transport_failure_is_not_retried_or_exposed():
    client = httpx.AsyncClient()
    client.send = AsyncMock(side_effect=httpx.ReadError("SECRET URL AND TOKEN"))
    try:
        response = await forward_raw(
            proxy(client),
            request(),
            route="responses",
            body=b"media",
            content_length=5,
            request_id="hr_raw",
            reason="request_size",
        )
        assert response.status_code == 502
        assert b"SECRET" not in response.body
        assert client.send.await_count == 1
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_custom_base_preserves_path_but_never_receives_untrusted_extra_secret():
    client = httpx.AsyncClient()
    captured = []

    async def send(upstream, **kwargs):
        captured.append(upstream)
        return httpx.Response(200, stream=WireStream([b"ok"]))

    client.send = AsyncMock(side_effect=send)
    app = proxy(client)
    app.config.openai_extra_headers = {"x-gateway-secret": "CONFIGURED_SECRET"}
    req = request(
        headers={
            "x-headroom-base-url": "https://custom.example/root",
            "x-headroom-original-path": "/model/responses",
            "authorization": "Bearer caller-key",
        }
    )
    try:
        with (
            patch("headroom.proxy.handlers.openai.is_safe_upstream_url", return_value=True),
            patch("headroom.proxy.upstream_trust.is_trusted_upstream", return_value=False),
        ):
            response = await forward_raw(
                app,
                req,
                route="responses",
                body=b"raw",
                content_length=3,
                request_id="hr_raw",
                reason="request_size",
            )
        assert b"".join([part async for part in response.body_iterator]) == b"ok"
    finally:
        await client.aclose()
    assert str(captured[0].url) == "https://custom.example/root/model/responses?beta=true"
    assert captured[0].headers["authorization"] == "Bearer caller-key"
    assert "x-gateway-secret" not in captured[0].headers
    assert "x-headroom-base-url" not in captured[0].headers


@pytest.mark.asyncio
async def test_copilot_auth_helper_runs_for_resolved_url_without_body_decoding():
    client = httpx.AsyncClient()
    client.send = AsyncMock(return_value=httpx.Response(200, stream=WireStream([b"ok"])))
    app = proxy(client)
    app.OPENAI_API_URL = "https://api.githubcopilot.com"
    auth = AsyncMock(
        side_effect=lambda headers, **kwargs: {**headers, "authorization": "Bearer copilot-api"}
    )
    try:
        with patch("headroom.copilot_auth.apply_copilot_api_auth", auth):
            response = await forward_raw(
                app,
                request(),
                route="responses",
                body=b"\xffmedia",
                content_length=6,
                request_id="hr_raw",
                reason="bypass_header",
            )
        assert b"".join([part async for part in response.body_iterator]) == b"ok"
    finally:
        await client.aclose()
    auth.assert_awaited_once()
    upstream = client.send.call_args.args[0]
    assert upstream.headers["authorization"] == "Bearer copilot-api"
    assert auth.call_args.kwargs["url"] == str(upstream.url)


@pytest.mark.asyncio
async def test_cancelled_downstream_headers_close_upstream_before_body_iteration():
    client = httpx.AsyncClient()
    wire = WireStream([b"not yet consumed"])
    client.send = AsyncMock(return_value=httpx.Response(200, stream=wire))
    req = request()
    req.scope["asgi"] = {"spec_version": "2.4"}
    cancelled = asyncio.CancelledError()

    async def send(_message):
        raise cancelled

    try:
        response = await forward_raw(
            proxy(client),
            req,
            route="responses",
            body=b"raw",
            content_length=3,
            request_id="hr_raw",
            reason="request_size",
        )
        with pytest.raises(asyncio.CancelledError) as caught:
            await response(req.scope, AsyncMock(), send)
        assert caught.value is cancelled
        assert wire.closed
    finally:
        await client.aclose()
