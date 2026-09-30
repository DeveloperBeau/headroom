"""Exercise real public routes: oversized/media uploads bypass JSON processing."""

import gzip

import httpx
import pytest
from fastapi.testclient import TestClient

from headroom.proxy import helpers
from headroom.proxy.server import ProxyConfig, create_app


@pytest.mark.parametrize("chunked", [False, True])
def test_oversized_upload_with_token_limit_stays_rejected(chunked, monkeypatch):
    from types import SimpleNamespace

    monkeypatch.setattr(helpers, "MAX_REQUEST_BODY_SIZE", 64)
    app = create_app(
        ProxyConfig(
            optimize=False,
            cache_enabled=False,
            rate_limit_enabled=False,
            cost_tracking_enabled=False,
            disable_kompress=True,
        )
    )
    with TestClient(app) as client:
        app.state.proxy.rate_limiter = SimpleNamespace(tokens_per_minute=100)
        payload = b"x" * 65
        response = client.post(
            "/v1/responses",
            content=iter([payload]) if chunked else payload,
            headers={"Authorization": "Bearer sk-test"},
        )
        app.state.proxy.rate_limiter = None
    assert response.status_code == 413


@pytest.mark.parametrize("path", ["/v1/responses", "/v1/messages"])
@pytest.mark.parametrize("kind", ["declared", "chunked", "bypass", "decompressed"])
def test_large_upload_is_forwarded_opaque(path, kind, monkeypatch):
    monkeypatch.setattr(helpers, "MAX_REQUEST_BODY_SIZE", 64)
    monkeypatch.setattr(helpers, "MAX_DECOMPRESSED_BODY_SIZE", 64)
    payload = b"\x00\xffmedia" * 12
    headers = {"Authorization": "Bearer sk-test", "Content-Type": "application/octet-stream"}
    if kind == "bypass":
        payload = b"\xff"
        headers["x-headroom-bypass"] = "true"
    elif kind == "decompressed":
        payload = gzip.compress(b"x" * 2048)
        headers["Content-Encoding"] = "gzip"
        assert len(payload) < 64
    app = create_app(
        ProxyConfig(
            optimize=False,
            cache_enabled=False,
            rate_limit_enabled=False,
            cost_tracking_enabled=False,
            disable_kompress=True,
        )
    )
    calls = []

    async def send(request, **kwargs):
        calls.append((request, await request.aread()))
        return httpx.Response(
            200,
            headers={"Content-Type": "application/octet-stream"},
            stream=httpx.ByteStream(b"provider reply"),
            request=request,
        )

    with TestClient(app) as client:
        monkeypatch.setattr(app.state.proxy.http_client, "send", send)
        content = iter([payload[:35], payload[35:]]) if kind == "chunked" else payload
        response = client.post(path, headers=headers, content=content)
    assert response.status_code == 200, response.text
    assert response.content == b"provider reply"
    assert len(calls) == 1
    assert calls[0][1] == payload
    assert calls[0][0].headers.get("content-encoding") == headers.get("Content-Encoding")
    assert "x-headroom-bypass" not in calls[0][0].headers
