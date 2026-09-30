"""Transport-only forwarding for bodies that must not enter JSON/ML processing."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterable

import anyio
import httpx
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from headroom.proxy.upstream_diagnostics import current_stream

logger = logging.getLogger("headroom.proxy")
_HOP_HEADERS = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)


def _hop_headers(headers) -> set[str]:
    return set(_HOP_HEADERS) | {
        value.strip().lower() for value in headers.get("connection", "").split(",") if value.strip()
    }


def raw_forwarding_allowed(proxy, route: str) -> bool:
    """Body-dependent enforcement and protocol translation cannot be skipped."""
    if getattr(getattr(proxy, "rate_limiter", None), "tokens_per_minute", None) is not None:
        return False
    if getattr(getattr(proxy, "cost_tracker", None), "budget_limit_usd", None) is not None:
        return False
    return route != "messages" or not (
        getattr(proxy, "security", None) or getattr(proxy, "anthropic_backend", None)
    )


class _RawResponse(StreamingResponse):
    """Close upstream even if sending headers fails before iteration starts."""

    def __init__(self, *args, upstream, **kwargs):
        super().__init__(*args, **kwargs)
        self.upstream = upstream

    async def close_upstream(self):
        # Starlette's disconnect scope may already be cancelled when we unwind.
        with anyio.CancelScope(shield=True):
            await self.upstream.aclose()

    async def __call__(self, scope, receive, send):
        try:
            await super().__call__(scope, receive, send)
        finally:
            await self.close_upstream()


async def forward_raw(
    proxy,
    request: Request,
    *,
    route: str,
    body: bytes | AsyncIterable[bytes],
    content_length: int | None,
    request_id: str,
    reason: str,
) -> StreamingResponse | JSONResponse:
    """Forward once, without parsing payloads, decompressing, estimating, or retrying.

    Caller owns inbound authentication and size classification. Only the two
    direct provider protocols are supported: translated backend routes still
    need their existing body-aware handlers.
    """
    from headroom.copilot_auth import apply_copilot_api_auth, build_copilot_upstream_url
    from headroom.proxy.helpers import _strip_internal_headers, merge_extra_headers

    if route not in {"responses", "messages"}:
        raise ValueError("Unsupported raw forwarding route")
    if not raw_forwarding_allowed(proxy, route):
        return JSONResponse(
            status_code=413,
            content={
                "error": {
                    "type": "request_too_large",
                    "message": "This request requires body processing for configured limits, security, or provider translation.",
                }
            },
        )
    headers = dict(request.headers.items())
    dropped = _hop_headers(headers) | {"host", "content-length"}
    headers = {key: value for key, value in headers.items() if key.lower() not in dropped}
    headers = _strip_internal_headers(headers)

    if route == "responses":
        # Lazy imports avoid a handler/helper import cycle. These own the
        # validated custom upstream and OAuth-versus-API routing decisions.
        from headroom.providers.codex.responses import codex_responses_http_url
        from headroom.providers.codex.runtime import resolve_codex_routing_headers
        from headroom.proxy.handlers.openai import (
            _CODEX_RESPONSES_LITE_HEADER,
            _append_request_query,
            _openai_rate_limit_key,
            _resolve_openai_handler_path,
            _resolve_openai_upstream_base,
        )

        custom_base = _resolve_openai_upstream_base(request.headers)
        configured_headers = merge_extra_headers(
            headers,
            proxy.config.openai_extra_headers,
            upstream_url=custom_base,
            config=proxy.config,
        )
        resolved_headers, chatgpt_auth = resolve_codex_routing_headers(configured_headers)
        if chatgpt_auth:
            url = codex_responses_http_url(request.url.query)
            # Configured OpenAI gateway secrets must not follow OAuth routing
            # to a different host just because no custom-base header was sent.
            headers = merge_extra_headers(
                headers,
                proxy.config.openai_extra_headers,
                upstream_url=url,
                config=proxy.config,
            )
            headers, _ = resolve_codex_routing_headers(headers)
        else:
            path = (
                _resolve_openai_handler_path(request.headers, handler_path="/responses")
                if custom_base is not None
                else "/v1/responses"
            )
            url = _append_request_query(
                build_copilot_upstream_url(custom_base or proxy.OPENAI_API_URL, path),
                request.url.query,
            )
            headers = resolved_headers
        headers = {
            key.lower(): value
            for key, value in headers.items()
            if key.lower() != _CODEX_RESPONSES_LITE_HEADER
        }
        rate_key = _openai_rate_limit_key(headers)
        provider = "openai"
    else:
        from headroom.proxy.anthropic_wire import build_anthropic_upstream_url
        from headroom.proxy.forwarded_headers import resolve_client_ip

        url = build_anthropic_upstream_url(
            proxy.ANTHROPIC_API_URL, request.url.path, request.url.query
        )
        headers = merge_extra_headers(
            headers, proxy.config.anthropic_extra_headers, upstream_url=None, config=proxy.config
        )
        headers = {key.lower(): value for key, value in headers.items()}
        key = headers.get("x-api-key", "")
        authorization = headers.get("authorization", "")
        if not key and authorization.startswith("Bearer "):
            key = authorization[7:]
        client_ip = resolve_client_ip(request) or "unknown"
        rate_key = f"{key[:16]}:{client_ip}" if key else client_ip
        provider = "anthropic"

    if proxy.rate_limiter:
        allowed, wait_seconds = await proxy.rate_limiter.check_request(rate_key)
        if not allowed:
            await proxy.metrics.record_rate_limited(provider=provider, source="headroom")
            raise HTTPException(
                429,
                detail=f"Rate limited. Retry after {wait_seconds:.1f}s",
                headers={"Retry-After": str(int(wait_seconds) + 1)},
            )
    if proxy.cost_tracker:
        allowed, _remaining = proxy.cost_tracker.check_budget()
        if not allowed:
            raise HTTPException(429, detail=proxy.cost_tracker.budget_denial_detail())

    headers = await apply_copilot_api_auth(headers, url=url)
    dropped = _hop_headers(headers) | {"host", "content-length"}
    headers = {key: value for key, value in headers.items() if key.lower() not in dropped}
    if isinstance(body, bytes):
        content_length = len(body)
    if content_length is not None:
        if type(content_length) is not int or content_length < 0:
            raise ValueError("Invalid raw forwarding content length")
        headers["content-length"] = str(content_length)
    # Preserve content-encoding: the upload is still the caller's wire bytes.
    reason = (
        reason
        if reason in {"request_size", "bypass_header", "decompressed_size"}
        else "bypass_header"
    )
    diagnostic = current_stream.get()
    upstream_request = proxy.http_client.build_request(
        request.method, url, headers=headers, content=body
    )
    if diagnostic is not None:
        diagnostic.bind_request(request_id)
        diagnostic.start_attempt(1, upstream_request.extensions.get("timeout", {}))
        upstream_request.extensions["trace"] = diagnostic.trace
    logger.info(
        "event=raw_passthrough request_id=%s route=%s reason=%s content_length=%s",
        request_id,
        route,
        reason,
        content_length,
    )
    try:
        upstream = await proxy.http_client.send(upstream_request, stream=True)
    except BaseException as error:
        if diagnostic is not None:
            diagnostic.observe_exception(error)
        if not isinstance(error, httpx.TransportError):
            raise
        logger.warning(
            "event=raw_passthrough_failed request_id=%s error_type=%s",
            request_id,
            type(error).__name__,
        )
        return JSONResponse(
            status_code=502,
            content={
                "error": {
                    "type": "connection_error",
                    "message": "Unable to reach upstream.",
                }
            },
        )
    if diagnostic is not None:
        diagnostic.response(upstream)

    async def relay():
        try:
            chunks = upstream.aiter_raw()
            if diagnostic is not None:
                chunks = diagnostic.iter_chunks(chunks)
            async for chunk in chunks:
                if diagnostic is not None:
                    diagnostic.wait_start("downstream_yield")
                try:
                    yield chunk
                finally:
                    if diagnostic is not None:
                        diagnostic.wait_end("downstream_yield", size=len(chunk))
        except BaseException as error:
            if diagnostic is not None:
                diagnostic.observe_exception(error)
            raise
        finally:
            await response.close_upstream()

    response = _RawResponse(relay(), upstream=upstream, status_code=upstream.status_code)
    dropped = _hop_headers(upstream.headers) | {"x-headroom-bypass"}
    # Preserve duplicate headers and raw response entity headers. aiter_raw()
    # does not decode gzip/br, so content-encoding and content-length stay valid.
    response.raw_headers = [
        (key.lower(), value)
        for key, value in upstream.headers.raw
        if key.decode("ascii").lower() not in dropped
    ]
    response.raw_headers.append((b"x-headroom-bypass", reason.encode("ascii")))
    return response
