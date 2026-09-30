"""Large uploads must reach the transport without JSON/media materialization."""

import pytest
from starlette.requests import Request


def request_from_chunks(chunks, headers=()):
    consumed = []
    iterator = iter(chunks)

    async def receive():
        chunk = next(iterator, None)
        if chunk is None:
            return {"type": "http.request", "body": b"", "more_body": False}
        consumed.append(chunk)
        return {"type": "http.request", "body": chunk, "more_body": True}

    return Request(
        {"type": "http", "method": "POST", "path": "/v1/responses", "headers": headers}, receive
    ), consumed


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "headers",
    [
        [(b"content-length", b"1000")],
        [(b"x-headroom-bypass", b"true")],
        [(b"x-headroom-mode", b"passthrough")],
    ],
)
async def test_known_large_or_explicit_bypass_starts_without_reading(headers):
    from headroom.proxy.large_request_body import prepare_raw_body

    request, consumed = request_from_chunks([b"not-json", b"\x00\xffmedia"], headers)
    raw = await prepare_raw_body(request, limit=5)
    assert raw is not None
    assert consumed == []
    assert b"".join([chunk async for chunk in raw.content]) == b"not-json\x00\xffmedia"


@pytest.mark.asyncio
async def test_unknown_length_peeks_bounded_prefix_then_forwards_every_byte():
    from headroom.proxy.large_request_body import prepare_raw_body

    request, consumed = request_from_chunks([b"abcd", b"efgh", b"ijkl"])
    raw = await prepare_raw_body(request, limit=5)
    assert raw is not None and raw.reason == "request_size"
    assert consumed == [b"abcd", b"efgh"]
    assert raw.content_length is None
    assert b"".join([chunk async for chunk in raw.content]) == b"abcdefghijkl"


@pytest.mark.asyncio
async def test_small_body_is_cached_for_normal_parser_without_rereading():
    from headroom.proxy import helpers
    from headroom.proxy.large_request_body import prepare_raw_body

    request, consumed = request_from_chunks([b"{}", b"  "])
    assert await prepare_raw_body(request, limit=5) is None
    assert await helpers._read_request_body_bytes(request) is request._body
    assert request._body == b"{}  "
    assert consumed == [b"{}", b"  "]


@pytest.mark.asyncio
async def test_understated_length_does_not_lose_bytes_or_forward_wrong_length():
    from headroom.proxy.large_request_body import prepare_raw_body

    request, _ = request_from_chunks([b"abcd", b"efgh"], [(b"content-length", b"2")])
    raw = await prepare_raw_body(request, limit=5)
    assert raw is not None and raw.content_length is None
    assert b"".join([chunk async for chunk in raw.content]) == b"abcdefgh"
