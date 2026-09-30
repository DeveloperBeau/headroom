"""Choose bounded optimization or an untouched streaming upload."""

from collections.abc import AsyncIterator
from dataclasses import dataclass

from starlette.requests import Request

from headroom.proxy import helpers


@dataclass(frozen=True)
class RawBody:
    content: AsyncIterator[bytes]
    content_length: int | None
    reason: str


async def prepare_raw_body(request: Request, *, limit: int | None = None) -> RawBody | None:
    """Return a streaming body when optimization is unsuitable; cache small bodies.

    Known large uploads and explicit opt-outs are never read here. Unknown sizes
    retain at most the optimization budget plus one ASGI chunk before forwarding.
    The original encoding and bytes remain intact; this function never parses JSON.
    """
    if limit is None:
        limit = helpers.MAX_REQUEST_BODY_SIZE
    try:
        length = int(request.headers["content-length"])
        if length < 0:
            length = None
    except (KeyError, ValueError):
        length = None
    if helpers._headroom_bypass_enabled(request.headers):
        return RawBody(request.stream(), length, "bypass_header")
    if length is not None and length > limit:
        return RawBody(request.stream(), length, "request_size")

    chunks: list[bytes] = []
    size = 0
    stream = request.stream()
    async for chunk in stream:
        chunks.append(chunk)
        size += len(chunk)
        if size > limit:

            async def replay() -> AsyncIterator[bytes]:
                for prefix in chunks:
                    yield prefix
                chunks.clear()
                async for remainder in stream:
                    yield remainder

            # An understated Content-Length cannot describe the forwarded body.
            return RawBody(replay(), None, "request_size")
    request._body = b"".join(chunks)
    return None
