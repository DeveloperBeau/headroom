# Controlled proxy comparisons

`python -m headroom.proxy.diagnostic_probe` is an opt-in, sequential comparison
tool. It sends the supplied request independently using HTTP/1.1 and HTTP/2,
with a fresh client for each attempt and with a client reused within each mode.
Nothing schedules it, changes proxy configuration, or restarts a service.
`--execute` is required to send traffic. Real provider requests may incur charges.

Supply an endpoint file containing one complete URL, a request file containing
the exact request bytes, and optionally a headers file containing a JSON object
of string header names and values. Keep request and headers files private:

```sh
chmod 600 request.json direct-headers.json
```

For example, a headers file can supply `Content-Type: application/json` and the
provider's required authorization header. The tool does not construct a provider
request or select a model. Use an intentionally small request suitable for your
provider, and check that your account permits the comparison.

Validate files and inspect the request count without opening an HTTP client:

```sh
python -m headroom.proxy.diagnostic_probe \
  --endpoint-file direct-endpoint.txt \
  --request-file request.json --headers-file direct-headers.json --dry-run
```

The default direct matrix has eight requests: two attempts in each of four
protocol/client combinations. Replace `--dry-run` with `--execute` only when
you intend to send those requests. Use `--count 1` for a smaller initial run;
reuse evidence requires at least two attempts. `--method GET` is available for
an endpoint that expects GET; the supplied request bytes are still sent.

Add `--proxy-endpoint-file proxy-endpoint.txt` to run the same matrix against a
Headroom endpoint. This makes sixteen requests at the default count. Proxy
headers are separate: supply `--proxy-headers-file proxy-headers.json` if needed
and protect it with `chmod 600`. Direct credentials are never copied implicitly
to the proxy endpoint. Both routes receive the identical request body.

HTTP/2 selection on a proxy comparison controls the client-to-proxy connection.
It does not change Headroom's upstream HTTP protocol. Use direct comparisons to
isolate upstream transport, and proxy comparisons to inspect the proxy path.
The requested protocol and `negotiated_protocol` are reported separately. An
HTTP/2-enabled client may negotiate HTTP/1.1; `protocol_matched: false` reports
that fallback, rather than claiming an HTTP/2 comparison succeeded.

## Bounds, TLS and permissions

- `--count` is 1..5 requests per cell, at most forty requests including proxy
  comparison. Requests are sequential and each client has one connection slot.
- `--timeout` is 1..60 seconds per entire request, default 30, as well as the
  HTTP client's operation timeout. `--max-seconds` is a 1..300 second run budget,
  default 120. At exhaustion, stop the remaining matrix and report incomplete.
  Client cleanup has its own one-second cap; this can extend the run budget.
- `--max-response-bytes` is 1..33554432, default 1048576. Oversized responses are
  closed and marked `response_limit`. Request files are limited to 1 MiB, headers
  to 16 KiB/64 fields, and endpoint files to 8 KiB. SSE lines/events retain at
  most 64 KiB each, marking `sse_parser_limited` when exceeded.
- TLS certificate and hostname verification are always enabled. `--ca-file`
  supplies a PEM CA bundle if your endpoint uses a private CA; it never disables
  verification. Environment proxies and environment CA overrides are ignored.
- URLs must use HTTPS and cannot contain credentials or fragments. Query strings
  may be supplied but are never emitted. Redirects are never followed, including
  redirects to a different host or plaintext endpoint.
- Plain HTTP requires `--allow-loopback-http` and a literal loopback address,
  such as `http://127.0.0.1:8787/v1/messages` or `http://[::1]:8787/v1/messages`.
  `localhost` is rejected because it requires DNS resolution. This exception is
  for an explicitly selected local fixture or proxy, not a remote provider.
- Request/header inputs must be regular files, and on POSIX must have no group
  or other permission bits. Protect endpoint files and output too. Windows does
  not provide equivalent POSIX mode enforcement; use an appropriate user-only
  ACL. The probe needs only normal file access and endpoint network access, with
  no sudo, packet capture permission, service control, or configuration writes.

The `headroom-ai[proxy]` dependencies already include `httpx[http2]`; the probe
adds no dependency. If HTTP/2 support is missing, the affected rows report
`dependency_unavailable`. It does not install anything automatically.

## Reading the output

One bounded JSON object goes to stdout. It includes a generated run ID, process
ID, UTC timestamps, per-request IDs, route/mode, requested and negotiated HTTP,
validated TLS/ALPN metadata when available, HTTP status, monotonic timing,
response byte count, stream ID where available, and categorical errors. There
are no supplied URLs, paths, query strings, header values, request/response
bodies, or exception messages in the output. Input errors emit only
`{"error": "invalid_input"}`; unknown runtime errors emit `probe_unavailable`.

Every request carries a generated `x-client-request-id`, also emitted as
`request_id`, so diagnostics can correlate it. Any supplied value for that
header is replaced. The allowlisted provider response identifiers (`request-id`,
`x-request-id`, `anthropic-request-id`, `cf-ray`) are accepted only as short
ASCII identifiers and emitted as 24-character SHA-256 prefixes, never raw values.
Use the same hash calculation to correlate a known provider ID locally.

`connection_reused` is based on the same `network_stream` object appearing in a
prior response, with strong references retained during the bounded run. Generated
`connection_id` values are scoped to the run. Reusing an HTTP client alone does
not prove reusing its TCP/TLS connection. When the transport exposes no stream,
reuse is `null` and `connection_evidence` is `unavailable`; HTTP/2 stream IDs and
TLS fields likewise stay `null` if the dependency does not expose them.

For SSE, `sse_terminal` indicates a dispatched successful terminal event:
`message_stop`, `response.completed`, or `data: [DONE]`. A JSON data event with
one of those `type` values also qualifies. Incomplete final events do not qualify.
The tool requests `Accept-Encoding: identity` and inspects raw bytes, avoiding
unbounded decompression. If the server nevertheless compresses SSE, terminal
inspection is unavailable (`null`, outcome `sse_unavailable`). Other response
bodies are counted and discarded. A missing successful terminal is reported
even when HTTP status is 200. Timing measures this probe's observations and does
not establish the cause of a production interruption.

Exit codes: 0 for dry-run or a completed matrix of complete responses; 1 for
incomplete/error responses or unavailable execution; 2 for invalid inputs; 130
for interruption. Protocol fallback is visible in the metadata and does not
alone change the exit code. Check `protocol_matched` before comparing H1 and H2.

## Running this checkout with installed dependencies

The installed service may still use an older package. On the current workstation,
run the checkout without replacing that package or installing dependencies:

```sh
rtk proxy env PYTHONPATH=/Users/beau/Developer/Personal/tools/coding/headroom \
  /Users/beau/.local/share/uv/tools/headroom-ai/bin/python \
  -m headroom.proxy.diagnostic_probe \
  --endpoint-file direct-endpoint.txt --request-file request.json \
  --headers-file direct-headers.json --dry-run
```

Run the deterministic checks with that interpreter from the repository root:

```sh
rtk proxy env PYTHONPATH=/Users/beau/Developer/Personal/tools/coding/headroom \
  /Users/beau/.local/share/uv/tools/headroom-ai/bin/python \
  -m unittest tests.test_diagnostic_probe
```

Tests use fake HTTP fixtures, including httpcore's real HTTP/1.1 and HTTP/2 wire
parsers/pool over an in-memory network backend. The HTTP/2 fixture simulates ALPN;
it proves parser/reuse behavior, not actual TLS certificate negotiation. This
works when the sandbox denies loopback listeners and requires no live provider.

Runtime rollout is separate from this repository implementation. Publish a new
immutable fork revision, update the deployment pin (ATS `lib/headroom.sh` still
pins the previous baseline until integrated), and install it through the normal
deployment workflow. Before activation, verify the resolved package location
and revision. If an operator later authorizes a service restart, record the old
and new process IDs and `/debug/streams` snapshots to prove which code is running.
Run this probe's dry-run first; execute a bounded comparison only when explicitly
selected. A checkout test or CLI dry-run does not prove live logging activation.
