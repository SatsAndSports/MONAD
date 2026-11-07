# Opt-in SOCKS5 diagnostics v1

MONAD's local SOCKS listeners support a private diagnostics method alongside
standard SOCKS5/no-auth. This is not authentication or encryption and does not
change relay bootstrap, payment, or CONNECT protocols. Standard clients continue
to offer method `0x00` and receive only standard SOCKS replies.

## Negotiation

1. The application offers private method **0x80** in the SOCKS5 greeting. This is
   a private-use identifier, not an IANA-assigned globally interoperable method.
2. A supporting MONAD listener selects 0x80 if offered, otherwise selects 0x00
   if offered, otherwise replies `05 ff` and ends negotiation. It never selects
   an unoffered method.
3. After selection of 0x80, the application sends exactly six bytes:
   `4d 4f 4e 41 44 01` (`MONAD` followed by version 1).
4. The listener responds with two bytes: `01 00` for acceptance, or `01 01`
   for unsupported identification/version and closes the connection. A truncated
   or stalled exchange may close without an acknowledgement.
5. Only after acceptance does the application send its standard SOCKS5 CONNECT
   request. There is no fallback or retry after selecting the private method.

The Rust `socks_client::connect_with_diagnostics` API offers **only** 0x80 and
requires successful v1 negotiation. `socks_client::connect` continues to offer
only 0x00. An older SOCKS server can reject the private-only greeting; callers
must not mistake that for a destination refusal.

## Replies

### Success

The complete standard SOCKS5 reply is followed immediately by destination data.
There is no length prefix, JSON, or other extension payload after a successful
CONNECT. The extension must never contaminate the tunneled byte stream.

### Failure

Every SOCKS failure reply emitted after private-method acceptance is:

```text
standard SOCKS5 reply (VER, REP, RSV, ATYP, BND.ADDR, BND.PORT)
uint32_be JSON_length
JSON_length bytes of UTF-8 JSON
connection closure
```

`REP` is nonzero. The address/port portion is still present, even on failure.
The length must be 1–4096 bytes; check it before allocating the payload buffer.

Example diagnostic:

```json
{
  "stage": "connect",
  "code": "SESSION_CONNECT_SETUP_LIMIT_REACHED",
  "message": "This session has reached its concurrent CONNECT setup limit.",
  "http_status": 429
}
```

- `stage`: required nonempty ASCII alphanumeric/underscore token, at most 64 bytes.
  Current values are `request`, `route`, and `connect`.
- `code`: existing MONAD rejection code, or null/absent when unavailable; a
  nonempty ASCII alphanumeric/underscore token of at most 128 bytes when present.
- `message`: required nonempty explanatory text, at most 1024 UTF-8 bytes, without
  Unicode control characters. MONAD sends fixed/canonical descriptions rather
  than raw upstream bodies, URLs, credentials, or arbitrary transport error text.
- `http_status`: original relay CONNECT status when known, otherwise null/absent;
  an integer in 100–599 when present.
- Optional `context` and `last_route_failure` provide bounded attribution and
  explicitly historical route-setup context; see [connection failures](connect-failures.md).

Receivers preserve unknown valid codes/stages and ignore unknown fields for
forward-compatible diagnostics. Diagnostics are advisory; they do not authorize
retry or imply a particular remote cause beyond what the reporting component knows.

The primary SOCKS reply code remains authoritative for SOCKS success/failure.
`RejectedWithDiagnostic` exposes a valid diagnostic. `DiagnosticFailure` preserves
the received SOCKS failure code if the frame is missing, truncated, oversized,
malformed, or late. Without a complete valid SOCKS reply header, errors remain
protocol/transport errors rather than fabricated refusals. Invalid/incomplete
requests may be closed without a SOCKS failure reply; EOF is not a valid diagnostic.

## Bounds and lifecycle

The outbound client retains its explicit per-stage timeout, including private
sub-negotiation and the complete reply/diagnostic read. Dropping its future cancels
the operation and closes its owned socket. The listener bounds private
sub-negotiation and private request parsing to five seconds each. Failure reply
writing (standard reply, optional payload, and write shutdown) is bounded to five
seconds. All failure paths finish the connection; no diagnostics are written once
a successful CONNECT has handed the socket to the tunnel proxy.

The server's `socks5_handshake_with_diagnostics` returns the selected reply mode.
Callers carry that mode into `send_failure` and `open_tunnel_with_reply_mode`.
The legacy `socks5_handshake` and `open_tunnel` entry points remain standard-only.

## Initial diagnostic coverage

Existing structured MONAD limits, disabled-admission states, initial-payment
requirements and destination-policy refusals retain their exact code and canonical
description. Typed TCP/QUIC setup failures now retain the categories and attribution
described in [connection failures](connect-failures.md). An unstructured HTTP 502
stays an HTTP 502; unknown causes are not inferred. A missing active local route is
explicitly identified as a `route`-stage failure.

Destination-policy denial is 0x02; TCP refusal and existing admission/limit
refusals are 0x05; typed TCP resolution/unreachability is 0x04; typed TCP timeouts,
generic TCP errors, QUIC failures and local tunnel-setup failures are 0x01.

## Testing and issue #171

Most tests use ordinary SOCKS. Only the 32 concurrent probes of
`tcp_sse_api_drives_real_manual_funding_disable_and_channel_close` now require
the extension. Their payloads, concurrency, 15-second batch timeout and success
assertions are unchanged. No retries are added. Diagnostics confirmed that an
overlapping burst exceeded the default 16 session setup slots; this fixture now
explicitly allows 32 setups before starting its relay. Production defaults remain
16. The test exercises successful concurrent traffic, while the dedicated limit
tests exercise capacity refusals independently of scheduling.

Separate tests cover framing, version negotiation, strict opt-in, both address
families and hostnames, unchanged application bytes, ordinary reply compatibility,
and malformed/oversized/truncated/late diagnostics. An end-to-end test holds a real
relay's sole setup permit using an unresponsive QUIC target, then verifies that
the extended SOCKS client receives `SESSION_CONNECT_SETUP_LIMIT_REACHED`/HTTP 429
while an ordinary SOCKS client receives its standard refusal. The denied target
is never contacted, and the control session remains usable.
