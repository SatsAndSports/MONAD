# Connection failure diagnostics

Relay CONNECT failures retain a canonical code/status pair. TCP resolution,
refusal, timeout and unreachable errors are distinguished only from typed
resolver/io results. QUIC connection timeout, connection failure, invalid peer
attestation, unavailable attestation and stream-open failure are separate stages.
Unknown causes stay generic. Raw transport messages are never sent to SOCKS or
management consumers. Existing admission codes retain their meanings.

All transport/setup failure codes use HTTP 502, preserving the existing CONNECT
failure status. Clients accept only known matching code/status pairs. The existing
bounded suffix retry window includes transient transport codes as well as legacy
unstructured 502, but invalid authentication is not made retryable.

Attribution is attached by the client, not supplied as a global hop number by a
relay. A typed rejection from an authenticated preceding session is relay-reported;
a locally observed connection/handshake failure does not identify a failed relay.
Indices are one-based and omitted when unknown. Exit CONNECT and onward relay
CONNECT are distinguished. A route failure retained in a management snapshot is
historical context, not proof of the cause of a later SOCKS request's failure.

SOCKS diagnostics v1 gains optional context fields (old readers ignore them).
Standard SOCKS remains standard; unknown causes are not converted to destination
refusal. Existing concurrency, accounting, capability, and funding policies remain
independent of these advisory diagnostics.

## CONNECT code registry (HTTP 502)

| Code | Evidence |
| --- | --- |
| `TCP_RESOLUTION_FAILED` | Resolver error or empty address result |
| `TCP_CONNECTION_REFUSED` | TCP dial returns `ConnectionRefused` |
| `TCP_CONNECT_TIMED_OUT` | Typed dial timeout or overall TCP setup deadline |
| `TCP_DESTINATION_UNREACHABLE` | Typed host/network unreachable error |
| `TCP_CONNECT_FAILED` | Other TCP setup failure, cause not inferred |
| `QUIC_RESOLUTION_FAILED` | Resolver error or empty address result |
| `QUIC_CONNECT_TIMED_OUT` | Quinn timeout or overall QUIC setup deadline |
| `QUIC_CONNECT_FAILED` | Other QUIC connection/setup failure (including unavailable local pool) |
| `QUIC_AUTHENTICATION_FAILED` | Complete secp256k1 attestation received and failed verification |
| `QUIC_AUTHENTICATION_UNAVAILABLE` | Attestation exchange could not complete; not evidence of a wrong identity |
| `QUIC_STREAM_FAILED` | Session-stream opening on the new authenticated connection failed |

Overall setup deadlines may include resolution/authentication; they do not prove
which sub-operation stalled. OS errors are classified by typed kind, not text.
TCP attempts retain the existing resolved-address traversal and IPv4/IPv6 support.
Both ordinary and blinded onward QUIC CONNECT paths use these codes; diagnostic
messages never disclose decrypted blinded-hop destinations or raw backend strings.

The bounded suffix retry window accepts the new transient codes alongside legacy
unstructured 502. Invalid attestation verification is not retried in that window;
the runtime's broader route reconnect/startup-attempt policy is unchanged. No
admission error becomes retryable merely because it resembles a transport error.

## Client attribution

Diagnostics add optional `context`:

```json
{"origin":"relay","operation":"relay_connect","reporting_hop":1,"target_hop":2}
```

`origin` is `relay` for a received CONNECT/bootstrap rejection and `local` for a
locally observed failure. Operations include `exit_connect`, `relay_connect`,
`session_handshake`, `session_setup`, `route` and `request`. Hop numbers are
one-based, or null when unavailable. Origin/operation are bounded ASCII tokens;
unknown future values are advisory. A local failure never supplies a reporting hop.
For an exit rejection, reporting hop is the authenticated final session's route
position. For onward CONNECT, it is the preceding relay and target hop is the
next session. A broken nested transport identifies the target attempt, not the
culprit among the prefix relays. Legacy unstructured HTTP errors retain status
without inventing a reason code. Low-level connections with no route metadata
leave hop attribution null.

For a local exit-setup failure, target hop identifies the intended exit session,
not a claim that this relay caused the transport loss. A local deadline may expire
before a relay's timeout response arrives; then only the local timeout is reported.

When SOCKS cannot acquire an active route, the root diagnostic stays a **local
route-unavailable** error. Optional `last_route_failure` contains the previous
route-setup diagnostic (`context`, `code`, `message`, `http_status`), explicitly
historical rather than asserted to be the cause of this SOCKS request. The entire
JSON frame still fits the existing 4096-byte limit. Each message is bounded to
1024 bytes; origin to 32, operation to 64, and non-null hop indices to 1–65535.

Management `ClientFailure.connection_failure` retains the same structured route
detail, including at startup-attempt exhaustion. Exit snapshots/events retain the
same diagnostic as the SOCKS failure. Their legacy `rejection` is now nullable:
local/unclassified failures do not fabricate a relay rejection. Typed rejections
emit `exit_refused`; other failures emit `exit_failed`. Existing generation checks
prevent stale failures from replacing current state.

## Standard SOCKS and compatibility

TCP refusal remains 0x05; TCP resolution/unreachability uses 0x04; typed TCP
timeouts/generic failures and QUIC failures use 0x01. Destination policy remains
0x02; existing admission/limit and unstructured reply mappings are preserved.
Timeout is not misrepresented as SOCKS TTL expiry. Standard clients receive no
diagnostic bytes. The v1 extension version is unchanged: context fields are
optional and old diagnostic readers ignore them.

MONAD peers should be upgraded together for the expanded CONNECT code registry:
older peers may reject unfamiliar `monad-rejection-code` metadata rather than
provide the new classification. No funding/session-protocol negotiation or
capability policy is changed here.

Rust API consumers should account for the boxed diagnostic in
`SocksClientError::RejectedWithDiagnostic`, new optional diagnostic/context fields,
and nullable `ExitFailure.rejection`. No stored wallet/journal format changes.
