# Structured admission refusals (#84)

Administrative refusal is distinct from transport failure and destination policy.
Clients branch on codes, never on human-readable message strings.

## Bootstrap

A refused Noise NK handshake sends the normal encrypted responder message with:

```json
{"result":"reject","error":{"code":"RELAY_DISABLED","message":"This relay is disabled."}}
```

For session admission wind-down:

```json
{"result":"reject","error":{"code":"SESSION_ADMISSION_DISABLED","message":"This relay is not accepting new sessions."}}
```

No selected protocol, capabilities, pricing, Cashu negotiation or supported-version
list is included. Other negotiation/validation failures use `BOOTSTRAP_REJECTED`
with a diagnostic message. The cryptographic handshake produces an authenticated
negative result; it does not establish an H2/control/payment session.

The ordinary accept payload is unchanged. Rejection delivery is best effort:
malformed/incomplete Noise, exhausted rejection slots, a deadline or transport loss
may still appear as a connection failure. The rejection path has a five-second
deadline and 64 concurrent slots per relay. Disabling cancels accepted sessions
immediately without waiting for rejection-only traffic. New retries can receive the
current policy reason. QUIC authentication is still possible while disabled so a
new stream on either a new or pooled connection can reach the Noise rejection.

## CONNECT and control

| Code | Delivery | Meaning |
| --- | --- | --- |
| `RELAY_DISABLED` | Bootstrap; CONNECT 503 where still deliverable | Relay administratively disabled |
| `SESSION_ADMISSION_DISABLED` | Bootstrap | Existing sessions continue, new sessions refused |
| `TUNNEL_ADMISSION_DISABLED` | CONNECT 503 | Existing tunnels continue, new tunnels refused |
| `CHANNEL_ADMISSION_DISABLED` | Control `Error {code,message}` | Stored channels may relink/pay; first-time acceptance refused |
| `DESTINATION_POLICY_DENIED` | CONNECT 403 | This destination is not permitted |

CONNECT supplies the code in `monad-rejection-code`, without a response body that
the client would have to wait to read. The client derives the standard explanation
and retains the requested destination locally. Unknown/duplicate headers and
code/status mismatches are invalid metadata, not reasons for indefinite waiting.
A plain 503 without MONAD metadata remains a generic CONNECT failure.

Destination-policy refusal is protocol/client preparation only. There is no new
whitelist, regex configuration or destination-policy engine in this change.
It applies equally to TCP and QUIC onward tunnels, including pooled connections.

## Client behavior and timing

- Administrative refusal during setup retries every five seconds at the same hop.
  Healthy prefix sessions and their funded channels remain owned and active.
- First-hop refusal waits without manufacturing wallet funding. Later-hop refusal
  opens a fresh stream for each new handshake attempt through the preserved prefix.
- The administrative episode (sleep plus bounded retry attempts) pauses the setup
  budget. Otherwise cumulative retry handshake time would eventually turn an
  indefinite administrative wait into an unintended startup failure. After success,
  normal setup budget accounting resumes. Each transport/Noise attempt is limited
  to ten seconds; H2/readiness still has the remaining setup budget.
- Mint requests and control heartbeats retain their own deadlines. Prefix failure
  interrupts an administrative wait and allows ordinary route recovery.
- Channel refusal retains the intended funded channel and retries its link every
  five seconds, even in automatic-provisioning mode. No replacement is provisioned
  because of administrative refusal.
- Destination denial while building a route is returned as a typed policy error.
  The configured runtime stops retrying that route and remains available to
  management. Disable/re-enable requests a fresh attempt; YAML changes need restart.
- A final-exit denial fails that individual SOCKS request: policy denial maps to
  SOCKS reply 0x02 (ruleset), other CONNECT rejection to 0x05 (connection refused).
  It does not invalidate the established route or its other tunnels.
- Management `set_enabled(false)` cancels sleeping retries and in-flight setup,
  awaiting supervisor cleanup before completion. Browser/SSE disconnect is not
  cancellation authority. No data tunnels migrate across rebuilt routes.

## Monitoring

Configured client snapshots expose:

- `admission_wait`: refusing/target hop (one-based), operation (`session` or
  `connect`), destination, structured error, next retry timestamp and interval.
- `route_refusal`: current structured route refusal, including non-retrying policy
  blockage. Cleared on success, non-refusal failure, or disable cleanup.
- `last_exit_refusal`: session ID, destination and structured refusal for a failed
  individual exit. Cleared on successful CONNECT, published route change or disable.
- Hop `funding_rejection` and `waiting_for_relay_admission`: channel-link refusal;
  cleared when the intended channel is accepted.

`route_refused` and `exit_refused` events provide discrete diagnostics. An onward
CONNECT refusal attributes the reason to the preceding relay; a bootstrap refusal
attributes it to the destination relay itself.

## Alpha compatibility

This changes the rejection envelope from `{result,supported_versions,reason}` to
`{result,error:{code,message}}`, renames `LINK_ADMISSION_DISABLED` to
`CHANNEL_ADMISSION_DISABLED`, and makes the responder accept-builder API fallible.
Update MONAD clients/relays together. No wallet schema changes, migrations, database
resets or legacy-error compatibility paths are introduced.

## Validation

- Workspace suite: 642 passed, zero failed, 20 ignored; strict Clippy and formatting
  passed. Includes TCP/QUIC bootstrap rejection, pooled QUIC reuse, mixed-transport
  prefix preservation beyond the setup budget, channel retention in automatic mode,
  prefix failure, management-command cancellation, policy classification and SOCKS
  failure replies, and bounded rejection timeout.
- Buffered stress: 62,500/62,500 streams, zero circuit/link/control errors.
- Relink stress: 25,000/25,000 streams and 300 relinks. The first run recorded one
  control-stream broken pipe near completion and one no-new-funds payment response.
  A focused repeat completed 25,000/25,000 streams with 299 relinks, zero control
  errors and two no-new-funds responses. The first broken pipe is consistent with
  teardown timing but the log does not establish that conclusively; no zero-error
  claim is made for the first run.
- Graceful chaos: eight restarts, 6/6 suffix rebuilds, no suffix failures/fallbacks.
- Abrupt chaos: 26 restarts, 19/19 suffix rebuilds, no suffix failures/fallbacks.
- Actual-process funds-lifecycle baseline passed with exact conservation:
  16,177 client + 200 relay + 7 fees = 16,384 initial sats.

Implementation-machine logs: `/tmp/opencode/monad-admission-tests.log`,
`/tmp/opencode/monad-admission-regression.log`, and
`/tmp/opencode/monad-admission-relink-repeat.log`.
