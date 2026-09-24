# Headless management implementation

## Goal and delivery

Deliver a tested localhost HTTP command/snapshot API and SSE monitoring stream,
aggregating separately running configured clients and relays through Unix sockets.
No browser UI is required. Work is split into four intended PRs: relay controls,
client controls, local process interfaces, and HTTP/SSE aggregation with end-to-end
validation.

## Runtime contract

- Overrides last for the process lifetime; restart restores configured defaults.
- Relay controls independently gate new channels, tunnels, and MONAD sessions.
  Stored channels may relink while new-channel admission is disabled. New QUIC
  streams count as sessions even on an existing transport; new onward tunnels
  count as tunnels even when they reuse a pooled connection.
- Relay disable initiates teardown of all owned sessions, prevents admission, and
  preserves admission settings for re-enable. It does not close payment channels.
  Completion must mean cleanup, not merely that cancellation was requested.
- Client disable tears down route and SOCKS work. Disabling automatic provisioning
  preserves existing-channel selection, relinks, and ordinary payments.
- Manual provisioning is a single operation for a specific live hop generation,
  serialized with the existing payment driver. Submitted ambiguous mint work is
  recovery state, never an excuse to release reservations or initiate another spend.
- Partial route construction is observable and can wait for manual funding without
  exhausting the network setup deadline. Transport and control deadlines remain.
- Manual relay closure reuses the wallet manager's existing close/recovery paths.

## Monitoring and API contract

- Sample traffic counters at 5 Hz; update wallet inventories more slowly/on change.
- Accepted payments are discrete events. Traffic and monetary amounts retain
  explicit units; cleartext and wire counters are distinct.
- One Unix socket per process, one localhost TCP service for aggregation.
- Commands and snapshots use HTTP; monitoring uses SSE, not a second WebSocket API.
- Long operations return operation IDs; stale generation commands are rejected.
- Bounded event history supports reconnect replay or explicit resynchronization.
  Slow or disconnected observers never block traffic or payment processing.
- Never expose proof secrets, private keys, immutable secret-bearing mint requests,
  or refund derivation material in management data.
- Expose process availability/staleness, not frozen data masquerading as live state.

## Validation gates

1. Test admission races, pending CONNECT publication, pooled QUIC streams, existing
   tunnel preservation, disable completion and re-enable, stored-channel relinks.
2. Test cold-start manual funding hop by hop, exhaustion/resumption, duplicate
   commands, automatic/manual races, stale hops, cancellation, insufficient funds,
   and ambiguous mint outcomes with existing wallet authority guarantees.
3. Test real Unix sockets and HTTP/SSE: multiple instances, process restart,
   replay/gaps, disconnected subscribers, manual close, and service shutdown.
4. Run formatting, strict Clippy, cargo test, relevant chaos/funds regressions,
   and a monitored traffic run. Record actual results and limitations.

Update README for operation, ARCHITECTURE for ownership/layering, and supply an API
reference and curl examples before declaring the headless system complete.

## Delivered stages

1. PR #79: relay admission and disable controls.
2. PR #80: client lifecycle, one-shot provisioning and partial-route funding waits.
3. PR #81: Unix HTTP process endpoints, bounded operation ownership and monitoring.
4. `feat/management-http-sse`: localhost TCP aggregation, SSE replay/resynchronization,
   process restart handling, directly owned HTTP connections, and end-to-end tests.

Usage and protocol details are in [management-api.md](management-api.md).

## Validation record

Final workspace suite: **631 passed, zero failed, 20 ignored**. Formatting, strict
workspace/all-target/all-feature Clippy, and diff checks passed.

| Run | Result |
| --- | --- |
| Payment buffered | 62,500/62,500 streams; 2,898 topups; zero circuit/link/control errors |
| Payment relink | 25,000/25,000 streams; 300 relinks across all 50 sessions; zero circuit/link/control errors |
| Graceful chaos | 8 restarts; 6/6 suffix rebuilds; zero suffix failures/fallbacks; max recovery 896 ms |
| Abrupt chaos | 26 restarts; 19/19 suffix rebuilds; zero suffix failures/fallbacks; max recovery 1,082 ms |
| Funds crash matrix | All 11 scenarios passed |
| Seeded funds stress | Seed 1; 12 cycles passed; 15,307 client + 1,000 relay + 77 fees = 16,384 initial sats |

The real-mint API integration test manually provisions through the public TCP
endpoint, observes payments over SSE, passes 4 MiB roundtrip through 32 concurrent
SOCKS tunnels while monitoring, disables the client, and closes its relay channel
through HTTP. Dedicated tests cover Unix idempotency, stale generations, process
restart, replay gaps, unavailable processes, non-reading SSE subscribers, and
preservation of preexisting socket paths. Custody summaries separately validate
available/reserved/spent state and wallet isolation.

Logs on the implementation machine:

- `/tmp/opencode/monad-management-final-tests.log`
- `/tmp/opencode/monad-management-stress.log`
- `/tmp/opencode/monad-management-funds.log`

The first regression wrapper lowered the hard file-descriptor limit before the
stress recipe tried to raise it; that recipe stopped before running a stress test.
The normal recipes were then rerun successfully with their repository-defined limit.

## Explicit scope boundaries

- No webpage, authentication, remote TCP binding, route editing, or persisted
  runtime overrides. The aggregator rejects non-loopback binds and configured
  `auth_token` rather than pretending authentication exists.
- API traffic metrics are cleartext/session accounting; encrypted wire metrics
  remain in transport logs. The monitored traffic test is a correctness/load
  check, not a controlled before/after CPU or latency benchmark.
- Event rings are transient and bounded to 512 entries. Operations retain at most
  4,096 idempotency records per process lifetime; capacity exhaustion is explicit.
- Wallet categories are shown separately. Historical spent proofs and channel
  capacities must not be added to spendable balances. The API never exports proofs
  or secret-bearing recovery requests and never automatically replays management
  commands after a process restart.
- Network failures during manual waits still trigger normal heartbeat/rebuild
  behavior. This change does not migrate existing data tunnels between routes.
