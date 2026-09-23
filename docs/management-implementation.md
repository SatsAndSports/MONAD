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
