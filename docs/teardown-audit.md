# Structured Teardown Audit (#26)

Implementation and validation record for the #26 teardown scope. Runtime-owned
Quinn draining and non-cancellable blocking work have explicit boundaries below.
Baseline: `3a0e96c` (merged PR #74). Branch: `fix/structured-teardown`.

## Ownership Contract

An explicit asynchronous close must await owned children before releasing their
authority. Drop-triggered abort requests are fallback cancellation, not evidence
of quiescence. Blocking work cannot be forcibly stopped by aborting its async
wrapper; its authority must remain held until the work finishes. Session cleanup
must release only that session's ownership, never a replacement owner's or a
sibling's. Shared pools can outlive sessions. Durable ambiguous payment journals
are recovery state, not leaks, and teardown must not release their reservations.

## Implemented

| Owner | Resource | Change | Evidence |
| --- | --- | --- | --- |
| `RelayConnection::wait_for_failure` caller | Cloned hop watch receivers | Directly owned futures replace detached nested tasks; current true and sender closure report failure | `failure_watcher_tests`: 32 poll/drop cycles return receiver count to baseline; initial true and sender loss return the hop |
| Shared `QuicPool` | Cached connection or pending attempt | Stale cleanup matches Quinn stable connection identity or watch channel identity, not enum variant alone | `pool::tests::stale_pending_waiter_does_not_match_replacement` tests the pending identity predicate |
| Relay session | Control/setup/data children | Directly owned futures polled alongside H2; no detached proxy/control tasks | Root abort, gated panic, transport loss, and termination finish with target EOF and zero active tunnels |
| Relay session | Registry and channel ownership | Synchronous link bookkeeping before reducer awaits; idempotent Drop cleanup with conditional-owner release | Registry/owner cleanup, link-before-reducer window, replacement-owner preservation |
| Relay session | CONNECT setup | Concurrent setup with a 10-second deadline; publication rechecks pause/termination | UDP-gated pending QUIC setup permits control bootstrap, cancels without publication, and returns 502 at deadline; publication tests require 402/reset |
| Relay proxy/control | Blocked I/O and counters | Whole-operation cancellation; drop accounting; unchanged normal half-close | Gated target write/shutdown, zero H2 window, zero-window control bootstrap, reply after request EOF |

The original watcher and pending-pool defects were confirmed by code inspection;
their first tests were run after implementation. Follow-up Ready-pool coverage
uses two real Quinn connections and a deterministic replacement-before-failed-
cleanup interleaving through the production eviction path.

## Follow-Up Implementation

| Owner | Change | Evidence |
| --- | --- | --- |
| Runtime wallet | Runtime filesystem locks live in the shared wallet, not only the manager | Gated blocking child plus manager drop and abort formerly allowed reopen; now authority stays held until the child exits |
| Payment driver | Drop guard scans session-owned attachments and conditionally detaches; retries also use conditional detach | Explicit connection close formerly left its channel attached; fixed close permits reuse; pre-intended and sibling/replacement ownership tests |
| Route watcher | Direct per-connection futures, no outer spawned watchers | Existing failed-hop/debounce/setup cancellation tests pass |
| SOCKS listener | Direct connection futures; select route after handshake | Greeting gate proves a stalled handshake does not acquire an old route; abort closes the socket |
| Client control | All writes, including heartbeat, use the existing 15-second send deadline | Zero-window test with virtual time requires timeout rather than a hung driver |
| Relay listener | Direct connection/stream futures with child panic isolation; explicit finish drains Quinn | Live TCP and QUIC children lose registry/channel ownership before root completion; targets see EOF; explicit finish permits TCP/UDP rebind |
| Auto-close worker | Directly owned future, shutdown checks between candidates and cancels active sweep | Mint swap-response gate: graceful/abrupt root cancellation leaves no worker, retains Closing journal, leaves next candidate Open, and journal recovery completes the payout |
| Shared and relay proxy | Hard errors cancel the opposite direction; EOF still drains. The shared proxy independently observes H2 reset while application writes are blocked, including after local EOF | Idle-reset and blocked-write gates cover reset/connection loss; normal EOF still drains buffered data |
| Echo server | Direct connection/stream futures; tests now use production server | Root abort closes a live echo stream; 1000-stream and large-payload tests pass |

## Contract Boundaries

- Explicit close/finish awaits task cleanup where tasks are used. Directly owned
  futures require no join; drop synchronously removes their application work.
- Aborting a configured runtime requests task cancellation, not forced termination
  of `block_in_place`. Shared wallet handles retain authority while operations or
  setup supervisors can still mutate the wallet. Shutdown completion and dropping
  the last outstanding wallet handle are different boundaries.
- Abrupt relay/echo cancellation cannot await Quinn's runtime-owned protocol
  drivers. They can temporarily retain UDP sockets after all MONAD descendants
  and ownership are gone. Explicit relay finish uses `wait_idle` and the rebind
  regression passes without retry sleeps.
- No wallet schema, funding/keyset policy, reservation, or ambiguous journal is
  discarded by these changes. Shared pools and cache refresh work intentionally
  retain their service-level lifetimes.
- Initial tranches were self-reviewed. The parent subsequently coordinated two
  independent reviews: the relay reviewer reported no correctness findings and
  noted coverage/performance gaps; the client reviewer identified the P2
  blocked-write reset issue recorded below and no other client findings.
  The client reviewer subsequently re-reviewed correction `6b86a2a`, confirmed
  independent reset observation and preserved half-close behavior, and found no
  new actionable defects. This was source review, not another test run.
  Exhaustive transport/failure Cartesian testing and abrupt OS-socket
  reclamation are not claimed here.

## Watcher/Pool Validation

- Full `cargo test -- --test-threads=4`: 598 passed, 20 ignored, zero failures.
  The initial 200-second tool invocation timed out; the 900-second retry passed.
- Strict `cargo clippy --workspace --all-targets --all-features -- -D warnings`:
  passed after moving the watcher test module below production items.
- Default `make stress-chaos-rebuild`: seed `5570757306307527496`, 7 restarts,
  6 successful suffix rebuilds, zero suffix failures/fallbacks, 6121/6233 probes
  successful, maximum recovery 1136 ms, 3 channel records (bound 6).
- Default `make stress-chaos-rebuild-abrupt`: same seed, 25 restarts,
  19 successful suffix rebuilds, zero suffix failures/fallbacks, 3105/3488 probes
  successful, maximum recovery 1230 ms, 7 channel records (bound 21).
- Both stress commands used `ulimit -n 65536`; failed in-flight probes during
  rebuilds are allowed by the existing harness.

Logs are outside the worktree in `/tmp/opencode/monad-structured-teardown-*.log`.
The original eleven untracked artifacts and `AGENTS.md` were not changed.

## Relay Reproductions

- Before the relay ownership change, the new session-abort regression failed
  because the aborted session remained registered. With the change, abort, gated
  owner panic, transport loss, and token termination all release the owned
  channel, remove the registry entry, decrement the tunnel counter, and close the
  paused target before the test proceeds.
- Restoring the old proxy `join!` without whole-operation cancellation makes the
  gated blocked-write regression time out after termination. Restoring the outer
  cancellation select passes write, shutdown, and H2-capacity cases.
- Restoring the old control-handler await without the outer cancellation select
  makes the zero-window bootstrap regression time out. The fixed handler reaches
  its cleanup epilogue and releases ownership.
- The QUIC pending-setup test uses a bound UDP receiver to observe an Initial
  without answering it, then requires a control response on the same H2 session.
  It tests both explicit cancellation and the actual 10-second setup deadline.
- The existing active/future-stream control-detach integration test now rejects
  unexpected data and requires EOF or reset rather than accepting any read.

The later listener/client tranche establishes the additional contracts recorded
above. No background cleanup framework or production fault knobs were added.

## Relay Validation

- Final full `cargo test -- --test-threads=4`: 605 passed, 20 ignored, zero
  failures. This includes existing TCP/QUIC/nested, IPv4/IPv6, paused/funded,
  detach, and payment-conflict integration coverage.
- All nine `session::tests` pass, including seven new lifecycle regressions;
  the focused suite was repeated during validation.
- Strict workspace/all-targets/all-features Clippy, formatting, and diff checks
  pass.
- Default graceful chaos: seed `5570757306307527496`, 7 restarts, 6 successful
  suffix rebuilds, zero suffix failures/fallbacks, 5745/5857 successful probes,
  maximum recovery 1089 ms, 3 channel records (bound 6).
- Default abrupt chaos: same seed, 25 restarts, 19 successful suffix rebuilds,
  zero suffix failures/fallbacks, 3092/3471 successful probes, maximum recovery
  1234 ms, 7 channel records (bound 21).
- Both stress commands used `ulimit -n 65536`. Relay validation logs are in
  `/tmp/opencode/monad-relay-teardown-*.log`; `*-final.log` contains the final
  full test and Clippy results. These runs preceded the independent parent reviews.

## Pre-Review Validation

- `cargo test -- --test-threads=4`: **613 passed, 20 ignored, zero failures**.
  Payment-conflict wire, first-hop rebuild, and middle-hop suffix tests all pass.
- Strict workspace/all-targets/all-features Clippy, formatting, and diff checks
  pass. Focused client, listener, auto-close, proxy, pool, and production echo
  tests were run separately as well as in the full suite.
- Default graceful chaos: seed `5570757306307527496`, 7 restarts, 6 successful
  suffix rebuilds, zero suffix failures/fallbacks, 5740/5823 successful probes,
  maximum recovery 940 ms, 3 channel records (bound 6).
- Default abrupt chaos: same seed, 26 restarts, 19 successful suffix rebuilds,
  zero suffix failures/fallbacks, 3080/3392 successful probes, maximum recovery
  1140 ms, 7 channel records (bound 24).
- Both runs used `ulimit -n 65536`; allowed failed in-flight probes were 83 and
  312 respectively. Logs: `/tmp/opencode/monad-teardown-complete-*.log`.
- All work remains local; no PR/push. The original eleven untracked artifacts and
  `AGENTS.md` remain unchanged.

## Independent Review Correction

The client's P2 finding was reproduced before the fix: an H2 peer sends 64 bytes
into an application socket with capacity 8, a gate confirms `poll_write` returned
Pending, and the peer then resets the stream. The existing `try_join!` never saw
the reset because both copy directions were blocked outside H2; the regression
timed out. The earlier idle-reset test did not cover this state.

The send-side future now polls `SendStream::poll_reset` independently while
waiting for application data. H2 capacity waits already observe reset/failure.
After local EOF, the send-side future continues observing resets until a oneshot
confirms the receive-side write/shutdown drain finished. There is no spawned
watcher, shared send lock, polling loop, or timing heuristic.

The regression covers explicit peer reset, peer-driver loss, and local H2-driver
abort (the route-close transport action), each before and after local EOF. A
normal-EOF case confirms that blocked buffered data still drains successfully.
These are selected lifecycle interleavings, not exhaustive failure coverage.

## Review Correction Validation

- `cargo test -- --test-threads=4`: **614 passed, 20 ignored, zero failures**.
- Strict `cargo clippy --workspace --all-targets --all-features -- -D warnings`,
  formatting, and diff checks pass. Both focused shared-proxy tests pass.
- Logs: `/tmp/opencode/monad-teardown-review-tests.log` and
  `/tmp/opencode/monad-teardown-review-clippy.log`.

The transport run used the existing configurable harness with the stable-five-
hop recipe's topology, ten times its streams per circuit, and bounded in-flight
work. The extreme recipe requests 2.5 million streams with much higher
concurrency; inspection found 30 GiB RAM, about 17 GiB available, and 21 GiB swap
already in use, so the bounded run was selected instead. Exact command:

```bash
ulimit -n 65536 && \
NO_COLOR=1 RUST_LOG=error \
MONAD_STRESS_PAYMENT_MODE=transport \
MONAD_STRESS_CHANNEL_CAPACITY_MSATS=1000000000000 \
MONAD_STRESS_RELAYS=10 \
MONAD_STRESS_CIRCUITS=200 \
MONAD_STRESS_HOPS=5 \
MONAD_STRESS_STREAMS=250 \
MONAD_STRESS_MAX_IN_FLIGHT_PER_CIRCUIT=25 \
MONAD_STRESS_TARGETS=100 \
MONAD_STRESS_PAYLOAD_BYTES=3000 \
cargo test -p monad-relay --test stress -- \
  --ignored --exact stress_three_hop_quic_configurable --nocapture
```

Results: 200/200 circuits, 1,000 sessions, and 50,000/50,000 streams successful;
`failures=0`, `control_errors=0`, `channel_link_failures=0`, `pause_events=0`,
`channel_relinks_total=0`, `topups_total=0`. Sent and received bytes were
150,000,000 each (300,000,000 total). Elapsed time including setup was 119.925 s;
reported aggregate bidirectional cleartext throughput was 2.39 MiB/s. Average
per-circuit setup/data times were 6,057.35/102,047.40 ms. Log:
`/tmp/opencode/monad-teardown-review-transport.log`.

This is one passing workload on the current implementation, not a before/after
benchmark. Direct futures still serialize synchronous CPU-heavy handshake and
payment work within each listener task. Ten listeners can execute independently,
and this transport-focused harness uses mocked huge prefunding, not sustained
real payment verification. CPU-heavy single-listener performance and baseline
throughput/latency equivalence were not measured.
