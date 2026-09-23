# Structured Teardown Audit (#26)

This is a partial implementation record, not a claim that #26 is complete.
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

The watcher and pool defects were confirmed by code inspection. The new tests
were run after implementation, not as recorded failing-before/fixed-after runs.
The pool test does not yet exercise a concurrent Ready replacement race through
real connections.

## Outstanding Work

| Owner | Resource | Outstanding requirement |
| --- | --- | --- |
| Relay listener | QUIC stream descendants | Distinguish JoinSet drop-abort from awaited descendant quiescence and verify listener rebind |
| Client route/runtime | Attachments and wallet authority | Close children before scoped detachment; cover attach bookkeeping and top-level cancellation windows |
| Client setup supervisor | Blocking wallet operations | Retain manager authority until blocking work finishes, including wrapper cancellation |
| Auto-close worker | Active sweep and durable journal | Stop selecting candidates on shutdown; own active work and preserve journal recovery |
| SOCKS and heartbeat | Handshake/proxy/control-send waits | Reproduce ownership or liveness gaps before changing policy |
| QUIC echo tooling | Spawned children | Complete lower-priority ownership review |

These rows are requirements/candidates from the approved scope, not newly
reproduced defects. No independent subagent review was possible because the
session's available tools do not include delegation or agent-session resumption.

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

The relay tranche does not yet establish listener-root descendant quiescence,
worker cancellation safety, or client wallet authority retention. The direct
relay-child approach needs no background cleanup supervisor or production fault
knobs. Shared pool/cache work intentionally retains its existing lifetime.

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
  full test and Clippy results. No independent subagent review was available.
