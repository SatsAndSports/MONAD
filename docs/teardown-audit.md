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

The watcher and pool defects were confirmed by code inspection. The new tests
were run after implementation, not as recorded failing-before/fixed-after runs.
The pool test does not yet exercise a concurrent Ready replacement race through
real connections.

## Outstanding Work

| Owner | Resource | Outstanding requirement |
| --- | --- | --- |
| Relay session | CONNECT proxy children | Replace discarded spawn handles with explicit ownership and awaited completion |
| Relay session/control handler | Registry and channel ownership | Cancellation/panic-safe cleanup with idempotent conditional-owner release |
| Relay session | CONNECT setup | Concurrent owned setup while H2 progresses; bounded deadline; no publish after pause/termination |
| Relay proxy/control | Blocked writes, shutdown, H2 capacity | Cancellation around the complete operation without changing normal half-close semantics |
| Relay listener | QUIC stream descendants | Distinguish JoinSet drop-abort from awaited descendant quiescence and verify listener rebind |
| Client route/runtime | Attachments and wallet authority | Close children before scoped detachment; cover attach bookkeeping and top-level cancellation windows |
| Client setup supervisor | Blocking wallet operations | Retain manager authority until blocking work finishes, including wrapper cancellation |
| Auto-close worker | Active sweep and durable journal | Stop selecting candidates on shutdown; own active work and preserve journal recovery |
| SOCKS and heartbeat | Handshake/proxy/control-send waits | Reproduce ownership or liveness gaps before changing policy |
| QUIC echo tooling | Spawned children | Complete lower-priority ownership review |

These rows are requirements/candidates from the approved scope, not newly
reproduced defects. No independent subagent review was possible because the
session's available tools do not include delegation or agent-session resumption.

## Validation

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
