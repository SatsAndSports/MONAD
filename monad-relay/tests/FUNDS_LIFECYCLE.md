# Process Funds Lifecycle

Release-pinned CDK, Nutmix and Nutshell HTTP/keyset and actual MONAD process
characterization is documented separately in
[`characterization/REPORT.md`](characterization/REPORT.md). It records failures
as well as successful recovery; ordinary swap compatibility is not treated as
proof of full signed-channel behavior.

Run `make test-funds-lifecycle`. This explicitly builds the real client and relay
CLIs before running the ignored integration target. The parent owns a real CDK
HTTP mint and an echo target; each client, relay, and maintenance invocation is a
separate OS process. Runtime processes are killed and reaped before maintenance
opens their persisted databases. The parent holds no wallet handles across those
transitions. The mint remains alive; mint durability and machine power loss are
not covered.

`make test-funds-crashes` additionally builds client and relay with the explicit
`funds-lifecycle-test` feature. Both it and `make stress-funds-lifecycle` build
their CLIs in `target/funds-lifecycle/debug` and pass those absolute binary paths
to the harness. Normal `target/debug` and `target/release` binaries are untouched;
no normal-binary rebuild is required afterward. The baseline target continues to
use normal builds. The test harness is also built in the isolated target directory,
with the relay feature, since Cargo may rebuild the relay binary for integration tests.
**Never use the isolated instrumented binaries
for real funds.** Normal builds contain neither the IPC hooks
nor the lifetime environment override. The test build uses bounded loopback IPC:
the child reports only a fixed durable-boundary name and blocks awaiting an
acknowledgement. The parent kills and reaps it before allowing any continuation.
Local finalization recovery runs with all mint HTTP requests rejected and asserts
that no request was even attempted, twice, in separate CLI processes.

Receiver close covers acknowledged SIGKILL at prepared, submitting, initial
rejection, successor persistence, finalizing, and completed boundaries. HTTP
gates cover accepted-response loss, output key rotation after preparation, and
successor accepted-response loss followed by another rotation. Each resumes in a
fresh CLI against the retained mint and same DB, with no parent wallet handle.
Finalizing and completed cases assert zero attempted HTTP. The same strict purse
oracle covers the later sender recovery and receiver drain. These cases exposed
and now cover preservation of the signed nominal split across fee rotation and
sender discovery under historical non-funding output keys.

Receiver drain covers the same six durable boundaries, prepared-only recovery,
HTTP request/response gates, and changed-output-keyset successor response loss.
Finalizing and completed drain recovery is repeated in fresh offline CLIs and
asserts zero attempted HTTP; terminal proofs remain solely in the relay DB.
Drain journal v2 gives each of at most two same-input candidates its own bounded
execution allowance and records the verified winner. These process tests retain
the existing SIGKILL/request-gate/rotation coverage against the new journal.
`common/drain_successor.rs` adds direct orchestrator tests for ambiguity followed
by a replay `12002`, either actual mint winner, cancellation/reopen with B saved,
per-candidate budget exhaustion, no C, and exact-input/winner binding. The A-winner
case deliberately delays real pre-commit state/empty-restore snapshots to control
reply ordering; it never edits the mint spent-state DB. All actual successful
swaps and payout spends use the real mint; output verification is not mocked.
Receiver close journal v5 retains A/B and the verified winner. Existing close
process SIGKILL/rejection/rotation cases exercise this format. The separate
`common/close_successor.rs` orchestrator tests cover A/B wins, signature reuse,
independent replay budgets, cancellation before B submission/after B commitment,
NUT-09 A-query/B-issuance and B-query/A-issuance routing, invalid/partial restores,
offline winner validation, no C and incompatible journal retention. Actual mint
commits and receiver payout spends are real; delayed state snapshots control
visibility and are not an additional actual-process concurrent-commit test.
The close/refund race matrix also kills the winning close with its accepted
response withheld while the sender attempts recovery.

Sender refund journal v3 retains the actual winning preparation with finalizing
proofs. Existing process refund response-loss, rotation, local-finalization and
close/refund races exercise the new format. Client unit integration module
`sqlite_client_wallet/tests/competing_refunds.rs` adds real-mint A/B/close winners,
separate replay budgets, keyset-only signature/output retention, no C, cancelled B
submission with A recovery after reopening, wrong-winner rejection before import,
offline completion and spending imported payouts. These controlled response/state
orderings supplement, rather than replace, the actual-process crash coverage.

Opening journal v4 retains competing A/B channels under one reservation. The client
`sqlite_client_wallet/tests/competing_openings.rs` real-mint matrix exercises either
winner, both target-capacity and nominal-funding preparation, rising/falling keyset
fees, fixed funding/change values, winner metadata interruption and reopen, and a
real close of the winning funding token. Pending A/B recovery submits no swaps;
shared-input export deduplicates the proofs and transitions both attempts, with
delayed B completion afterward. A B-keyset rejection creates no third candidate.
These controlled transport/state orderings supplement existing process opening
request gates, rotation and finalization SIGKILL tests. The deterministic candidate
process matrix below checks the persisted A/B records directly across SIGKILL.

## Deterministic A/B Process Crashes

Three opt-in tests add seven isolated, fixed-purse scenarios to
`make test-funds-crashes`. They are not in the seeded stress chooser, and add no
new drain scenarios:

| Test | Crash and recovery cases |
|---|---|
| `process_close_candidate_crashes` | Kill at `close-successor`, then a fresh close CLI completes B; kill after B commits with its successful HTTP response withheld, then restore B with no new swap. |
| `process_refund_candidate_crashes` | Kill at `refund-successor`, then recover B; kill after B commits and restore without re-submission; kill at successor persistence, let Charlie close, then recover Alice's close share with no refund winner. |
| `process_opening_candidate_crashes` | Kill at `opening-successor`, cancel definitively rejected A and never-submitted B and release their inputs without submitting; kill after B commits, then restore-only recovery installs exactly B and its change. |

Every scenario uses actual client/relay child processes, their on-disk wallets,
and a retained real CDK HTTP mint. A's first request is held before mint execution,
the mint rotates to a different keyset, and the resulting real HTTP `12002`
authorizes B. Thus these cases test definitive A rejection, not an A-late-winner
ordering or a fabricated rejection. The latter orderings remain covered by the
controlled orchestrator tests. `hold_success` holds only successful responses;
A's rejection reaches the wallet before B's committed response is withheld.

After each kill and reap, read-only DB inspection checks both preparations, exact
input identity, distinct output keys and the pre-recovery states/counters. B is
either durably prepared but unsubmitted, or recorded as submitted with no saved
completion. Recovery runs twice in fresh CLIs. Tests check the actual winner/source,
unchanged candidate requests, exact submission counts and zero repeat-terminal
HTTP requests. Refund fallback must recover less than the full refund; opening
checks B's fee-adjusted capacity and one import per change proof. Subsequent normal
settlement verifies the full purse and all mint-issued outputs.

The clean opening cancellation case is intentionally different from an ambiguous
pre-execution death: A was definitively rejected with no earlier uncertainty, and
B was not submitted. Both journal attempts become `cancelled` atomically with
input release; a fresh client run can spend those proofs to open a new channel.
An uncertain A still blocks cancellation/release. A storage trigger test verifies
rollback of both cancellation and custody when release fails.

`refund-successor` and `opening-successor` use the existing compile-gated IPC
boundary mechanism; no production-build hook or CLI is added. The mint success
ledger permits cached replays only for the same output/signature set and rejects
conflicting successful payouts for identical inputs instead of hiding them by
deduplication. No mint spent-state or wallet journal is edited to create a race.

Established-channel recovery now checks NUT-07 before NUT-09 using the upstream
ordinary-channel APIs. Alice restores retained refunds before close discovery;
Charlie restores retained close attempts. A refund winner yields relay
`CollectionAbandoned` after expiry, not inferred `SenderRefundedAfterExpiry`.
The relay remains `Closing` with a v5 journal: expiry sweeps and drains perform
no mint I/O for it, while an explicit close remains an online recovery attempt.
The race oracle still identifies the actual winner from accepted swaps and exact
custody conservation, independently of the relay's administrative outcome.

Opening boundaries cover durable finalizing, upstream saved, change imported,
and metadata saved. Refund boundaries cover durable finalizing, loose-proof
import, upstream closed, and metadata closed. Refund tests sign eight-second
channels at opening time, set the relay minimum expiry to one second, and wait
on the actual wall clock. Signed conditions are never edited. The refund HTTP
matrix includes response loss, direct inactive-output-keyset rejection followed
by one successor, and successor commit followed by process death.

The purse is funded once. Every completed cycle opens a real channel, pays for a
QUIC/SOCKS echo, kills both runtime processes, and either closes with a cold relay
CLI or waits for real expiry and refunds. Sender recovery uses a cold client CLI;
receiver proofs from successful closes are drained. A later cycle spends
recovered funds. Recovery is repeated and must not submit again.
The opening response-loss case holds a successful swap response, kills and reaps
the client, then runs restore-only recovery in fresh processes.

The independent oracle checks `initial = client + relay + fees`. It counts only
unique successful input sets, checks every accepted transaction against mint
restore and spent-state evidence, and charges `ceil(sum(input keyset ppk)/1000)`
per transaction. Final custody proofs must be unique, unspent at the mint, and
have valid DLEQs. Receiver drain outputs, not historical channel proof copies,
are final receiver custody. Nonzero fees are enabled from initial funding.

The pre-execution opening death is intentionally unresolved: recovery cannot
prove that an absent request will never commit. That isolated case counts the
still-reserved, mint-verified unspent inputs as client custody, asserts that they
remain reserved, and does not claim they are available to spend again. The
pre-execution refund case restarts and compares immutable outputs and inputs
before allowing exactly one successful spend. HTTP gates acknowledge either
completion or cancellation before reuse; unused permits cannot skip later gates.

The race matrix forces each winner separately, then barriers both real swap
requests immediately before mint execution. Exactly one funding spend may commit.
Rotation covers before preparation and direct `12002` after preparation for both
opening and refund paths, including successor committed-response loss. Refund
rotation explicitly verifies old input keysets and new output keysets separately.

`MONAD_FUNDS_SEED=20260921 MONAD_FUNDS_CYCLES=256 make stress-funds-lifecycle`
replays a bounded schedule of clean cycles, response losses, local crashes, and
rotations. Defaults are seed 1 and 12 cycles; cycles must be in 1..=1000. No cycle
mints more money. The harness stops below 2048 available sats, a conservative
capacity/fee margin, rather than intentionally failing the last affordable open.
This is not an exact fee-only exhaustion threshold test.

Requests, witnesses, responses, wallet files, and child stdout/stderr are private.
Successful runs delete their temporary directory. Failures retain it with a
warning; never upload it. Each CLI invocation writes separate mode-0600
`process-N-BINARY.stderr` and (unless JSON output is consumed) `.stdout` files.
Children use INFO logging so startup failures can be investigated after a failure;
these logs are not copied into test output. Console events identify the diagnostic
file prefix alongside operation names and totals. Short-lived channel setup checks
relay/client exit status while probing SOCKS and reports the last probe error and
attempt count, without changing startup order, expiry, or retry policy.

Fixture setup reserves the relay address on both TCP and UDP/QUIC. A candidate
with occupied UDP is discarded and selection retries (at most 128 candidates).
Both sockets remain reserved through configuration and initial funding, then are
released before child launch. This intentionally accepts the small handoff race;
later relay restarts also reuse the configured address without a reservation.

## Work Tracking

- [x] Actual CLI processes, persisted cold restart, kill and reap cleanup.
- [x] Baseline lifecycle and committed opening response loss.
- [x] Independent nonzero-fee conservation and idempotent recovery.
- [x] Request-before-execution crash gates.
- [x] Refund response loss and signed short-lived channels.
- [x] Opening/refund offline local-finalization boundary crashes.
- [x] Refund rotation after preparation and bounded successor crashes.
- [x] Opening rotation and rotation before preparation.
- [x] Controlled close/refund winners and concurrent mint-execution races.
- [x] Seeded bounded-purse stress and safe capacity/fee stop guard.
- [x] Receiver close local journal boundary SIGKILL and offline finalization.
- [x] Receiver close rejection/successor persistence and rotated response loss.
- [x] Receiver drain journal SIGKILL, preparation recovery and offline completion.
- [x] Receiver drain rejection/successor persistence and rotated response loss.
- [x] Close/refund/opening A/B state and winner assertions across successor SIGKILL and B response loss.
- [x] Charlie closes while Alice is dead with B prepared; Alice recovers her close share.
- [x] Definitively rejected opening A + unsubmitted B cancel and release atomically without recovery submission.

## Validation

Candidate-process extension validation:

- `cargo test -- --test-threads=4`, strict workspace/all-target Clippy, and formatting passed.
- The three `process_*_candidate_crashes` tests passed independently (seven scenarios).
- `make test-funds-lifecycle` passed with normal binaries.
- `make test-funds-crashes` passed all 14 selected process tests, including the
  three new candidate tests; the seeded stress schedule was not changed or rerun.

Historical relay-recovery stack validation (before the A/B process extension):

- Default and isolated all-feature `cargo test`: 556 passed each, no failures.
- Strict all-target/all-features Clippy and formatting checks pass.
- `make test-funds-crashes`: ten process tests passed, including six close and
  six drain persistence boundaries, historical-key rotation/response loss,
  offline finalization and close/refund races with a lost winning close response.
- Expanded-schedule seeds 1, 2 and 3: 12 cycles each, all passed.
- Expanded-schedule seed 20260921, 256-cycle limit: stopped at the capacity/fee
  margin after 157 cycles in 568.95s, with 448 unique successful input sets.
  Final custody was 1946 client sats + 13417 receiver sats + 1021 actual fee sats
  = the original 16384 sats. No replenishment or relaxed oracle.

The baseline and stress results below were recorded at commit `fb488bd`
(2026-09-21). They predate this extension and are not a claim of validation at
the current revision:

- Full default `cargo test` and `cargo test --all-features`: each 547 passed,
  no failures (opt-in process/stress tests run separately).
- Strict `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
- Six focused process tests, with eight local durable boundaries plus HTTP gates,
  rotation, repeated recovery and close/refund races.
- Seeds 1 through 8, 12 cycles each.
- Seed 20260921 with a 256-cycle limit stopped safely after 160 cycles in 481.29s:
  453 unique successful transactions, 2038 client sats + 13300 receiver sats +
  1046 actual fee sats = the original 16384 sats. Repeated with identical totals.
- Existing abrupt three-hop chaos, seed 20260921: 18 restarts, zero suffix rebuild
  failures/fallbacks, five channel records against a bound of 24.

The process tests use SQLite process-death durability, not physical power-loss
durability. They do not cover an actual mint restart, external stale-input token
export or every byte-level persistence interruption. Those are not implied by
the boundary matrix. The extended seeded schedule includes relay close/drain
boundary crashes and successor response loss; old seed totals are historical.

Stale export to an external wallet is explicitly out of scope.

## Persistent Mint Restart

`process_persistent_mint_restart_after_close_commit` is included in
`make test-funds-crashes`. Unlike the retained in-memory mint used by the other
scenarios, it launches an actual child process with a file-backed CDK mint and
signatory database, fixed test keys, and unchanged fee/configuration on restart.
The parent is only a forwarding HTTP gate and ledger, not a mint or response cache.
After receiving the complete successful close response from the child, it withholds
that response, kills/reaps the relay close process and mint process, and restarts
the mint on the same port and database. A fresh relay restores the journaled close
without resubmission; sender recovery and receiver drain follow. All final proof
DLEQs, NUT-07 custody states, accepted-output restores, and exact fixed-purse
conservation are checked against the restarted mint over HTTP.

The bootstrap proof file has mode 0600 in the fixture's private temporary directory.
Persistent-mint artifacts are removed on success and failure; child processes are
killed and reaped before cleanup. The ordinary scenarios retain their existing
failure-artifact behavior. No normal binary gains a persistent-test-mint mode.
