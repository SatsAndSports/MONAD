# Process Funds Lifecycle

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
The close/refund race matrix also kills the winning close with its accepted
response withheld while the sender attempts recovery.

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

Requests, witnesses, responses, wallet files, and child stderr are private.
Successful runs delete their temporary directory. Failures retain it with a
warning; never upload it. Console events contain only operation names and totals.

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

## Validation

Full relay-recovery stack validation:

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

The earlier baseline and stress results below predate this extension:

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
