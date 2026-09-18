# Client Channel Opening Review

Status: implementation in progress. The first implementation PR covers the
upstream validation/storage API pin, client wallet manager, cross-process locking,
read-only inspection, and multi-client supervision. The stacked opening-journal
authority PR now covers exact durable inputs, submission authority/execution
records, monotonic submission uncertainty, exact atomic completion, and removal of
legacy opening recovery state.

This document is a handoff for resuming work on client channel-opening swaps. It
records the current findings, decisions, open questions, and proposed sequence.
Do not expand the review to refunds, relay closes, drains, or other swaps until
the channel-opening path is considered robust enough to serve as their model.

## Goal And Scope

The immediate goal is to make client channel opening consistent and robust across:

- preparation
- input selection and reservation
- durable journaling
- initial submission
- live restore and immutable replay
- keyset-rotation successors
- ambiguous outcomes
- startup and administrative recovery
- local finalization after funding proofs are received
- concurrent sessions and, where supported, concurrent client processes

Breaking changes in MONAD and `cashu_spilman_channels` are acceptable. This is an
alpha, test-only system with one user, so legacy compatibility is not a goal.

The broader plan remains to use channel opening as the reference implementation
before reviewing the other Cashu swap paths and adding journals where appropriate.

## First PR Implemented

- All `cashu_spilman_channels` dependencies are pinned to upstream commit
  `78aa7f2` (stacked PR #40), including its fallible opening reads, validated
  direct/restore completion, insert-or-verify opening storage, and read-only
  SQLite client storage.
- One `ClientWalletManager` owns one `SqliteClientWallet`; startup migration and
  restore-only opening recovery run once before any managed client starts.
- Runtime-owner and maintenance sidecars are acquired for normalized,
  deduplicated loose/channel database paths in deterministic order. Runtime
  startup is exclusive, steady state is shared for inspection, and mutating CLI
  maintenance is exclusive and fail-fast.
- `channels` and `proofs` are true read-only operations and do not require or load
  the sender secret. CLI mode is classified before databases are opened.
- Omitted `--client` starts all configured clients in YAML order. A named selector
  starts one leaf but still owns the whole logical wallet. Supervision propagates
  SOCKS failures and awaits children before manager teardown.
- Submitted startup/manual recovery is restore-only and non-abandoning. Empty
  restore evidence remains unresolved and its inputs remain reserved. The wider
  journal/replay/aged-abandonment policy remains future scope.

## Opening Journal Authority PR Implemented

- Opening attempts persist canonical exact selected local proof IDs. Creation and
  recovery verify those IDs against the exact reserved proof rows and immutable
  prepared input token.
- Initial submissions and immutable live replays use two-step move-only authority.
  A typed transactional claim creates only a durable `Claimed` execution; after all
  fallible request/journal/reservation checks, authorization consumes that permit,
  rechecks current state, transitions the execution to `Authorized`, and atomically
  advances `latest_submitted_at` immediately before the HTTP call.
- A failed initial claim exits without restore, replay, submission, or cleanup.
  Once any execution may have reached the mint, later local/recovery failures retain
  the original uncertainty and generic reservation release is fenced out.
- A replay rejection is recorded for that execution but does not resolve an earlier
  ambiguous execution, release inputs, or authorize a keyset successor.
- Finalization atomically verifies/transitions every exact selected proof together
  with `Finalizing -> Completed`. Idempotency requires the exact proofs already be
  spent for that channel; missing, available, reassigned, extra, or differently
  spent proofs are conflicts.
- The `monad_client_channel_opening_recoveries` compatibility path/table is removed.
  Empty obsolete tables are dropped; nonempty obsolete recovery or pre-authority
  journal state is rejected rather than inferred.
- Detailed live replay policy, one-hour administrative abandonment, and in-memory
  same-channel singleflight remain explicitly deferred to the next stacked PR.

## Current Model

The current journaled path has several useful properties:

- Initial proof reservation and `Prepared` journal insertion happen in one SQLite
  transaction.
- The exact serialized prepared opening is durable before swap submission.
- The transition from `Prepared` to `Submitted` is conditional.
- A direct response or complete restore is serialized into a `Finalizing` journal
  payload before ordinary upstream/local finalization continues.
- Replaying an identical `Finalizing` payload is accepted; a conflicting payload
  is rejected.
- Change import and MONAD channel metadata updates are designed to be idempotent.
- Keyset successors are bounded to one and use a distinct immutable request.
- Restore coverage checks reject partial or mismatched output sets.
- Exact-input NUT-07 checks reject duplicates, unknown inputs, and incomplete
  evidence.
- Existing tests cover ordinary sequential crash boundaries during journaled
  finalization.

These are worth preserving. The main gaps concern cryptographic response
validation, submission authority, concurrent recovery, delayed remote execution,
and storage APIs that conflate absence with failure.

## Decisions Made

### Review Scope

- Finish client channel opening first.
- Do not review or redesign the other swaps yet.
- Related stability changes are in scope when they are necessary for opening
  correctness.

### Output Validation

- Correct output validation is required.
- Direct swap and restore responses must be checked against the exact prepared
  funding and change outputs.
- A breaking upstream library API is acceptable if needed to represent a
  validated completion rather than unvalidated response data.

### Submission Uncertainty

- Once a submission may have reached the mint, a later local/storage error must
  not downgrade it to safe-to-release.
- Spend uncertainty should be monotonic until there is suitable terminal evidence.
- A worker that fails to acquire submission authority must not reach another code
  path that submits or replays the opening.

### Recovery Restrictions

- It is acceptable and desirable to restrict administrative recovery instead of
  supporting dangerous arbitrary concurrency.
- One client runtime process exclusively owns the logical client wallet and shares
  one in-process `ClientWalletManager` among all clients it launches.
- Startup recovery runs once through that manager before any of those clients'
  normal session workers start.
- CLI recovery should refuse to run while the wallet is in use.
- Recovery is allowed either at startup under exclusive ownership or
  administratively while the runtime is shut down.
- Read-only inspection commands remain allowed while the runtime is active.
- Live restore/replay owned by the worker opening its own channel remains separate
  from administrative recovery.

### Wallet Manager And Process Model

- Client and relay should converge on the same process model.
- A runtime process contains one in-process wallet manager; the manager is not a
  separate daemon.
- Omitting `--client` or `--relay` will launch all configured entries through that
  process's single manager. Supplying the selector launches only that entry, but
  still exclusively owns its configured logical wallet.
- Two runtime processes must not use the same logical wallet, even if they select
  different named clients or relays from one YAML file. Parallel runtime processes
  require separate wallet configurations/databases.
- The client side is implemented first because it directly simplifies channel
  opening. Equivalent relay supervision and wallet ownership follows later as a
  stability/consistency change, without starting the review of relay swaps.
- The client binary now implements this model. Equivalent relay process
  supervision remains future work.

The lock protocol should permit inspection without permitting a second runtime or
mutating maintenance:

- An exclusive runtime-owner lock prevents a second runtime process.
- A separate maintenance gate is held shared by the runtime; mutating or recovery
  commands require it exclusively.
- Read-only inspection may share the maintenance gate and rely on SQLite read
  concurrency.
- Schema migration or other database-open work that can write must occur under
  exclusive maintenance access.
- Locks should be OS-backed rather than PID-file conventions so process death
  releases ownership automatically.
- The lock identity covers the loose-proof and channel databases together as one
  logical client wallet.

Within the client process, `ClientWalletManager` owns the shared wallet instance,
startup recovery, and active opening coordination. An in-memory map may coalesce
same-channel callers, but database uniqueness, atomic reservation/journal creation,
and conditional submission claims remain the correctness boundary.

### Ambiguous Abandonment

- Mints do not provide cancellation for a possibly submitted swap.
- A practical risk-based abandonment policy is acceptable during suitable,
  exclusive recovery.
- The minimum age is one hour since the latest authorized submission or replay.
- A dedicated `latest_submitted_at` must be persisted immediately before each
  authorized mint submission; generic mutable `updated_at` is not sufficient.
- Abandonment still requires an empty funding restore and all exact inputs reported
  `UNSPENT`.
- Recent or inconclusive attempts should remain reserved.
- Submitting a compensating swap back to loose proofs is considered too complex
  for now.

### Funding Amount Semantics

- The intended configured value is the desired funding-token value; input fees
  are additional.
- Channel capacity remains explicitly committed in the channel parameters. There
  is no concern that the mint can silently increase that committed capacity.
- Rename misleading `input_budget` terminology and align documentation and proof
  selection with the intended funding-token-value semantics.
- Selection must gather enough gross input value to cover the desired funding
  token plus input fees.

### Channel Identity

- Equal complete channel parameters intentionally identify the same channel.
- Do not add an opening nonce.
- A duplicate opening should return a clear already-opening/already-open result.
- A duplicate must not submit another funding operation or overwrite established
  state.

### Proof Selection

- Preserve smallest-first selection for plain channel opening. Its purpose is to
  consume small proofs routinely rather than accumulate a large collection of
  tiny proofs.
- If a selected set is too large for the reservation implementation, return a
  specific error such as `TooManyInputProofs` rather than silently switching the
  policy.
- Target-capacity selection is a separate fee-aware policy and can be corrected
  independently.

### Legacy Data

- Legacy compatibility is unnecessary.
- Prefer removing the legacy opening-recovery path over repairing it.
- Database migrations may discard or reject unsupported alpha-era opening state if
  that makes the current invariant substantially simpler.

## Confirmed Findings

### 1. Opening Responses Are Not Fully Validated

Severity: high.

MONAD delegates direct and restored opening completion to the pinned Spilman
library. That code calls Cashu `construct_proofs` with a comment implying DLEQ
verification. The pinned Cashu implementation unblinds signatures and copies the
DLEQ values into proofs, but does not verify them.

The response path also does not sufficiently bind every returned blind signature's
amount and keyset ID to the exact prepared output with which it is paired. Shape,
count, and restore coverage checks are not substitutes for cryptographic and
denomination validation.

Required direction:

- Validate both direct swap and restore responses through the same checked path.
- Check exact output correspondence, amount, keyset ID, counts, and totals.
- Require and verify DLEQ against the pinned mint key and exact blinded output.
- Validate funding and change outputs separately.
- Do not treat equality between two unvalidated responses as proof of validity.
- Consider distinct `UnvalidatedOpenResponse` and `ValidatedCompletedOpen` types
  with checked construction.

Important references:

- `monad-client/src/sqlite_client_wallet.rs`, direct completion around
  `submit_prepared_open` and restored completion around `restore_journaled_opening`
- upstream `cdk-spilman/src/bindings.rs`, opening completion
- pinned `cashu/src/dhke.rs`, `construct_proofs`

Required tests include invalid DLEQ, wrong denomination, wrong keyset, valid funding
with invalid change, and underfunded responses, through both direct and restore
paths.

### 2. Post-Submission Recovery Can Incorrectly Release Inputs

Severity: high.

The live executor currently replaces an original possibly-spent submission error
with a later recovery error. Upstream storage reads can turn database or
deserialization failures into apparent absence, which can be reported as a
pre-submission-style error. Generic error cleanup may then release the reservation
even though the mint may already have spent those inputs.

Failure sequence:

1. The journal reaches `Submitted`.
2. The mint accepts the request, but the response is lost.
3. Live recovery encounters a local opening-storage failure.
4. The later error loses the original submission uncertainty.
5. Cleanup releases potentially spent proofs.

Required direction:

- Make possibly-submitted state sticky for the whole operation.
- Base release decisions on durable operation state and explicit terminal evidence,
  not the stage label of the most recent error.
- Remove generic reservation release from post-submission paths.
- Make upstream reads return `Result<Option<T>, StorageError>` rather than treating
  read failure as absence.

### 3. Failed Submission Claims Can Still Lead To Submission

Severity: high when recovery overlaps an active opening.

The initial `Prepared -> Submitted` claim is conditional, but claim failure is
currently represented as submission ambiguity. The executor then enters live
recovery, and an empty restore plus unspent-input observation can call the direct
submission function without acquiring another claim.

One concrete race is:

1. Worker A prepares and journals an opening.
2. Administrative recovery cancels that `Prepared` attempt and releases its inputs.
3. Worker A loses the submission claim.
4. Worker A enters the recovery/replay path and submits the cancelled request.

This requires overlapping actors, such as another client process or CLI recovery.
It should still be fixed even if administrative recovery becomes exclusive.

Required direction:

- Return a typed claim result rather than translating every false claim into
  `SwapSubmitted` ambiguity.
- A losing worker must stop and must not submit, replay, or clean up an operation it
  does not own.
- Submission APIs should require an operation permit/ownership token rather than
  accept any prepared opening.

### 4. `UNSPENT` Plus Empty Restore Is Not Remote Cancellation

Severity: high as a protocol assumption, with an explicit availability/safety
tradeoff.

For a possibly submitted opening, empty restore and `UNSPENT` inputs mean the mint
had not observably completed the request at those observation points. They do not
prove an old request cannot execute later.

Examples:

- A local worker claims submission, is paused before the HTTP call, and recovery
  observes no remote effects.
- A timed-out HTTP request remains queued at the mint and executes after recovery's
  restore and checkstate calls.

The accepted direction is a controlled, risk-based abandonment policy rather than
claiming that the evidence is mathematically terminal:

- Administrative recovery must have exclusive wallet maintenance access.
- The attempt must be at least one hour past its latest authorized submission or
  replay.
- Funding restore must be empty.
- Every exact input must be `UNSPENT`.
- The risk and timestamp basis must be documented.

The age is measured from the most recent submission or replay because a recent
request can still be in flight even when the first request is old. Persist a
dedicated `latest_submitted_at` immediately before each authorized submission. The
database currently has only `created_at` and mutable `updated_at`, which are not an
adequate substitute.

### 5. A Replay Rejection Does Not Resolve an Earlier Ambiguous Execution

Severity: high.

Live replay already performs restore and exact-input checkstate first. The problem
is a race after those observations:

1. Original submission times out but remains in flight.
2. Live restore reports no outputs.
3. NUT-07 reports every exact input `UNSPENT`.
4. The original request subsequently succeeds.
5. The output keyset rotates inactive.
6. The immutable replay returns mint code `12002` before the mint checks whether the
   original request spent the inputs.

The replay was definitively rejected, but that does not prove the earlier execution
failed. Current logic can classify the whole attempt as rejected and authorize a
keyset successor or reservation release.

Required direction:

- Distinguish an immutable opening operation from each HTTP execution of it.
- Once an earlier execution is ambiguous, a later execution's rejection does not
  retroactively settle the earlier one.
- Restore again or leave the original operation unresolved.
- Do not authorize a keyset successor from the replay rejection alone.
- Preserve recovery visibility for every execution/request that may have succeeded.

Open terminology clarification: "restore" here includes the automatic live restore
performed after an ambiguous submission, not only startup/manual recovery.

### 6. Wallet Process And Recovery Concurrency Is Not Currently Fenced

Severity: high for the intended multi-client deployment model.

The YAML contains one top-level wallet configuration and multiple named clients,
but the current CLI starts one selected client per process. Each process opens its
own wallet objects against the same database paths and performs startup recovery
before starting its own connector. Recovery preceding one process's workers does
not mean it precedes every other process already using the wallet.

Current synchronization consists of object-local mutexes, SQLite transactions, and
busy timeouts. There is no lifetime cross-process wallet lock.

Decided model:

- One `ClientWalletManager` and one runtime process exclusively own the logical
  wallet.
- That process may launch all configured clients or one selected client.
- A second runtime process fails clearly rather than skipping recovery and joining
  normal use.
- Startup recovery runs once before the manager starts any configured clients.
- CLI recovery and all mutating administration require exclusive maintenance
  access and refuse while the runtime is active.
- Read-only inspection remains available during runtime.
- OS-backed runtime-owner and maintenance locks enforce this across processes.

Multiple live sessions/clients still need to reserve distinct proofs and open
distinct channels concurrently through the manager. Process ownership does not
replace per-opening atomic reservation and submission claims.

### 7. Upstream Storage Can Destructively Replace Existing State

Severity: high under storage faults, duplicate calls, or concurrent wallet
instances.

The pinned upstream channel table uses `channel_id` as its primary key, but saving
an opening uses `INSERT OR REPLACE`. Re-saving the same channel ID can clear
funding, payment, and failure state. Some upstream getters return `None` both for
absence and for storage/deserialization errors, and MONAD may respond to apparent
absence by re-saving the prepared opening.

Required direction:

- Preserve same-parameters/same-channel identity.
- Replace destructive save with insert-if-absent-or-verify-identical.
- Return explicit already-opening/already-open/conflict outcomes.
- Make reads fallible without conflating errors and absence.
- Make completion an atomic open-if-opening-or-verify-identical operation.
- Never reset an established channel's payment state during opening recovery.

Current uniqueness notes:

- MONAD initial attempt IDs are channel IDs and are primary keys.
- Successor indexes bound successors, but do not provide worker ownership.
- Upstream `channel_id` is a primary key; `INSERT OR REPLACE` defeats its protective
  value by intentionally replacing the existing row.

### 8. Funding-Token Target And Input Selection Are Misnamed/Misaligned

Severity: medium.

The API currently calls the value `input_budget_msats`, but plain provisioning uses
it as the desired funding-token amount. It selects gross proof value until gross
value reaches that target, while upstream requires the target to fit after input
fees.

Example:

- desired funding token: 1,000 sat
- selected gross inputs: exactly 1,000 sat
- input fees: 1 sat
- post-fee value: 999 sat
- preparation fails even if another proof could have covered the fee

This does not permit capacity to exceed the committed channel parameters. It is a
selection and naming issue.

Required direction:

- Rename the amount to express desired funding-token value.
- Select enough gross input value to cover that target plus actual input fees.
- Return surplus as change under the existing upstream model.
- Update configuration, APIs, logging, and docs together; breaking renames are
  acceptable.

### 9. Target-Capacity Selection Can Lack Input Fee Metadata

Severity: medium availability issue.

The target-capacity path looks up cached keyset/fee metadata for every available
input proof before selection. If one proof's keyset is absent from the client cache,
it returns an error before reservation or submission. It does not crash and does
not guess a fee, but it also does not fetch the missing metadata. An uncached proof
can block opening even if known proofs would suffice.

Required direction:

- Perform one bounded metadata refresh/fetch before fee-aware selection.
- Retry selection using validated metadata.
- Return a clear metadata-unavailable result if it remains unavailable.
- Consider selecting from understood proofs when they suffice, while ensuring the
  chosen policy is explicit and deterministic.

### 10. Plain Selection Can Exceed The Reservation SQL Limit

Severity: medium availability issue.

Plain provisioning intentionally consumes proofs in smallest-first order. The
reservation code guards against roughly 999 SQLite parameters and currently checks
`proof_ids.len() + 5 > 999`, although the update statement appears to bind seven
fixed parameters. This is a local SQL implementation constraint, not a Cashu
protocol limit.

Required direction:

- Preserve smallest-first selection.
- Correct the parameter accounting or batch the SQL safely in one transaction.
- Detect the selected-set limit before expensive opening preparation.
- Return a typed error such as `TooManyInputProofs { selected, maximum }`.
- Do not silently switch to a largest-first policy.

### 11. Target Fee-Aware Selection Has A Feasible-Subset Edge Case

Severity: medium.

The target-capacity selector is a largest-first heuristic with a lower-fee
tie-break. A high-fee proof with nonpositive net value can be included first and
make the aggregate appear insufficient even when another proof alone satisfies the
target.

Required direction:

- At minimum, exclude individually nonpositive-net candidates.
- Add a regression test where a toxic-fee proof precedes a feasible proof.
- Decide what feasibility guarantee the heuristic should provide; it need not
  become a fully optimal knapsack solver unless required.

### 12. Reservation Completion Needs Exact-State Verification

Severity: medium invariant hardening.

After successful opening, `mark_reservation_spent` transitions currently reserved
proofs and returns the number changed. Finalization ignores that count. Zero can
mean an idempotent replay where the inputs were already spent correctly, or an
inconsistent state where the reservation was released/reassigned.

Required invariant:

- Every exact expected input is either still reserved for this opening and is
  transitioned to spent, or is already spent for this exact channel/opening.
- Any released, available, differently reserved, or differently spent input is an
  explicit conflict.

Required direction:

- Bind the journal's prepared exact inputs to reservation membership.
- Replace count-only completion with transition-or-verify semantics.
- Keep idempotent replay valid only when existing state matches this completion.
- Restrict generic reservation release for operation-owned reservations.

### 13. Legacy Recovery Should Be Removed

The current journaled finalization ordering is substantially correct: it records a
durable `Finalizing` completion before advancing ordinary finalization, allowing
later replay after partial local completion.

A separate legacy recovery path can advance upstream state to `Open` before it has
an equivalent durable MONAD finalization payload. A crash can then remove upstream
opening data needed to complete local recovery.

Decision: do not repair this compatibility path. Remove it and simplify the state
model around the authoritative opening journal.

## Open Questions

These decisions were not finalized and should be revisited before implementation:

1. Does live immutable replay remain automatic after an ambiguous initial execution,
   or should live handling become restore-only and leave replay to exclusive
   recovery? Current preference appears to retain live replay with corrected
   operation-level ambiguity semantics.
2. After an ambiguous execution followed by a replay rejection, how frequently and
   for how long should automatic restore continue before leaving the operation for
   exclusive recovery?
3. What exact user-facing duplicate outcomes are needed: already preparing,
   already submitted, already open, and conflicting existing state?
4. Should target-capacity selection ignore proofs whose metadata remains unavailable
   when known proofs suffice, or fail the whole offer to avoid silently excluding
   wallet value?
5. Is the current SQLite proof-count limit best fixed by corrected preflight and a
   typed error, or by batching reservation updates inside the same transaction?
6. Resolved for the client: each normalized, deduplicated database path has
   adjacent runtime-owner and maintenance sidecars, acquired in deterministic
   path order. Equivalent relay lock placement remains future work.
7. Should `first_submitted_at` also be retained for observability, separately from
   the authoritative `latest_submitted_at` abandonment clock?

## Proposed Implementation Order

The latest proposed sequence, subject to the remaining open questions above, is:

1. Add `ClientWalletManager`, all-or-selected client process supervision, and the
   runtime-owner/maintenance lock protocol. Run opening recovery once before any
   managed client starts; keep read-only inspection available.
2. Add adversarial tests for invalid direct/restored outputs and implement exact
   cryptographic response validation upstream.
3. Make submission uncertainty monotonic and remove every post-submission path that
   can generically release a reservation.
4. Introduce typed submission claims/operation ownership so a losing worker cannot
   submit or replay, and ensure same-channel concurrent callers produce one opening
   operation and one mint submission.
5. Correct live replay semantics so a replay rejection cannot resolve an earlier
   ambiguous execution or authorize a successor.
6. Implement the explicit aged-abandonment policy under exclusive recovery, with a
   dedicated `latest_submitted_at`, a one-hour threshold, and clear risk
   documentation.
7. Harden upstream storage APIs: fallible reads, insert-or-verify opening creation,
   idempotent compare-and-transition completion, and no destructive replacement.
8. Remove legacy opening recovery and unsupported alpha-era compatibility state.
9. Strengthen exact reservation membership and transition-or-verify completion.
10. Rename funding-target concepts and make plain selection include actual input
    fees while preserving smallest-first behavior.
11. Fetch missing input keyset metadata before target selection and fix toxic-fee
    candidate handling.
12. Correct or remove the SQL proof-count limitation and add a typed oversized
    reservation error if a limit remains.
13. Run a fault-injection matrix across every durable transition and the important
    concurrent/delayed-response interleavings.
14. After client channel opening is stable, give the relay runtime the equivalent
    all-or-selected supervision, single `RelayWalletManager`, and exclusive wallet
    ownership policy. Do not broaden this step into a review of relay swap logic.

## Test Matrix To Add

At minimum:

- Direct response with invalid DLEQ.
- Restore response with invalid DLEQ.
- Correct output count but wrong amount or keyset.
- Valid funding with invalid change.
- Successful mint submission followed by injected local recovery-read failure;
  inputs remain reserved.
- Prepared attempt cancelled by exclusive recovery while an old worker is paused;
  the losing worker performs zero HTTP submissions.
- Two workers attempt the same channel; one receives a clear duplicate/ownership
  result and there is one swap submission.
- Original request completes after empty restore/checkstate but before replay
  rejection; original remains recoverable and no successor is submitted.
- Administrative recovery refuses while a runtime holds the wallet usage lock.
- Recent ambiguous opening cannot be abandoned.
- Old ambiguous opening with empty restore and exact-input `UNSPENT` can be
  explicitly abandoned under exclusive maintenance.
- Desired funding-token amount succeeds when additional proofs are needed for
  input fees.
- Target selection refreshes missing input-keyset metadata.
- A nonpositive-net proof does not hide a feasible target subset.
- Smallest-first selection exceeding any retained reservation limit returns the
  typed error before preparation.
- Finalization accepts exact idempotent replay but rejects released, reassigned, or
  differently spent reservation inputs.

## Important Non-Decisions

- Do not add a channel-opening nonce.
- Do not change the committed channel-capacity model based on the funding-target
  naming issue.
- Do not silently replace smallest-first plain proof selection.
- Do not start redesigning refunds, closes, drains, or loose-proof compensation
  swaps as part of this review.
- Do not preserve legacy opening-recovery behavior solely for backward
  compatibility.
