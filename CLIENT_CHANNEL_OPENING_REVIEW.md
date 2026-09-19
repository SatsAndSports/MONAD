# Client Channel Opening Review

Status: current implementation and coverage ledger after the opening-hardening,
wallet-ownership, relay-supervision, input-selection, and CDK 0.18.1 work.

This document used to be the defect handoff that drove those changes. Historical
findings are retained below as resolved rationale rather than presented as current
bugs. The canonical runtime behavior is documented in `docs/payments.md`; this
file records why the stronger boundaries exist and what remains genuinely open.

## Scope And Dependency Baseline

The reviewed path is client channel opening:

- proof selection and reservation
- durable opening attempts and execution authority
- initial mint submission
- direct and restored response validation
- live restore and bounded immutable replay
- direct keyset-rejection successors
- startup/manual recovery
- local finalization
- duplicate and process coordination

The current dependency baseline is:

- CDK/Cashu `v0.18.1` (`a056e0f0f69e94f431b1aeb90d883f18c61ea4c6`)
- `cashu_spilman_channels` commit
  `82533cc25f3588032b5f50aa57c310cd27576ed6`

Refunds, relay closes, and relay drains have different durable boundaries and
recovery policies. They must not be assumed to have inherited the opening
journal's replay authority or stale-input export rules.

## Current Guarantees

### Preparation And Reservation

- The exact serialized prepared opening and selected local proof IDs are durable
  before mint submission.
- Initial proof reservation and `Prepared` attempt insertion occur in one SQLite
  transaction.
- The journal verifies its proof IDs against the exact reserved rows and immutable
  prepared input material.
- Plain selection is deterministic smallest-first `(amount, proof_id)` and selects
  enough post-input-fee value to meet `channel_funding_token_target_msats`.
- Input keyset metadata gets one bounded refresh when needed. Exact-capacity
  selection may proceed from known positive-net proofs when they suffice.
- Preparation and storage enforce a portable 992-input limit with a typed error.

### Submission Authority

- Initial submission and immutable replay require move-only typed authority.
- A transactional claim creates a durable `Claimed` execution. Authorization
  rechecks the attempt, request, reservation, and current execution state,
  transitions to `Authorized`, and advances `latest_submitted_at` immediately
  before mint I/O.
- A failed initial claim stops. It does not enter restore, replay, submission, or
  cleanup through another path.
- Once any execution may have reached the mint, later local or recovery failures
  preserve that uncertainty and cannot use generic reservation release.
- Complete deterministic opening identities use process-local fail-fast
  singleflight plus database uniqueness. Duplicate callers receive typed
  `AlreadyOpen`, `OpeningInProgress`, or `Conflict` outcomes.

### Response Validation

The pinned Spilman completion path validates direct and restored responses against
the exact prepared outputs. It checks:

- exact signature/output count
- aggregate amount
- each output's amount and keyset ID
- availability of the expected denomination key
- DLEQ against that key and the exact blinded output
- complete funding and change output correspondence

MONAD uses this checked path before journaling a completion. A direct successful
swap is also followed by checked funding NUT-09 restore comparison before ordinary
local finalization.

The completion structs are public data structures, not unforgeable validated
types. The guarantee comes from using the checked execution path and trusted
durable journal, not from arbitrary deserialization of those structs.

### Ambiguity And Live Replay

- A submitted attempt first restores its exact funding and change outputs.
- If funding restore is valid and empty, one NUT-07 request must account for every
  persisted input Y exactly and report every input `UNSPENT`.
- That evidence may authorize at most one byte-identical replay of the same
  immutable request during the live opening operation.
- Replay also requires current execution authority and a wall-clock second
  strictly later than the preceding authorized execution. The live path does not
  wait solely to create that clock advance, so satisfying remote evidence does not
  guarantee a replay will occur.
- Replay success finalizes. Replay ambiguity or rejection gets one immediate exact
  restore and otherwise remains unresolved and reserved.
- A replay rejection settles only that execution. It cannot settle an earlier
  ambiguous execution, release inputs, or authorize a keyset successor.

### Keyset Successors

- Only a direct, unambiguous initial `12002` inactive-output-keyset rejection may
  create a successor.
- The rejected attempt is persisted, the client refreshes, and selection must
  produce a different active output keyset.
- There is at most one successor for the live opening operation.
- The successor is a separate immutable attempt with its own at-most-one exact
  replay allowance.
- Ambiguous initial or replay outcomes never authorize a changed request.

### Startup And Manual Recovery

Configured-client startup and `recover-openings` run under exclusive wallet
ownership and never submit opening swaps. Recovery:

- cancels prepared attempts that were never authorized
- cancels explicitly rejected attempts without a successor
- completes idempotent local work for `Finalizing` attempts
- finalizes `Submitted` attempts only from complete checked funding/change restore
- otherwise retains the reservation; eligible stale inputs can be exported without release

One `ClientWalletManager` opens/migrates the logical wallet and runs this recovery
once before starting managed clients. OS-backed runtime-owner and maintenance
sidecars exclude a second runtime and mutating CLI while preserving read-only
inspection. Locks cover normalized, deduplicated loose-proof and channel database
paths and are released by the kernel after process death.

### Finalization

- A checked completion payload is durable as `Finalizing` before advancing the
  ordinary channel/change/metadata steps.
- Those steps are idempotent and replayable across crashes; they are not one
  transaction spanning both databases.
- Exact proof-state completion and `Finalizing -> Completed` are atomic.
- Every selected proof must still be reserved for this opening or already spent
  for this exact channel. Available, released, reassigned, extra, or differently
  spent proofs are conflicts.
- Opening persistence is insert-or-verify, and completion is
  complete-or-verify. Reopening cannot destructively replace established channel
  payment/lifecycle state.
- The obsolete compatibility recovery table/path has been removed. Unsupported
  nonempty pre-authority state is rejected rather than inferred.

## Accepted Policy Risk

### Stale-Input Export Retains Custody

Under exclusive wallet maintenance access, `export-stale-opening-inputs` may mark a
submitted attempt `Exported`
only when all of these are true:

1. At least 3600 seconds have elapsed since its latest authorized submission or
   replay.
2. Exact funding and change restores are valid and empty.
3. One complete exact-input NUT-07 response reports every input `UNSPENT`.
4. The durable export transition revalidates attempt state, latest timestamp,
   latest execution sequence, and exact reservation membership.

The proofs remain reserved after export. Mints do not offer cancellation for a
possibly submitted swap, so empty restore and `UNSPENT` observations prove only that
no remote effect was visible at those observation points. Recovery still accepts a
delayed completion. It marks an exported attempt `ExternallySpent` only after all
exact inputs are `SPENT` and a final exact restore is empty.

Recent, clock-rollback, stale, partial, invalid, unavailable, pending, or spent
evidence remains unresolved and reserved.

## Resolved Historical Findings

The original review identified the following defects. They are resolved in the
current dependency pin and MONAD implementation:

| Historical finding | Current resolution |
| --- | --- |
| Direct/restored outputs were not fully validated | Shared checked completion verifies output identity, amount, keyset, totals, denomination keys, and DLEQ. |
| A later recovery error could erase submission uncertainty and release inputs | Submission uncertainty is monotonic; post-submission generic release is fenced out. |
| A worker that lost its submission claim could enter replay and submit | Typed claim/authorization is required immediately before mint I/O; claim failure exits. |
| Replay rejection could authorize release or a successor despite an earlier ambiguous execution | Executions are tracked separately; replay rejection preserves operation-level uncertainty and gets final restore only. |
| Runtime and recovery could overlap across processes | Client wallet manager plus OS-backed runtime/maintenance locks enforce the supported process model. |
| Upstream opening save could destructively replace established state | Opening save is insert-or-verify and completion is compare-and-transition/verify. |
| Funding target omitted input fees | Selection treats the configured target as funding-token value and adds input fees. |
| Missing input-keyset metadata always blocked exact selection | One bounded refresh is attempted; understood proofs may proceed when policy permits. |
| Smallest-first selection could exceed SQLite variable limits late | Typed 992-input checks run before preparation and at reservation. |
| Nonpositive-net exact-selection inputs could hide a feasible candidate | Individually nonpositive-net inputs are excluded. The selector remains a deterministic heuristic, not an optimal subset solver. |
| Reservation completion used count-only updates | Completion verifies the exact reservation state atomically with journal completion. |
| Legacy opening recovery could advance upstream state without equivalent MONAD durability | The legacy path/table was removed. |

One narrower upstream diagnostic limitation remains: some established-funding
lookup APIs still map read/decode failure to absence. Insert-or-verify prevents the
old destructive overwrite failure, but this API should not be described as fully
fallible across every read.

## Coverage Ledger

Existing MONAD or pinned-upstream tests cover:

- invalid DLEQ, wrong amount, wrong keyset, wrong denomination, wrong counts, and
  restore correspondence in the checked Spilman completion primitive
- atomic prepared-attempt creation and reservation
- preflight/claim failure making zero HTTP calls
- same-opening concurrent handles producing one submission
- successful HTTP followed by execution-record failure retaining uncertainty
- replay rejection retaining reservation and creating no successor
- cancellation and authorization races
- one-hour export age, clock rollback, and stale export evidence
- exact idempotent completion and conflicting proof states
- sequential local-finalization crash boundaries
- input-fee target selection, metadata refresh, nonpositive-net filtering, and
  the 992-input limit
- wallet ownership exclusion and process-death lock release

The following are worthwhile orchestration-level additions, not evidence that the
underlying invariant is absent:

- inject each invalid direct/restored response through MONAD and assert final
  journal/reservation state, including valid funding plus invalid change
- delay the original request until after restore/checkstate and reject the replay,
  then demonstrate later recovery of the original completion
- exercise the complete stale-input export orchestration with controlled mint
  restore/checkstate responses, not only storage-level evidence races
- broaden multi-process and CLI lifecycle tests around ownership and mint-I/O
  exclusion

## Separate Follow-Up Areas

- Review client refund, relay close, and relay drain boundaries independently.
  The opening policy is a reference, not an implicit specification for them.
- Decide whether unresolved submitted attempts need periodic background recovery;
  current startup/manual recovery deliberately favors safety over automatic
  liquidity release.
- Keep established-channel fund recovery separate from opening recovery. It has
  its own refund/relay-close classification and persistence ordering.
- Continue operational and fault-injection coverage without weakening ambiguous
  outcomes into assumed failures.

## Non-Decisions To Preserve

- Do not add a channel-opening nonce; complete channel parameters intentionally
  determine channel identity.
- Do not silently replace smallest-first plain selection.
- Do not treat relay-advertised keyset IDs as an exhaustive acceptance list.
- Do not generalize opening replay or stale-input export to other swap types without
  a separate review.
