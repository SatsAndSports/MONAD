# WALLET

This note captures the current client-side payment model in MONAD.

## Big Picture

See `docs/payments.md` for the current maintainer-oriented funding and payment
code map. This file stays focused on wallet/backend responsibilities.

`cashu_spilman_channels` provides the per-channel Spilman client layer:

- `SpilmanClientBridge`
- `SpilmanClientHost`
- `SpilmanClientNetworking`
- `ClientStorage`
- per-channel funding / payment / lifecycle state

MONAD adds a higher-level wallet / selector / per-session driver layer on top of
that.

That MONAD layer is responsible for:

- finding already-usable channels for a relay offer
- provisioning a new channel when no suitable one exists
- choosing which single channel to link to a relay session
- driving `ChannelLink` and `ChannelPayment` over the relay control channel
- retiring channels that should no longer be used
- keeping local attachment metadata so parallel sessions do not accidentally
  reuse the same channel

## Current MONAD Split

### 1. Pure selector

The selector has no side effects.

It:

- inspects existing local channels
- matches them against a relay offer
- prefers unattached channels
- falls back to a channel already attached to the same session
- excludes channels attached to another session

Matching keys are:

- `receiver_pubkey`
- `mint_url`
- `unit`
- a mutually negotiated keyset-format version; relay-advertised keyset IDs rank
  otherwise compatible channels as preferences rather than forming an exhaustive
  acceptance list

Only `Open` channels are selectable.

### 2. Wallet backend

The wallet backend owns local channel metadata and payload construction.

It is responsible for:

- listing channels
- attaching / detaching channels to local MONAD sessions
- marking channels unusable
- provisioning a new channel for a relay offer
- building the zero-balance `ChannelLink` payload
- building a `ChannelPayment` payload for an exact next cumulative balance

Current code has:

- `MonadWallet`
- `MockWallet`
- `LooseProofWallet`
- `SqliteClientWallet`
- `proof_selection`

`MockWallet` remains a deterministic test/harness backend. `SqliteClientWallet`
is the real channel wallet implementation used by the library path: it bridges
loose Cashu proof custody into upstream Spilman channel creation and payment
signing. `LooseProofWallet` owns bearer-proof persistence, quote/premint records,
proof reservations, release, and spend marking.

The configured `monad-client run --config ...` runtime opens the persisted loose
proof and channel wallets from top-level `client_wallet` YAML config. The
`monad-client wallet` CLI can use that same config for channel/proof inspection,
token import, and recovery commands, while explicit DB/key flags remain available
for manual or emergency access.

Channel-opening recovery and stale-input export have separate responsibilities.
`recover-openings` restores and finalizes delayed openings without submitting a
swap. `export-stale-opening-inputs` only assesses and emits eligible bearer value:
after one hour, empty exact restores, and all-`UNSPENT` exact inputs, it groups
proofs by mint/unit and atomically marks every attempt represented by each token
`Exported` before output. The command returns both successful exports and unresolved
attempts; repeated exports may overlap while proofs remain reserved. A nonempty
restore is never finalized by export and must be handled by `recover-openings`.
Only recovery may later mark an exported attempt `ExternallySpent`, after all exact
inputs are `SPENT` and a final exact restore remains empty.

What is still missing is the rest of the user-facing wallet UX: mint quote/mint
commands, richer balance inspection, an automatic established-channel fund
recovery policy, and sweep/close flows for client-side value. Startup recovery of
the separate channel-opening journal is implemented and runs once through
`ClientWalletManager` before configured clients start.

### 3. Per-session payment driver

Each relay session gets its own control-loop driver.

It is responsible for:

- opening the control stream
- receiving `SessionStatus`
- selecting or provisioning a channel
- sending `ChannelLink`
- computing the next requested cumulative balance
- sending `ChannelPayment`
- reacting to `ChannelEvicted`
- reacting to server `Error` messages
- reselecting / relinking when the linked channel is invalid or too small

MONAD currently has:

- `monad_client::session_driver::start_session_payment_driver(...)`

The client payment driver is now implemented as one serialized direct control
loop across `monad-client/src/session_driver/`:

- `session_driver.rs` - public entrypoints
- `runtime.rs` - serialized executor loop
- `state.rs` - local driver state
- `funding.rs` - link/payment progression and recovery
- `payment.rs` - payment math and safety checks

Important details:

- payment-driver startup still means `open control`, then wait for the first
  `SessionStatus`; protocol bootstrap refers separately to Noise-payload
  version/capability negotiation
- `paused` is the real operational state; the startup oneshot waiter is only an
  executor concern
- one relay session is handled by one serialized executor loop, so the client
  state itself does not need a mutex
- nested client sessions end indirectly via transport collapse when a parent
  session dies

## Relay-Authoritative Session Model

The relay is authoritative for the currently linked channel state.

`SessionStatus` now includes:

- `linked_channel: Option<LinkedChannelStatus>`

Where `LinkedChannelStatus` contains:

- `channel_id`
- `balance_raw`
- `capacity_raw`
- `unit`

This means the client should trust the relay for:

- which channel is linked
- the latest accepted linked-channel balance
- the linked channel's capacity
- the unit in which that raw balance is expressed

The relay remains the authoritative baseline for linked-channel state and
accepted session totals, but the client now combines that baseline with its own
local cleartext byte counters when sizing payments.

On the server side, steady-state control/session handling is now modeled as an
explicit reducer-style FSM after bootstrap. The Noise-payload bootstrap handles
version/capability negotiation before H2 starts, and the initial `SessionStatus`
exchange stays outside that FSM.

If the control stream detaches, the server fully tears the session down:

- release linked-channel ownership
- stop accepting new streams
- terminate active streams relatively soon

## Payment Construction

The driver thinks in session balance.

The wallet thinks in exact cumulative channel balance.

When the relay reports:

- `session_total_in`
- `session_total_out`
- `total_paid_millisats`
- `linked_channel.balance_raw`
- `linked_channel.capacity_raw`
- `linked_channel.unit`

the driver does this:

1. chooses a target positive remaining session balance
2. reads its own local cleartext byte counters and estimates the current
   remaining session balance against the latest authoritative relay baseline
3. computes the requested delta in millisats from that local estimate
4. converts that delta into raw channel units
5. computes:
   - `next_balance_raw = linked_channel.balance_raw + requested_delta_raw`
6. asks the wallet to build a payment for that exact next balance

More precisely, payment planning now follows this policy:

1. start with `target_topup_buffer_msats - estimated_remaining_milli_sats`
2. clamp that delta to at least `minimum_topup_msats`
3. convert the millisat delta into the channel's raw unit (`msat` stays exact,
   `sat` rounds up)
4. cap the raw delta at the linked channel's remaining raw capacity
5. if capping is what forces the delta below `minimum_topup_msats`, still allow
   that smaller non-zero payment when it exactly fills the channel to capacity

Reaching exact capacity does not immediately retire a channel. The client keeps
using that linked channel until a later needed payment cannot increase the
balance any further, at which point the client abandons it locally and starts a
replacement acquire/link flow.

So the wallet API is centered on:

- `build_link_request(...)`
- `build_channel_payment(..., latest_server_balance_raw, next_balance_raw)`

## Local Attachment Metadata

Each local channel stores:

- `attached_session_id: Option<[u8; 32]>`

Purpose:

- prefer channels not already claimed by another live MONAD session
- allow the same session to keep using its own channel
- keep concurrent client-side session drivers from accidentally reusing one
  channel at the same time

This is local MONAD policy metadata, not relay-authoritative protocol state.

## Rejections and Channel Retirement

Not every server rejection should retire a channel.

### Channel-invalidating rejection

Examples:

- wrong receiver key
- unsupported unit
- wrong mint / keyset
- expired / closed / unusable channel

These should usually cause the client to mark the channel unusable.

### Session-local rejection

Examples:

- wrong currently linked channel
- no new funds
- local desync that can be recovered by relinking

These do not necessarily mean the underlying channel is globally bad.

## Capacity-Based Relinking

If the currently linked channel cannot support the next requested cumulative
balance, the driver should:

1. treat that channel as insufficient for this session
2. locally detach it
3. select or provision another channel
4. send `ChannelLink`
5. wait for the next relay-authoritative `SessionStatus`
6. retry payment against the new linked channel

The current session driver and both wallet implementations follow this model.

## Client Keyset Cache Model

Client channel opening is also cache-first.

For a relay offer, `SqliteClientWallet` prefers an advertised active output
keyset, then may use another locally active same-mint/unit keyset whose format was
negotiated. It refreshes before using a non-preferred fallback when nonempty
preferences are unavailable and before concluding that no compatible active
keyset exists. The prepared opening and exact inputs are then atomically journaled
and reserved before submission.

An ambiguous submission first uses exact NUT-09 restore and exact-input NUT-07
evidence. That may authorize one permit-backed byte-identical replay, but never a
changed request. Only a direct, unambiguous initial `12002` rejection may create
one successor, and only with a changed active output keyset. Startup/manual
opening recovery is restore-only and does not submit swaps.

Important boundaries:

- input proofs can come from old, inactive, or mixed keysets as long as the mint
  accepts them
- output funding uses an active keyset selected from the local cache
- a direct inactive-output-keyset successor requires a changed output keyset
- replay rejection after an earlier ambiguous execution remains unresolved and
  cannot create a successor

## Channel Fund Recovery

`SqliteClientWallet::recover_channel_funds(access, channel_id, mint_connection)`
requires matching `ExclusiveWalletAccess` for the normalized loose/channel DB
pair. The CLI obtains it for `wallet recover-channel`; a running client excludes
maintenance. Per-channel in-process singleflight also excludes overlapping calls
across wallet handles. This explicit operation is separate from startup and manual
opening recovery, which never submit opening swaps.

### Durable State

The v2 `monad_client_channel_recoveries` journal binds each recovery to its
normalized loose-proof DB path, `wallet_name`, and sender public key. The binding
is checked before mint I/O, proof import, or even returning `AlreadyRecovered`.
Upstream funding supplies the channel identity and original inputs; recovered
bearer value belongs in `LooseProofWallet`, not just channel metadata.

| Status | Meaning |
| --- | --- |
| `prepared` | Exact signed refund and output material persisted before submission. |
| `submitting` | Execution recorded before I/O; acceptance may be uncertain. |
| `finalizing` | Verified complete proof payload persisted for local completion. |
| `completed` | Proof import and upstream/MONAD closure finished; totals recorded. |

`monad_client_refund_executions` retains each exact request and its outcome;
`monad_client_refund_predecessors` retains the rejected request if a successor is
authorized. These records survive even when relay close wins. Any noncompleted
recovery row exposes the channel as `Closing`, excluding selection and attachment.

### Preparation And Replay

Refund outputs use an active same-mint/unit keyset from the client cache, sorted
by ID, with refresh when none is available. Relay advertisements and negotiated
session keyset formats do not filter this loose-proof recovery. Output keys are
independent of the historical funding keyset; funding input fees still determine
the net refund value.

The upstream `prepare_sender_refund_after_expiry(sender_secret, now,
output_keyset, derivation_context)` API returns an immutable `PreparedSenderRefund`:
mint/unit/channel identity, historical output keys, exact signed swap, expected
value, secrets and blindings, and derivation version/context. Version 1 derivation
includes sender-private material, not just the channel secret known to the relay.
MONAD supplies a fresh random context for each new request. Unknown derivation
versions are rejected. Protect journal/backups as bearer-value material; never log
prepared records, output secrets, blindings, sender secrets, or derivation preimages.

Recovery follows these boundaries:

1. A completed row returns locally. A `finalizing` row resumes proof import and
   closure from its persisted verified payload without mint I/O.
2. A `submitting` row verifies and restores the exact persisted outputs before
   clock or funding-state checks. Invalid, partial, or unavailable restore evidence
   is not absence and blocks replay. A valid complete restore finalizes.
3. After valid absence, check funding state. `Pending` returns `FundingPending`;
   unspent funding at or before expiry returns `NotExpiredOrSpentYet`. Expired,
   unspent funding permits submission of the persisted request, preparing it first
   if needed. Each execution atomically records `submitting` and an `uncertain`
   execution before the network call.
4. Each invocation allows at most two submissions per immutable request (one
   submission plus one exact replay), with restore/state checks between them.
   Later invocations may retry that same request; this is not a lifetime replay
   limit and not the opening journal's wall-clock replay rule.
5. Only a direct initial typed HTTP 4xx rejection with numeric JSON `code: 12002`,
   no prior execution uncertainty, and no predecessor can authorize one durable
   successor. Refresh must select a different active output keyset. Persist the
   rejected predecessor and replacement atomically; the successor gets its own
   per-invocation replay allowance but cannot create another successor. A timeout,
   cancellation, lost response, or rejection after ambiguous execution never
   authorizes new outputs. A durably recorded initial rejection can resume after
   restart; failure to record it conservatively retains uncertainty.

The CLI mint adapter bounds each swap/restore/checkstate request to 15 seconds.
It retains structured rejection bodies for classification but redacts them from
error `Display`/`Debug`; arbitrary error text is not successor authority.

### Spent Funding And Finalization

NUT-07 checks exactly the first funding proof's Y and validates response count and
identity. This representative check assumes supported generated close/refund
transactions spend all funding proofs atomically; it is not a guarantee for
arbitrary transactions. The first input carries the generated SIG_ALL witness.
Signature count is advisory, not cryptographic settlement evidence: one normally
indicates refund, two close, and extra/missing signatures can yield `Unknown`.

If funding becomes spent after an empty submitted-refund restore, recovery makes
one final exact restore before discovery, covering completion between observations.
Both `RelayClose` and `Unknown` permit checked deterministic sender-close discovery;
a refund-shaped witness alone does not. Only verified nonempty discovered proofs
complete relay-close recovery. An empty scan is `UnknownSpent`, not successful
zero-value recovery. With an unresolved submitted refund, that unknown result
becomes `RecoveryRetryLater` and retains the request; invalid or unavailable
discovery also returns retry-later. Relay close-balance hints are not authority.

Verified proofs are persisted as `finalizing` before import. Import checks immutable
proof data and is idempotent without resurrecting reserved or spent proofs. Only
then are upstream state and MONAD metadata closed and recovery marked `completed`.
These are separate database steps, not one cross-database transaction: failures
resume from the persisted payload offline, including after import but before
closure/completion.

### Compatibility And Coverage

This is a testnet-breaking refund schema/API change, not a migration. A nonempty
legacy refund journal or incompatible journal version is rejected; only an empty
legacy recovery table is replaced automatically. Preserve funded databases and
recovery records. Resetting disposable, operator-owned test databases is an
explicit operator decision, never automatic deletion of incompatible wallet data.

Current MONAD test cases exercise keyset rotation before/after preparation,
successor exact replay, lost-response restore, ambiguous-replay rejection without
successor, invalid restore blocking replay, authority/singleflight and cancellation,
custody mismatch and path aliases, journal-write failures, offline finalization at
metadata/completion boundaries, proof-import conflict and spent-proof preservation,
the final-restore spent race, and checked close discovery with extra signatures,
empty/invalid/network results, and close winning submission. The relay integration
fixture also seeds a pending refund and verifies its history survives real relay
close recovery; it is not a process-crash test. CLI tests check structured rejection
retention/redaction, not a live HTTP timeout. These assertions do not establish
exhaustive crash coverage or a dedicated `FundingPending` fixture.

## Current Runtime State

Today:

- configured `monad-client run --config ...` runs SOCKS routes backed by
  persisted wallet config
- `SqliteClientWallet` is the real persisted wallet backend for configured
  clients
- `MockWallet` remains for deterministic connector tests and stress/harness
  flows
- default integration-test relays advertise a synthetic mint/keyset offer so
  intermediate hops can provision mock channels
- route failures are handled at hop granularity:
  - first-hop failure triggers full reconnect
  - later-hop failure attempts suffix rebuild
  - suffix rebuild failure falls back to full reconnect
- active SOCKS/TCP streams are not migrated across rebuilds; they fail if their
  original route breaks
- new SOCKS/TCP streams use the next published route
- startup misconfiguration fails fast with bounded attempts before the first
  successful route connect
- once a route has connected, later route failures retry indefinitely with capped
  backoff
- the server uses an explicit steady-state session FSM while keeping byte
  accounting on the fast path under the per-session mutex

The current client admin/funding/recovery commands are:

- `monad-client wallet --loose-db <path> --channel-db <path> [--wallet-name default] channels`
- `monad-client wallet --loose-db <path> --channel-db <path> [--wallet-name default] proofs`
- `monad-client wallet --loose-db <path> --channel-db <path> --sender-secret-hex <hex> [--wallet-name default] import-token --token <cashu-token>`
- `monad-client wallet --loose-db <path> --channel-db <path> --sender-secret-hex <hex> [--wallet-name default] import-token --token-file <path>`
- `monad-client wallet --loose-db <path> --channel-db <path> --sender-secret-hex <hex> [--wallet-name default] recover-channel --channel-id <id>`
- `monad-client wallet --loose-db <path> --channel-db <path> --sender-secret-hex <hex> [--wallet-name default] recover-openings`

`import-token` is a trusted-custody operation: it stores the existing bearer proofs
without swapping them into fresh wallet-only proofs. Import does not invalidate
other copies of the token or prove exclusive ownership. Operators should import
only tokens they control and stop using any other copies in another wallet.

Use `--json` for machine-readable output.

Future wallet/UX tasks live in `FOR_LATER.md`.

## Relay Wallet Manager

Relay-side wallet state now has its own in-process manager layer, separate from
the client wallet work above.

Current relay-side model:

- one MONAD process may host multiple relay runtimes
- each relay runtime still has its own Cashu receiver key / relay wallet name
- all hosted relays may share one SQLite-backed relay-wallet database
- each hosted relay constructs one live payment backend shared by that relay's
  sessions; the manager itself does not cache payment objects by wallet name

The shared relay-wallet DB also stores a small MONAD-managed metadata table that
maps `channel_id -> relay_name / receiver_pubkey_hex` for admin queries and
runtime identity ownership. Process-level relay supervision is implemented.

Operator-facing admin commands now exist on `monad-relay` itself:

- `monad-relay wallet ... list` to enumerate relay identities in a wallet DB
- `monad-relay wallet ... show` to inspect one relay identity
- `monad-relay wallet ... channels` to list stored channels for a relay
- `monad-relay wallet ... close --channel-id <id>` to close a stored channel by
  channel id, discovering the owning relay identity from the metadata table
- `monad-relay wallet ... drains` to list relay drain attempts
- `monad-relay wallet ... drain --mint-url <url> --unit <unit> [--limit N]` to
  swap closed-channel receiver proofs into fresh proofs
- `monad-relay wallet ... recover-drain --drain-id <id>` to restore a previously
  submitted drain attempt

These commands accept either:

- `--wallet-db-path <path>` directly, or
- `--config relay.yaml --relay <name>` to resolve the DB path from the shared
  YAML config

Use `--json` for machine-readable output.

Drain restore validates exact blinded output identities against persisted secrets
and historical output keys, including amount/keyset/DLEQ checks. Reordered
output/signature pairs are canonicalized. Empty, partial, duplicate, or unknown
outputs leave the attempt `Submitted` and its channels reserved; they are not
successful zero-value drains and do not authorize replay. Completed drain proofs
are stored in the relay DB. Repeating completion requires identical serialized
proofs and preserves the original completion timestamp; a conflicting completion
or late failure cannot overwrite those proofs or release their reservations.

Drain preparation-only recovery, checked immutable replay, typed rejection
authority, retained keyset-retry predecessors, and full-operation singleflight
remain separate outstanding work; the close guarantees below do not apply to
the old drain retry path.

### Relay Close Recovery

Close journal version 1 binds the normalized relay DB path, wallet name, receiver,
funding, accepted payment, exact mint requests, historical output metadata, and
execution counts. Closing plus the first journal is an atomic payment CAS;
payments accepted before that boundary must be in the frozen snapshot, and later
payments are rejected. Old Closing records without exact journals and incompatible
or corrupt journals fail closed, retaining the database without conversion.

Each attempt records submission uncertainty before HTTP. Resumption restores
saved outputs before selecting keys or replaying, validates amount/keyset/DLEQ,
and requires exact all-input Unspent evidence before bounded immutable replay.
At most two submissions occur per invocation. Only the first typed HTTP 4xx
numeric `12002` rejection, with no earlier uncertainty, can authorize one changed
output keyset; the rejected request and its evidence remain in the journal.
Invalid restore responses never become absence. If deterministic predecessor and
successor points overlap, only verification against a saved exact attempt can
establish success. Unresolved spent/pending/unknown evidence retains Closing;
it is never classified as a successful zero-value close or an arbitrary refund.

Verified completion is persisted as finalizing before the journal, Closed state,
and payout are atomically committed. Finalizing/completed resumes offline. Expiry
enables a competing sender refund but does not invalidate the authorized close;
the mint arbitrates the atomic spend. Output fee rotation does not change the
signed nominal split. Client sender discovery keeps original channel derivation
and verifies discovered proofs using same-unit historical output keys.

The manager owns matching OS-backed authority for the lifetime of every derived
payment handle. `open` acquires maintenance ownership; runtime and CLI entrypoints
transfer their matching locks with `open_with_locks`. Runtime ownership permits
auto-close, while drains require exclusive maintenance access. `reopen` creates
fresh storage/cache under the same exclusive owner, not independent authority.
Per-channel close singleflight and journal CAS protect concurrent operations.
The former synchronous unchecked close API is removed; use the async recovery
transport, whose typed errors retain status/code but never response bodies.

Current relay mint policy rule:

- the operator's current trusted mint policy comes from config at startup
- it governs new advertisement and first-time channel acceptance
- it does not retroactively invalidate already-stored channels accepted under an older policy
