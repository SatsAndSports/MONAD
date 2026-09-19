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

`SqliteClientWallet::recover_channel_funds(channel_id, mint_connection)` is the
single library entrypoint for getting the client's money back from a channel.
It handles every relevant channel state:

- already recovered
- unexpired and unspent
- expired and unspent
- refund submit may have reached the mint but response was lost
- spent by client refund
- spent by relay close
- pending funding token
- unknown spent state

The recovery source of truth is the mint-observable funding-token state plus
locally persisted channel funding data; relay-provided close-balance hints are
intentionally not used here.

Persisted state involved in recovery:

- upstream `ClientChannelFunding` in the Spilman client storage
- MONAD channel metadata in `monad_client_channels`
- MONAD recovery progress in `monad_client_channel_recoveries`
- recovered spendable proofs in `LooseProofWallet`

Recovered proofs must end up in `LooseProofWallet`. Channel and recovery metadata
records provenance and completion state, but it is not long-term proof custody.
For post-expiry refunds, the recovery row stores the full prepared refund attempt
before the mint swap is submitted. Recovery must use that persisted prepared
attempt first, so safety does not depend on refund outputs being regenerated the
same way forever.

The recovery row status has three active values:

- `prepared`: a post-expiry refund has been prepared but not yet submitted
- `submitting`: the prepared refund is in the ambiguous submit window; the mint
  may or may not have accepted it
- `completed`: recovery finished and proofs are in `LooseProofWallet`

The algorithm is:

1. If the recovery row is already `completed`, return `AlreadyRecovered` without
   contacting the mint.
2. Load the persisted upstream channel funding for the channel id and reconstruct
   the upstream `EstablishedChannel`.
3. Check the funding-token state at the mint using NUT-07.
4. If the funding token is `Pending`, return `FundingPending` without changing
   local state.
5. If the funding token is `Unspent` and the channel has not expired, return
   `NotExpiredOrSpentYet` without changing local state.
6. If the channel is expired and the local row is `submitting`, first try
   restoring the persisted prepared refund outputs. If restore succeeds, import
   proofs and mark recovery completed.
7. If the funding token is `Unspent` and the channel has expired:
   - if no prepared refund exists, prepare a full post-expiry sender refund and
     persist it with status `prepared`
   - mark the recovery row as `submitting` before making the network call
   - submit the persisted prepared refund swap
   - if submit succeeds, import the returned proofs and mark recovery completed
   - if submit fails, try restoring the prepared refund outputs once
   - if restore still fails, return `RecoveryRetryLater`
8. If the funding token is `Spent`, classify the NUT-07 witness signature shape:
   - two P2PK signatures means relay close; restore the sender's deterministic
     close outputs
   - one P2PK signature means post-expiry refund; if local restore did not
     already complete it, return `UnknownSpent`
   - unknown witness shape returns `UnknownSpent`
9. Relay-close recovery is attempted only after the witness classifies the spend
   as `RelayClose`.
10. If relay-close sender-output restore succeeds, import those proofs into
     `LooseProofWallet`, then close local channel state and mark the recovery row
     completed with kind `relay_close`.
11. If no recovery path can identify spendable outputs, return `UnknownSpent` and
    leave the channel recoverable for a future attempt.

The NUT-07 witness classifier uses signature count to distinguish refund from
relay close:

- one P2PK signature on the spent funding proof -> post-expiry refund
- two P2PK signatures on the spent funding proof -> relay close

This is reliable because only the client can initiate the refund, and the refund
path signs with the sender refund key only; the relay-close path carries both
sender and receiver stage-1 signatures.

The important durability ordering is:

1. persist the exact prepared refund attempt for an ambiguous local refund submit
2. mark the attempt `submitting` before the network call
3. perform the mint operation
4. import recovered proofs into `LooseProofWallet`
5. only after proof import succeeds, mark channel metadata closed and recovery
   completed

That ordering is required so a restart can safely retry. A channel must not be
marked `Closed`, and a recovery row must not be marked `completed`, if recovered
proof import fails.

Expected restart behavior:

- restart before the refund marker exists: check funding state again and choose the
  correct branch
- restart after the prepared refund is persisted but before submit: the attempt is
   still `prepared`, so the funding state branch will submit it
- restart after `submitting` but before importing returned proofs: the marker
  causes exact persisted refund-output restore to run before any other branch; if
  the funding token remains `Unspent`, the same persisted refund is submitted
  again
- restart after importing proofs but before metadata completion: proof import is
  idempotent, so rerunning recovery can import/observe the same proofs and finish
  metadata updates
- restart after completed metadata: the recovered value is already in
  `LooseProofWallet`; future UX can treat the channel as closed

Current direct MONAD tests cover:

- `AlreadyRecovered` on rerun after success
- unexpired unspent funding token returns `NotExpiredOrSpentYet`
- expired unspent funding token recovers by post-expiry refund into
  `LooseProofWallet`
- the prepared refund attempt is persisted in the recovery row
- existing persisted refund restores outputs after a simulated crash-after-submit
  and wallet reopen
- `submitting` plus `Unspent` retries the same persisted refund attempt
- invalid recovery statuses and corrupted `submitting` rows are rejected
- spent-by-refund without a local prepared attempt returns `UnknownSpent`
- refund submit/restore failure returns `RecoveryRetryLater`
- completed recovery records `post_expiry_refund`
- recovered channels are marked `Closed` only on the successful path
- proof-import failure leaves recovery incomplete and retryable
- relay-side close followed by explicit client recovery returns `relay_close`
  recovery and imports the sender-side proofs
- NUT-07 witness classifier matches post-expiry refund and relay-close spends

Additional tests should cover:

- `FundingPending` returns without metadata changes, if a stable pending-state
  fixture is available

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

Current relay mint policy rule:

- the operator's current trusted mint policy comes from config at startup
- it governs new advertisement and first-time channel acceptance
- it does not retroactively invalidate already-stored channels accepted under an older policy
