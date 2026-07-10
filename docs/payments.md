# Payments And Funding

This note is the maintainer-oriented reference for MONAD's current payment and
session-funding implementation.

Use it together with:

- `ARCHITECTURE.md` for protocol and lifecycle overview
- `WALLET.md` for wallet/backend responsibilities

## Canonical Code Paths

The canonical client funding implementation is in `monad-client`:

- `monad-client/src/session_driver.rs` - public entrypoints
- `monad-client/src/session_driver/runtime.rs` - serialized control-loop executor
- `monad-client/src/session_driver/state.rs` - local driver state and publishing helpers
- `monad-client/src/session_driver/funding.rs` - channel acquisition, link, payment, recovery
- `monad-client/src/session_driver/payment.rs` - payment math and protocol-safety checks
- `monad-client/src/wallet.rs` - wallet abstraction, selector, mock wallet
- `monad-client/src/sqlite_client_wallet.rs` - SQLite-backed `MonadWallet` using upstream Spilman channels
- `monad-client/src/loose_proof_wallet.rs` - loose Cashu proof custody, quote/premint records, reservations, and spend/release state
- `monad-client/src/proof_selection.rs` - mixed-keyset proof selection for exact post-swap channel capacity

Shared helpers used by multiple crates live in `monad-common`:

- `monad-common/src/control_codec.rs` - JSON newline control-stream framing
- `monad-common/src/payment_units.rs` - `msat` / `sat` raw-unit conversion helpers

The relay-side steady-state authority lives in:

- `monad-relay/src/session.rs`
- `monad-relay/src/session_fsm.rs`

Non-canonical harnesses intentionally keep their own orchestration:

- `monad-test-client/src/lib.rs`
- `monad-relay/tests/stress.rs`

Those paths reuse the wire protocol and some shared helpers, but they are not the
source of truth for the main client funding algorithm.

## State Ownership

The relay is authoritative for accepted session state:

- whether the session is paused
- which channel is currently linked
- the latest accepted linked-channel raw balance
- accepted session totals (`session_total_in`, `session_total_out`)
- accepted session payment total (`total_paid_millisats`)

The client is authoritative for local intent and local authorization:

- which channel it is trying to use next
- which channels it has locally excluded for the current session
- how much payment it has locally authorized through the wallet
- local cleartext byte counters observed by the client transport path

The client does not treat its local estimate as accepted relay state. It uses
that estimate only to decide when and how much to pay.

## Relay Keyset Model

The relay wallet manager owns one shared in-memory `SpilmanMintCache` plus the
SQLite-backed relay wallet database.

The in-memory cache stores all keysets returned by configured mints: all units,
active and inactive. The relay's trusted mint/unit policy is applied when reading
from that cache, not when storing it.

Consequences:

- `SessionStatus` advertises only configured trusted mint/unit options.
- `ChannelLink` / `ChannelPayment` accept only known keysets that belong to a trusted unit for that mint.
- old inactive keysets can remain usable for existing channels as long as the keyset metadata is known.
- channel close and relay drain swaps start from the shared cache and refresh that mint into SQLite and memory only if the mint rejects the swap with a keyset error.

This cache-first, single-refresh retry shape is the shared model for relay close
and drain swaps.

## Relay Channel Policy

Each relay has an optional `channel_policy` block in YAML. `min_expiry` controls
how much time must remain before the relay accepts a new `ChannelLink`.
`min_capacity` and `max_amount_per_output` require explicit `sat` or `msat`
suffixes; the config stores them as millisats and converts them to the linked
channel's raw unit before passing policy to upstream Spilman validation.

Expiry maintenance settings live under `channel_policy.expiring_channels`.
`close_before_expiry` is parsed and validated alongside link policy. It is used
by relay wallet detection to report `Open` and `Closing` channels that are close
to expiry. `auto_close.enabled` is disabled by default; when enabled, the relay
runs a close sweep for its own identity at startup and then every
`auto_close.interval`.

Operators can inspect the current close-to-expiry set with
`monad-relay wallet --config monad.yaml --relay <name> expiring-channels`.
They can close that set non-interactively with
`monad-relay wallet --config monad.yaml --relay <name> close-expiring-channels`;
add `--dry-run` to preview the candidates. The command attempts every candidate,
prints each result as it completes, and exits non-zero if any close fails.
Omitting `--relay` / `--wallet-name` scans all relay identities and prints a flat
list with a `RELAY` column.

## Client Keyset Model

The client wallet has the same cache-first shape for channel-opening swaps.

Before the shared keyset retry helper runs, each call site ensures the upstream
client cache has at least one keyset for the relevant `(mint, unit)`. That cache
may be stale and may include inactive keysets. Inside the helper, output-keyset
selection reads cache only. If the mint rejects the first open with a retryable
keyset error, the helper refreshes that mint, reselects from cache, and retries
once only if the selected output keyset id changed.

Input proof keysets are independent from the selected output funding keyset:
input proofs may be old, inactive, or mixed-keyset proofs as long as the mint
accepts them and fee metadata is known.

## Funding Lifecycle

For one relay session, the client funding flow is:

1. Open the H2 control stream.
2. Wait for the initial `SessionStatus`.
3. Validate pricing and safety invariants.
4. Choose or provision a compatible channel.
5. Attach that channel locally to the session id.
6. Send `ChannelLink { payment_json }`.
7. Wait for a relay `SessionStatus` that confirms the linked channel.
8. Use relay-authoritative state plus local cleartext counters to decide whether a `ChannelPayment` is needed.
9. Ask the wallet to build a payment for an exact next cumulative balance.
10. Send `ChannelPayment { payment_json }`.
11. Repeat as more balance is needed.

If a channel is evicted, invalidated, or exhausted, the client abandons its local
intent for that channel and starts another acquire/link attempt.

If the control stream detaches, the session is considered ended. Local wallet
attachment metadata is cleared for the intended channel.

## Driver Shape

Each relay session is handled by one serialized executor loop in
`monad-client/src/session_driver/runtime.rs`.

Important consequences:

- no mutex is needed for the driver state itself
- relay messages and timer ticks are just two ordered inputs into one loop
- link/payment in-flight markers prevent duplicate work
- `paused` is the real operational state, not the startup readiness oneshot

The loop intentionally preserves this progression order after each input:

1. `maybe_ensure_linked_channel(...)`
2. `maybe_progress_payment(...)`
3. `maybe_ensure_linked_channel(...)`

That ordering is behavior-sensitive and should not be casually rearranged.

## Payment Sizing

The current policy remains intentionally simple.

Inputs:

- relay `remaining_milli_sats`
- relay `linked_channel.balance_raw`
- relay `linked_channel.capacity_raw`
- relay `linked_channel.unit`
- client-local cleartext byte counters
- immutable session pricing
- `PaymentPolicy { target_topup_buffer_msats, minimum_topup_msats }`

Configured clients load `target_topup_buffer_msats` and `minimum_topup_msats`
from `wallets.client` in YAML, defaulting to `10000000` and `0` msats.

The client computes:

1. a local estimated remaining session balance from locally observed bytes
2. the gap from that estimate to `target_topup_buffer_msats`
3. a delta clamped to at least `minimum_topup_msats`
4. the same delta converted into raw channel units
5. a capped next cumulative raw balance that cannot exceed channel capacity

If capacity capping is the only reason the payment falls below the configured
minimum, the client still allows that smaller non-zero payment when it exactly
fills the channel.

## Safety Invariants

The client currently enforces several important checks before trusting a relay
status update as a payment baseline.

1. Active pricing is immutable after first status.
2. Relay `linked_channel.balance_raw` must never exceed the client's own locally signed balance for that same channel.
3. Relay `session_total_out` must never exceed the client's locally observed outbound total.
4. Relay `total_paid_millisats` must never exceed the client's locally authorized payment total.

These checks live with the payment logic in
`monad-client/src/session_driver/payment.rs`.

## Harnesses And Tests

The main client funding path is tested primarily through relay integration tests,
especially:

- `test_session_payment_driver_links_unpauses_and_allows_data_flow`
- `test_session_payment_driver_proactively_pays_from_local_counters`
- `test_session_payment_driver_timer_does_not_duplicate_payment_builds`
- `test_session_payment_driver_marks_invalid_channel_and_reselects`
- `test_session_payment_driver_detaches_evicted_channel`

Stress and manual harnesses intentionally differ:

- `monad-relay/tests/stress.rs` keeps alternate prefunding / buffered / relink behavior
- `monad-test-client/src/lib.rs` keeps periodic `GetSessionStatus` polling for health and observability

Do not use those harnesses as the reference for production client behavior.

## Maintenance Rules

When changing payment code, keep these boundaries clear:

- protocol framing belongs in `monad-common`
- raw-unit conversion belongs in `monad-common`
- wallet semantics belong in `monad-client/src/wallet.rs`
- session funding policy belongs in `monad-client/src/session_driver/*`
- relay authority and acceptance rules belong in `monad-relay`

When reviewing future changes, verify at least:

- single-hop and nested funding still work
- timer-driven payments do not duplicate in-flight payments
- relay-authoritative linked-channel sync still gates payment construction
- control detach still releases local and relay ownership cleanly
