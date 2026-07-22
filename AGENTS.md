# AGENTS.md

This repository is the MONAD (Monetized Onion Network Access Daemon) Rust workspace for a multi-hop TCP tunneling system.

## Build and Test

Use:

```bash
cargo test
```

For binaries during development:

```bash
cargo run -p monad-relay -- ...
cargo run -p monad-client -- ...
cargo run -p monad-quic -- ...
```

## Repo Shape

- `monad-common`
  - shared transport, protocol, and session code
  - `SecpNoiseStream` (`noise_secp256k1.rs`) — secp256k1 Noise transport with buffered writes and wire-byte logging
  - `H2ConnectStream` (`h2stream.rs`)
  - `ClientMessage` / `ServerMessage` wire protocol, `KeysetAdvertisement`, `LinkedChannelStatus` (`protocol.rs`)
  - `RelayConnection`, `SessionPricing`, `SessionSpilmanInfo`, billing math (`session.rs`)
  - `proxy_bidirectional` shared proxy (`proxy.rs`)
  - `QuicCertIdentity`, Ed25519 key derivation for QUIC certificate plumbing (`quic_cert_identity.rs`)
  - `Secp256k1Pubkey` (32-byte x-only, implied even Y), `SecpTransportKeypair`, transport auth helpers (`secp_identity.rs`)
- `monad-client`
  - reusable library code plus binary entrypoint
  - multi-hop connector (`connector.rs`)
  - session payment driver (`session_driver.rs`)
  - wallet abstraction and mock wallet (`wallet.rs`)
  - SQLite-backed channel wallet (`sqlite_client_wallet.rs`), loose proof custody (`loose_proof_wallet.rs`), proof selection (`proof_selection.rs`)
  - tunnel proxying (`tunnel.rs`)
  - binary supports `run --config ...` for configured QUIC SOCKS clients backed by persisted wallets
- `monad-relay`
  - reusable library code plus binary entrypoint
  - YAML config loading with env-var / `.env` substitution (`config.rs`)
  - TCP+QUIC listener, `SpilmanMintCache`, `discover_spilman_mint_cache` (`listener.rs`)
  - `RelaySession<T>`, billing, control stream handler, version negotiation (`session.rs`)
  - explicit steady-state session reducer (`session_fsm.rs`)
  - `proxy_bidirectional_accounted` with pause/resume enforcement (`proxy.rs`)
  - QUIC connection pool (`quic_pool.rs`)
  - relay-wallet identity/channel admin CLI (`wallet_cli.rs`)
- `monad-quic`
  - shared QUIC transport code plus standalone echo tooling
  - reusable library code plus binary entrypoint
  - Ed25519 self-signed cert generation
  - QUIC echo server with pinned-key auth
  - QUIC echo client with custom `ServerCertVerifier`

## Current Protocol Model

- Outer transport: TCP or QUIC
- Encryption: secp256k1 Noise NK on both TCP and QUIC
- Multiplexing: HTTP/2
- Control stream: `POST /control`
- Data stream: `CONNECT host:port`
- Nesting: another full Noise+H2 session can run on top of an H2 CONNECT tunnel via `H2ConnectStream`

### Control Protocol

- Wire format: JSON newline-delimited messages on the H2 control stream (`POST /control`)
- Bootstrap: the two Noise handshake payloads negotiate the session version/capabilities and post-Noise session protocol (`h2` today); this is currently hardcoded, and the relay can reject with a reason before H2 starts
- Initial state: once the H2 control stream is established, the relay immediately sends a unified `SessionStatus` containing advertisements and initial state
- Sessions start paused-by-default with zero balance; control stream is always free while paused
- Billing formula: `ceil(in_bytes / in_rate + out_bytes / out_rate)` in millisats, integer-only via precomputed LCM
- `CONNECT` rejected with 402 while paused
- Balance can go negative (chunk-boundary overshoot); session repauses
- `GetSessionStatus` requests a fresh `SessionStatus` snapshot
- `Error { code, message }` for relay-initiated rejections and notifications
- `ChannelLink { payment_json }` links a Spilman channel to the session; relay validates and then sends an authoritative `SessionStatus` on success or `Error` on failure. Only one session can own a channel at a time.
- `ChannelPayment { payment_json }` increments the session balance based on the delta of the channel's max balance seen.
- `SessionStatus.linked_channel` carries the relay-authoritative linked channel id, latest accepted raw balance, raw capacity, and unit.
- control-stream detach fully ends the session: linked ownership is released, active streams are torn down, and new streams are no longer accepted.
- Session ID is the Noise handshake hash (32 bytes, identical on both sides)
- Relay keyset handling: the relay wallet manager owns one shared in-memory `SpilmanMintCache` plus SQLite persistence. The memory cache stores all keysets returned by configured mints (all units, active and inactive); trusted mint/unit policy filters advertisements and incoming channel acceptance at read time. Channel close and relay drain swaps are cache-first and refresh that mint into SQLite + the shared cache only if a swap retry path sees a mint keyset error.

### Current Client Runtime State

- `monad-client` library now has a wallet abstraction, `SqliteClientWallet`, `LooseProofWallet`, and per-session payment driver.
- client steady-state control/payment behavior now lives in a direct imperative control loop in `session_driver.rs`; the relay stays authoritative for linked channel / accepted balance / pause state, while the client uses its local cleartext counters to size payments against the latest authoritative relay baseline.
- channel-payment sizing now follows an explicit target/minimum-topup policy in that control loop: the client computes a local estimated remaining balance, clamps the desired refill to at least the configured minimum topup, then caps it at the linked channel's remaining raw capacity.
- the main client no longer needs frequent `GetSessionStatus` polling for payment sizing; the relay stress harness and `monad-test-client` still poll periodically for load generation, health checks, and observability.
- `SqliteClientWallet` provisions real upstream Spilman channels from loose proofs, stores MONAD channel metadata, persists ambiguous opening recovery, and uses cache-first active output-keyset selection with refresh/retry only after retryable keyset mint errors.
- `connector.rs` uses `MockWallet` + `session_driver` for default test/harness flows so multi-hop tests exercise the real `ChannelLink` / `ChannelPayment` control path.
- the `monad-client` binary runs configured QUIC SOCKS routes from YAML with persisted wallet config.
- configured-client route failures are handled at hop granularity: first-hop failure does a full reconnect, later-hop failure tries a suffix rebuild that preserves prefix sessions/channels, and suffix rebuild failure falls back to a full reconnect. Rebuilds are serialized; stale failures from the old route during an in-flight rebuild are ignored. Active SOCKS/TCP streams are not migrated across rebuilds; they fail if their original route breaks, and new streams use the next published route. Route connects fail fast with bounded attempts before the first successful connect (loud startup misconfiguration), then retry indefinitely with capped backoff once a route has connected (transient failures, including wallet funding exhaustion, must not permanently kill the SOCKS listener).
- relay-side byte accounting remains on the fast path under the per-session mutex rather than flowing through the control-session reducer.

### QUIC Transport

- Relay-to-relay transport: QUIC (replaces TCP between hops, does not replace Noise)
- QUIC authentication: secp256k1 attestation on top of the QUIC/TLS channel
- QUIC hop signaling: `CONNECT host:port` with `quic-secp256k1-pubkey: <64-hex-char x-only pubkey>` H2 header
- Configured clients use YAML route hop entries with secp256k1 pubkeys.
- Client and relay connector paths can use QUIC directly to the first hop and for nested relay-to-relay hops.
- Noise nesting is preserved — the inner Noise+H2 session runs unchanged inside the QUIC stream
- Server listens on the same port for both TCP and UDP (QUIC)
- QUIC connection pool: shared connections reused across client sessions, keyed by `(host, port)` plus auth mode

### Transport Identity Model

- Long-lived relay identities are 32-byte x-only secp256k1 pubkeys with implied even Y.
- Blinded-hop tweaked pubkeys are also represented as 32-byte x-only pubkeys and are forced even via rejection sampling.
- Ephemeral ECDH pubkeys remain 33-byte compressed points.
- Noise DH uses full curve points internally even when configured identities are x-only.

## Important Invariants

### 1. Keep direct and nested modes working

Do not break:
- single-hop client → relay usage
- multi-hop nested usage
- simultaneous multiple CONNECT tunnels

### 2. Preserve address-family support

Do not regress:
- IPv4 targets
- IPv6 targets
- hostname targets
- mixed IPv4/IPv6 hop chains

If you change connection logic, update tests accordingly.

### 3. Control and data streams are distinct

Do not collapse `POST /control` and `CONNECT` behavior together.

The control stream is reserved for metadata/payment/session management.

### 4. Avoid spin-polling

Use proper async wakeups, not `yield_now()` loops.

The shared helper for H2 flow control is:

```rust
monad_common::h2stream::wait_for_send_capacity
```

Use it instead of open-coded `poll_capacity` boilerplate where practical.

## Logging Conventions

### Plaintext tunnel logs

Use:
- `outbound`
- `inbound`
- `total`

for per-tunnel proxied byte counts.

### Encrypted hop logs

Use:
- `wire_read`
- `wire_written`
- `wire_total`

for per-hop encrypted byte counts from `SecpNoiseStream`.

### CONNECT logs

Each relay logs received CONNECT requests like:

```text
CONNECT example.com:22
```

Keep this simple and readable.

## Shutdown Behavior

The client and relay both implement graceful shutdown.

If you change shutdown logic:
- keep task tracking explicit
- prefer `JoinSet` / awaited tasks over heuristic sleeps
- preserve reliable `SecpNoiseStream` drop logging

## Test Expectations

The test suite currently covers:
- secp256k1 Noise transport correctness
- large payload chunking
- secp256k1 Noise partial-write tolerance and shutdown flushing
- session starts paused by default
- second control stream rejected
- CONNECT rejected while paused (402)
- funded data channel (payment unpauses, then data flows)
- session repauses and resumes after second payment
- session overshoot with negative balance and resume
- underpayment stays paused until balance is positive
- concurrent tunnels
- nested 2-hop and 3-hop routes
- IPv6 targets and IPv6 listeners
- mixed-family hop chains
- hostname resolution at the final hop
- SOCKS5 IPv6 parsing
- TCP secp single-hop and nested plain-CONNECT secp tunnels
- QUIC echo with pinned-key authentication
- QUIC pinned-key rejection (wrong key)
- 1,000 concurrent QUIC streams over one connection
- large single QUIC stream payload (4MB)
- multiple independent QUIC connections
- QUIC single-hop (Noise+H2 over QUIC stream)
- QUIC control + data channels over QUIC transport
- nested QUIC tunnel (TCP relay forwarding via QUIC to next relay)
- client connector with QUIC hop
- client QUIC first hop (direct QUIC connection from client)
- QUIC first hop then TCP second hop
- Noise session ID (handshake hash) matches on both sides
- Spilman channel implementation (delta-based) is exercised through relay validation, client wallet provisioning/recovery tests, and connector/session-driver flows
- relay advertises multiple mint/unit pricing options
- relay loads its trusted mint policy from a per-relay YAML config entry and advertises only configured mints/units
- default integration-test relays advertise a synthetic test mint/keyset offer so connector-driven intermediate hops can provision mock channels through the test wallet path
- control detach releases linked channel ownership and tears down active/future streams
- relay restart preserves accepted Spilman channel state in SQLite; the client re-links the same channel and delta accounting resumes from the persisted balance (`TestSigningWallet` produces real BIP-340 Cashu signatures for the full `SpilmanRelayPayments` validation path)
- relay unilateral channel close moves the stored channel to `Closed`, returns the correct receiver/sender split, and rejects further `ChannelLink` / `ChannelPayment` attempts on that channel
- relay-wallet manager can close a stored channel by channel id using the owning relay identity discovered from SQLite metadata
- two hosted relays with different receiver keys can share one in-process relay wallet manager / SQLite DB while keeping distinct channel ownership metadata keyed by relay wallet name
- changing a relay's current trusted mint policy can stop new advertisement/acceptance for that mint without invalidating previously stored channels; existing channels can still be re-linked and paid after restart

### Stress Harness Notes

- `monad-relay/tests/stress.rs` now supports transport-focused stress runs with:
  - huge per-hop prefunding to keep payment timing out of the critical path
  - `MONAD_STRESS_MAX_IN_FLIGHT_PER_CIRCUIT` to cap burst concurrency per circuit
  - `MONAD_STRESS_TARGETS` to shard final-hop exits across many loopback targets in `127.127.x.y`
- `make stress-transport-extreme` is the current high-end manual transport recipe and expects a high `ulimit -n`
- `make stress-payment-buffered` is the current stable payment-focused recipe:
  - one large-capacity channel per session
  - repeated `ChannelPayment` topups on that same channel
  - frequent `SessionStatus` polling to drive buffered refills
  - expected summary pattern:
    - `channel_relinks_total=0`
    - `max_links_on_one_session=1`
    - `topups_proactive` should dominate `topups_reactive`
    - `payment_no_new_funds=0` or near-zero
    - `pause_events` should stay rare
    - `failures=0` and `control_errors=0`
  - high `ulimit -n` expected
- `make stress-payment-relink` is the current stable relink-focused recipe:
  - one active channel per session at a time
  - fresh mocked channel provisioned and linked when the current channel lacks capacity for the next refill
  - repeated buffered `ChannelPayment` topups continue on the newly linked channel
  - expected summary pattern:
    - `channel_relinks_total` should be high
    - `channel_link_failures=0`
    - most or all sessions should relink at least once over a meaningful run
    - `topups_proactive` should dominate `topups_reactive`
    - `pause_events` should stay rare
    - `failures=0` and `control_errors=0`
  - high `ulimit -n` expected
- `make stress-chaos-rebuild` runs the configured-client chaos restart harness with the real YAML client runtime, persisted client wallet, real Spilman channels, and repeated relay restarts; `make stress-chaos-rebuild-intense` is the longer 5-hop variant.
  - knobs: `MONAD_CHAOS_HOPS`, `MONAD_CHAOS_DURATION_SECS`, `MONAD_CHAOS_RESTART_INTERVAL_MS`, `MONAD_CHAOS_CONCURRENT_PROBES`, `MONAD_CHAOS_RECOVERY_DEADLINE_MS`, `MONAD_CHAOS_SEED`, `MONAD_CHAOS_PROOF_BATCHES`
  - the chaos fixture deliberately uses a small `target_topup_buffer_msats` (100k) with a 1M msat channel budget: a re-linked session funds its buffer from the channel's remaining capacity, so channels pinned near capacity are effectively single-use and drain the purse. Keep chaos channels far from capacity.
  - the `chaos summary` line prints the initial `seed=` so a failing run can be reproduced with `MONAD_CHAOS_SEED=<seed>`
  - expected summary pattern:
    - `suffix_rebuild_failures_total=0`
    - `suffix_rebuild_fallbacks_total=0`
    - `channel_records` should stay at or below `channel_record_bound`
    - `probes_failed` can be non-zero because active SOCKS/TCP streams are allowed to fail during rebuilds

### Stress Result Reading

- `stress-transport-extreme` should usually show only large initial prefunding, little or no follow-up payment traffic, and `failures=0` / `control_errors=0`.
- `stress-payment-buffered` should usually keep one linked channel per session and produce many proactive topups with little or no relink activity.
- `stress-payment-relink` should usually produce many successful relinks with little or no link failures and only rare pauses.
- `stress-chaos-rebuild` should recover after each relay restart, report no suffix rebuild failures/fallbacks, and keep channel record growth bounded by the number of full reconnect generations.
- small amounts of pause/recovery activity can still be acceptable because chunk-boundary overshoot is allowed, but repeated control errors, repeated `payment_no_new_funds`, or non-zero `channel_link_failures` are warning signs worth investigating.

If you change routing, transport, or SOCKS behavior, extend tests rather than weakening them.

## Documentation Expectations

If you change externally visible behavior, update:
- `README.md` for usage
- `ARCHITECTURE.md` for protocol / layering details

Keep README practical and Architecture conceptual.
