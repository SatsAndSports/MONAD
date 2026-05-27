# AGENTS.md

This repository is the MONAD (Monetized Onion Network Access Daemon) Rust workspace for a multi-hop TCP tunneling system.

## Build and Test

Use:

```bash
cargo test
```

For binaries during development:

```bash
cargo run -p monad-server -- ...
cargo run -p monad-client -- ...
cargo run -p monad-quic -- ...
```

## Repo Shape

- `monad-common`
  - shared transport, protocol, and session code
  - `NoiseStream` (`noise.rs`) — legacy X25519 Noise transport, includes session ID (handshake hash)
  - `SecpNoiseStream` (`noise_secp256k1.rs`) — secp256k1 Noise transport with buffered writes and wire-byte logging
  - `H2ConnectStream` (`h2stream.rs`)
  - `ClientMessage` / `ServerMessage` wire protocol, `KeysetAdvertisement` type (`protocol.rs`)
  - `RelayConnection`, `SessionPricing`, `SessionSpilmanInfo`, billing math (`session.rs`)
  - `proxy_bidirectional` shared proxy (`proxy.rs`)
  - `Ed25519Pubkey`, `ServerIdentity`, key derivation (`identity.rs`)
  - `Secp256k1Pubkey`, `SecpTransportKeypair`, transport auth helpers (`secp_identity.rs`)
- `monad-client`
  - reusable library code plus binary entrypoint
  - SOCKS5 listener
  - multi-hop connector (`connector.rs`)
  - tunnel proxying (`tunnel.rs`)
  - client control task with auto-payment and Spilman channel management (`control.rs`)
- `monad-server`
  - reusable library code plus binary entrypoint
  - TCP+QUIC listener, `SpilmanMintCache`, `discover_spilman_mint_cache` (`listener.rs`)
  - `RelaySession<T>`, billing, control stream handler, version negotiation (`session.rs`)
  - `proxy_bidirectional_accounted` with pause/resume enforcement (`proxy.rs`)
  - QUIC connection pool (`quic_pool.rs`)
- `monad-quic`
  - shared QUIC transport code plus standalone echo tooling
  - reusable library code plus binary entrypoint
  - Ed25519 self-signed cert generation
  - QUIC echo server with pinned-key auth
  - QUIC echo client with custom `ServerCertVerifier`

## Current Protocol Model

- Outer transport: TCP or QUIC
- Encryption: secp256k1 Noise NK on TCP; legacy X25519 Noise NK or secp256k1 Noise NK on QUIC
- Multiplexing: HTTP/2
- Control stream: `POST /control`
- Data stream: `CONNECT host:port`
- Nesting: another full Noise+H2 session can run on top of an H2 CONNECT tunnel via `H2ConnectStream`

### Control Protocol

- Wire format: JSON newline-delimited messages on the H2 control stream (`POST /control`)
- Handshake: client sends `Hello { version }`, server responds with a unified `SessionStatus` containing advertisements and initial state
- Version negotiation: `min(client_version, SERVER_MAX_VERSION)`, reject if < `SERVER_MIN_VERSION`
- Sessions start paused-by-default with zero balance; control stream is always free while paused
- Billing formula: `ceil(in_bytes / in_rate + out_bytes / out_rate)` in millisats, integer-only via precomputed LCM
- `FakePayment` credits the session; server unpauses when balance > 0 and sends `SessionStatus`
- `CONNECT` rejected with 402 while paused
- Balance can go negative (chunk-boundary overshoot); session repauses
- `GetSessionStatus` requests a fresh `SessionStatus` snapshot
- `Error` for server-initiated rejections (e.g. version mismatch)
- `ChannelLink { payment_json }` links a Spilman channel to the session; server validates and responds with `ChannelLinkAccepted { channel_id, capacity }` or `Error`. Only one session can own a channel at a time.
- `ChannelPayment { payment_json }` increments the session balance based on the delta of the channel's max balance seen.
- Session ID is the Noise handshake hash (32 bytes, identical on both sides)

### QUIC Transport

- Relay-to-relay transport: QUIC (replaces TCP between hops, does not replace Noise)
- QUIC authentication: either pinned self-signed Ed25519 certificates (legacy) or secp256k1 attestation
- QUIC hop signaling: `CONNECT host:port` with `quic-pin: <hex>` or `quic-secp256k1-pubkey: <hex>` H2 header
- Client hop syntax: `--hop quic:addr:port,<ed25519_pubkey>` or `--hop quic:addr:port,secp256k1:<pubkey>`
- Client can also use QUIC directly to the first hop with the same `--hop quic:` syntax
- Noise nesting is preserved — the inner Noise+H2 session runs unchanged inside the QUIC stream
- Server listens on the same port for both TCP and UDP (QUIC)
- QUIC connection pool: shared connections reused across client sessions, keyed by `(host, port)` plus auth mode

## Important Invariants

### 1. Keep direct and nested modes working

Do not break:
- single-hop client → server usage
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

for per-hop encrypted byte counts from `NoiseStream` and `SecpNoiseStream`.

### CONNECT logs

Each server logs received CONNECT requests like:

```text
CONNECT example.com:22
```

Keep this simple and readable.

## Shutdown Behavior

The client and server both implement graceful shutdown.

If you change shutdown logic:
- keep task tracking explicit
- prefer `JoinSet` / awaited tasks over heuristic sleeps
- preserve reliable `NoiseStream` and `SecpNoiseStream` drop logging

## Test Expectations

The test suite currently covers:
- Noise transport correctness (both legacy X25519 and secp256k1)
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
- client connector with QUIC hop (`--hop quic:` end-to-end path)
- client QUIC first hop (direct QUIC connection from client)
- QUIC first hop then TCP second hop
- legacy Ed25519/plain-noise QUIC first hop still works
- non-QUIC Ed25519 hop rejected by client connector
- Noise session ID (handshake hash) matches on both sides
- Spilman channel implementation (delta-based) is currently being integrated and tested
- server advertises multiple mint/unit pricing options

If you change routing, transport, or SOCKS behavior, extend tests rather than weakening them.

## Documentation Expectations

If you change externally visible behavior, update:
- `README.md` for usage
- `ARCHITECTURE.md` for protocol / layering details

Keep README practical and Architecture conceptual.
