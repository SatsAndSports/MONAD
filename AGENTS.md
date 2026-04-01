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
  - shared transport and helper code
  - `NoiseStream`
  - `H2ConnectStream`
- `monad-client`
  - reusable library code plus binary entrypoint
  - SOCKS5 listener
  - multi-hop connector
  - tunnel proxying
- `monad-server`
  - reusable library code plus binary entrypoint
  - listener
  - H2 session handling
  - TCP proxying
- `monad-quic`
  - shared QUIC transport code plus standalone echo tooling
  - reusable library code plus binary entrypoint
  - Ed25519 self-signed cert generation
  - QUIC echo server with pinned-key auth
  - QUIC echo client with custom `ServerCertVerifier`

## Current Protocol Model

- Outer transport: TCP or QUIC
- Encryption: Noise NK
- Multiplexing: HTTP/2
- Control stream: `POST /control`
- Data stream: `CONNECT host:port`
- Nesting: another full Noise+H2 session can run on top of an H2 CONNECT tunnel via `H2ConnectStream`

### QUIC Transport

- Relay-to-relay transport: QUIC (replaces TCP between hops, does not replace Noise)
- QUIC authentication: pinned self-signed Ed25519 certificates (one-way, no CA)
- QUIC hop signaling: `CONNECT host:port` with `quic-pin: <hex>` H2 header
- Client hop syntax: `--hop quic:addr:port,<ed25519_pubkey>`
- Client can also use QUIC directly to the first hop with the same `--hop quic:` syntax
- Noise nesting is preserved — the inner Noise+H2 session runs unchanged inside the QUIC stream
- Server listens on the same port for both TCP and UDP (QUIC)
- QUIC connection pool: shared connections reused across client sessions, keyed by `(host, port)`

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

for per-hop encrypted byte counts from `NoiseStream`.

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
- preserve reliable `NoiseStream` drop logging

## Test Expectations

The test suite currently covers:
- Noise transport correctness
- large payload chunking
- control + data channel behavior
- concurrent tunnels
- nested 2-hop and 3-hop routes
- IPv6 targets and IPv6 listeners
- mixed-family hop chains
- hostname resolution at the final hop
- SOCKS5 IPv6 parsing
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

If you change routing, transport, or SOCKS behavior, extend tests rather than weakening them.

## Documentation Expectations

If you change externally visible behavior, update:
- `README.md` for usage
- `ARCHITECTURE.md` for protocol / layering details

Keep README practical and Architecture conceptual.
