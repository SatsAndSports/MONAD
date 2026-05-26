# MONAD

MONAD is a multi-hop, VPN-like TCP tunneling system built in Rust.

It provides:
- a local SOCKS5 proxy for normal applications
- hop-by-hop encrypted transport using Noise NK
- multiplexed control and data channels using HTTP/2
- arbitrary TCP tunneling via HTTP/2 `CONNECT`
- recursive multi-hop nesting for onion-style routing
- IPv4, IPv6, and hostname support

## Status

Implemented today:
- `monad-server`: accepts client connections, performs Noise handshake, runs an H2 session, proxies `CONNECT` tunnels, enforces per-session billing with pause/resume, discovers trusted mint keysets at startup
- `monad-client`: exposes a local SOCKS5 proxy, connects through one or more MONAD hops, opens H2 `CONNECT` tunnels, auto-funds sessions via the control stream
- `monad-common`: shared Noise transport (with session ID from handshake hash), H2 stream helpers, control protocol types (`ClientMessage`/`ServerMessage`), session and billing types (`RelayConnection`, `SessionPricing`, `SessionSpilmanInfo`), shared bidirectional proxy
- `monad-quic`: shared QUIC transport code plus standalone echo tooling — `QuicStream`, pinned-key auth, echo server/client, and shared config/keygen helpers used by server and client
- QUIC hop support: server dual TCP+UDP listener, QUIC connection pool, `--hop quic:` client syntax, `quic-pin` H2 header for CONNECT forwarding
- deterministic developer tooling: pinned Rust toolchain, repo-local rustfmt config, `Makefile`, and GitHub Actions checks for formatting and tests
- session payment system: paused-by-default sessions, Hello/SessionStatus handshake, fake payments, totals-based billing with directional pricing, pause/resume enforcement
- Spilman advertisement plumbing: server discovers trusted mints/keysets at startup and includes a `KeysetAdvertisement` list plus its receiver pubkey in `SessionStatus`. The `ChannelLink`/`ChannelPayment`/`ChannelEvicted` wire messages exist but are not yet handled — the server only credits sessions via `FakePayment` today.
- low-level blinded-hop building blocks: blinded blob encryption/decryption, tweak compatibility rejection sampling, reverse-tweak key recovery, and a mixed cleartext/blinded path data model in `monad-common`
- integration tests for direct, nested, IPv6, hostname-resolution, QUIC single-hop, QUIC nested tunnels, mixed TCP/QUIC hop chains, and the session payment / pause / resume lifecycle

Not implemented yet:
- real Spilman byte-level payments — implementation of the new delta-based model is in progress
- server-side Spilman channel state persistence across restarts
- persistent route configuration file
- blinded transport integration (`CONNECT /blinded_hop_v1`, tweak-prefixed QUIC forwarded sessions, and end-to-end client/server blinded routing)

## Workspace

```text
monad-common/     Shared transport and protocol helpers
monad-client/     Local SOCKS5 proxy and multi-hop client
monad-server/     Tunnel server
monad-quic/       Shared QUIC transport code plus standalone echo tooling
```

## Build

```bash
cargo build
```

You can also just use `cargo run`, which builds automatically if needed.

## Test

```bash
cargo test
```

## Developer Workflow

The repo pins its Rust toolchain and formatting config so local runs and CI stay
deterministic.

Useful commands:

```bash
make fmt
make fmt-check
make lint
make test
make check
```

Current coverage includes:
- Noise handshake and large-payload transport tests
- Noise session ID (handshake hash) matches on both sides
- session starts paused by default
- second control stream rejected
- CONNECT rejected while paused (402)
- funded data channel (payment unpauses, then data flows)
- session repauses and resumes after second payment
- session overshoot with negative balance and resume
- underpayment stays paused until balance is positive
- multiple simultaneous tunnels
- 2-hop and 3-hop nested routing
- IPv6 final targets
- IPv6 relay listeners
- mixed IPv4/IPv6 hop chains
- hostname resolution at the final hop
- SOCKS5 IPv6 parsing
- QUIC echo with pinned-key authentication
- QUIC pinned-key rejection (wrong key)
- 1,000 concurrent QUIC streams over one connection
- large (4MB) single QUIC stream payload
- multiple independent QUIC connections
- QUIC single-hop (Noise+H2 over QUIC stream)
- QUIC control + data channels
- nested QUIC tunnel (TCP relay forwarding to QUIC relay)
- client connector with QUIC hop (end-to-end `--hop quic:` path)
- concurrent QUIC pool access
- client QUIC first hop (direct QUIC connection from client)
- QUIC first hop then TCP second hop
- session funding and incremental payments via Spilman channels (in progress)
- server advertises multiple mint/unit pricing options

## Quick Start

### 1. Generate keys for each server

```bash
cargo run -p monad-server -- keygen
```

This prints:
- a private key (Ed25519 seed) for the server process
- a public key (Ed25519) to give to clients
- a QUIC certificate (derived from the same key)

One key is used for both Noise and QUIC authentication.

### 2. Start one or more servers

Single hop (TCP only):

```bash
RUST_LOG=info cargo run -p monad-server -- run \
  --listen 127.0.0.1:9050 \
  --private-key <SERVER_PRIVATE_KEY>
```

With QUIC enabled (add `--quic`):

```bash
RUST_LOG=info cargo run -p monad-server -- run \
  --listen 127.0.0.1:9050 \
  --private-key <SERVER_PRIVATE_KEY> --quic
```

Multi-hop example:

```bash
RUST_LOG=info cargo run -p monad-server -- run --listen 127.0.0.1:9051 --private-key <HOP1_PRIV>
RUST_LOG=info cargo run -p monad-server -- run --listen 127.0.0.1:9052 --private-key <HOP2_PRIV> --quic
RUST_LOG=info cargo run -p monad-server -- run --listen 127.0.0.1:9053 --private-key <HOP3_PRIV> --quic
```

### 3. Start the client

Direct connection:

```bash
RUST_LOG=info cargo run -p monad-client -- \
  --hop 127.0.0.1:9050,<SERVER_PUBLIC_KEY> \
  --socks 127.0.0.1:1080
```

Three-hop chain:

```bash
RUST_LOG=info cargo run -p monad-client -- \
  --hop 127.0.0.1:9051,<HOP1_PUB> \
  --hop 127.0.0.1:9052,<HOP2_PUB> \
  --hop 127.0.0.1:9053,<HOP3_PUB> \
  --socks 127.0.0.1:1080
```

The client listens locally as a SOCKS5 proxy on `127.0.0.1:1080` by default.

Sessions start paused with zero balance. The client automatically opens a control stream and sends a fake payment to fund the session before accepting SOCKS traffic. The default funding amount is 1024 millisats per payment; override with `--fake-payment-millisats`.

QUIC hops:

```bash
RUST_LOG=info cargo run -p monad-client -- \
  --hop 127.0.0.1:9051,<HOP1_PUB> \
  --hop quic:127.0.0.1:9052,<HOP2_PUB> \
  --socks 127.0.0.1:1080
```

The `quic:` prefix tells the client to instruct the previous hop to connect via QUIC instead of TCP. Each hop uses a single Ed25519 public key — the Noise X25519 key and QUIC pinned key are both derived from it. See `ARCHITECTURE.md` for the full layering model.

QUIC first hop:

```bash
RUST_LOG=info cargo run -p monad-client -- \
  --hop quic:127.0.0.1:9051,<HOP1_PUB> \
  --socks 127.0.0.1:1080
```

The client connects directly to the first hop via QUIC, then runs the same Noise+H2 session on top.

## Example Usage

### HTTP through the SOCKS proxy

```bash
curl -x socks5h://127.0.0.1:1080 http://example.com/
```

Use `socks5h://` if you want hostname resolution to happen at the final hop instead of locally.

### SSH through the SOCKS proxy

With `ncat`:

```bash
ssh -o ProxyCommand='ncat --proxy 127.0.0.1:1080 --proxy-type socks5 %h %p' user@example.com
```

### SCP through the SOCKS proxy

```bash
scp -o ProxyCommand='ncat --proxy 127.0.0.1:1080 --proxy-type socks5 %h %p' \
  user@example.com:/path/to/file ./local-copy
```

## Logging and Accounting

### Per-tunnel plaintext byte counts

When a tunnel closes, the client and final server log plaintext proxied bytes:

```text
tunnel closed: example.com:22 | outbound=63630 inbound=5200 total=68830
```

### Per-hop encrypted wire counts

Each `NoiseStream` logs encrypted wire usage when the hop connection shuts down:

```text
NoiseStream closed label=client hop 2/3 to 127.0.0.1:9052 wire_read=... wire_written=... wire_total=...
```

To see these, use debug logging for the Noise module:

```bash
RUST_LOG=monad_common::noise=debug,monad_client=info,monad_server=info
```

### CONNECT visibility

Each server logs every `CONNECT` request it receives:

```text
CONNECT 127.0.0.1:9052
CONNECT 127.0.0.1:9053
CONNECT satsandsports.cash:22
```

In a multi-hop chain, only the final hop sees the actual target. Intermediate hops only see the next hop.

## Graceful Shutdown

Both client and server handle `Ctrl+C` gracefully:
- stop accepting new work
- wait briefly for active tunnels/sessions to finish
- shut down H2 connections cleanly
- emit `NoiseStream` wire-byte totals

## QUIC Echo Tool

The `monad-quic` crate also includes a standalone QUIC echo server/client for transport testing and experimentation. The main MONAD client and server now use shared code from this crate for QUIC support.

### Generate a keypair

```bash
cargo run -p monad-quic -- keygen
```

Save the private key block to `server.key`, the certificate block to `server.crt`, and note the pinned public key hex.

### Start the echo server

```bash
RUST_LOG=info cargo run -p monad-quic -- server \
  --listen 127.0.0.1:4433 \
  --cert server.crt \
  --key server.key
```

### Run the echo client

```bash
RUST_LOG=info cargo run -p monad-quic -- client \
  --connect 127.0.0.1:4433 \
  --pin <PINNED_PUBLIC_KEY_HEX> \
  --streams 16 \
  --bytes 65536
```

This opens 16 bidirectional QUIC streams, sends 64KB of random data on each, reads the echo, and verifies correctness.

## Further Reading

- `ARCHITECTURE.md` for the protocol and layering model
- `AGENTS.md` for repo-specific development guidance
