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
- `monad-server`: accepts client connections, performs Noise handshake, runs an H2 session, proxies `CONNECT` tunnels
- `monad-client`: exposes a local SOCKS5 proxy, connects through one or more MONAD hops, opens H2 `CONNECT` tunnels
- `monad-common`: shared Noise transport and H2 stream helpers
- `monad-quic`: standalone QUIC proof-of-concept for future shared relay-to-relay transport (pinned-key auth, echo server/client, tested with 1,000 concurrent streams)
- integration tests for direct, nested, IPv6, hostname-resolution, and QUIC scenarios

Not implemented yet:
- payments / accounting on the control channel beyond basic Ping/Pong scaffolding
- shared inter-relay QUIC multiplexing (standalone PoC exists in `monad-quic` but is not integrated into the main transport)

## Workspace

```text
monad-common/     Shared transport and protocol helpers
monad-client/     Local SOCKS5 proxy and multi-hop client
monad-server/     Tunnel server
monad-quic/       Standalone QUIC proof-of-concept (future relay-to-relay transport)
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

Current coverage includes:
- Noise handshake and large-payload transport tests
- direct single-hop tunneling
- concurrent H2 control + data channels
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

## Quick Start

### 1. Generate keys for each server

```bash
cargo run -p monad-server -- keygen
```

This prints:
- a private key for the server process
- a public key to give to clients

### 2. Start one or more servers

Single hop:

```bash
RUST_LOG=info cargo run -p monad-server -- run \
  --listen 127.0.0.1:9050 \
  --private-key <SERVER_PRIVATE_KEY>
```

Multi-hop example:

```bash
RUST_LOG=info cargo run -p monad-server -- run --listen 127.0.0.1:9051 --private-key <HOP1_PRIV>
RUST_LOG=info cargo run -p monad-server -- run --listen 127.0.0.1:9052 --private-key <HOP2_PRIV>
RUST_LOG=info cargo run -p monad-server -- run --listen 127.0.0.1:9053 --private-key <HOP3_PRIV>
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

## QUIC Proof-of-Concept

The `monad-quic` crate is a standalone PoC for the future shared relay-to-relay QUIC transport. It is not part of the main MONAD tunnel system yet.

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
