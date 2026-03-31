# MONAD Architecture

## Overview

MONAD is a multi-hop TCP tunneling system with three main layers:

```text
TCP -> Noise NK -> HTTP/2 -> control stream + CONNECT streams
```

The client exposes a local SOCKS5 proxy to applications. Internally, it converts SOCKS5 `CONNECT` requests into H2 `CONNECT` streams over one or more encrypted MONAD hops.

## Main Components

### `monad-common`

Shared transport and protocol helpers.

Important types:
- `NoiseStream<T>`
  - wraps an `AsyncRead + AsyncWrite` transport
  - performs encrypted Noise transport framing
  - tracks encrypted wire bytes
- `H2ConnectStream`
  - wraps an H2 `SendStream + RecvStream` pair as a bidirectional async stream
  - allows another Noise+H2 session to run on top of an existing CONNECT tunnel
- control message enums in `protocol.rs`

### `monad-client`

Responsibilities:
- parse local SOCKS5 requests
- build a single-hop or multi-hop MONAD chain
- expose a local SOCKS5 listener for normal tools (`curl`, `ssh`, `scp`, browsers)
- open H2 `CONNECT` streams to final targets

### `monad-server`

Responsibilities:
- accept TCP connections
- perform Noise handshake
- run an H2 server on top of the encrypted stream
- handle:
  - `POST /control`
  - `CONNECT host:port`
- proxy bytes between H2 streams and external TCP targets

### `monad-quic`

Standalone QUIC proof-of-concept for the future shared relay-to-relay transport.

This crate is not integrated into the main MONAD transport yet. It exists to validate QUIC fundamentals before integration:
- Ed25519 self-signed certificate generation via `rcgen`
- pinned public key authentication (SPKI DER comparison, no CA trust chain)
- QUIC echo server and client using `quinn`
- ALPN protocol identifier: `monad-relay/0`
- 0-RTT disabled

Subcommands:
- `keygen` — generate a self-signed certificate and print the pinned public key
- `server` — QUIC echo server that accepts connections and streams
- `client` — connect with a pinned key, open N bidirectional streams, send/verify echoed data

## Terminology

### Hop

A MONAD server in the route.

Example 3-hop route:

```text
Client -> Hop 1 -> Hop 2 -> Hop 3 -> Final target
```

### Control stream

An H2 stream using:

```text
POST /control
```

Currently used for Ping/Pong scaffolding. This is where payment and metadata messages are intended to live.

### Data stream

An H2 stream using:

```text
CONNECT host:port
```

After the `200 OK`, the stream becomes an arbitrary bidirectional byte pipe.

### Tunnel

One proxied TCP connection represented by one H2 `CONNECT` stream.

### Wire bytes

Encrypted bytes on the Noise transport, including Noise framing overhead.

### Plaintext tunnel bytes

Application bytes flowing through an individual CONNECT tunnel, excluding Noise wire overhead.

## Direct Single-Hop Flow

```text
Application
  -> SOCKS5 to monad-client
    -> Noise NK to monad-server
      -> H2 CONNECT example.com:443
        -> server opens TCP connection to example.com:443
          -> bytes flow both directions
```

## Multi-Hop / Nested Flow

For two hops:

```text
TCP -> Noise(H1) -> H2 -> CONNECT(H2)
                        \-> H2ConnectStream -> Noise(H2) -> H2 -> CONNECT(final)
```

For three hops:

```text
TCP
 -> Noise(H1)
  -> H2
   -> CONNECT(H2)
    -> H2ConnectStream
     -> Noise(H2)
      -> H2
       -> CONNECT(H3)
        -> H2ConnectStream
         -> Noise(H3)
          -> H2
           -> CONNECT(final target)
```

The key abstraction is that an H2 CONNECT stream is turned into an `AsyncRead + AsyncWrite` transport by `H2ConnectStream`, so another full MONAD session can run on top of it.

## Why Intermediate Hops Know So Little

Suppose the route is:

```text
Client -> T -> S -> C -> satsandsports.cash:22
```

Then:
- `T` only sees `CONNECT S`
- `S` only sees `CONNECT C`
- `C` sees `CONNECT satsandsports.cash:22`

The traffic inside each hop-to-hop tunnel is another Noise-encrypted MONAD session, so intermediate hops do not see the final destination or the application payload.

## SOCKS5 Boundary vs Internal Protocol Boundary

### External boundary

The client speaks real SOCKS5 to local applications.

Supported SOCKS5 address types:
- IPv4
- IPv6
- domain names

### Internal boundary

The client does not use SOCKS5 between MONAD hops.

Instead it uses:
- Noise NK for encrypted transport
- H2 `POST /control` for metadata/payment messages
- H2 `CONNECT` for arbitrary TCP tunnels

## DNS Behavior

### `socks5://`

The local application resolves DNS first and sends an IP to the client.

### `socks5h://`

The local application sends the hostname to the SOCKS5 proxy.

The client preserves that hostname and sends it through the hop chain unchanged. The final hop performs DNS resolution when it calls `TcpStream::connect(host:port)`.

This means:
- local machine DNS is avoided
- only the final hop sees the real hostname

## IPv6 Support

MONAD currently supports:
- IPv6 SOCKS5 destinations
- IPv6 final targets
- IPv6 relay listeners
- mixed IPv4 / IPv6 hop chains

This is covered by integration tests.

## H2 Multiplexing Model

One MONAD connection to one hop can carry multiple simultaneous streams:

```text
Noise+H2 connection to hop N
  - POST /control
  - CONNECT host1:port
  - CONNECT host2:port
  - CONNECT host3:port
```

This means:
- one control stream can fund many data streams in the future
- multiple SSH sessions, HTTP requests, and SCP transfers can coexist on the same hop connection

At intermediate hops in a nested route, the inner hop connection is itself just one long-lived CONNECT tunnel.

## Shutdown Model

Both client and server use graceful shutdown:
- stop accepting new work on `Ctrl+C`
- wait for active tunnels/sessions with a timeout
- close H2 connections cleanly
- allow `NoiseStream` drop hooks to emit wire-byte accounting logs

## Byte Accounting

### Per-tunnel plaintext accounting

Logged by:
- `monad-client::tunnel`
- `monad-server::proxy`

Fields:
- `outbound`
- `inbound`
- `total`

These are the actual application bytes proxied by one CONNECT tunnel.

### Per-hop encrypted accounting

Logged by `NoiseStream` on drop.

Fields:
- `wire_read`
- `wire_written`
- `wire_total`

These include encrypted framing overhead and therefore grow with each nested hop.

## Privacy Properties

MONAD currently provides:
- hop-by-hop encryption
- destination hiding from intermediate hops
- multi-hop nesting

MONAD does not currently provide Tor-style shared relay-to-relay traffic mixing. Each client maintains its own hop chain, so this is closer to a layered multi-hop paid proxy than a full anonymity network.

## Future: QUIC Transport Between Hops

### Motivation

The current nesting model creates a dedicated TCP connection between relays for each client chain.

For example, if many clients route through the same pair of relays:

```text
Client A -> Relay S -> Relay T -> ...
Client B -> Relay S -> Relay T -> ...
Client C -> Relay S -> Relay T -> ...
```

then today, S opens a separate TCP connection to T for each client.

QUIC solves this by letting S maintain one long-lived QUIC connection to T and multiplex many client sessions as separate QUIC streams inside it:

```text
many client sessions
        |
        v
Relay S == one shared QUIC connection == Relay T
                 with many streams
```

One QUIC handshake is amortized across many clients. Stream creation is lightweight (no new network round-trips), and QUIC's native multiplexing avoids head-of-line blocking between streams.

Why this is interesting:
- fewer per-client relay-to-relay connections
- lower handshake and connection setup overhead between relays
- better traffic mixing between relays
- small writes from multiple streams can be coalesced into encrypted QUIC packets
- closer to the anonymity properties of a shared relay fabric

### Layering: QUIC Replaces TCP, Not Noise

QUIC provides the encrypted transport between relays. It does **not** replace the Noise nesting that protects client-to-hop sessions.

Consider a 2-hop route where client C connects through relay S to relay T:

```text
C ---- TCP + Noise(S) + H2 ----> S ---- QUIC stream ----> T
                                              |
                               C ---- Noise(T) + H2 ----> T
                               (nested inside the QUIC stream)
```

The outer layers:
- C connects to S via TCP, establishes a Noise session (authenticating S), runs H2
- C sends `CONNECT quic:T_addr:port,<T_quic_pin>` to S over H2
- S opens a QUIC stream to T (authenticating T with T's pinned QUIC key)
- S proxies bytes between the H2 CONNECT stream and the QUIC stream

The inner layer:
- C runs a nested Noise+H2 session through the tunnel to T (authenticating T with T's Noise key)
- S sees only opaque Noise-encrypted bytes flowing through — it cannot read the C-to-T traffic

T authenticates itself twice:
- to S via QUIC/TLS (pinned self-signed certificate)
- to C via Noise NK (Noise static key)

These are separate keys serving separate purposes. The QUIC key authenticates T to its transport peer (S). The Noise key authenticates T to the client (C) with end-to-hop encryption. Both are required.

### QUIC Authentication Model

Authentication for the QUIC layer uses pinned self-signed certificates, not external certificate authorities. The initiator (S) verifies that the target (T) presented a certificate matching the expected pinned public key before sending any data.

This authentication is intentionally one-way: the target authenticates itself to the initiator, but the initiator does not authenticate itself at the QUIC layer. This aligns with MONAD's current Noise NK approach, where the initiator knows the server identity in advance and the server proves possession of the corresponding private key.

The same QUIC system can be used by an ordinary client or by another relay acting as the initiator. In both cases, the initiator only needs to know the pinned QUIC identity of the MONAD server it is contacting. The server does not need to distinguish whether the initiator is a client or a relay in order to complete the QUIC handshake.

If the opposite traffic direction ever needs its own initiator-driven link, that should be modeled as a separate independent QUIC connection in the reverse direction rather than by introducing mutual authentication. This keeps connection ownership, authentication rules, and future state machines simpler.

### Server Dual Listener

A MONAD server that supports QUIC listens on the same port number for both TCP and UDP:

- **TCP** (existing): accepts connections, performs Noise handshake, runs H2
- **UDP** (new): accepts QUIC connections, accepts bidirectional streams

TCP and UDP can share a port because they are different IP protocols at the kernel level.

On the receiving side, both transports feed into the same session handler. A QUIC bidirectional stream is wrapped as `AsyncRead + AsyncWrite` (a `QuicStream` type), and the server runs the same Noise handshake and H2 session on top of it as it does for TCP:

```text
TCP listener ──> accept() ──> TcpStream ──────────┐
                                                   ├──> Noise handshake ──> H2 session
QUIC listener ──> accept_bi() ──> QuicStream ──────┘
```

The session handler does not know or care which transport delivered the bytes. This means the entire existing Noise+H2 protocol works unchanged over QUIC streams.

A QUIC-capable server has two separate keys configured at startup:
- its Noise static key (for Noise NK handshakes, same as today)
- its QUIC pinned key (a self-signed Ed25519 certificate for QUIC/TLS)

### CONNECT Syntax for QUIC Hops

The client signals to a relay that it should use QUIC to reach the next hop by using the `quic:` prefix in the CONNECT target:

```text
CONNECT quic:host:port,<quic_pin_hex>
```

For example:

```text
CONNECT quic:10.0.0.5:9050,302a300506032b6570032100abcd...
```

The relay parses this as:
- strip the `quic:` prefix
- split on the last `,` to separate the address from the pinned key
- connect to `host:port` via QUIC, verifying the server's certificate against the pinned key
- proxy bytes between the H2 CONNECT stream (from the client) and the QUIC stream (to the target)

Without the `quic:` prefix, the relay connects via TCP as it does today. The client decides which transport to use for each hop based on its knowledge of the route.

The pinned QUIC key is passed by the client in the CONNECT request itself. This means the relay does not need pre-configured knowledge of other relays' QUIC identities — it is stateless with respect to the relay topology.

### QUIC Connection Pool

A relay that handles `CONNECT quic:...` requests maintains a connection pool keyed by `(host, port)`.

- The first `CONNECT quic:T:9050,...` to a given target establishes a new QUIC connection to T
- Subsequent requests to the same target reuse the existing QUIC connection and open new streams
- Each client session gets its own bidirectional QUIC stream inside the shared connection

This is the core scaling benefit: one QUIC handshake to T is amortized across all clients whose routes pass through S to T.

### Client `--hop` Syntax for QUIC Hops

The current `--hop` syntax is:

```text
--hop addr:port,<noise_key>
```

For a QUIC-capable hop, the syntax will be:

```text
--hop quic:addr:port,<noise_key>,<quic_pin>
```

The `quic:` prefix tells the client to send `CONNECT quic:addr:port,<quic_pin>` to the previous relay. The Noise key is still required because the client runs its own nested Noise+H2 session to that hop.

Example 2-hop route where the second hop uses QUIC:

```bash
monad-client \
  --hop 10.0.0.1:9050,<S_noise_key> \
  --hop quic:10.0.0.2:9050,<T_noise_key>,<T_quic_pin>
```

The client:
1. Connects to S at `10.0.0.1:9050` via TCP+Noise (authenticating S)
2. Sends `CONNECT quic:10.0.0.2:9050,<T_quic_pin>` to S over H2
3. S connects to T via QUIC (authenticating T with the pinned key)
4. Client runs a nested Noise+H2 session to T through the tunnel (authenticating T with T's Noise key)

### Design Constraints

- disable QUIC 0-RTT at first to avoid replay complexity
- keep current direct and nested MONAD modes working unchanged over TCP
- the inner MONAD Noise+H2 session model is unchanged — QUIC is a transport optimization only
- a MONAD server's QUIC identity (self-signed Ed25519 certificate) is separate from its Noise static key

### QUIC Proof-of-Concept Status

The `monad-quic` crate implements a standalone QUIC echo server and client to validate the core building blocks described above. It is not integrated into the main MONAD transport yet.

What has been validated:

- **Pinned self-signed certificate authentication works.** The client implements a custom `rustls::ServerCertVerifier` that extracts the SubjectPublicKeyInfo (SPKI) from the server's certificate and compares it byte-for-byte against a hex-encoded pinned key. Connections with a mismatched key are rejected during the TLS handshake with a clear error. This confirms the one-way, CA-free authentication model described above.

- **1,000 concurrent bidirectional streams over one QUIC connection work.** Each stream sends 4KB of random data and verifies the echoed response. All 1,000 streams complete successfully. Stream creation is lightweight — the entire test runs in under a second.

- **Multiple independent QUIC connections work.** Three separate connections, each carrying 10 streams, run concurrently without interference.

- **Large single-stream payloads work (with tuning).** A 4MB payload on a single stream succeeds, but required increasing the QUIC flow-control windows beyond the defaults (see below).

### QUIC Flow Control

Quinn's default `stream_receive_window` is 1MB and the default connection-level `receive_window` is also limited. These defaults are fine for typical web traffic but can cause problems with large payloads in a write-then-read pattern.

The specific issue: if a client sends a large payload (exceeding the receive window) and the server echoes it back before the client has started reading, both sides can deadlock. The client blocks trying to send because the server's receive window is full, and the server blocks trying to echo because the client's receive window is full — neither side makes progress.

This is specific to the echo test pattern (sequential write-all then read-all on the same stream). In real MONAD relay usage, the two directions of a stream are handled by separate tasks reading and writing concurrently, so this deadlock does not apply. Nevertheless, the current `monad-quic` transport config sets:

- `stream_receive_window`: 8MB
- `receive_window` (connection-level): 16MB

These values are generous for testing. Production tuning will depend on expected relay traffic patterns.

### What Remains

The QUIC transport is validated as a standalone PoC (`monad-quic`) but is not integrated into the main MONAD system yet. The current system still uses per-client TCP connections between hops.

Integration steps:

1. **`QuicStream` type in `monad-common`** — wrap a quinn bidirectional stream as `AsyncRead + AsyncWrite` so it can be used interchangeably with `TcpStream`
2. **QUIC listener in `monad-server`** — bind a UDP socket on the same port as the TCP listener, accept QUIC connections, feed incoming streams into the existing Noise+H2 session handler
3. **QUIC keygen in `monad-server`** — generate and load a QUIC self-signed certificate alongside the existing Noise keypair
4. **`CONNECT quic:` parsing in `monad-server`** — detect the `quic:` prefix, extract the pinned key, connect via QUIC instead of TCP
5. **QUIC connection pool in `monad-server`** — maintain shared QUIC connections keyed by `(host, port)`, reuse across client sessions
6. **`--hop quic:` parsing in `monad-client`** — parse the `quic:` prefix and QUIC pinned key from the hop spec, emit `CONNECT quic:...` to the previous relay
7. **Integration tests** — extend the existing test suite to cover QUIC hops alongside TCP hops in nested routes

## Current Limitations

- payment protocol is not implemented beyond control-channel scaffolding
- relay-to-relay shared QUIC multiplexing exists as a standalone PoC (`monad-quic`) but is not integrated into the main transport
- no persistent route configuration file yet
- no per-user/session accounting on the control channel yet
