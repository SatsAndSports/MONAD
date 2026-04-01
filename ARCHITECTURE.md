# MONAD Architecture

## Overview

MONAD is a multi-hop TCP tunneling system with three main layers:

```text
TCP -> Noise NK -> HTTP/2 -> control stream + CONNECT streams
```

The client exposes a local SOCKS5 proxy to applications. Internally, it converts SOCKS5 `CONNECT` requests into H2 `CONNECT` streams over one or more encrypted MONAD hops.

## Main Components

### `monad-common`

Shared transport, protocol, and session helpers.

Important types:
- `NoiseStream<T>` (`noise.rs`)
  - wraps an `AsyncRead + AsyncWrite` transport
  - performs encrypted Noise transport framing
  - tracks encrypted wire bytes
- `H2ConnectStream` (`h2stream.rs`)
  - wraps an H2 `SendStream + RecvStream` pair as a bidirectional async stream
  - allows another Noise+H2 session to run on top of an existing CONNECT tunnel
- `ClientMessage` / `ServerMessage` (`protocol.rs`)
  - wire protocol enums for the control stream (Hello, SessionParams, FakePayment, GetSessionStatus, SessionStatus, Error)
- `RelayConnection` (`session.rs`)
  - client-side handle to an established Noise+H2 session
  - manages H2 client, driver handles, task handles, session pricing
- `SessionPricing` (`session.rs`)
  - local billing metadata with precomputed LCM for integer-only arithmetic
- `proxy_bidirectional` (`proxy.rs`)
  - shared generic bidirectional proxy used by client tunnels
- `Ed25519Pubkey` / `ServerIdentity` (`identity.rs`)
  - unified server identity; derives X25519 (for Noise) and SPKI DER (for QUIC) from one Ed25519 key

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

Shared QUIC transport building blocks, fully integrated into the main MONAD system. Provides `QuicStream`, `build_server_config`, `build_client_config`, and keygen helpers used by both `monad-server` and `monad-client` for QUIC hop support.

Core functionality:
- Ed25519 self-signed certificate generation via `rcgen`
- pinned public key authentication (SPKI DER comparison, no CA trust chain)
- `QuicStream` type wrapping quinn bidirectional streams as `AsyncRead + AsyncWrite`
- ALPN protocol identifier: `monad-relay/0`
- 0-RTT disabled

Also includes standalone echo tooling for transport testing:
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

Used for session management: version negotiation (Hello/SessionParams), payments (FakePayment), and session status queries (GetSessionStatus/SessionStatus). See the "Control Protocol and Session Billing" section below for details.

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

## Control Protocol and Session Billing

### Wire Format

Control messages are JSON objects, newline-delimited, exchanged over the H2 control stream (`POST /control`). Each message is a single JSON line terminated by `\n`.

### Message Types

Client to server (`ClientMessage`):
- `Hello { version }` — first message; declares the highest protocol version the client supports
- `FakePayment { milli_sats }` — add fake credit to the session (placeholder for real payments)
- `GetSessionStatus` — request a fresh session status snapshot

Server to client (`ServerMessage`):
- `SessionParams { version, in_bytes_per_millisat, out_bytes_per_millisat }` — sent in response to Hello; contains the negotiated version and pricing rates
- `SessionStatus { session_total_in, session_total_out, total_paid_millisats, remaining_milli_sats, paused }` — current session accounting snapshot
- `Error { message }` — server-initiated error or rejection

### Version Negotiation

The client sends `Hello { version }` as the first control message. The server computes `negotiated = min(client_version, SERVER_MAX_VERSION)`. If `negotiated < SERVER_MIN_VERSION`, the server sends an `Error` and closes the control stream. Otherwise it responds with `SessionParams` containing the negotiated version and pricing rates.

### Paused-by-Default

Sessions start paused with zero balance. While paused:
- The control stream is always usable (free)
- `CONNECT` requests are rejected with HTTP 402
- The session unpauses only when the remaining balance becomes strictly positive

### Billing Formula

The amount due in millisats is computed as:

```text
amount_due = ceil(session_total_in / in_bytes_per_millisat + session_total_out / out_bytes_per_millisat)
```

The remaining balance is derived from totals:

```text
remaining = total_paid_millisats - amount_due
```

This is implemented with integer-only arithmetic via a precomputed `lcm(in_rate, out_rate)` and `u128` intermediate values to avoid overflow.

### Chunk-Boundary Overshoot

The balance can go negative between billing checks (a proxy chunk may push usage past the paid amount). When the server detects negative balance, it pauses the session and sends a `SessionStatus`. The client can then send another payment to resume.

### Two Pricing Structures

- **Wire**: `ServerMessage::SessionParams` carries the raw rates (no LCM). This is what crosses the network.
- **Local**: `SessionPricing` (in `monad-common/src/session.rs`) includes the precomputed LCM and negotiated version. Both client and server construct this from `SessionParams` for billing math.

### Client Auto-Funding

The client opens a control stream immediately after connecting and sends `Hello`. When it receives `SessionStatus { paused: true, remaining_milli_sats <= 0, .. }`, it automatically sends a `FakePayment`. The client waits for the session to become unpaused before accepting SOCKS traffic. Intermediate hops in multi-hop chains each get their own control task with automatic funding.

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

## QUIC Transport Between Hops

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
- C sends `CONNECT T_addr:port` with `quic-pin: <SPKI derived from T's Ed25519 key>` to S over H2
- S opens a QUIC stream to T (authenticating T with T's pinned QUIC key)
- S proxies bytes between the H2 CONNECT stream and the QUIC stream

The inner layer:
- C runs a nested Noise+H2 session through the tunnel to T (authenticating T with T's Noise key)
- S sees only opaque Noise-encrypted bytes flowing through — it cannot read the C-to-T traffic

T authenticates itself twice:
- to S via QUIC/TLS (pinned self-signed certificate derived from T's Ed25519 key)
- to C via Noise NK (X25519 key derived from T's Ed25519 key)

Both authentications derive from the same Ed25519 identity. The X25519 key for Noise is computed as `SHA-512(seed)[0..32]`, and the QUIC certificate is a self-signed Ed25519 cert. Clients and relays only need to know one public key per server.

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

A QUIC-capable server has one Ed25519 identity configured at startup. From it, two keys are derived internally:
- X25519 private key for Noise NK handshakes: `SHA-512(seed)[0..32]`
- self-signed Ed25519 certificate for QUIC/TLS

The `--quic` flag enables the QUIC listener; the QUIC certificate is generated from the same `--private-key` seed.

### CONNECT Syntax for QUIC Hops

The client signals to a relay that it should use QUIC to reach the next hop by including a `quic-pin` header in the H2 CONNECT request. The URI authority remains a standard `host:port`:

```text
CONNECT host:port HTTP/2
quic-pin: <quic_pin_hex>
```

For example:

```text
CONNECT 10.0.0.5:9050 HTTP/2
quic-pin: 302a300506032b6570032100abcd...
```

The relay checks for the `quic-pin` header:
- if present, connect to `host:port` via QUIC, verifying the server's certificate against the pinned key
- if absent, connect via TCP as before

The pinned key is carried as an H2 header because the CONNECT authority must be a valid HTTP authority (`host:port`). The `quic-pin` header is part of the H2 HEADERS frame that initiates the stream — it is sent once at stream creation and does not interfere with the DATA frames that carry tunneled bytes afterward.

This means the relay does not need pre-configured knowledge of other relays' QUIC identities — the client passes the pinned key in each CONNECT request, keeping the relay stateless with respect to the relay topology.

### QUIC Connection Pool

A relay that handles CONNECT requests with a `quic-pin` header maintains a connection pool keyed by `(host, port)`.

- The first CONNECT with a `quic-pin` to a given target establishes a new QUIC connection to T
- Subsequent requests to the same target reuse the existing QUIC connection and open new streams
- Each client session gets its own bidirectional QUIC stream inside the shared connection

This is the core scaling benefit: one QUIC handshake to T is amortized across all clients whose routes pass through S to T.

### Client `--hop` Syntax for QUIC Hops

The `--hop` syntax uses a single Ed25519 public key per hop:

```text
--hop addr:port,<pubkey>
--hop quic:addr:port,<pubkey>
```

The `quic:` prefix on any hop after the first tells the client to include a `quic-pin` header in the CONNECT request to the previous relay. On the first hop, `quic:` tells the client to connect directly via QUIC instead of TCP. In both cases, the client derives the X25519 public key (for Noise) and the SPKI DER (for QUIC pinning) from the same Ed25519 public key.

Example 2-hop route where the second hop uses QUIC:

```bash
monad-client \
  --hop 10.0.0.1:9050,<S_pubkey> \
  --hop quic:10.0.0.2:9050,<T_pubkey>
```

The client:
1. Connects to S at `10.0.0.1:9050` via TCP+Noise (authenticating S using X25519 derived from S's Ed25519 key)
2. Sends `CONNECT 10.0.0.2:9050` with header `quic-pin: <SPKI derived from T's Ed25519 key>` to S over H2
3. S connects to T via QUIC (authenticating T with the pinned key)
4. Client runs a nested Noise+H2 session to T through the tunnel (authenticating T using X25519 derived from T's Ed25519 key)

### Design Constraints

- disable QUIC 0-RTT at first to avoid replay complexity
- keep current direct and nested MONAD modes working unchanged over TCP
- the inner MONAD Noise+H2 session model is unchanged — QUIC is a transport optimization only
- a MONAD server's QUIC certificate and Noise key are both derived from a single Ed25519 identity

### QUIC Implementation Status

The QUIC transport is fully integrated into the main MONAD system. The `monad-quic` crate provides shared building blocks (`QuicStream`, `build_server_config`, `build_client_config`, keygen), and the server and client use them for QUIC hop support.

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

Initiator-side QUIC connections also enable periodic keep-alives so idle client-to-hop and relay-to-relay QUIC links stay up past the default Quinn idle timeout.

### What Has Been Integrated

The full QUIC transport chain is implemented and tested:

1. **`QuicStream` type in `monad-quic`** — wraps a quinn bidirectional stream as `AsyncRead + AsyncWrite`, used interchangeably with `TcpStream`
2. **QUIC listener in `monad-server`** — binds a UDP socket on the same port as the TCP listener, accepts QUIC connections, feeds incoming streams into the existing Noise+H2 session handler
3. **Unified identity in `monad-server`** — `monad-server keygen` generates a single Ed25519 identity; the X25519 key for Noise and the QUIC certificate are derived from it. The `--quic` flag enables the QUIC listener at startup.
4. **`quic-pin` header parsing in `monad-server`** — detects the `quic-pin` header on CONNECT requests, extracts the pinned key, connects via QUIC instead of TCP
5. **QUIC connection pool in `monad-server`** — maintains shared QUIC connections keyed by `(host, port)`, reuses across client sessions
6. **`--hop quic:` parsing in `monad-client`** — parses the `quic:` prefix from the hop spec, derives the SPKI from the Ed25519 public key, emits a CONNECT request with `quic-pin` header to the previous relay
7. **Integration tests** — cover QUIC single-hop, QUIC with control+data channels, nested QUIC tunnels (manual and via connector), alongside all existing TCP tests

## Current Limitations

- real payment integration (Lightning or similar) is not yet implemented — currently using `FakePayment`
- no persistent route configuration file yet
- QUIC connection pool does not yet handle connection eviction or stale entry cleanup
- asymmetric pricing (rates other than 1/1) is not yet tested
