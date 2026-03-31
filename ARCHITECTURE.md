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

## Future: Shared Relay-to-Relay Links

The current nesting model creates a dedicated relay-to-relay tunnel for each client chain.

For example, if many clients route through the same pair of relays:

```text
Client A -> Relay 1 -> Relay 2 -> ...
Client B -> Relay 1 -> Relay 2 -> ...
Client C -> Relay 1 -> Relay 2 -> ...
```

then today, Relay 1 opens a separate nested tunnel to Relay 2 for each client.

A future design would allow Relay 1 and Relay 2 to maintain one long-lived shared QUIC connection between them and multiplex many client-carried nested sessions over QUIC streams.

Conceptually:

```text
many client sessions
        |
        v
Relay 1 == one shared QUIC connection == Relay 2
                 with many streams
```

In this model:

- one QUIC connection is kept open between a relay pair
- many bidirectional QUIC streams are opened inside that connection
- each stream carries one nested MONAD session or other relay-to-relay tunnel unit

The client-carried inner MONAD sessions would still remain encrypted between the relevant hops. The shared relay-to-relay QUIC link would provide outer transport multiplexing and batching, not visibility into the nested payloads.

Authentication and encryption for the shared inter-relay link would come from QUIC/TLS. Relays would use pinned self-signed certificates or pinned public keys rather than external certificate authorities. An initiator would verify that the relay presented the expected pinned identity before sending application data.

This authentication is intentionally one-way: the server authenticates itself to the initiator, but the initiator does not authenticate itself at the QUIC layer. That keeps the shared-link model aligned with MONAD's current Noise `NK` approach, where the initiator knows the server identity in advance and the server proves possession of the corresponding private key.

This means the same QUIC system can be used by an ordinary client or by another relay acting as the initiator. In both cases, the initiator only needs to know the true pinned identity of the MONAD server it is contacting. The server does not need to distinguish whether the initiator is a client or a relay in order to complete the QUIC handshake.

If the opposite traffic direction ever needs its own initiator-driven shared link, that should be modeled as a separate independent QUIC connection in the reverse direction rather than by introducing mutual QUIC authentication or trying to make one connection serve two initiator roles. This keeps connection ownership, authentication rules, and future implementation state machines simpler.

This QUIC identity is separate from the current MONAD Noise static key. The existing direct and nested MONAD transport can continue using `Noise_NK_25519_ChaChaPoly_BLAKE2s`, while the future shared relay link uses QUIC's native transport security.

Why this is interesting:
- fewer per-client relay-to-relay connections
- lower handshake and connection setup overhead between relays
- better traffic mixing between relays
- small writes from multiple streams can be coalesced into encrypted QUIC packets
- closer to the anonymity properties of a shared relay fabric

Initial constraints for such a design would likely include:
- disable QUIC 0-RTT at first to avoid replay complexity
- keep current direct and nested MONAD modes working unchanged
- treat this as a relay-to-relay transport optimization, not a change to the inner MONAD session model

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

The shared relay-to-relay QUIC transport is not integrated into the main MONAD system yet. The current system still uses per-client nested relay tunnels.

Next steps toward integration would include:
- a `QuicStream` type in `monad-common` wrapping a QUIC bidirectional stream as `AsyncRead + AsyncWrite`
- a connection pool in the relay that maintains shared QUIC connections to peer relays
- routing logic to multiplex client sessions onto shared QUIC streams instead of opening per-client nested tunnels

## Current Limitations

- payment protocol is not implemented beyond control-channel scaffolding
- relay-to-relay shared QUIC multiplexing exists as a standalone PoC (`monad-quic`) but is not integrated into the main transport
- no persistent route configuration file yet
- no per-user/session accounting on the control channel yet
