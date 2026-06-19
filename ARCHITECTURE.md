# MONAD Architecture

## Overview

MONAD is a multi-hop TCP tunneling system with three main layers:

```text
TCP/QUIC -> secp Noise NK -> HTTP/2 -> control stream + CONNECT streams
```

The client exposes a local SOCKS5 proxy to applications. Internally, it converts SOCKS5 `CONNECT` requests into H2 `CONNECT` streams over one or more encrypted MONAD hops.

## Main Components

### `monad-common`

Shared transport, protocol, and session helpers.

Important types:
- `SecpNoiseStream<T>` (`noise_secp256k1.rs`)
  - wraps an `AsyncRead + AsyncWrite` transport
  - performs encrypted secp Noise transport framing
  - tracks encrypted wire bytes
  - carries a session ID (the Noise handshake hash) unique to each connection
- `H2ConnectStream` (`h2stream.rs`)
  - wraps an H2 `SendStream + RecvStream` pair as a bidirectional async stream
  - allows another Noise+H2 session to run on top of an existing CONNECT tunnel
- `ClientMessage` / `ServerMessage` (`protocol.rs`)
  - wire protocol enums for the control stream (ChannelLink, ChannelPayment, GetSessionStatus, ChannelEvicted, SessionStatus, Error)
  - `KeysetAdvertisement` plus `LinkedChannelStatus` for mint offers and relay-authoritative linked-channel sync
- `RelayConnection` (`session.rs`)
  - client-side handle to an established secp Noise+H2 session
  - manages H2 client, driver handles, task handles, session pricing, session ID
  - stores fetched `SessionSpilmanInfo` (mint, keyset, receiver pubkey, negotiated Cashu Spilman protocol version) for the active channel
- `SessionPricing` (`session.rs`)
  - local billing metadata with precomputed LCM for integer-only arithmetic
- `proxy_bidirectional` (`proxy.rs`)
  - shared generic bidirectional proxy used by client tunnels
- `Ed25519Pubkey` / `QuicCertIdentity` (`quic_cert_identity.rs`)
  - Ed25519 key material retained for QUIC certificate generation and SPKI helpers used by standalone QUIC tooling
- `Secp256k1Pubkey` / `SecpTransportKeypair` (`secp_identity.rs`)
  - secp256k1 transport identity used for TCP MONAD transport and secp-authenticated QUIC paths

### `monad-client`

Responsibilities:
- parse local SOCKS5 requests
- build a single-hop or multi-hop MONAD chain
- expose a local SOCKS5 listener for normal tools (`curl`, `ssh`, `scp`, browsers`) through the library; the binary entrypoint is gated on a real wallet backend
- open H2 `CONNECT` streams to final targets
- run one payment/session driver per relay session
- keep a shared wallet across relay sessions
- select or provision channels, send `ChannelLink`, and send incremental
  `ChannelPayment` messages using relay-authoritative linked-channel sync from
  `SessionStatus`

### `monad-relay`

Responsibilities:
- accept TCP connections
- perform secp Noise handshake
- run an H2 server on top of the encrypted stream
- handle:
  - `POST /control`
  - `CONNECT host:port`
- proxy bytes between H2 streams and external TCP targets
- populate a shared relay-wallet `SpilmanMintCache` from configured mint URLs, caching all keysets returned by those mints; trusted mint/unit policy comes from the relay's YAML config and is applied at advertisement/acceptance read sites
- advertise receiver pubkey and trusted mints/keysets in `SessionStatus`
  (per-(mint, unit) rate configuration is planned; today every advertisement
  carries the session's global default rates)
- load relay identity, wallet DB path, listen address, transport key, and mint policy from a per-relay entry in the shared YAML config file
- enforce per-session billing with pause/resume on the control stream
  using validated `ChannelLink` / `ChannelPayment` messages
- drive steady-state control/session transitions through an explicit relay-side
  session FSM after the initial bootstrap handshake
- fully tear down a session when the control stream detaches, releasing any
  linked channel and stopping active / future streams

### `monad-quic`

Shared QUIC transport building blocks, fully integrated into the main MONAD system. Provides `QuicStream`, QUIC client/server config helpers, attestation helpers, and keygen helpers used by both `monad-relay` and `monad-client` for QUIC hop support.

Core functionality:
- Ed25519 self-signed certificate generation via `rcgen`
- secp attestation bound to the QUIC exporter for MONAD transport authentication
- `QuicStream` type wrapping quinn bidirectional streams as `AsyncRead + AsyncWrite`
- ALPN protocol identifier: `monad-relay/0`
- 0-RTT disabled

Also includes standalone echo tooling for transport testing:
- `keygen` — generate a self-signed certificate and print the pinned public key
- `server` — QUIC echo server that accepts connections and streams
- `client` — connect with a pinned key, open N bidirectional streams, send/verify echoed data

### Why QUIC Still Uses Ed25519 Certificates

MONAD now uses secp256k1 x-only keys for user-visible relay transport
identity, plain MONAD transport authentication, and QUIC hop authentication.
The remaining non-secp piece is the QUIC/TLS certificate layer itself.

With the current `quinn` + `rustls` + `rcgen` stack, QUIC still needs a
standard TLS certificate path. In practice that means MONAD keeps an Ed25519
seed only for QUIC certificate generation and then binds the live QUIC channel
to the configured secp256k1 relay identity using post-TLS secp attestation.

So the current split is:
- secp256k1 for MONAD transport identity and QUIC attestation
- Ed25519 only for standards-compliant QUIC certificate plumbing

The remaining blocker to a fully secp-only QUIC transport story is therefore in
TLS/QUIC ecosystem support, not in MONAD's own transport identity model.

### `monad-test-client`

Developer-focused localhost test harness.

Responsibilities:
- spin up local relays in-process with mocked payment backends
- build a persistent TCP or QUIC circuit for manual browser/SSH testing
- monitor per-hop control state and process FD counts
- exercise reusable per-hop circuit rebuild primitives and targeted session failure handling

## Terminology

### Hop

A MONAD relay in the route.

Example 3-hop route:

```text
Client -> Hop 1 -> Hop 2 -> Hop 3 -> Final target
```

### Control stream

An H2 stream using:

```text
POST /control
```

Used for session management after the Noise-payload bootstrap has already negotiated the session version/capabilities and selected the `h2` session protocol. In this first version, HTTP/2 is the session protocol running inside the Noise transport, and the control stream then carries Spilman channel linking (`ChannelLink`) and unified session status synchronization (`SessionStatus`). See the "Control Protocol and Session Billing" section below for details.

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
    -> Noise NK to monad-relay
      -> H2 CONNECT example.com:443
        -> relay opens TCP connection to example.com:443
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

Control messages are JSON objects, newline-delimited, exchanged over the H2 control stream (`POST /control`). Each message is a single compact JSON line terminated by `\n`. Blank lines are not protocol-significant and are ignored defensively by both sides' parsers.

### Message Types

Client to server (`ClientMessage`):
- `ChannelLink { payment_json }` — link a Spilman channel to this session; requires a valid Spilman `Payment` with balance=0 and funding proofs
- `ChannelPayment { payment_json }` — increment session balance; requires a Spilman `Payment` signature for a higher balance than previously seen for this channel
- `GetSessionStatus` — request a fresh session status snapshot

Server to client (`ServerMessage`):
- `SessionStatus { ... }` — primary state synchronization message; sent immediately after control stream establishment and proactively whenever session state (balance, link, pricing) changes. Contains:
  - `version`: Negotiated protocol version
  - `receiver_pubkey`: Server's secp256k1 key for Spilman
  - `advertisements`: List of supported `(Mint, Unit, Rates)` options
  - `linked_channel`: Relay-authoritative linked channel status (if any), including channel id, latest accepted raw balance, raw capacity, and unit
  - `active_in_rate`: Rate currently being applied to inbound traffic
  - `active_out_rate`: Rate currently being applied to outbound traffic
  - `session_total_in`: Total inbound bytes processed
  - `session_total_out`: Total outbound bytes processed
  - `total_paid_millisats`: Total payments received
  - `remaining_milli_sats`: Current session balance
  - `paused`: Boolean indicating if traffic is currently blocked
- `SessionStatus { ... linked_channel: Some(...) ... }` — authoritative relay state after a successful link or payment
- `ChannelEvicted { channel_id }` — notification that another session has claimed this channel; the current session is now `Unlinked` but preserves its current balance
- `Error { code, message }` — relay-initiated error or rejection

### Version Negotiation

Here, "bootstrap" means the MONAD-specific negotiation carried inside the two Noise handshake payloads before the post-handshake session begins.

MONAD currently uses the Noise `NK` pattern instantiated with secp256k1 DH, ChaCha20-Poly1305 for transport encryption, BLAKE2s for hashing, and the fixed prologue `monad-noise-secp256k1-v1`. The client sends a bootstrap request in the first handshake payload, the relay replies with an accept-or-reject payload in the second, and this bootstrap is intentionally strict rather than open-ended negotiation: the client must offer `h2`, at least one mutually supported Cashu Spilman channel protocol version, and at least one mutually supported pricing policy, and the relay selects exactly one of each or rejects the session before H2 starts. Today the only accepted post-handshake session protocol is `h2` (HTTP/2), the only supported Cashu Spilman channel protocol version is `2026-03-20`, and the only supported pricing policy is `session_constant`.

This bootstrap sequence stays outside the explicit session FSM. The reducer-style
state machine begins only after the initial `SessionStatus` has been sent.

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

The balance can go negative between billing checks (a proxy chunk may push usage past the paid amount). When the relay detects negative balance, it pauses the session and sends a `SessionStatus`. The client can then send another payment to resume.

### Two Pricing Structures

- **Wire**: `ServerMessage::SessionStatus` carries the active rates and the list of alternatives. This is what crosses the network.
- **Local**: `SessionPricing` (in `monad-common/src/session.rs`) includes the precomputed LCM of the active rates. Both client and relay construct this from the active rates in `SessionStatus` for billing math.

### Client Auto-Funding

The client opens a control stream immediately after connecting. Once it receives the initial `SessionStatus`, the per-session payment driver runs one serialized direct control loop. That loop chooses or provisions a local channel, sends `ChannelLink`, and later sends `ChannelPayment` updates. Intermediate hops in multi-hop chains use the same session-driver model.

The relay remains authoritative for:

- which channel is currently linked
- the latest accepted linked-channel balance
- the accepted session-total baseline (`session_total_in`, `session_total_out`, `total_paid_millisats`)
- whether the session is currently paused

The client combines that authoritative baseline with its own local cleartext byte counters to estimate current spend between relay status updates. A small periodic timer in the control loop checks those counters and can trigger proactive `ChannelPayment` updates before the relay sends another `SessionStatus`.

The client still only treats the relay as authoritative for accepted state. The
local estimate is used to decide how much to pay, not whether a link or payment
has already been accepted.

The developer stress harness in `monad-relay/tests/stress.rs` can also run alternate payment policies on top of the same wire protocol. Unlike the main client, those stress modes still use frequent `GetSessionStatus` polling intentionally to exercise relay control-plane behavior under load:
- transport-focused mode with one huge prefunding payment per hop session
- buffered payment mode with frequent `SessionStatus` polling and repeated `ChannelPayment` topups on one linked channel
- relink-buffered mode that provisions and links a fresh mocked channel when the current one lacks capacity for the next refill

### Client Control Loop

After the control stream is established and the initial `SessionStatus` arrives, steady-state client behavior is handled by one serialized direct control loop in `monad-client/src/session_driver.rs`.

The current code is organized as:

- `monad-client/src/session_driver.rs` - public entrypoints only
- `monad-client/src/session_driver/runtime.rs` - executor loop and input ordering
- `monad-client/src/session_driver/state.rs` - local driver state and publishing helpers
- `monad-client/src/session_driver/funding.rs` - channel acquisition / link / payment progression
- `monad-client/src/session_driver/payment.rs` - payment math and protocol-safety checks

Shared control-stream framing and raw-unit conversion helpers are intentionally
kept out of the client driver and live in `monad-common/src/control_codec.rs`
and `monad-common/src/payment_units.rs` so relay and harness code use the same
wire framing and `msat` / `sat` conversions.

That loop keeps small local state for:

- the latest relay-authoritative session snapshot
- immutable session pricing
- the client's intended active channel / offer
- session-local excluded channels
- link/payment operations currently in flight
- blocked funding reason and readiness state

On each relay control message, and on a small periodic timer tick, the loop can:

- reconcile the relay-linked channel against the client's intended channel
- ensure a channel is selected/provisioned and linked when funding needs it
- size payments from the client's own cleartext byte counters using the latest authoritative relay baseline
- react to `ChannelEvicted`
- classify relay `Error` messages into channel-invalidating vs non-rejecting outcomes
- end the local session on control detach

When payment is needed, the client currently plans the topup by taking the gap
between a configured target remaining balance and the locally estimated
remaining balance, clamping that delta to at least the configured minimum
topup, converting into channel raw units, and then capping at the linked
channel's remaining raw capacity. A capped non-zero payment smaller than the
minimum is still allowed when it exactly fills the channel to capacity.

Important design points:

- one client relay session is handled by one serialized executor loop
- the per-session client state does not need a mutex
- `paused` is the real operational state; there is no separate long-lived `ready`
  state inside the funding logic
- the startup oneshot waiter is executor-only coordination, not session state
- a parent session collapse still indirectly ends deeper nested client sessions via
  transport teardown rather than explicit tree-walking

The canonical maintainer reference for this code path is `docs/payments.md`.
The stress harness and localhost test client intentionally keep separate control
orchestration for observability and alternate payment modes, but they are not the
source of truth for main client funding behavior.

### Server Session FSM

After bootstrap, the relay handles steady-state control/session logic as an
explicit event/effect reducer.

Conceptually:

- incoming control messages and internal notifications become session events
- the reducer updates session state and emits effects
- the executor performs those effects (send control messages, validate
  link/payment requests, notify evicted sessions, release ownership, terminate
  the session)

Important steady-state events include:

- client `GetSessionStatus`
- client `ChannelLink`
- client `ChannelPayment`
- internal `ChannelEvicted`
- control-stream detach / teardown

Important effects include:

- send `SessionStatus`
- send `SessionStatus`, `ChannelEvicted`, or `Error`
- run link/payment validation outside the session mutex
- notify another session that it has been evicted
- release linked-channel ownership
- terminate the session

### Fast-Path Byte Accounting

Per-byte accounting is intentionally not routed through the main control/session
reducer.

Instead, active proxy tasks update the session byte counters directly under the
per-session mutex as soon as possible:

- increment `session_total_in` / `session_total_out`
- recompute paused state
- notify the pause watcher if the pause state changed

This keeps the hot data path low-latency while still allowing the control FSM to
handle the more complex protocol transitions.

### Session ID

Each Noise NK handshake produces a 32-byte **handshake hash** that is identical on both sides and unique per session. This is used as a session identifier:

- Computed during the handshake, before `into_transport_mode()` consumes the handshake state
- Stored on `SecpNoiseStream`, `RelayConnection` (client), and `RelaySession` (relay)
- Deterministic: both initiator and responder derive the same value from the DH transcript
- Unique: the client generates a fresh ephemeral key per connection
- Not transmitted over the wire — derived locally from the shared transcript
- Will be used for channel_id → session_id binding (enforcing one channel per session)

MONAD integrates Cashu Spilman payment channels for per-session prepaid relay access. The design enforces channel exclusivity and uses delta-based accounting. Before any `ChannelLink` or `ChannelPayment` traffic can happen, the client and relay must already have negotiated a mutually supported Cashu Spilman channel protocol version during the Noise bootstrap.

#### 1. Server Advertisement
The relay is configured with a map of `Mint -> Unit -> Rates`. In the `SessionStatus` message, it advertises these options to the client as a list of `KeysetAdvertisement` objects. Each option includes the `in_bytes_per_millisat` and `out_bytes_per_millisat` specific to that mint/unit choice.

The relay wallet manager owns a shared in-memory `SpilmanMintCache`. The cache stores all keysets returned by configured mints, active and inactive, for all units the mint reports. Trusted mint/unit policy filters what is advertised and what incoming channel funding/payment keysets are accepted; it does not mean the cache only stores trusted units. Channel close uses the same shared cache and relies on the Spilman close retry path to refresh that mint into SQLite and memory if the mint rejects the first close swap because of stale keyset state.

#### 2. Channel Linking
The client selects a mint/unit and sends a `ChannelLink` message containing a Spilman `Payment` with `balance: 0` and the required multisig funding proofs. If the bootstrap did not negotiate a supported Cashu Spilman channel protocol version, the relay rejects linking immediately.
- **One Session Per Channel**: The relay maintains a global registry of `ChannelId -> SessionId`.
- **Exclusivity**: If a channel is already linked to another session, the relay sends `ChannelEvicted` to the old session and links the channel to the new one.
- **Stateless Session Start**: Every new Noise session starts with a `total_paid_millisats` of 0. Only *new* payments made within the current session count as credit.

#### 3. Orthogonal State Model
A session's ability to proxy data is determined by two orthogonal variables:
- **Flow State**: Is the session balance strictly positive? (`Active` if balance > 0, else `Paused`)
- **Linked State**: Is there a Spilman channel currently associated with this session? (`Linked` vs `Unlinked`)

#### 4. Incremental Payments (Delta Model)
When the session balance runs low, the client sends a `ChannelPayment` with a signed balance update.
- **Credit Calculation**: The relay tracks the `max_balance_seen` for every channel ID.
- **Delta**: `credit_millisats = (new_balance - max_balance_seen) * unit_multiplier`.

#### 5. Relay-Authoritative Linked-Channel Sync
Every `SessionStatus` carries the relay's authoritative view of the currently linked channel.

The client uses that to learn:

- which channel is linked
- the latest accepted cumulative raw balance
- the raw capacity of that channel
- the unit (`sat` or `msat`)

The client driver then computes the next requested cumulative balance from:

- current `remaining_milli_sats`
- target positive remaining balance
- relay-reported `linked_channel.balance_raw`

and asks the wallet backend to build a payment for that exact next balance.
- **Eviction Fairness**: If a session is evicted, it **remains Active** as long as it has a positive balance. The user can spend their existing credit, but cannot send further `ChannelPayment` updates until they link a new channel.

### Relay Wallet Layer

Relay-side Spilman validation and durable channel state are now mediated by an
in-process relay wallet manager.

That manager owns:

- the shared SQLite relay-wallet database
- the registry of `relay_wallet_name -> Cashu receiver key`
- the shared in-memory mint keyset cache used by sessions and wallet close paths

This lets one MONAD process host multiple relays with different receiver keys
while still sharing one persistent relay-wallet DB. Transport identity remains a
separate concern from the Cashu receiver identity used for Spilman channels.

The relay binary now also exposes wallet-admin commands over that same durable
state (`monad-relay wallet ...`) so operators can list identities, inspect
stored channels, and close a channel by `channel_id` using metadata stored in
SQLite.

#### 6. Session Teardown on Control Detach

If the control stream detaches, the relay treats the session as fully ended.

That means:

- release any linked-channel ownership immediately
- stop accepting new H2 requests for that session
- terminate active proxy streams relatively soon
- end the underlying H2 / Noise session gracefully where easy, but fully

If the relay itself decides to terminate the session while the control stream
still exists, it can send `Error { code, message }` first. If the control stream is
already gone, no final control error message is possible.

#### 5. Session State Matrix

```text
    +-----------+
    |  Connect  |
    +-----+-----+
          |
          v
    +-----------------+
    |   Noise + H2    |
    |   Handshake     |
    +--------+--------+
             |
             v
    +--------+--------+
    |   Send Hello    |
    +--------+--------+
             |
             v
    +-----------------+
    | Receive         |
    | SessionStatus   |
    | (Pricing&Mints) |
    +--------+--------+
             |
             v
    +-----------------------------------------------------------------------+
    |                         SESSION STATE MATRIX                          |
    |                         ====================                          |
    |                                                                       |
    |                       UNLINKED                         LINKED         |
    |               (No associated channel)          (Channel associated)   |
    |               +-------------------------+  Link  +--------------------+|
    |               |                         |------->|                    ||
    |     PAUSED    |     Unlinked / Paused   |        |   Linked / Paused  ||
    |   (Bal <= 0)  |  (Initial / Exhausted)  |<-------|   (Awaiting Pay)   ||
    |               |                         | Evict  |                    ||
    |               +------------+------------+        +----------+---------+|
    |                  |         ^                        ^       |         |
    |          FakePay |         | Drain            Drain |       | Payment |
    |                  v         |                        |       v         |
    |               +------------+------------+  Link  +----------+---------+|
    |               |                         |------->|                    ||
    |     ACTIVE    |     Unlinked / Active   |        |   Linked / Active  ||
    |   (Bal > 0)   |     (The Evicted state) |<-------|   (Normal Flow)    ||
    |               |                         | Evict  |                    ||
    |               +-------------------------+        +--------------------+|
    +-----------------------------------------------------------------------+
             |
             v
       +-----------+
       | Disconnect|
       +-----------+
```


## Blinded Routing

MONAD's normal routing model assumes the client knows every hop's real
`addr:port` and published secp256k1 x-only public key up front. A blinded route changes
 that model: the client only knows the public **introduction hop**, then learns
 each subsequent hop one layer at a time by establishing nested sessions through
 the existing MONAD tunneling machinery.

This is conceptually similar to BOLT 12 blinded paths in Lightning: a service
publishes an introduction hop plus opaque hop data for the remainder of the
route.

### Why This Fits MONAD Well

MONAD already does recursive nesting:

- connect to a hop
- open a `CONNECT` tunnel through it
- run another full Noise+H2 MONAD session inside that tunnel

Blinded routing therefore does **not** require a new general routing fabric. It
only needs one new kind of hop-to-hop setup: a **blinded QUIC connect** that
lets one relay open the next relay connection without the client knowing the
next relay's real identity or real address. Once that blinded hop is
established, the existing nested Noise+H2 model takes over unchanged.

### Current State

Implemented today:

- blinded-hop blob encryption/decryption `(E, ciphertext)`
- deterministic adjusted-tweak derivation for MONAD's secp256k1 x-only identity model
- reverse-tweak recovery of the original secp256k1 x-only public key from
  `(tweaked_pubkey, tweak)`
- a mixed client-facing `Path` model with:
  - a required cleartext first hop
  - later hops that may be cleartext or blinded
- `CONNECT blinded.monad.invalid:443` transport integration using blinded hop headers
- QUIC `STREAM_KIND_TWEAKED_NOISE` carrying a 32-byte tweak preamble before the nested Noise handshake
- end-to-end client/relay blinded-hop routing on top of the existing nesting machinery
- `RouteHop::Blinded` / `Route` connector integration with bootstrap capability enforcement

### Published Path Shape

A service publishes a mixed path:

- one public **cleartext first hop** `(addr:port, secp256k1_xonly_pubkey)`
- then a sequence of later hops, each of which may be cleartext or blinded

Each blinded hop is a tuple visible to the client:

```text
(tweaked_pubkey, E, ciphertext)
```

where:

- `tweaked_pubkey` is the public key the client will use to authenticate the
  next nested Noise session
- `E = e * G` is an ephemeral public key generated by the service for that hop
- `ciphertext` is an opaque encrypted blob that the current relay can decrypt

In the current implementation:

- `tweaked_pubkey` is a 32-byte x-only secp256k1 pubkey with implied even Y
- `E` is a 33-byte compressed secp256k1 point
- the decrypted plaintext inside `ciphertext` is the compact binary payload
  `[next_hop_tweak:32][next_hop_addr:utf8...]`

The client cannot decrypt `ciphertext`, and it does not know the real long-term
identity behind `tweaked_pubkey`.

In the current low-level `Path` model, the introduction relay for a blinded hop
is implicit from position: the immediately preceding real hop decrypts the blob
for the next blinded hop.

### What The Encrypted Blob Contains

For a hop `R1 -> R2`, the blob decrypted by `R1` contains exactly the
information needed to establish the next relay-to-relay connection:

- the real network address of `R2`
- the tweak scalar that `R2` must apply when serving the next nested Noise
  session

The client does **not** need to know `R2`'s real address or real public key.

### Blob Encryption

Suppose the service wants the introduction relay Bob to be able to decrypt the
first blinded blob. The service generates a fresh scalar `e` and corresponding
ephemeral public key:

```text
E = e * G
```

It then derives an ECDH shared secret with Bob's **real** long-term public key:

```text
shared_secret = e * Bob_pubkey
key = HKDF(shared_secret)
```

and encrypts the plaintext payload with that symmetric key:

```text
plaintext = (next_hop_address, next_hop_tweak)
ciphertext = Encrypt(key, plaintext)
```

The current binary payload layout is:

```text
[next_hop_tweak:32][next_hop_addr:utf8...]
```

The address bytes must be non-empty valid UTF-8 and may not contain NUL bytes.
The ciphertext includes a standard 16-byte ChaCha20-Poly1305 authentication tag.

Bob later performs the matching ECDH with his real private key and `E`:

```text
shared_secret = Bob_private * E
key = HKDF(shared_secret)
plaintext = Decrypt(key, ciphertext)
```

### Which Key Is Tweaked?

Blinding is applied to the MONAD secp256k1 transport identity itself.

That means:

- relay-to-relay QUIC still authenticates the next relay using its real long-lived secp transport identity
- the nested client-to-hop Noise session authenticates the next relay using a tweaked secp key derived from that relay's real identity plus a tweak scalar

In practice, the client is given a tweaked x-only public key, while the
receiving hop is given the tweak scalar so it can derive the matching tweaked
private key.

### Tweak Mechanics

Let the next relay's real private scalar be `s`, real public key be
`S = s*G`, and tweak scalar be `t`.

Then:

```text
tweaked_private = s + t
tweaked_public  = S + t*G
```

The client sees only `tweaked_public`, not `S` and not `t`.

The receiving relay applies the tweak on its private side before serving the
Noise handshake.

In MONAD's current x-only/even-Y transport identity model, blinded-hop
construction does **not** use rejection sampling anymore.

- sample a candidate tweak `t`
- derive the candidate tweaked private scalar `s + t`
- if `(s + t)G` has even Y, keep it
- if `(s + t)G` has odd Y, negate the tweaked secret to `-(s + t)` and adjust the transmitted tweak to `t' = -(s + t) - s`

This preserves the same x-only public key while ensuring the hidden relay serves
the even-Y representative that matches MONAD's 32-byte x-only identity format.
The hidden relay later reconstructs the correct tweaked secret with the normal
formula `real_secret + tweak` using that adjusted tweak value.

The original long-lived public key can later be recovered from:

```text
real_public = tweaked_public - t*G
```

Because the client-visible `tweaked_public` is always even-Y, it can stay in
the same 32-byte x-only format as ordinary MONAD relay identities.

### Relay-To-Relay QUIC + Noise Preamble

For a blinded hop, the current relay will open a normal QUIC stream to the next
relay using the next relay's **real** identity. The QUIC layer is therefore:

- encrypted
- authenticated against the next relay's real QUIC key
- unchanged from today's relay-to-relay QUIC pool design

Implemented today, all MONAD QUIC streams begin with a 1-byte stream-kind
preamble. Two kinds are accepted:

```text
[1 byte stream kind = secp-noise-v1]
[then normal Noise handshake bytes]

[1 byte stream kind = tweaked-noise-v1]
[32 bytes tweak scalar]
[then normal Noise handshake bytes]
```

Unknown kinds are rejected immediately at the QUIC stream layer.

This keeps the tweak delivery inside the already-encrypted QUIC relay-to-relay
channel.

### Blinded CONNECT Dispatch

Blinded transport integration uses a special CONNECT authority instead of a real
`host:port` target:

```text
CONNECT blinded.monad.invalid:443
```

The request carries enough data for the relay to recover:

```text
tweaked_pubkey
ephemeral_pubkey
ciphertext
```

In the current implementation these are sent as H2 headers:

```text
monad-blinded-tweaked-pubkey
monad-blinded-ephemeral-pubkey
monad-blinded-ciphertext
```

The relay interprets `blinded.monad.invalid:443` as:

- do **not** parse the authority as an address
- decrypt the blinded payload using the relay's real private key and `E`
- learn the real next-hop address and tweak
- open the next relay connection over QUIC
- send the tweak preamble
- then proxy bytes exactly as MONAD already does today

The client-facing connector also checks the relay's bootstrap capability bits
before attempting the next hop. For example, a route containing
`RouteHop::Blinded` hard-fails if the current relay does not advertise
`blinded_connect_v1`.

### Sequential Client-Driven Progression

The client still progresses hop-by-hop, just without knowing the real identity
of the blinded hops.

Example:

1. Client connects to the public introduction relay Bob using Bob's real key
2. Client asks Bob for `CONNECT blinded.monad.invalid:443` with Bob's blinded blob for
   Carol
3. Bob decrypts that blob, learns Carol's real address and tweak, opens QUIC to
   Carol, sends the tweak preamble
4. Client runs a nested Noise+H2 session to Carol using **Carol's tweaked key**
5. Inside that nested session, client performs another `CONNECT blinded.monad.invalid:443`
   for the next blinded hop

So each hop only needs to decrypt **its own** blob. The client does not need to
hand future-hop blobs forward inside earlier blobs; it can present each blinded
hop's `(tweaked_pubkey, E, ciphertext)` when it reaches that nesting level.

### Who Knows What?

For a blinded hop `R1 -> R2`:

- the **client** knows only `R2`'s tweaked public key
- `R1` knows `R2`'s real address and the tweak after decrypting its blob
- `R2` learns the tweak from `R1`'s QUIC preamble and uses it to derive the
  tweaked private key
- the publishing **service** knows the whole blinded route because it chose the
  introduction relay, next-hop addresses, and all tweaks

This gives the intended privacy property:

- the client does not know the real identity or real address of the blinded hop
- the hop still gets a normal authenticated nested Noise session
- relay-to-relay transport remains standard QUIC underneath

For the rationale behind MONAD's Ed25519-rooted QUIC certificate plumbing and
why the transport layer is not currently fully secp256k1-native, see
"Why QUIC Still Uses Ed25519 Certificates" above.



## Shutdown Model

Both client and relay use graceful shutdown:
- stop accepting new work on `Ctrl+C`
- wait for active tunnels/sessions with a timeout
- close H2 connections cleanly
- allow `NoiseStream` drop hooks to emit wire-byte accounting logs

## Byte Accounting

### Per-tunnel plaintext accounting

Logged by:
- `monad-client::tunnel`
- `monad-relay::proxy`

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

## Current Transport Identity Model

MONAD transport now uses secp256k1 throughout.

- **Plain TCP MONAD transport** uses secp Noise.
- **QUIC MONAD transport** uses secp attestation plus secp Noise.

Clients now store one transport identity form per hop:

```text
addr:port,secp256k1:<secp_pubkey>
quic:addr:port,secp256k1:<secp_pubkey>
```

On the relay side, startup still takes both:

- a 32-byte **Ed25519 seed** for QUIC certificate generation
- a 32-byte **secp256k1 transport private key** for MONAD TCP and QUIC transport auth

The secp256k1 transport key is used directly for:

- **TCP MONAD transport** via `Noise_NK_secp256k1_ChaChaPoly_BLAKE2s`
- **QUIC secp auth** via the attestation stream
- **QUIC secp MONAD sessions** via secp Noise on `STREAM_KIND_SECP_NOISE`

The Ed25519 seed is retained only for QUIC/TLS certificate plumbing.

### Public-Key Representation

The secp256k1 transport public key is a 33-byte compressed SEC1 point.

So today:

- the client stores one transport public key per hop
- the secp path uses the secp public key directly for both TCP MONAD transport and QUIC attestation

Ed25519 is retained only because the current standards-compliant QUIC/TLS stack
still needs a conventional certificate path for the TLS handshake; MONAD then
layers secp attestation above that encrypted channel.

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

Consider a 2-hop route where client C connects through relay S to relay T using
the current default TCP transport:

```text
C ---- TCP + Noise(S) + H2 ----> S ---- QUIC stream ----> T
                                              |
                               C ---- Noise(T) + H2 ----> T
                               (nested inside the QUIC stream)
```

The outer layers:
- C connects to S via TCP, establishes a secp Noise session, runs H2
- C sends `CONNECT T_addr:port` with `quic-secp256k1-pubkey: <T's secp transport pubkey>` to S over H2
- S opens a QUIC stream to T and completes secp attestation
- S proxies bytes between the H2 CONNECT stream and the QUIC stream

The inner layer:
- C runs a nested secp Noise+H2 session through the tunnel to T
- S sees only opaque Noise-encrypted bytes flowing through — it cannot read the C-to-T traffic

T authenticates itself twice:
- to S via QUIC attestation using T's secp transport key
- to C via secp Noise using the same secp transport key

Relay transport identities are represented at the MONAD configuration layer as
32-byte x-only secp256k1 pubkeys with implied even Y. When a transport layer
needs an actual curve point, MONAD reconstructs the corresponding even-Y
compressed point internally.

The QUIC/TLS certificate is still Ed25519-backed internally, but MONAD transport
authentication itself is secp-based.

### QUIC Authentication Model

QUIC uses a self-signed Ed25519 certificate for the standard TLS 1.3 handshake.
That certificate establishes an encrypted channel, but MONAD does not treat it as
the long-term transport identity.

After the QUIC connection is up, the initiator requests a secp256k1 attestation.
The responder signs a challenge plus QUIC exporter-derived keying material with
its configured secp256k1 transport key. The initiator verifies that signature
against the expected 32-byte x-only secp256k1 public key, which binds the
MONAD transport identity to the live QUIC channel.

This authentication is intentionally one-way: the target authenticates itself to
the initiator, but the initiator does not authenticate itself at the QUIC layer.
This aligns with MONAD's current model, where the initiator knows the relay
identity in advance and the relay proves possession of the corresponding
private key.

If the opposite traffic direction ever needs its own initiator-driven link, that should be modeled as a separate independent QUIC connection in the reverse direction rather than by introducing mutual authentication. This keeps connection ownership, authentication rules, and future state machines simpler.

### Server Dual Listener

A MONAD relay that supports QUIC listens on the same port number for both TCP and UDP:

- **TCP** (existing): accepts connections, performs secp Noise handshake, runs H2
- **UDP** (new): accepts QUIC connections, accepts bidirectional streams

TCP and UDP can share a port because they are different IP protocols at the kernel level.

On the receiving side, both transports feed into the same session handler. A QUIC bidirectional stream is wrapped as `AsyncRead + AsyncWrite` (a `QuicStream` type), and the relay runs the same H2 session on top of it as it does for TCP.

- TCP: secp Noise
- QUIC: secp Noise on `STREAM_KIND_SECP_NOISE`

```text
TCP listener ──> accept() ──> TcpStream ──────────┐
                                                   ├──> Noise handshake ──> H2 session
QUIC listener ──> accept_bi() ──> QuicStream ──────┘
```

After the handshake completes, the session handler does not care which transport delivered the bytes.

A QUIC-capable relay has both:
- an Ed25519 identity for QUIC certificate generation
- a secp256k1 transport key whose public MONAD identity is a 32-byte x-only pubkey for TCP MONAD transport and secp-authenticated QUIC

The `--quic` flag enables the QUIC listener; the QUIC certificate is generated from the `--quic-cert-seed` Ed25519 seed, while `--transport-key` supplies the shared secp transport key.

### CONNECT Syntax for QUIC Hops

The client signals to a relay that it should use QUIC to reach the next hop by including a `quic-secp256k1-pubkey` header in the H2 CONNECT request. The URI authority remains a standard `host:port`, and the header value is the next hop's 32-byte x-only secp256k1 identity encoded as 64 hex characters:

```text
CONNECT host:port HTTP/2
quic-secp256k1-pubkey: <64-hex-char-x-only-pubkey>
```

For example:

```text
CONNECT 10.0.0.5:9050 HTTP/2
quic-secp256k1-pubkey: abcd...
```

The relay checks for the QUIC transport header:
- `quic-secp256k1-pubkey`: connect via QUIC and require secp attestation
- if neither is present, connect via TCP as before

The secp transport key is carried as an H2 header because the CONNECT authority must be a valid HTTP authority (`host:port`). The `quic-secp256k1-pubkey` header is part of the H2 HEADERS frame that initiates the stream — it is sent once at stream creation and does not interfere with the DATA frames that carry tunneled bytes afterward.

This means the relay does not need pre-configured knowledge of other relays' QUIC identities — the client passes the pinned key in each CONNECT request, keeping the relay stateless with respect to the relay topology.

### QUIC Connection Pool

A relay that handles CONNECT requests with `quic-secp256k1-pubkey` maintains a connection pool keyed by `(host, port)` plus auth mode.

- The first CONNECT with a `quic-secp256k1-pubkey` to a given target establishes a new QUIC connection to T
- Subsequent requests to the same target reuse the existing QUIC connection and open new streams
- Each client session gets its own bidirectional QUIC stream inside the shared connection

This is the core scaling benefit: one QUIC handshake to T is amortized across all clients whose routes pass through S to T.

### Client `--hop` Syntax for QUIC Hops

The `--hop` syntax uses 32-byte x-only secp256k1 identities:

```text
--hop addr:port,secp256k1:<pubkey>
--hop quic:addr:port,secp256k1:<pubkey>
```

The `quic:` prefix on any hop after the first tells the client to include `quic-secp256k1-pubkey` in the CONNECT request to the previous relay. On the first hop, `quic:` tells the client to connect directly via QUIC instead of TCP.

Example 2-hop route where the second hop uses QUIC:

```bash
monad-client \
  --hop 10.0.0.1:9050,secp256k1:<S_pubkey> \
  --hop quic:10.0.0.2:9050,secp256k1:<T_pubkey>
```

The client:
1. Connects to S at `10.0.0.1:9050` via TCP+secp Noise
2. Sends `CONNECT 10.0.0.2:9050` with `quic-secp256k1-pubkey` to S over H2
3. S connects to T via QUIC using the requested auth mode
4. Client runs a nested secp Noise+H2 session to T through the tunnel

### Design Constraints

- disable QUIC 0-RTT at first to avoid replay complexity
- keep current direct and nested MONAD modes working over TCP, now using secp transport
- the inner MONAD Noise+H2 session model is unchanged — QUIC is a transport optimization only
- QUIC/TLS still uses a self-signed Ed25519 certificate internally, while MONAD transport auth uses the secp transport key

### QUIC Implementation Status

The QUIC transport is fully integrated into the main MONAD system. The `monad-quic` crate provides shared building blocks (`QuicStream`, `build_server_config`, `build_client_config`, keygen), and the relay and client use them for QUIC hop support.

What has been validated:

- **Exporter-bound secp attestation works.** The client and relay establish a normal QUIC/TLS channel, then the responder signs a challenge bound to the QUIC exporter with its secp256k1 transport key. The initiator rejects mismatched keys, confirming that MONAD transport identity is anchored in the secp key rather than the self-signed TLS certificate.

- **1,000 concurrent bidirectional streams over one QUIC connection work.** Each stream sends 4KB of random data and verifies the echoed response. All 1,000 streams complete successfully. Stream creation is lightweight — the entire test runs in under a second.

- **Multiple independent QUIC connections work.** Three separate connections, each carrying 10 streams, run concurrently without interference.

- **Large single-stream payloads work (with tuning).** A 4MB payload on a single stream succeeds, but required increasing the QUIC flow-control windows beyond the defaults (see below).

### QUIC Flow Control

Quinn's default `stream_receive_window` is 1MB and the default connection-level `receive_window` is also limited. These defaults are fine for typical web traffic but can cause problems with large payloads in a write-then-read pattern.

The specific issue: if a client sends a large payload (exceeding the receive window) and the relay echoes it back before the client has started reading, both sides can deadlock. The client blocks trying to send because the relay's receive window is full, and the relay blocks trying to echo because the client's receive window is full — neither side makes progress.

This is specific to the echo test pattern (sequential write-all then read-all on the same stream). In real MONAD relay usage, the two directions of a stream are handled by separate tasks reading and writing concurrently, so this deadlock does not apply. Nevertheless, the current `monad-quic` transport config sets:

- `stream_receive_window`: 8MB
- `receive_window` (connection-level): 16MB

These values are generous for testing. Production tuning will depend on expected relay traffic patterns.

Initiator-side QUIC connections also enable periodic keep-alives so idle client-to-hop and relay-to-relay QUIC links stay up past the default Quinn idle timeout.

### What Has Been Integrated

The full QUIC transport chain is implemented and tested:

1. **`QuicStream` type in `monad-quic`** — wraps a quinn bidirectional stream as `AsyncRead + AsyncWrite`, used interchangeably with `TcpStream`
2. **QUIC listener in `monad-relay`** — binds a UDP socket on the same port as the TCP listener, accepts QUIC connections, feeds incoming streams into the existing Noise+H2 session handler
3. **Dual transport identity plumbing in `monad-relay`** — `monad-relay keygen` emits both an Ed25519 identity set for QUIC certificate generation and a secp256k1 transport key for MONAD transport auth.
4. **QUIC transport header parsing in `monad-relay`** — detects `quic-secp256k1-pubkey` on CONNECT requests and connects via secp-authenticated QUIC instead of TCP
5. **QUIC connection pool in `monad-relay`** — maintains shared QUIC connections keyed by `(host, port)`, reuses across client sessions
6. **`--hop quic:` parsing in `monad-client`** — parses the `quic:` prefix from the hop spec, emits `quic-secp256k1-pubkey`, and uses secp256k1 directly for non-QUIC hops
7. **Integration tests** — cover QUIC single-hop, QUIC with control+data channels, nested QUIC tunnels (manual and via connector), alongside all existing TCP tests

## Current Limitations

- Spilman channel implementation follows the delta-based model described above, but is exercised only through the mock wallet path in tests and the localhost test harness.
- relay does not yet persist Spilman channel state across restarts (registry is in-memory).
- multi-hop Spilman channel funding is wired but not yet fully tested with the new lifecycle.
- no persistent route configuration file yet.
- QUIC connection pool does not yet handle connection eviction or stale entry cleanup.
- asymmetric pricing (rates other than 1/1) is not yet tested.
