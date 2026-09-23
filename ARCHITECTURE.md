# MONAD Architecture

## Overview

### Terminal Refunds

The focused persistent-mint crash test gates a completed HTTP close response
before killing an actual file-backed CDK mint child. Restart reuses the same
mint/signatory database and deterministic test keys; restoration and conservation
are checked through HTTP, with no parent in-memory mint or response cache.

`SenderRefundedAfterExpiry` is an upstream persistent channel state, distinct from
normal `Closed` with no fabricated payout. The relay close journal v3 saves the
full mint NUT-07 evidence in the same transaction as the terminal state before
returning it. Every saved close attempt is restored before input-state checks and
again after spent evidence, so an actual verified close payout takes precedence.
Each attempt caches the SHA-256 digest of its exact NUT-11 `SIG_ALL` message and
the blinded receiver key; recovery authenticates both against the immutable swap
request and channel before use. Under the honest-mint, complete-witness assumption,
exact all-spent funding-Y coverage attests the refund branch only when every
well-formed NUT-07 witness signature fails verification against every authenticated
attempt. A matching receiver signature identifies a relay close even when unrelated
signatures are also present. This is mint attestation, not independent verification
of the unavailable full spending request. `UnknownSpent` retains the journal when
evidence is missing; pending, partial, malformed, unauthenticated, or unavailable
evidence cannot install a terminal state. Terminal reopen validates saved evidence
locally and does no mint I/O. No payments, links, autosweep candidates, or drain
payouts are available for terminal refunds; sender proof restoration remains
independent.

### Wallet Durability

Every writable file-backed wallet connection, including short-lived relay
metadata/drain connections and the client loose-proof, metadata, refund, and
upstream channel stores, applies and verifies SQLite `synchronous=EXTRA` before
writes. The shared upstream helper retains durable journal modes and rejects
OFF/MEMORY modes. EXTRA includes FULL's WAL commit sync and also syncs the
directory after rollback-journal deletion. In-memory tests and read-only
inspection are separate paths. This policy does not change transaction scope:
cross-database recovery still requires the durable journals and idempotent import.
Process-kill tests cannot establish power-loss safety on hardware that lies about
sync completion. Backups require consistent SQLite snapshots of every wallet DB,
not copies that omit live WAL state.

Output selection treats activity and final expiry independently. A keyset is
expired when `now > final_expiry`, matching the pinned CDK; absent expiry is
unlimited and zero is expired at current wall time. New MONAD funding additionally
requires `K >= C + W`, where `K` is the funding keyset's final expiry, `C` is the
chosen immutable channel expiry, and `W` is the larger of the client's configured
recovery window and the relay's advertised requirement. Both default to 24 hours.
Absent `K` is allowed; explicit zero is rejected even when `W` is zero. Finite
expiry checks use checked arithmetic and reject overflow; equality passes.
Selection and safe changed-keyset successors use the same actual channel expiry,
not a reconstructed wall-clock lifetime.

Each wire `KeysetAdvertisement` includes `funding_keyset_recovery_window_secs`.
The relay applies its configured window to both new links and stored relinks
before channel persistence or ownership changes. Stored parameters and keyset
metadata, not caller replacements, govern relinks. This is admission policy,
not a new ongoing payment cutoff or a grandfathering rule. Discovery preserves
`final_expiry` through upstream HTTP metadata, bridge JSON, shared caches, and
SQLite persistence. V1 expiry metadata is not ID-bound; positive V2 expiry is
part of the keyset ID commitment (absent and zero share a hash representation
but have different admission semantics). Neither format is excluded.

Close/drain/refund outputs have no funding recovery-window, relay advertisement
or negotiated-format filter; funding keeps those policy filters. Cache warmup
tests usable output selection, not merely same-unit metadata presence. Historical
keys remain available for exact restore and sender denomination discovery, and
offline finalization never rejects already-verified proofs using current time.
Expiry errors (`12003`) do not authorize changed immutable requests. CDK may hide
expired signatures in restore, so an empty restore is not proof of nonexecution.
No keyset-expiry-driven proactive swaps or workers are introduced; the existing
channel-expiry auto-close worker is unchanged. Warnings and UI are separate work.

After close funding is observed non-unspent, the final exact restore pass checks
every saved close attempt, including a rejected predecessor. A verified payout
wins over conflicting-keyset responses from another saved attempt. Malformed or
unavailable evidence remains unresolved and never becomes a zero-value close.

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
  - stores fetched `SessionSpilmanInfo` (mint, keyset, receiver pubkey, negotiated Cashu Spilman protocol and keyset-format versions) for the active channel
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
- expose a local SOCKS5 listener for normal tools (`curl`, `ssh`, `scp`, browsers`) through the configured-client binary path
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

## Configured Client Route Rebuilds

The client process has one `ClientWalletManager`. It acquires OS-backed locks for
the normalized, deduplicated loose-proof and channel database paths, opens and
migrates one `SqliteClientWallet`, and runs one startup opening-recovery pass
under exclusive maintenance access. It then converts the maintenance locks to
shared mode and starts either every configured client in YAML order or one named
client. All leaves share the same wallet instance. A `JoinSet` supervises the
leaves; SOCKS listener failure is fatal to the process, shutdown is broadcast to
all leaves, and their route/listener/accepted-connection tasks are awaited before
the manager and its runtime-owner locks are dropped.

Each database has runtime-owner and maintenance sidecars. Runtime ownership is
exclusive. Startup open/migration/recovery and mutating CLI operations take the
maintenance gate exclusively; runtime steady state and read-only CLI inspection
take it shared. Mutating CLI acquisition is fail-fast. Channel/proof inspection
opens MONAD SQLite connections and upstream `SqliteClientStorage` read-only,
performs no schema initialization, and does not load the sender secret. Inspection
still participates in filesystem coordination through adjacent lock sidecars and
therefore requires sidecar access in the database directories. Existing database
files with multiple hard links are rejected because path normalization cannot
safely establish one lock identity for hard-link aliases.

The configured client owns a `RouteConnection`, not just the final hop. That
handle keeps the final `RelayConnection`, all prefix hop connections, and per-hop
session metadata together so route failures can be handled at hop granularity.

Each funded hop has a session/payment driver failure watcher. When one or more
watchers fire, the route manager briefly debounces the signals and treats the
lowest failed hop index as authoritative. This collapses cascaded failures where
a broken middle hop also causes downstream sessions to end.

Route rebuilds are serialized. Once a rebuild starts, old-route watchers are
dropped; additional stale failures from that old route are ignored. The rebuilt
route installs fresh watchers after it is published.
`RelayConnection::wait_for_failure` owns its watch futures directly rather than
spawning tasks. Dropping the wait releases every cloned receiver synchronously,
including those for a surviving prefix. An already-true value or a closed sender
is a failure; neither requires a subsequent watch notification.

Shared QUIC pools intentionally outlive individual sessions. Failed cached-stream
opens evict only the same Quinn connection identity, and abandoned pending waits
evict only the same watch channel. A stale waiter must not remove a replacement
entry merely because it is also `Ready` or `Pending`.

Route (re)connect retry policy is split by lifecycle: before the first
successful connect the client fails fast after a bounded number of attempts so
startup misconfiguration is loud; once a route has connected, reconnects retry
indefinitely with capped backoff. Transient correlated failures (relay
restarts, wallet funding exhaustion) withdraw the route from SOCKS but never
permanently kill the listener — the client recovers when the route (or an
operator refilling the wallet) lets it.

Failure handling is deliberately scoped:

- hop `0` failure closes the whole route and uses the normal reconnect loop
- hop `N > 0` failure temporarily withdraws the route from SOCKS so new local
  CONNECT requests fail fast while no route is published, detaches only wallet
  channels attached to old suffix session IDs, and attempts to rebuild from hop
  `N`
- suffix rebuild preserves prefix sessions and channels before the failed hop for
  future streams
- suffix rebuild failure falls back to a full route reconnect

Route setup runs under an owned supervisor. Each H2 connection is registered
immediately, and its payment task is attached before waiting for funded
readiness. Caller cancellation or the setup deadline drops the setup future,
but not the supervisor: it aborts and awaits every owned child before detaching
wallet channels. The supervisor retains ownership of a buffered successful result
until the receiver synchronously acknowledges receipt; dropping that receiver
instead triggers cleanup. A per-connector completion chain prevents subsequent
attempts from overtaking this handoff or cleanup, including cancellation while
queued. This matters for
synchronous mint calls using `block_in_place`, which can complete a channel
opening after task abortion was requested. Completed compatible channels remain
available for reuse; opening journals and ambiguous-opening recovery are unchanged.
The deadline bounds setup work, not cleanup latency. Suffix rebuild closes and
awaits old suffix tasks before detaching their channels, preserving prefix tasks
on success; failure cleans up the partial suffix and prefix before full fallback.
`RelayConnection::close` retains pending handles if it is itself cancelled; Drop
only provides a last-resort abort, not an asynchronous quiescence guarantee.
Library callers should reuse one `ConnectorRuntime` across retries and retain
the `RouteConnection` while using its final-hop handle, which does not own prefix
tasks. Await route closure before shutting down the Tokio runtime.

Active application streams are not migrated across rebuilds. A local TCP/SOCKS
stream stays bound to the route it started on and fails if that route breaks;
new SOCKS connections use the next route published by the manager.

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
- `ChannelLink { payment_json }` — link a Spilman channel to this session; requires a valid Spilman `Payment` with balance=0, funding proofs, sufficient capacity for the relay's configured channel policy, and an expiry at least `channel_policy.min_expiry` in the future
- `ChannelPayment { payment_json }` — increment session balance; requires a Spilman `Payment` signature for a higher balance than previously seen for this channel
- `GetSessionStatus` — request a fresh session status snapshot

Server to client (`ServerMessage`):
- `SessionStatus { ... }` — primary state synchronization message; sent immediately after control stream establishment, in response to `GetSessionStatus`, and after accepted link/payment or eviction transitions. Fast-path byte accounting and repause do not independently push a snapshot. Contains:
  - `version`: Negotiated protocol version
  - `receiver_pubkey`: Server's secp256k1 key for Spilman
  - `advertisements`: Ordered `(Mint, Unit, Rates)` options whose keyset ID lists are relay-known preferences and may be empty
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

### Relay Keyset Refresh

Relay keyset refresh is bounded trusted-mint maintenance, not a client control operation or open mint discovery. A first-time channel link with an unknown keyset triggers it automatically.

- A first-time `ChannelLink` rejected only because its trusted mint/unit keyset is unknown first undergoes metadata-independent structural checks. The relay then invokes the coordinator and retries the same immutable payment once after a fresh successful result.
- Stored channel relinks use authoritative persisted funding and never trigger keyset refresh.
- Refresh is eligible only when `mint_url` is already configured as trusted and `unit` is trusted for that mint.
- The relay refreshes all keysets for that mint into the shared relay-wallet cache, not only the submitted channel's unit, because mint keyset endpoints are mint-scoped.
- Automatic link refresh returns transient `LinkKeysetRefreshRateLimited`, `LinkKeysetRefreshBusy`, or `LinkKeysetRefreshFailed` errors when it cannot make a fresh decision. A fresh successful response that still does not contain the keyset yields permanent `LinkMintOrKeysetUnacceptable`.
- Startup discovery still populates the cache. Close and drain swaps remain cache-first and refresh the mint on missing-cache warmup or when a mint keyset error requires a bounded retry.
  Cold wallet CLI close also warms missing metadata before preparing outputs;
  already-closed channels do not require that warmup.

DoS resistance is part of the protocol behavior. Each hosted relay's coordinator validates submitted mint/unit sizes and trusted policy before any network fetch, permits at most one actual attempt per mint per cooldown regardless of outcome, shares cancellation-safe in-flight results among that relay's concurrent same-mint links, fails fast when its cross-mint capacity is saturated, and wraps mint I/O in a timeout. Hosted relays share the wallet cache but not one process-wide refresh budget. Refresh I/O runs outside session accounting locks, so slow or failing mints do not block data-path accounting or unrelated control state.

Refresh does not invalidate old keysets by itself. The relay cache stores all keysets returned by configured mints, active and inactive, and trusted policy filters advertisements and first-time funding acceptance at read time. Stored channels relink and pay using persisted funding without requiring the current mint cache, while newly opened channels should use a currently active keyset once both client and relay have refreshed.

### Version Negotiation

Here, "bootstrap" means the MONAD-specific negotiation carried inside the two Noise handshake payloads before the post-handshake session begins.

MONAD currently uses the Noise `NK` pattern instantiated with secp256k1 DH, ChaCha20-Poly1305 for transport encryption, BLAKE2s for hashing, and the fixed prologue `monad-noise-secp256k1-v1`. The client sends a bootstrap request in the first Noise handshake payload, the relay replies with an accept-or-reject payload in the second, and this bootstrap is intentionally strict rather than open-ended negotiation: the client maps each Cashu Spilman channel protocol version to its supported keyset-format versions, must offer `h2` and a mutually supported pricing policy, and the relay selects one session protocol, one Cashu Spilman protocol, and the full mutual keyset-format set or rejects the session before H2 starts. Today the only accepted post-handshake session protocol is `h2` (HTTP/2), `2026-09-14` supports keyset-format versions `v1` and `v2` and requires a nonempty intersection, and the only supported pricing policy is `session_constant`. Concrete mint keyset IDs remain relay advertisements on the post-H2 control stream; these bootstrap keyset-format versions are capability identifiers rather than mint keyset IDs.

The `2026-09-14` version retains the canonical deterministic P2PK secret serialization introduced by `2026-08-29`, treats advertised keyset IDs as preferences, and replaces explicit client refresh requests with relay-side refresh during `ChannelLink`. It intentionally rejects earlier peers so mixed versions cannot disagree about channel authorization or keyset discovery.

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

The balance can go negative between billing checks (a proxy chunk may push usage past the paid amount). When the relay detects nonpositive balance, it pauses the session and wakes pause-aware proxy tasks. The client detects the need for more funding from its local counters or a later requested/transition-driven `SessionStatus`, then sends another payment to resume.

### Two Pricing Structures

- **Wire**: `ServerMessage::SessionStatus` carries the active rates and the list of alternatives. This is what crosses the network.
- **Local**: `SessionPricing` (in `monad-common/src/session.rs`) includes the precomputed LCM of the active rates. Both client and relay construct this from the active rates in `SessionStatus` for billing math.

### Client Auto-Funding

The client opens a control stream immediately after connecting. Once it receives the initial `SessionStatus`, the per-session payment driver runs one serialized direct control loop. That loop chooses or provisions a local channel, sends `ChannelLink`, and later sends `ChannelPayment` updates. Intermediate hops in multi-hop chains use the same session-driver model.

The client stores each channel's expiry timestamp in local channel metadata and excludes already-expired channels from selection. If a relay rejects a link because the channel expiry is too soon or the capacity does not satisfy the relay's channel policy, the driver marks that channel globally unusable locally and selects or provisions another channel.

Relay channel policy is configured per relay. Duration fields such as `min_expiry` and `expiring_channels.close_before_expiry` accept human-readable strings like `3600s`, `60m`, `2h`, or `1d`. Capacity fields require explicit `sat` or `msat` suffixes; MONAD stores them internally as millisats and converts to the channel's raw unit before returning upstream Spilman `ChannelPolicy` values. Close-to-expiry detection currently reports `Open` and `Closing` channels whose expiry timestamp is inside `expiring_channels.close_before_expiry`; `expiring_channels.auto_close` is opt-in config for the periodic close worker.

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

`session_driver.rs` contains the public entrypoints and private `runtime`,
`state`, `funding`, and `payment` modules for executor input ordering, local
state publishing, channel acquisition/link/payment progression, and payment
protocol-safety checks.

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
- Used for channel-id to session ownership binding (enforcing one owning session per channel)

MONAD integrates Cashu Spilman payment channels for per-session prepaid relay access. The design enforces channel exclusivity and uses delta-based accounting. Before any `ChannelLink` or `ChannelPayment` traffic can happen, the client and relay must already have negotiated a mutually supported Cashu Spilman channel protocol version and a nonempty mutual keyset-format set during the Noise bootstrap.

#### 1. Server Advertisement
The relay is configured with trusted mint/unit options plus one session pricing policy. In the `SessionStatus` message, it advertises those options as `KeysetAdvertisement` objects; each currently carries the same session-wide `in_bytes_per_millisat` and `out_bytes_per_millisat` rates.

The relay wallet manager owns a shared in-memory `SpilmanMintCache`. The cache stores all keysets returned by configured mints, active and inactive, for all units the mint reports. Trusted mint/unit policy filters advertisements and first-time funding acceptance; stored channels can relink and pay after a policy change. Close and drain use the same shared cache-selection mechanics but different durable recovery state machines. Each can warm an empty mint/unit cache and perform at most one changed-output-keyset retry after a recognized keyset rejection.

#### 2. Channel Linking
The client selects a mint/unit and sends a `ChannelLink` message containing a Spilman `Payment` with `balance: 0` and the required multisig funding proofs. If the bootstrap did not negotiate a supported Cashu Spilman channel protocol version and keyset-format set, the relay rejects linking immediately.

Production hellos offer both `v1` (`00` keyset IDs) and `v2` (`01` keyset IDs). The relay selects the full nonempty intersection; clients validate selections against the actual hello. Session advertisements apply negotiated-version filtering in addition to trusted mint/unit policy and retain every configured mint/unit option even when its ordered relay-known preference list is empty. Preferences may include compatible inactive IDs and are not an exhaustive accepted-ID allowlist. The shared cache, channel close/drain output selection, and loose input proofs are unaffected.

Before persisting a new channel or changing ownership, `ChannelLink` checks its funding keyset version. Existing channels use authoritative stored funding, never caller-supplied replacement or omitted params. A mismatch yields `LinkKeysetVersionNotNegotiated`, releases the offending session's previous ownership, and ends its data/control streams after a bounded best-effort error send. Other MONAD sessions on the same QUIC connection remain usable. The client terminates its driver without invalidating the wallet channel.

For a first-time channel on a negotiated keyset format, an unknown keyset is refreshable only when the submitted mint/unit is already trusted. Before mint I/O, the relay recomputes the channel identity and checks funding-proof structure that does not require mint key metadata. It then invokes the shared bounded coordinator and retries the immutable link once after a fresh successful result. A still-unknown keyset is permanently rejected. Cooldown, saturation, and refresh failure remain transient; the client retains its intended channel and backs off. Stored `Open` channels bypass this path and validate against persisted funding, while `Closing` and `Closed` channels remain unusable.
- **One Session Per Channel**: One live relay payment backend maintains a registry of `ChannelId -> SessionId` shared by that relay's sessions. Process/database ownership and durable channel ownership metadata are separate layers.
- **Exclusivity**: If a channel is already linked to another session, the relay sends `ChannelEvicted` to the old session and links the channel to the new one.
- **Stateless Session Start**: Every new Noise session starts with a `total_paid_millisats` of 0. Only *new* payments made within the current session count as credit.

#### 3. Orthogonal State Model
A session's ability to proxy data is determined by two orthogonal variables:
- **Flow State**: Is the session balance strictly positive? (`Active` if balance > 0, else `Paused`)
- **Linked State**: Is there a Spilman channel currently associated with this session? (`Linked` vs `Unlinked`)

#### 4. Incremental Payments (Delta Model)
When the session balance runs low, the client sends a `ChannelPayment` with a signed balance update.
The relay commits that update only if the sending session still owns the channel
and the exact previously observed payment remains current. Ownership transfer is
serialized with this payment CAS. A stale-session or payment-versus-close race
returns `PAYMENT_CONFLICT` without granting credit; the client treats that result
as fatal to the affected MONAD session so normal route rebuilding relinks from
durable relay state rather than retrying an obsolete authorization.
The [payment-conflict integration tests](monad-relay/tests/PAYMENT_CONFLICT.md)
exercise this path with real signed payments and an ownership loss at the payment
boundary, including prefix preservation during a middle-hop suffix rebuild.
The fault injection exists only in the integration-test payment adapter, not in
the production relay or client.
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

- the locally authorized payment total
- the client's cleartext byte counters and immutable session pricing
- target positive remaining balance
- relay-reported `linked_channel.balance_raw`

and asks the wallet backend to build a payment for that exact next balance.
- **Eviction Fairness**: If a session is evicted, it **remains Active** as long as it has a positive balance. The user can spend their existing credit, but cannot send further `ChannelPayment` updates until they link a new channel.

### Client Wallet Layer

Client-side channel funding is split between loose-proof custody and Spilman
channel metadata.

- `LooseProofWallet` stores spendable Cashu proofs, mint quote records, premint
  batches, proof reservations, and spend/release state in SQLite.
- `SqliteClientWallet` implements `MonadWallet` by selecting/reserving loose
  proofs, opening upstream Spilman channels, persisting MONAD channel metadata,
  building zero-balance link payments, and signing incremental channel payments.
- `MockWallet` remains available for deterministic tests and harnesses.

Client channel opening is cache-first. Each opening call site prefers an active
client output keyset from the relay's ordered advertised IDs, then may use any
other locally active keyset for the same mint/unit whose format was negotiated.
When the preference list is nonempty but unavailable locally, the client
refreshes its own mint cache before using a non-preferred fallback. It also
refreshes before concluding that no compatible active keyset exists. Before
submitting the opening swap, the loose-proof store atomically reserves the
selected inputs and records the exact serialized prepared opening.
The configured `channel_funding_token_target_msats` is a desired funding-token
value. Plain provisioning selects strict smallest-first `(amount, proof_id)`
inputs until their post-input-fee value covers that target, so input fees are
additional rather than deducted from the configured value. Input keyset metadata
gets one bounded refresh when needed; an unresolved proof cannot be skipped
before the plain target, while exact-capacity selection can proceed from known,
positive-net inputs after refresh when they suffice. Both preparation and storage
enforce a portable maximum of 992 selected proof IDs.
The journal is authoritative across restarts. Submitted attempts first recover
their original funding/change outputs through NUT-09. If a valid funding restore
is empty, one NUT-07 request checks every persisted input Y; only an all-`UNSPENT`
response may authorize one replay of the byte-identical swap during live opening
recovery only, subject to current execution authority and a wall-clock second
strictly later than the previous authorization. The live path does not wait solely
for that clock advance. Each immutable attempt has at most one authorized replay
submission. Replay
success finalizes normally; replay ambiguity or rejection performs one immediate
exact restore and otherwise leaves the operation submitted and reserved. A replay
rejection cannot authorize a keyset successor because it does not settle the
earlier ambiguous execution.
Finalization replays local channel, change-proof, and metadata updates
idempotently. Prepared attempts that were never claimed for submission are
cancelled and their proofs released.

If the mint explicitly rejects an inactive output keyset with code `12002`, the
client records that immutable predecessor, refreshes, and may create one successor
using a changed active keyset. Transport and protocol ambiguity never authorizes a
successor submission. Live ambiguous opens run bounded recovery once immediately.

Opening and refund HTTP adapters share a body-discarding rejection type carrying
only HTTP status and an optional numeric NUT-00 code. HTTP 4xx `12002` is rejection
evidence, not successor authority: the separate opening and refund journals enforce
their own initial-execution, ambiguity, and predecessor checks. Opening never
reconstructs rejection evidence from formatted error strings.

Exact NUT-09 output/signature matching and cryptographic completion use upstream's
checked completion paths for both operations. MONAD only classifies empty paired
arrays as absence and enforces opening's funding/change consistency. Structurally
valid nonempty funding and change responses are fetched before upstream exact
matching; partial, duplicate, unknown, or invalid signatures cannot finalize an
opening. Journals, retry budgets, and the distinct relay-compatible funding versus
unfiltered same-mint/unit refund keyset policies remain separate.

The configured runtime manager runs one restore-only opening recovery pass
before route provisioning, also exposed by manual `recover-openings`. This pass
never submits swaps: prepared attempts and rejected attempts without a successor
are cancelled; finalizing attempts finish local idempotent updates; submitted
attempts with complete restored funding/change finalize. Empty, partial, invalid,
or network-failed restore evidence normally remains unresolved and reserved. Under
the manager's exclusive startup/maintenance lock, `export-stale-opening-inputs`
may select eligible submitted or already-exported attempts after 3600 seconds,
exact empty funding/change restore, and complete all-`UNSPENT` NUT-07 evidence.
It groups proofs by mint/unit, deterministically constructs one Cashu token per
group, then atomically revalidates and marks every represented attempt `Exported`
before exposing that token. Independent group failures become unresolved report
entries rather than suppressing successful groups. Token construction sorts both
input proofs and the encoded keyset groups, including mixed-input-keyset exports.
Repeated runs are overlapping
best-effort snapshots and can re-emit still-reserved proofs. Export never applies a
restored completion; it directs the operator to `recover-openings`. Recovery still
checks exported attempts: a delayed completion wins; all exact inputs `SPENT` plus
a final empty restore atomically marks the attempt `ExternallySpent` and its proofs
spent.
Incompatible nonempty opening journals are rejected; there is no migration or
automatic wallet reset. Preserve funded databases and recovery records. The current
`export-stale-opening-inputs` command does not read incompatible older journals;
any pre-upgrade export requires tooling compatible with that older schema.
Resetting disposable, operator-owned test databases is an explicit operator
decision. Other swap policies are unchanged.
The live exact-replay
allowance is independent per immutable attempt, so a keyset successor receives
its own allowance without authorizing a second successor.

Exact duplicate opening identities are coordinated in-process and protected by
journal/database uniqueness across wallet handles. Duplicate callers receive a
typed already-open, opening-in-progress, or conflict result rather than sharing a
channel that another session may already have attached.

If that refreshed client cache has no active same-mint/unit keyset with a
negotiated format, `SqliteClientWallet` reports that no compatible active keyset
exists. For new channels, the session driver tries advertised mint/unit offers in
order. It advances only after an explicitly safe offer-local failure, such as no
compatible active keyset, insufficient loose proofs, or a pre-reservation
preparation failure; ambiguous opening failures stop traversal. Before readiness,
all unavailable offers block acquisition; after readiness, they retry with the
funding backoff. The client never asks the relay to refresh. If a first-time link
uses a trusted, compatible keyset still unknown to the relay cache, it
transparently drives the relay's bounded refresh and one immutable retry.

The reusable wallet library path exists, and `monad-client wallet ...` exposes
token import, proof/channel inspection, and recovery commands using either
top-level `client_wallet` YAML config or explicit DB/key flags. The configured
SOCKS runtime uses the persisted loose-proof and channel wallets from that same
YAML config. Inspection is read-only and does not require sender key material;
mutating commands require exclusive wallet maintenance access. Remaining wallet
UX work is mostly mint quote/mint commands, richer balance inspection, and
close/sweep flows.

### Established-Channel Recovery

`recover_channel_funds(access, channel_id, mint_connection)` requires matching
exclusive maintenance authority plus per-channel singleflight. It is not the
startup opening-recovery pass. Refund journal v2 binds the normalized loose DB,
wallet name, and sender; noncompleted recoveries expose `Closing` and exclude
channel reuse. Its `prepared` / `submitting` / `finalizing` / `completed` phases
retain immutable requests, execution outcomes, a rejected predecessor if present,
and verified finalization proofs.

Refund output selection is cache-first for active same-mint/unit keys, independent
of historical funding keys and without relay/session keyset filters. Upstream
prepared-refund validation and checked response completion use persisted output
keys. Versioned output derivation includes sender-private material; serialized
records contain secrets and blindings and must not be logged.

Submitted refunds restore before clock/state checks. Valid absence and expired,
unspent funding permit at most one submission plus one exact replay per request
per invocation. Only an initial structured `12002` rejection without earlier
uncertainty permits one durable changed-keyset successor. A final exact restore
after observing spent funding covers the restore/checkstate race. The first-proof
state check assumes generated transactions atomically spend all funding inputs;
witness cardinality is advisory. Checked sender-close discovery also accepts an
`Unknown` witness, but an empty scan never completes recovery.

Verified proofs persist before import, then upstream and MONAD closure precede
completion. These separate local writes resume offline from `finalizing`; imports
preserve reserved/spent custody. The v2 journal is testnet-breaking: incompatible
nonempty journals are rejected with no migration or automatic wallet reset.
See [WALLET](WALLET.md#channel-fund-recovery) for exact recovery and custody rules.

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

The relay runtime validates all selected identities and pre-binds every TCP and
QUIC listener before wallet mutation. It then acquires the normalized database's
OS-backed runtime-owner and maintenance sidecars, opens/migrates exactly one
`RelayWalletManager`, registers the selected receiver identities, and refreshes
the union of their trusted mint URLs into one shared cache. Startup holds the
maintenance gate exclusively. Steady state downgrades it to shared mode. Omitting
`--relay` starts every configured relay in YAML order; selecting one relay still
owns the complete configured wallet, preventing a second process from hosting a
sibling identity against the same database.

Each listener receives the same manager and cache but constructs and shares its
own live payment backend with
its own wallet name, receiver key, trusted mint/unit policy, pricing, and channel
policy. A process-level `JoinSet` treats any listener exit as fatal, broadcasts
shutdown to siblings, and awaits all listener, connection, stream, session,
control-stream, keyset-refresh, and auto-close task trees before releasing wallet
ownership. Within a listener, session cleanup is followed by refresh-coordinator
drain; the wrapper then stops the auto-close worker and aborts-and-awaits it after
the bounded shutdown grace period.

Read-only wallet commands take the maintenance gate shared and open SQLite with
read-only flags, without schema initialization. Mutating close/drain/recovery
commands take it exclusively and fail before normal database opening or network
work while a runtime is active. Read-only here describes SQLite access; inspection
still opens or creates the adjacent maintenance sidecar and requires directory
permission for it. Hard-linked existing wallet databases are rejected. Kernel
file locks provide process-death release.

The relay binary now also exposes wallet-admin commands over that same durable
state (`monad-relay wallet ...`) so operators can list identities, inspect
stored channels, close a channel by `channel_id`, drain closed-channel receiver
proofs, and recover submitted drain attempts using metadata stored in SQLite.

Drain restore completion preserves NUT-09 output identities and uses the shared
exact restore/signature validators with persisted output secrets and historical
keys. Invalid or empty restore results preserve the submitted reservation.
Terminal drain proof storage uses an atomic conditional update: repeated identical
completion is idempotent, conflicting proof payloads fail, and late failure cannot
release a completed drain's channels. These guards are not full-operation
singleflight or an immutable execution-history journal on their own. The drain
orchestrator now supplies both: a versioned identity/input/fee-bound journal is
inserted atomically with channel reservations. Every request and submission count
is retained; a single typed initial 4xx/12002 may authorize a retained-predecessor
successor. Exact restore and all-input Unspent checks gate bounded replay.
Verified Finalizing payloads permit offline completion, with terminal custody
remaining in the relay DB. Matching exclusive maintenance authority and journal
CAS protect the full operation, not just completion.

Receiver close uses a separate versioned exact-request journal. Storage freezes
the accepted payment with Closing and the journal atomically, rejecting later
payments. The request is authenticated against persisted funding/payment/receiver;
each submission first records uncertainty. Recovery verifies exact historical
restores and all input states before bounded replay. One initial typed 4xx/12002
may authorize a retained-predecessor output-keyset successor, never an ambiguous
replay rejection. Verified finalizing data precedes the atomic Closed/payout
commit, allowing offline completion. Expiry does not invalidate the receiver's
signed spending branch. Wallet ownership is retained by derived payment handles,
with per-channel close singleflight plus durable journal CAS.

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

#### 7. Session State Matrix

Bootstrap version/capability negotiation occurs inside the two Noise handshake
payloads. After Noise, the peers start H2, open `POST /control`, and the relay
sends the initial `SessionStatus`; there is no post-H2 `Hello` message.

```text
Connect
   |
   v
Noise bootstrap negotiation -> H2 -> POST /control -> initial SessionStatus
   |
   v
+-----------------------------------------------------------------------+
|                         SESSION STATE MATRIX                          |
|                                                                       |
|                       UNLINKED                         LINKED          |
|               +-------------------------+  Link  +--------------------+|
|     PAUSED    |     Unlinked / Paused   |------->|   Linked / Paused  ||
|   (Bal <= 0)  |  (Initial / Exhausted)  |<-------|   (Awaiting Pay)   ||
|               +-------------------------+ Evict  +----------+---------+|
|                         ^                                  | Payment   |
|                         |                                  v           |
|               +-------------------------+  Link  +----------+---------+|
|     ACTIVE    |     Unlinked / Active   |------->|   Linked / Active  ||
|   (Bal > 0)   |       (Evicted)         |<-------|   (Normal Flow)    ||
|               +-------------------------+ Evict  +--------------------+|
+-----------------------------------------------------------------------+
   |
   v
control detach -> ownership release and session teardown
```

Usage can move either active state back to its corresponding paused state. That
fast-path transition updates the pause watcher but does not itself send a
`SessionStatus`.


## Blinded Routing

### Compact Route Configuration

Configured route lists serialize the existing `PathNode` model as strings:
`<key>::<clear-address>` or `<key>:B:<data>`. Keys reuse the standard `npub` /
64-hex x-only parser and serialize as lowercase hex. Clear addresses are opaque,
length-delimited UTF-8 strings: parsing, Serde, serialization, and offline path
construction preserve them byte-for-byte without endpoint parsing, bracket
insertion, normalization, or a default port. They are nonempty, NUL-free, and
bounded to 975 bytes so the same value can fit in a blinded payload. The first
hop is clear, and each blinded node retains the same predecessor/hidden-target
semantics as the low-level path constructor.
The configured runtime maps these nodes to the existing QUIC `RouteHop`s;
library TCP routes and all Noise/H2 nesting remain unchanged.
Library callers use `FromStr`, Serde, or fallible `PathNode::to_compact_string()`;
encoding validates hand-built nodes too, rather than using an infallible
`Display` implementation for publicly constructible, potentially oversized data.

The blinded key outside the blob is the hidden target's tweaked x-only key.
The canonical unpadded base64url blob decodes to this version-0 binary envelope:

| Bytes | Meaning |
| --- | --- |
| 0 | Envelope version, exactly `0` |
| 1..=33 | Full compressed ephemeral secp256k1 ECDH point, including 02/03 parity |
| 34..=35 | Ciphertext length, unsigned 16-bit big-endian |
| 36.. | Exactly that many ciphertext bytes, including the existing AEAD tag |

Ciphertext is bounded to 50..=1024 bytes (the minimum is a 32-byte tweak,
one parity byte, one nonempty address byte, and a 16-byte tag). The maximum
decoded envelope is 1060 bytes, or 1414 unpadded base64url characters. The parser
bounds encoded input before allocation and rejects unknown versions, invalid
points, noncanonical encoding, truncation and trailing bytes. The hidden address,
tweak and tweak parity remain inside the existing authenticated ciphertext;
the client cannot validate that plaintext. No extra address or introduction
key is needed in the envelope because the preceding route entry supplies the
introduction session. Consecutive blinded hops still encrypt to the real
predecessor identity, as required by the relay resolver.

This is a configuration/publication envelope version, independent of the
bootstrap version, `blinded_connect_v1`, `tweaked_noise_v1`, and the existing
blinded AEAD domain labels. No CONNECT headers or cryptography change.
`monad-client blind-route` uses `build_path` offline and serializes its nodes
directly into a YAML route block; it needs only public clear hop inputs.

Endpoint semantics apply only when an address is dispatched by the current
TCP/QUIC transports. At that boundary MONAD requires DNS or IPv4 `host:port`, or
bracketed IPv6 `[address]:port`, with an explicit numeric port in 1..=65535.
This check covers first-hop connections, ordinary nested CONNECT forwarding,
relay TCP/QUIC egress, and decrypted blinded next-hop addresses. The special
blinded CONNECT descriptor authority is not treated as a network endpoint; its
decrypted address is validated instead.

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
- public-key-only blinded-hop construction with a parity flag for MONAD's
  secp256k1 x-only identity model
- reverse-tweak recovery of the original secp256k1 x-only public key from
  `(tweaked_pubkey, tweak, parity_flag)`
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
  `[next_hop_tweak:32][l_prime_y_is_odd:1][next_hop_addr:utf8...]`

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
- whether the pre-normalization tweaked point had odd Y

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
plaintext = (next_hop_address, next_hop_tweak, l_prime_y_is_odd)
ciphertext = Encrypt(key, plaintext)
```

The current binary payload layout is:

```text
[next_hop_tweak:32][l_prime_y_is_odd:1][next_hop_addr:utf8...]
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

Let the next relay's real private scalar be `s`, real public key be `S = s*G`,
and tweak scalar be `t`. The path constructor needs only `S`, not `s`.

Then:

```text
L' = S + t*G
L  = even-Y representative of L'
```

The client sees only the x-only encoding of `L`, not `S` and not `t`. The
encrypted blob contains `t` and one flag recording whether `L'` had odd Y.

The receiving relay applies the tweak on its private side before serving the
Noise handshake:

```text
candidate_secret = s + t

if candidate_secret * G has even Y:
    responder_secret = candidate_secret
else:
    responder_secret = -candidate_secret
```

This lets the target relay derive the private key matching the client-visible
even-Y `L` without revealing `s` to the path constructor.

The introduction relay needs the encrypted parity flag to recover the original
long-lived public key for relay-to-relay QUIC authentication:

```text
if L' had even Y:
    real_public = L - t*G
else:
    real_public = -L - t*G
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

Within one relay `RelaySession`, control handling, outbound CONNECT setup, and
data proxies are directly owned futures in a `FuturesUnordered`, polled alongside
the H2 accept driver. They are not separately spawned tasks. Dropping or unwinding
the session future synchronously drops those children; awaiting an aborted
session task therefore establishes quiescence of its control/setup/data futures.
This is deliberately different from a `JoinSet` drop, which only requests abort
of independently scheduled tasks. It does not strengthen the listener's separate
connection-task ownership contract.

Successful link validation records ownership synchronously before the reducer's
next await. Session drop cancels the termination token, conditionally releases
all still-recorded channel ownership for that session ID, and deregisters the
session. Cleanup is idempotent and cannot release a replacement owner's channel.
No journal state or durable funding reservations are discarded.

CONNECT setup has a 10-second budget for TCP, QUIC, or blinded QUIC (including
tweak write/flush), without blocking H2 acceptance or control progress. Setup
completion rechecks pause/termination before sending 200. Session cancellation
drops pending setup, so it cannot publish a tunnel later. Proxy cancellation
covers the complete bidirectional operation, including blocked writes, shutdown,
and H2 capacity waits; ordinary EOF still preserves the opposite half of the
connection. Control cancellation similarly covers bootstrap and message writes.
Per-tunnel accounting drop guards close counters and log byte totals on normal
completion, cancellation, and unwinding.

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

MONAD does not provide Tor-style anonymity guarantees. Each client maintains its
own logical Noise+H2 hop chain, although many such sessions can share pooled
relay-to-relay QUIC connections and therefore some transport packets. There is no
padding, batching, cover traffic, or anonymity-set guarantee, so this remains a
layered multi-hop paid proxy rather than a full anonymity network.

## Current Transport Identity Model

MONAD transport now uses secp256k1 throughout.

- **Plain TCP MONAD transport** uses secp Noise.
- **QUIC MONAD transport** uses secp attestation plus secp Noise.

Configured clients store one secp256k1 transport identity per YAML route hop.

On the relay side, startup still takes both:

- a 32-byte **Ed25519 seed** for QUIC certificate generation
- a 32-byte **secp256k1 transport private key** for MONAD TCP and QUIC transport auth

The secp256k1 transport key is used directly for:

- **TCP MONAD transport** via `Noise_NK_secp256k1_ChaChaPoly_BLAKE2s`
- **QUIC secp auth** via the attestation stream
- **QUIC secp MONAD sessions** via secp Noise on `STREAM_KIND_SECP_NOISE`

The Ed25519 seed is retained only for QUIC/TLS certificate plumbing.

### Public-Key Representation

The configured secp256k1 transport identity is a 32-byte x-only public key with
implied even Y. Code that needs a full point reconstructs the corresponding
33-byte compressed SEC1 point internally.

So today:

- the client stores one transport public key per hop
- the secp path uses the secp public key directly for both TCP MONAD transport and QUIC attestation

Ed25519 is retained only because the current standards-compliant QUIC/TLS stack
still needs a conventional certificate path for the TLS handshake; MONAD then
layers secp attestation above that encrypted channel.

## QUIC Transport Between Hops

### Motivation

Plain TCP nesting creates a dedicated relay-to-relay connection for each client
chain. Configured routes instead use pooled QUIC between hops.

For example, if many clients route through the same pair of relays:

```text
Client A -> Relay S -> Relay T -> ...
Client B -> Relay S -> Relay T -> ...
Client C -> Relay S -> Relay T -> ...
```

then a plain-TCP route opens a separate TCP connection from S to T for each
client, while configured QUIC routes multiplex those sessions as streams.

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
- small writes from multiple streams can be coalesced into encrypted QUIC packets

### Layering: QUIC Replaces TCP, Not Noise

QUIC provides the encrypted transport between relays. It does **not** replace the Noise nesting that protects client-to-hop sessions.

Consider a 2-hop library/manual route where client C reaches relay S over TCP and
then uses the configured QUIC connector to relay T:

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

Configured relay startup binds TCP and QUIC listeners from each YAML relay entry.
`quic_cert_seed` supplies certificate-generation material and `transport_key`
supplies the secp transport key; there is no separate runtime `--quic` enable flag.

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

### Configured Client QUIC Hops

Configured client routes use 32-byte x-only secp256k1 identities from YAML
route entries. The configured runtime currently uses QUIC for each hop. For
non-first hops, the client includes `quic-secp256k1-pubkey` in the CONNECT
request to the previous relay. On the first hop, the client connects directly
via QUIC instead of TCP.

Example 2-hop route where the second hop uses QUIC:

```yaml
clients:
  - name: local
    socks: 127.0.0.1:1080
    route:
      - "<S_pubkey>::10.0.0.1:9050"
      - "<T_pubkey>::10.0.0.2:9050"
```

The client:
1. Connects to S at `10.0.0.1:9050` via QUIC with secp256k1 attestation, then runs secp Noise+H2 over that QUIC stream
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

MONAD deliberately uses no QUIC keep-alives: idle connections are meant to die and be re-established on demand (the pool evicts a dead connection on the next failed stream open and reconnects fresh). Both sides set a 20s QUIC idle timeout, which also bounds silent peer-death detection at the transport layer. Above QUIC, the client's session heartbeat (status request after 5s idle, 15s timeout) provides MONAD-level detection of an unresponsive session, so active sessions keep their transport warm without transport-level keep-alives.

Relay QUIC stream sessions are tracked under the accepting connection task with a per-connection `JoinSet`. Graceful shutdown waits for active connection tasks, while abrupt task cancellation drops the connection's stream task tree. This keeps stream sessions from outliving their connection and prevents detached stream tasks from holding the QUIC endpoint socket open after an ungraceful relay loss.

### What Has Been Integrated

The full QUIC transport chain is implemented and tested:

1. **`QuicStream` type in `monad-quic`** — wraps a quinn bidirectional stream as `AsyncRead + AsyncWrite`, used interchangeably with `TcpStream`
2. **QUIC listener in `monad-relay`** — binds a UDP socket on the same port as the TCP listener, accepts QUIC connections, feeds incoming streams into the existing Noise+H2 session handler
3. **Dual transport identity plumbing in `monad-relay`** — `monad-relay keygen` emits both an Ed25519 identity set for QUIC certificate generation and a secp256k1 transport key for MONAD transport auth.
4. **QUIC transport header parsing in `monad-relay`** — detects `quic-secp256k1-pubkey` on CONNECT requests and connects via secp-authenticated QUIC instead of TCP
5. **QUIC connection pool in `monad-relay`** — maintains shared QUIC connections keyed by `(host, port)`, reuses across client sessions
6. **configured QUIC route handling in `monad-client`** — uses YAML route hop identities, emits `quic-secp256k1-pubkey` for nested QUIC hops, and uses secp256k1 directly for transport auth
7. **Integration tests** — cover QUIC single-hop, QUIC with control+data channels, nested QUIC tunnels (manual and via connector), alongside all existing TCP tests

## Current Limitations

- client wallet funding UX is not yet fully wired: mint quotes, premint submission, richer balance inspection, and client close/sweep flows still need commands.
- configured-client startup still fails fast before the first successful route connect; after a route has connected once, reconnects retry indefinitely with capped backoff while SOCKS stays alive.
- QUIC connection pool entries are only evicted lazily (on failed stream open) plus transport idle timeout; there is no proactive stale-entry cleanup.
- configured mint/unit advertisements currently share the relay session's pricing
  rates rather than carrying independently configured rates per offer.
