# MONAD Design

*Implementation status: September 6, 2026.*

MONAD, the **Monetized Onion Network Access Daemon**, is a paid multi-hop TCP
tunneling system. It is similar in broad shape to a VPN or Tor: applications
use a local proxy, and the client can send their TCP connections through one or
more relays. Unlike a conventional VPN, each **MONAD relay** -- a server in
this network, unrelated to a Nostr relay -- is paid directly in Cashu for the
bytes it forwards. Hereafter, this document uses "relay" to mean a MONAD relay.

This is the high-level design for a developer joining the project. It explains
the major concepts and their rationale, not every wire format or recovery path.
For those details, see [ARCHITECTURE.md](ARCHITECTURE.md),
[Payments and Funding](docs/payments.md).

## The User-Facing Model

`monad-client` exposes a local SOCKS5 proxy. A browser, SSH client, or any
other SOCKS5-capable application connects to that proxy normally; it does not
need to know that MONAD exists. SOCKS5 is also the familiar user-space boundary
used by Tor.

The simplest route has one relay. The client asks that relay to connect to the
requested TCP destination, much like using a VPN exit. A user may instead
choose a chain of relays. In a three-hop route, the client reaches relay 2
through relay 1, and relay 3 through the tunnel to relay 2. Normally
the last relay is the exit, although the client can make a destination
connection through any relay for which it holds a session.

The privacy benefit is limited but useful: an intermediate relay sees the next
relay, not the final destination or application traffic. MONAD is not Tor. It
does not pad messages, normalize packet sizes, or otherwise attempt to resist
traffic analysis.

## Sessions And Streams

A **session** is the client-to-relay relationship that carries encrypted,
multiplexed traffic. After its encrypted transport is established, a session
uses one HTTP/2 connection with two kinds of stream:

- A single `POST /control` stream manages session status and payments.
- Any number of HTTP/2 `CONNECT` streams ask the relay to open an onward
  connection. This is usually a TCP connection to a destination such as a web
  server or SSH host, but it can also be a QUIC connection to the next MONAD
  relay in a chain, or a blinded-route instruction rather than a real address.

This lets one session carry many application connections without making a new
encrypted connection for each one. The control stream is deliberately separate
from data streams: it remains available for payment and session management even
when the session is paused and new `CONNECT` requests are not allowed.

## Nesting Creates Multi-Hop Routes

A relay connection is itself an ordinary bidirectional byte stream. MONAD turns
an H2 `CONNECT` stream into the transport for another full MONAD session:

```text
application
  -> SOCKS5 -> client
    -> Noise + H2 session with relay 1
      -> CONNECT relay 2
        -> Noise + H2 session with relay 2
          -> CONNECT relay 3
            -> Noise + H2 session with relay 3
              -> CONNECT final destination
```

The client therefore has a separate session with each relay. Relay 1 only
proxies the encrypted client-to-relay-2 session; it cannot read that session's
control messages, destination requests, or application bytes. This recursive
construction is the central onion-routing property of MONAD, and it avoids
inventing a separate tunnel protocol for intermediate hops.

## Encryption And Relay Authentication

HTTP/2 never runs directly over the network. Each MONAD session wraps it in a
Noise `NK` handshake and encrypted transport using secp256k1 Diffie-Hellman,
ChaCha20-Poly1305, and BLAKE2s.

Noise serves two purposes at once:

- It agrees fresh transport keys for the client and the relay.
- It authenticates the relay to the client with the relay's long-lived
  secp256k1 transport key, while requiring no long-lived client identity.

Today a relay identity is a 32-byte x-only secp256k1 public key, conventionally
configured as 64 hexadecimal characters, plus some reachable address. MONAD
does not prescribe how the client discovers that address or key; it only checks
that the reachable peer proves possession of the configured key.

The two Noise handshake payloads also carry MONAD's bootstrap negotiation. The
client offers the post-handshake protocol, maps each supported Spilman channel
version to supported keyset-format versions, and offers pricing policies. The
relay selects one compatible Spilman version plus the full mutual keyset-format
set, or rejects the session before HTTP/2 starts. This makes protocol upgrades
explicit rather than allowing two peers to establish a session and later
disagree about its meaning.

## TCP And QUIC

MONAD supports TCP and QUIC as outer transports for the client-to-first-relay
hop. Between two MONAD relays, the connection is always QUIC: QUIC replaces TCP
there, but it never replaces the nested Noise session.

When relay A forwards sessions to relay B, it reuses one pooled QUIC connection
and opens a separate QUIC stream for each session. To an outside observer there
is a single encrypted QUIC connection between the relay pair. Inside it, each
stream carries a session that is independently encrypted: a Noise session
between the original client and the destination relay. The result is two nested
levels of encryption and multiplexing between the relays: QUIC provides
transport encryption and stream multiplexing; each stream contains a
client-to-relay Noise session, which in turn carries multiplexed HTTP/2.

Because many users' sessions can share that encrypted QUIC connection, the link
also gains a modest degree of mixing: an observer sees one busy connection
rather than cleanly separable per-user traffic. MONAD does not extend this
across the network, and does not pad or shape timing, so this is a side benefit
of the transport rather than a full anonymity set.

QUIC peers additionally authenticate their relay transport identities. TLS
certificate plumbing is an implementation detail, not MONAD's primary
application identity model; the long-lived MONAD transport identity remains
secp256k1.

## Paying Relays

MONAD is natively denominated in millisatoshis (`msat`). A relay advertises how
many inbound and outbound bytes it will forward per millisatoshi, and may set
different rates for each direction. A payment in sats is converted to its
equivalent number of millisatoshis.

The relay accounts for the session's total inbound and outbound bytes and
derives the amount due from its advertised prices. The client receives the
relay's authoritative status over the control stream and keeps the session
funded ahead of that amount. A session starts paused with zero balance; its
control stream remains free, but the relay accepts `CONNECT` streams only while
the total accepted payment to the session is greater than the total amount due.

Payments use Cashu Spilman channels. At a high level, a channel commits Cashu
value to a relay and lets the client authorize monotonically increasing payment
claims against that committed value. The client can therefore make frequent,
small payment updates without opening a new Cashu channel for every amount due.
The relay validates the update and credits only the newly authorized delta. Once
a channel is established, each payment is a small signed authorization sent over
the control stream; no communication with the mint is needed because the relay
can validate the signature itself.

There are two primary control messages:

1. `ChannelLink` associates one channel with a session after the client has
   opened it.
2. `ChannelPayment` advances that linked channel's cumulative payment balance.

Only one channel is linked to a session at a time, but a session's accepted
payment total spans every channel that has been linked to it. When the current
channel is exhausted, the client opens and links a replacement, then continues
funding the same session.

If the control stream or transport dies, the session ends. MONAD does not try
to resurrect the exact session or refund its remaining prepaid balance. This is
intentional: Cashu channels allow the client to keep its funding buffer very
small. For example, a client that tops up around every five seconds can bound
its expected loss from a dead session to roughly five seconds of service.

## Durable Wallets

Cashu value is stateful enough that a successful network request with a lost
response must be treated as a normal failure mode. Both MONAD wallet sides use
SQLite as their durable recovery source of truth. The key rule is simple: a
mint operation is fully prepared and persisted before it is submitted, and a
record is not marked complete until the resulting value is in local custody.

On the relay side, each accepted `ChannelPayment` is validated and persisted as
a monotonic channel-balance update. After a relay restart, a client can relink
the same channel and delta accounting resumes from that stored balance. Relay
channel closes likewise persist the validated close state and its receiver-side
proofs. One SQLite database can safely serve multiple MONAD relays while storing
which relay wallet owns each channel.

The relay's most important ambiguous-submit path is a **drain**: swapping the
receiver proofs accumulated from closed channels into fresh proofs at a mint.
Before the swap request is sent, the relay atomically stores the exact prepared
swap and restore requests, output secrets, selected keyset data, and reservations
for every input channel in one SQLite transaction. It marks that record
`Submitted` before the network call. If the relay dies after submission but
before it sees the response, the operator can run `monad-relay wallet
recover-drain` to restore the exact persisted outputs instead of attempting a
new, potentially conflicting swap.

The client has the same discipline. It persists channel-opening recovery data
before submitting a funding swap, so `recover-openings` can resolve an ambiguous
open rather than lose the funding proofs. For expired-channel refunds, it saves
the exact prepared refund, marks it `submitting` before contacting the mint, and
imports recovered proofs into the loose-proof wallet before marking the channel
closed. Those imports are idempotent, so a restart at any point can repeat the
safe recovery path. NUT-07 state checks and the funding proof's witness shape
distinguish an expiry refund from a relay-initiated close. Client proof
reservations also use `IMMEDIATE` SQLite transactions, preventing concurrent
session drivers from selecting the same proofs.

See [Payments and Funding](docs/payments.md) for the complete state machines,
recovery orderings, and wallet responsibilities.

## Blinded Routes

Normal MONAD routes give the client every relay's address and public key. The
implemented blinded-route machinery lets a service publish a route whose first
hop is public but whose later hops are opaque.

For each blinded hop, the client receives a tweaked public key, an ephemeral
public key, and an encrypted blob. The immediately preceding relay can decrypt
that blob to learn the real address of the next relay and the key tweak needed
to establish the next nested session. The client can authenticate the next
session using the tweaked key without learning that relay's real identity or
address.

The cryptographic construction and end-to-end route path are implemented and
tested. It is newer and less operationally polished than ordinary configured
routes, so it should be treated as an advanced capability rather than the
default deployment path. See [Blinded Routing](ARCHITECTURE.md#blinded-routing)
for the construction and exact privacy properties.

## What MONAD Does Not Promise

MONAD provides hop-by-hop encryption, nested multi-hop routing, and destination
hiding from intermediate relays. It does not provide the anonymity guarantees
of a mature anonymity network:

- The client chooses the route; MONAD does not provide a directory, relay
  selection algorithm, or reputation system.
- Message sizes and timing are not padded or shaped.
- The exit relay necessarily sees the requested destination and plaintext TCP
  application traffic unless the application supplies its own end-to-end
  encryption.

## Next Steps

Most of this design is implemented and covered by unit, integration, and stress
tests. Important work still includes:

- Accepting Nostr-style bech32 `npub` encodings for relay public keys alongside
  the current 32-byte x-only hexadecimal form. Both represent the same public
  key material.
- Maturing blinded-route configuration, publication, and operational tooling.
- Improving user-facing wallet operations such as mint quotes, proof minting,
  and richer balance visibility.
- Continuing transport, payment, and relay-restart stress testing as the
  network model evolves.

## Further Reading

- [README.md](README.md): installation, configuration, and everyday use.
- [ARCHITECTURE.md](ARCHITECTURE.md): protocol details, state machines, wire
  behavior, transport internals, and privacy analysis.
- [Payments and Funding](docs/payments.md): the session driver, relay payment
  authority, wallet integration, and funding invariants.
