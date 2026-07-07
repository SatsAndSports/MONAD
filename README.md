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
- `monad-relay`: accepts client connections, performs Noise handshake, runs an H2 session, proxies `CONNECT` tunnels, enforces per-session billing with pause/resume, keeps a shared in-memory cache of configured mint keysets, and persists relay-side Spilman channel state in SQLite
- `monad-client`: provides reusable route selection, the session payment driver, a SQLite-backed channel wallet, a loose-proof wallet, and multi-hop connection setup
- `monad-common`: shared Noise transport (with session ID from handshake hash), H2 stream helpers, control protocol types (`ClientMessage`/`ServerMessage`), session and billing types (`RelayConnection`, `SessionPricing`, `SessionSpilmanInfo`), shared bidirectional proxy
- `monad-quic`: shared QUIC transport code plus standalone echo tooling — `QuicStream`, secp attestation helpers, echo server/client, and shared config/keygen helpers used by relay and client
- `monad-test-client`: localhost SOCKS5/manual test harness for mocked relay funding, circuit rebuild testing, and daily-driver browser/SSH experiments
- QUIC hop support: relay dual TCP+UDP listener, QUIC connection pool, `--hop quic:` client syntax, and `quic-secp256k1-pubkey` H2 header for CONNECT forwarding
- Noise-payload bootstrap: MONAD uses the Noise `NK` pattern over secp256k1 with ChaCha20-Poly1305 and BLAKE2s; the client sends a bootstrap request in the first Noise handshake payload, the relay replies in the second, and today this strictly negotiates the post-handshake session protocol (`h2`), the Cashu Spilman channel protocol version (`2026-03-20`), and the pricing policy (`session_constant`) before H2 starts
- deterministic developer tooling: pinned Rust toolchain, repo-local rustfmt config, `Makefile`, and GitHub Actions checks for formatting and tests
- session payment system: paused-by-default sessions, initial `SessionStatus` after control stream establishment, totals-based billing with directional pricing, pause/resume enforcement, `ChannelLink`, `ChannelPayment`, and `ChannelEvicted`
- relay-authoritative linked-channel sync: `SessionStatus` includes the currently linked channel's id, latest accepted cumulative balance, capacity, and unit
- relay-side session FSM for steady-state control handling and full teardown on control-stream detach
- in-process relay wallet manager: multiple hosted relays can share one SQLite-backed relay wallet database while keeping distinct Cashu receiver keys / wallet names
- client-side direct control-loop funding logic for per-session channel acquisition, linking, and payments, with periodic local cleartext-counter checks sizing payments against the latest authoritative relay baseline
- client wallet library path: `SqliteClientWallet` manages Spilman channels, `LooseProofWallet` stores spendable Cashu proofs, and `session_driver` handles per-session linking and payments; `MockWallet` remains for tests and connector harnesses
- blinded-hop routing over QUIC: `CONNECT blinded.monad.invalid:443`, tweak-prefixed QUIC forwarded sessions, `RouteHop` / `Route` connector support, reverse-tweak key recovery, and deterministic adjusted-tweak derivation for MONAD's x-only secp256k1 identity model
- integration tests for direct, nested, IPv6, hostname-resolution, TCP secp transport, QUIC single-hop, QUIC nested tunnels, mixed TCP/QUIC hop chains, and the session payment / pause / resume lifecycle

Not implemented yet:
- usable `monad-client` CLI runtime wired to the SQLite client wallet
- user-facing client wallet commands for mint quotes, proof minting, and richer balances
- persistent route configuration file

## Relay Wallet

`monad-relay` now uses a named relay-wallet identity inside a shared SQLite relay-wallet database.  Relay configuration lives in a single YAML file; one file can describe many relays, and each relay process selects its relay with `--relay <name>`.

Example `monad.yaml`:

```yaml
wallets:
  relay:
    db_path: /var/lib/monad/relay.db
  client:
    loose_db_path: /var/lib/monad/client-loose.db
    channel_db_path: /var/lib/monad/client-channels.db
    wallet_name: default
    sender_secret_hex: "${MONAD_CLIENT_SENDER_KEY}"
    channel_input_budget_msats: 1000000
    target_topup_buffer_msats: 10000000
    minimum_topup_msats: 0

management:
  listen: 127.0.0.1:9090

relays:
  - name: relay-a
    receiver_secret_hex: "${MONAD_RELAY_A_RECEIVER_KEY}"
    quic_cert_seed: "${MONAD_RELAY_A_QUIC_SEED}"
    transport_key: "${MONAD_RELAY_A_TRANSPORT_KEY}"
    listen: 127.10.0.11:9050
    trusted_mints:
      - url: https://dev.mint.camelus.app
        units: [sat]
    pricing:
      in_bytes_per_millisat: 1
      out_bytes_per_millisat: 1

clients:
  - name: local
    socks: 127.10.0.1:1080
    route:
      - addr: 127.10.0.11:9050
        pubkey: "${MONAD_RELAY_A_TRANSPORT_PUBKEY}"
```

Environment variables are substituted from the process environment or from a `.env` file in the same directory as the config.  Defaults are supported: `${VAR:-default}`.

Run the relay:

```bash
monad-relay run --config monad.yaml --relay relay-a
```

Inspect the shared relay-wallet DB:

```bash
monad-relay wallet --config monad.yaml --relay relay-a list
monad-relay wallet --config monad.yaml --relay relay-a show
monad-relay wallet --config monad.yaml --relay relay-a channels
monad-relay wallet --wallet-db-path /var/lib/monad/relay.db close --channel-id <channel-id>
monad-relay wallet --config monad.yaml --relay relay-a drains
monad-relay wallet --config monad.yaml --relay relay-a drain --mint-url https://dev.mint.camelus.app --unit sat
monad-relay wallet --config monad.yaml --relay relay-a recover-drain --drain-id <drain-id>
```

Add `--json` to any wallet command for machine-readable output.

On first start, `receiver_secret_hex` is required so the relay can register its identity in the wallet database.  On later restarts of the same relay wallet identity, omit `receiver_secret_hex`; the relay will load the existing receiver key for `relay-a` from the shared wallet DB.

All configured relays share `wallets.relay.db_path` safely because each relay uses a distinct receiver key, so their channel rows are disjoint.  The config loader rejects any two relays that share the same `receiver_secret_hex`.

## Client Wallet

The reusable client wallet pieces exist in `monad-client`. The binary exposes
wallet admin/funding/recovery commands and can run a configured QUIC SOCKS
client with `monad-client run --config monad.yaml --client <name>`.

- `LooseProofWallet` stores loose Cashu proofs, mint quote state, premint batches, reservations, and spend/release state in SQLite.
- `SqliteClientWallet` uses those loose proofs to provision Spilman channels via upstream `cdk-spilman`, stores MONAD channel metadata including expiry timestamps in SQLite, and implements `MonadWallet` for the session driver.
- opening recovery is persisted for ambiguous funding-swap failures and can be recovered through upstream restore.
- output keyset selection is cache-first: the wallet ensures its mint/unit keyset cache is non-empty before entering the keyset retry helper, then selectors read cache only; refresh happens after retryable mint keyset rejection.

`wallets.client.channel_input_budget_msats` controls the loose-proof input budget for each newly provisioned channel. It is not a guaranteed channel capacity; fees and deterministic channel outputs can make the resulting capacity lower. The default is `1000000` msats.

`wallets.client.target_topup_buffer_msats` controls the positive session balance the client tries to restore when funding is needed; the default is `10000000` msats. `wallets.client.minimum_topup_msats` sets a lower bound for normal topups; the default is `0` msats.

Current admin/recovery commands use explicit DB paths and sender key material:

```bash
monad-client wallet \
  --loose-db ~/.monad/client-loose.sqlite \
  --channel-db ~/.monad/client-channels.sqlite \
  --sender-secret-hex <hex> \
  --wallet-name default \
  channels

monad-client wallet \
  --loose-db ~/.monad/client-loose.sqlite \
  --channel-db ~/.monad/client-channels.sqlite \
  --sender-secret-hex <hex> \
  proofs

monad-client wallet \
  --loose-db ~/.monad/client-loose.sqlite \
  --channel-db ~/.monad/client-channels.sqlite \
  --sender-secret-hex <hex> \
  import-token --token <cashu-token>

monad-client wallet \
  --loose-db ~/.monad/client-loose.sqlite \
  --channel-db ~/.monad/client-channels.sqlite \
  --sender-secret-hex <hex> \
  import-token --token-file ./token.txt

monad-client wallet \
  --loose-db ~/.monad/client-loose.sqlite \
  --channel-db ~/.monad/client-channels.sqlite \
  --sender-secret-hex <hex> \
  recover-channel --channel-id <channel-id>

monad-client wallet \
  --loose-db ~/.monad/client-loose.sqlite \
  --channel-db ~/.monad/client-channels.sqlite \
  --sender-secret-hex <hex> \
  recover-openings
```

Add `--json` to wallet commands for machine-readable output.

Remaining client-wallet work is operator/user experience rather than the core channel-payment library path: mint quote/mint commands, startup wiring for SOCKS operation in `monad-client`, richer proof balance inspection, and close/sweep flows.

## Workspace

```text
monad-common/     Shared transport and protocol helpers
monad-client/     Client library, wallet/driver logic, and binary entrypoint
monad-relay/      Relay binary and library
monad-quic/       Shared QUIC transport code plus standalone echo tooling
monad-test-client/ Local SOCKS5/manual test harness with mocked funding
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

The `Makefile` also includes named manual stress recipes for:
- transport-focused stress (`make stress-transport-extreme`)
- repeated `ChannelPayment` stress on one linked channel (`make stress-payment-buffered`)
- repeated relink stress with one active channel per session at a time (`make stress-payment-relink`)

These stress recipes expect a high `ulimit -n` and are intended for developer load testing rather than routine CI. The main client now uses timer-driven local counter checks for payment sizing; the stress recipes still use frequent `GetSessionStatus` polling intentionally to exercise relay control-plane behavior under load.

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
- connector blinded hop route (`RouteHop::Blinded`)
- connector two-consecutive-blinded-hop route
- connector hard-fails when a relay lacks required blinded/nested capability bits
- concurrent QUIC pool access
- client QUIC first hop (direct QUIC connection from client)
- QUIC first hop then TCP second hop
- TCP secp single-hop and nested plain-CONNECT secp tunnels
- session funding and incremental payments via `ChannelLink` / `ChannelPayment`
- relay advertises multiple mint/unit pricing options
- control detach releases linked channels and tears down active / future streams
- changing a relay's current trusted mint policy stops new advertisement/acceptance for that mint without invalidating previously stored channels

Relay keyset handling is deliberately simple: each relay wallet manager owns one shared in-memory `SpilmanMintCache` populated from configured mint URLs. The cache stores all keysets returned by those mints, active and inactive, for all units the mint reports. The relay applies its configured trusted mint/unit policy only when advertising options or accepting incoming channel funding/payments. Channel close and relay drain swaps start from the shared cache; if the mint rejects a swap with a keyset error, the retry path refreshes that mint into SQLite and the shared cache before re-preparing the swap.

## Payment Code Map

The canonical client funding implementation lives in `monad-client/src/session_driver/`:

- `session_driver.rs` exposes `PaymentPolicy` and `start_session_payment_driver(...)`
- `runtime.rs` runs the serialized control loop
- `state.rs` holds local driver state and publishing helpers
- `funding.rs` handles channel selection, link, payment, eviction, and recovery
- `payment.rs` holds payment math and relay/client safety checks

Shared protocol helpers used by client, relay, and harness code live in:

- `monad-common/src/control_codec.rs` for newline-delimited control messages
- `monad-common/src/payment_units.rs` for `msat` / `sat` raw-unit conversion

For maintainers, the most focused reference is `docs/payments.md`. `ARCHITECTURE.md`
stays the higher-level protocol overview, and `WALLET.md` covers wallet/backend
responsibilities.

## Transport Identities

MONAD transport now uses secp256k1 identities throughout:

- **TCP MONAD transport** uses secp Noise with 32-byte x-only relay identities
- **QUIC MONAD transport** uses secp attestation plus secp Noise with the same 32-byte x-only relay identities

The `monad-client` binary emits and accepts only secp256k1 hop identities. The
relay still keeps an Ed25519 seed internally for QUIC certificate generation,
but that is no longer a client-facing MONAD transport identity.

Identity model:
- long-lived relay identities are 32-byte x-only secp256k1 pubkeys with implied even Y
- blinded-hop tweaked pubkeys are also 32-byte x-only secp256k1 pubkeys, kept even via deterministic tweak adjustment
- ephemeral ECDH pubkeys remain 33-byte compressed curve points
- Noise DH operates on full curve points internally even though the configured relay identities are x-only

For QUIC, the relay first presents a self-signed Ed25519 certificate so the
standard TLS 1.3 handshake can establish an encrypted channel. MONAD then binds
that live QUIC channel to the configured secp256k1 transport identity by having
the relay sign a challenge plus QUIC exporter-derived keying material. Clients
verify that signature against the expected secp256k1 public key.

Quick reference:

| Transport | Hop syntax | Identity | Auth mechanism |
|-----------|-----------|----------|----------------|
| TCP | `addr:port,secp256k1:<pub>` | 32-byte x-only secp256k1 | secp Noise NK |
| QUIC (secp) | `quic:addr:port,secp256k1:<pub>` | 32-byte x-only secp256k1 | QUIC attestation + secp Noise NK |

## Quick Start

### 1. Generate keys for each relay

```bash
cargo run -p monad-relay -- keygen
```

This prints:
- an Ed25519 seed/public key used for QUIC certificate generation
- a secp256k1 transport private key plus its 32-byte x-only public identity for MONAD TCP and QUIC transport auth
- a QUIC certificate derived from the Ed25519 seed

### 2. Start one or more relays

Create a `monad.yaml` file.  A single file can hold the shared wallets, many relays, and one or more client route definitions. Each relay process selects one relay with `--relay <name>`.

```yaml
wallets:
  relay:
    db_path: /var/lib/monad/relay.db
  client:
    loose_db_path: /var/lib/monad/client-loose.db
    channel_db_path: /var/lib/monad/client-channels.db
    wallet_name: default
    sender_secret_hex: "${MONAD_CLIENT_SENDER_KEY}"
    channel_input_budget_msats: 1000000
    target_topup_buffer_msats: 10000000
    minimum_topup_msats: 0

relays:
  - name: hop1
    receiver_secret_hex: "${HOP1_RECEIVER_KEY}"
    quic_cert_seed: "${HOP1_ED25519_SEED}"
    transport_key: "${HOP1_SECP_KEY}"
    listen: 127.10.0.11:9051
    pricing:
      in_bytes_per_millisat: 1
      out_bytes_per_millisat: 1
    trusted_mints:
      - url: https://dev.mint.camelus.app
        units: [sat]

  - name: hop2
    receiver_secret_hex: "${HOP2_RECEIVER_KEY}"
    quic_cert_seed: "${HOP2_ED25519_SEED}"
    transport_key: "${HOP2_SECP_KEY}"
    listen: 127.10.0.12:9052
    pricing:
      in_bytes_per_millisat: 1
      out_bytes_per_millisat: 1
    trusted_mints:
      - url: https://dev.mint.camelus.app
        units: [sat]

clients:
  - name: local
    socks: 127.10.0.1:1080
    route:
      - addr: 127.10.0.11:9051
        pubkey: "${HOP1_SECP_PUBKEY}"
      - addr: 127.10.0.12:9052
        pubkey: "${HOP2_SECP_PUBKEY}"
```

The pricing fields are required for every relay entry and must be greater than zero.

Single relay:

```bash
RUST_LOG=info cargo run -p monad-relay -- run --config monad.yaml --relay hop1
```

Second relay:

```bash
RUST_LOG=info cargo run -p monad-relay -- run --config monad.yaml --relay hop2
```

Multi-hop example (run each in its own terminal / process):

```bash
RUST_LOG=info cargo run -p monad-relay -- run --config monad.yaml --relay hop1
RUST_LOG=info cargo run -p monad-relay -- run --config monad.yaml --relay hop2
```

### 3. Start the client

`monad-client wallet ...` exposes explicit-flag wallet inspection and recovery
commands. `monad-client run --config monad.yaml --client local` starts the
configured QUIC route and binds the configured SOCKS5 listener.

Configured client:

```bash
RUST_LOG=info cargo run -p monad-client -- run --config monad.yaml --client local
```

Direct connection:

```bash
RUST_LOG=info cargo run -p monad-client -- \
  --hop 127.0.0.1:9050,secp256k1:<SERVER_SECP256K1_PUBKEY> \
  --socks 127.0.0.1:1080
```

Three-hop chain:

```bash
RUST_LOG=info cargo run -p monad-client -- \
  --hop 127.0.0.1:9051,secp256k1:<HOP1_SECP_PUB> \
  --hop 127.0.0.1:9052,secp256k1:<HOP2_SECP_PUB> \
  --hop 127.0.0.1:9053,secp256k1:<HOP3_SECP_PUB> \
  --socks 127.0.0.1:1080
```

The eventual client runtime will listen locally as a SOCKS5 proxy on
`127.0.0.1:1080` by default.

QUIC hops:

```bash
RUST_LOG=info cargo run -p monad-client -- \
  --hop 127.0.0.1:9051,secp256k1:<HOP1_SECP_PUB> \
  --hop quic:127.0.0.1:9052,secp256k1:<HOP2_SECP_PUB> \
  --socks 127.0.0.1:1080
```

The `quic:` prefix tells the client to instruct the previous hop to connect via QUIC instead of TCP. The `monad-client` binary uses explicit `secp256k1:<pubkey>` transport identities for both QUIC and non-QUIC hops. See `ARCHITECTURE.md` for the full layering model.

QUIC first hop:

```bash
RUST_LOG=info cargo run -p monad-client -- \
  --hop quic:127.0.0.1:9051,secp256k1:<HOP1_SECP_PUB> \
  --socks 127.0.0.1:1080
```

The client connects directly to the first hop via QUIC, then runs the same Noise+H2 session on top using the secp QUIC path.

Blinded routes are currently exposed through the Rust library route model (`RouteHop::Blinded`) rather than the CLI `--hop` parser.

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

When a tunnel closes, the client and final relay log plaintext proxied bytes:

```text
tunnel closed: example.com:22 | outbound=63630 inbound=5200 total=68830
```

### Per-hop encrypted wire counts

Each `SecpNoiseStream` logs encrypted wire usage when the hop connection shuts down:

```text
SecpNoiseStream closed label=client hop 2/3 to 127.0.0.1:9052 wire_read=... wire_written=... wire_total=...
```

To see these, use debug logging for the Noise module:

```bash
RUST_LOG=monad_common::noise_secp256k1=debug,monad_client=info,monad_relay=info
```

### CONNECT visibility

Each relay logs every `CONNECT` request it receives:

```text
CONNECT 127.0.0.1:9052
CONNECT 127.0.0.1:9053
CONNECT satsandsports.cash:22
```

In a multi-hop chain, only the final hop sees the actual target. Intermediate hops only see the next hop.

## Graceful Shutdown

Both client and relay handle `Ctrl+C` gracefully:
- stop accepting new work
- wait briefly for active tunnels/sessions to finish
- shut down H2 connections cleanly
- emit `SecpNoiseStream` wire-byte totals

## QUIC Echo Tool

The `monad-quic` crate also includes a standalone QUIC echo server/client for transport testing and experimentation. The main MONAD client and relay now use shared code from this crate for QUIC support.

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
