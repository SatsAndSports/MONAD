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
- QUIC hop support: relay dual TCP+UDP listener, QUIC connection pool, configured client routes, and `quic-secp256k1-pubkey` H2 header for CONNECT forwarding
- Noise-payload bootstrap: MONAD uses the Noise `NK` pattern over secp256k1 with ChaCha20-Poly1305 and BLAKE2s; the client maps each supported Cashu Spilman channel protocol version to its supported keyset-format versions in the first handshake payload, and the relay selects one protocol plus the full mutual keyset-format set before H2 starts. Today `2026-09-14` supports `v1` and `v2` and requires a nonempty intersection, alongside `h2` and `session_constant` pricing
- deterministic developer tooling: pinned Rust toolchain, repo-local rustfmt config, `Makefile`, and GitHub Actions checks for formatting and tests
- session payment system: paused-by-default sessions, initial `SessionStatus` after control stream establishment, totals-based billing with directional pricing, pause/resume enforcement, `ChannelLink`, `ChannelPayment`, and `ChannelEvicted`
- relay-authoritative linked-channel sync: `SessionStatus` includes the currently linked channel's id, latest accepted cumulative balance, capacity, and unit
- relay-side session FSM for steady-state control handling and full teardown on control-stream detach
- in-process relay wallet manager: multiple hosted relays can share one SQLite-backed relay wallet database while keeping distinct Cashu receiver keys / wallet names
- client-side direct control-loop funding logic for per-session channel acquisition, linking, and payments, with periodic local cleartext-counter checks sizing payments against the latest authoritative relay baseline
- client wallet library path: `SqliteClientWallet` manages Spilman channels, `LooseProofWallet` stores spendable Cashu proofs, and `session_driver` handles per-session linking and payments; `MockWallet` remains for tests and connector harnesses
- blinded-hop routing over QUIC: `CONNECT blinded.monad.invalid:443`, tweak-prefixed QUIC forwarded sessions, `RouteHop` / `Route` connector support, public-key-only blinded-path construction, and parity-aware reverse-tweak key recovery for MONAD's x-only secp256k1 identity model
- integration tests for direct, nested, IPv6, hostname-resolution, TCP secp transport, QUIC single-hop, QUIC nested tunnels, mixed TCP/QUIC hop chains, and the session payment / pause / resume lifecycle

Production clients offer both `v1` (keyset IDs starting with `00`) and `v2` (`01`). For each trusted mint/unit, relays advertise an ordered list of relay-known preferred keysets compatible with the session's negotiated set. The list may be empty and may include compatible inactive keysets; it is not an exhaustive accepted-ID allowlist. Clients prefer an advertised active ID, but may use another locally active keyset with a negotiated format. Linking a channel funded by an unnegotiated version returns `LinkKeysetVersionNotNegotiated` and ends that MONAD session, not the shared QUIC connection. The client keeps the channel usable for a compatible session; loose input proofs are not restricted by this negotiation.

Not implemented yet:
- user-facing client wallet commands for mint quotes, proof minting, and richer balances
- unattended infinite retry before the first successful configured-client route connect; startup still fails fast on persistent misconfiguration

## Relay Wallet

`monad-relay` uses named relay-wallet identities inside one shared SQLite relay-wallet database. Relay configuration lives in a single YAML file. Omitting `--relay` starts every configured relay in YAML order in one process; `--relay <name>` starts only that relay while the process still exclusively owns the whole configured relay wallet.

Example `monad.yaml`:

```yaml
relay_wallet:
  db_path: /var/lib/monad/relay.db

client_wallet:
  loose_db_path: /var/lib/monad/client-loose.db
  channel_db_path: /var/lib/monad/client-channels.db
  sender_secret_hex: "${MONAD_CLIENT_SENDER_KEY}"
  channel_funding_token_target_msats: 1000000
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
    channel_policy:
      min_expiry: 1h
      min_capacity: 1msat
      max_amount_per_output: null
      expiring_channels:
        close_before_expiry: 24h
        auto_close:
          enabled: false
          interval: 1h

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
# Run every configured relay through one wallet manager.
monad-relay run --config monad.yaml

# Or run one selected relay while owning the same complete wallet.
monad-relay run --config monad.yaml --relay relay-a
```

Inspect the shared relay-wallet DB:

```bash
monad-relay wallet --config monad.yaml --relay relay-a list
monad-relay wallet --config monad.yaml --relay relay-a show
monad-relay wallet --config monad.yaml --relay relay-a channels
monad-relay wallet --config monad.yaml --relay relay-a expiring-channels
monad-relay wallet --config monad.yaml expiring-channels
monad-relay wallet --config monad.yaml --relay relay-a close-expiring-channels --dry-run
monad-relay wallet --config monad.yaml --relay relay-a close-expiring-channels
monad-relay wallet --config monad.yaml close-expiring-channels --dry-run
monad-relay wallet --wallet-db-path /var/lib/monad/relay.db close --channel-id <channel-id>
monad-relay wallet --config monad.yaml --relay relay-a drains
monad-relay wallet --config monad.yaml --relay relay-a drain --mint-url https://dev.mint.camelus.app --unit sat
monad-relay wallet --config monad.yaml --relay relay-a recover-drain --drain-id <drain-id>
```

`recover-drain` verifies exact restored output identities and signatures. Empty or
invalid restores retain the submitted attempt and channel reservations rather
than reporting success. Completed proofs remain in the relay wallet DB; repeated
completion cannot replace them with conflicting proofs. See [WALLET.md](WALLET.md)
for the remaining relay recovery limitations.

Add `--json` to any wallet command for machine-readable output.

One runtime process exclusively owns `relay_wallet.db_path`. It holds exclusive
maintenance access while opening/migrating the database, registering identities,
and populating the startup keyset cache, then shared maintenance access while
listeners run. `list`, `show`, `channels`, `expiring-channels`, `drains`, and
`close-expiring-channels --dry-run` remain available during runtime and use
read-only SQLite connections without migrations. Closing, draining, recovery,
and other mutating commands require exclusive maintenance access and fail before
opening the wallet or contacting a mint when a runtime is active. OS-backed
sidecar locks are released automatically if the process exits or dies. Inspection
does not write SQLite, but it still opens or creates the adjacent maintenance
sidecar for cross-process coordination, so the wallet directory must permit that
sidecar access. Existing database files with multiple hard links are rejected.

On first start, `receiver_secret_hex` is required so the relay can register its identity in the wallet database.  On later restarts of the same relay wallet identity, omit `receiver_secret_hex`; the relay will load the existing receiver key for `relay-a` from the shared wallet DB.

All configured relays in a process share one `RelayWalletManager`, persistent store, and in-memory mint cache while retaining distinct receiver keys and wallet-name metadata. The config loader rejects any two relays that share the same `receiver_secret_hex`.

## Client Wallet

The reusable client wallet pieces exist in `monad-client`. The binary exposes
wallet admin/funding/recovery commands and can run configured QUIC SOCKS
clients. `monad-client run --config monad.yaml` runs every `clients` entry in
YAML order; add `--client <name>` to run only one entry.

- `LooseProofWallet` stores loose Cashu proofs, mint quote state, premint batches, reservations, and spend/release state in SQLite.
- `SqliteClientWallet` uses those loose proofs to provision Spilman channels via upstream `cdk-spilman`, stores MONAD channel metadata including expiry timestamps in SQLite, and implements `MonadWallet` for the session driver.
- channel opening atomically reserves its loose proofs and journals the exact prepared swap before submission. Live ambiguous submissions restore their exact funding/change outputs through NUT-09; a valid empty funding restore plus every exact input `UNSPENT` may authorize at most one byte-identical replay submission. Authorization also requires execution authority and a wall-clock second later than the preceding authorized submission.
- configured-client startup and manual `recover-openings` never submit opening swaps. They finish restored or finalizing channels and cancel prepared attempts and rejected attempts without successors. `wallet export-stale-opening-inputs` requires exclusive wallet access and, after one hour plus exact empty NUT-09 restore and all-`UNSPENT` NUT-07 evidence, groups eligible inputs by mint/unit and atomically marks every attempt represented by a bearer token `Exported` before printing it. The proofs remain reserved. The command reports successful tokens and unresolved attempts independently, so one failed group does not suppress another. Repeated exports are overlapping snapshots and may emit the same still-reserved proofs again. Export never finalizes a restorable opening; it reports that `recover-openings` is required. Recovery later finalizes a delayed opening, or marks exported proofs `ExternallySpent` only after exact all-`SPENT` evidence and a final empty restore. Recent, stale, clock-rollback, partial, invalid, or unavailable evidence remains reserved.
- output keyset handling is cache-first: channel opening prefers an advertised active keyset, then falls back to another locally active same-mint/unit keyset with a negotiated format. When preferences are nonempty but unavailable locally, the client refreshes its own mint cache before using a non-preferred fallback; it also refreshes before concluding that no compatible active keyset exists. A direct, unambiguous initial inactive-output-keyset rejection (`12002`) may create one persisted successor using a changed active keyset. Ambiguous outcomes may authorize the one identical replay described above, but never a changed-request successor.
- opening and refund HTTP rejections report the HTTP status and numeric NUT-00 code without retaining the mint's response body. Only a structured HTTP 4xx `12002`, subject to the operation's journal authority, can permit changed output keys; error-message text is not rejection evidence.

`client_wallet.channel_funding_token_target_msats` controls the desired funding-token value for each newly provisioned channel. Cashu input fees are selected in addition to this target; output fees and deterministic channel outputs can make usable channel capacity lower. The default is `1000000` msats.

`client_wallet.target_topup_buffer_msats` controls the positive session balance the client tries to restore when funding is needed; the default is `10000000` msats. `client_wallet.minimum_topup_msats` sets a lower bound for normal topups; the default is `0` msats.

Admin/recovery commands can use the configured singleton `client_wallet`:

```bash
monad-client wallet --config monad.yaml channels
monad-client wallet --config monad.yaml proofs
monad-client wallet --config monad.yaml import-token --token <cashu-token>
monad-client wallet --config monad.yaml import-token --token-file ./token.txt
monad-client wallet --config monad.yaml recover-channel --channel-id <channel-id>
monad-client wallet --config monad.yaml recover-openings
monad-client wallet --config monad.yaml export-stale-opening-inputs
```

`import-token` stores the token's existing bearer proofs without swapping them
into fresh proofs. It does not invalidate other copies or establish exclusive
ownership. Import only tokens you control, and do not continue using another copy
from another wallet.

Exports group inputs by mint/unit. Unchanged eligible proofs produce the same
token encoding even when they span multiple input keysets; repeated output is not
additional value and may contain proofs already present in an earlier export.

One in-process `ClientWalletManager` owns the configured loose-proof and channel
databases. Startup opens/initializes supported schemas and performs opening
recovery once before any client starts, then all client leaves share that wallet.
A second runtime using
either database fails immediately. `channels` and `proofs` use read-only SQLite
access, require no sender secret in explicit-path mode, and may run while
the runtime is active. Import and recovery commands require exclusive maintenance
access and fail immediately while a runtime owns the wallet. Lock sidecars are
created next to each normalized, deduplicated database path, including for
inspection when absent; the containing directories must allow sidecar access.
Existing database files with multiple hard links are rejected.

`recover-channel` explicitly recovers an established channel, unlike the startup
opening-recovery pass. Stop the client runtime first and keep the same loose DB,
`wallet_name`, channel DB, and sender key. Pending refunds remain `Closing` and
cannot be reused. Rerun the command after a retry-later outcome: it restores the
persisted request before bounded exact replay, rather than choosing fresh outputs
after uncertainty. Verified proofs awaiting local import/closure can finish
offline; completed recovery returns locally. Each CLI mint request has a 15-second
timeout. An empty sender-close scan is not reported as successful recovery.

Refund journal v2 is a **testnet-breaking change with no data migration**.
Nonempty incompatible journals are rejected, not deleted; an empty legacy table
can be replaced. Preserve funded databases and backups. Only explicitly reset
disposable test databases you own, accepting loss of their local state; MONAD does
not automatically reset wallets. Refund records contain secret output material,
so do not publish database dumps or prepared requests. See
[Channel Fund Recovery](WALLET.md#channel-fund-recovery) for recovery boundaries.

Wallet commands can also use explicit DB paths and sender key material for manual
or emergency access:

```bash
monad-client wallet \
  --loose-db ~/.monad/client-loose.sqlite \
  --channel-db ~/.monad/client-channels.sqlite \
  --wallet-name default \
  channels

monad-client wallet \
  --loose-db ~/.monad/client-loose.sqlite \
  --channel-db ~/.monad/client-channels.sqlite \
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

Remaining client-wallet work is operator/user experience rather than the core channel-payment library path: mint quote/mint commands, richer balance inspection, and close/sweep flows.

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
- configured-client chaos route rebuilds (`make stress-chaos-rebuild`, the longer 5-hop `make stress-chaos-rebuild-intense`, or abrupt-kill coverage with `make stress-chaos-rebuild-abrupt`)

The throughput/payment stress recipes expect a high `ulimit -n` and are intended for developer load testing rather than routine CI. The chaos rebuild recipes run at a smaller scale and need no special `ulimit`. `MONAD_CHAOS_KILL_MODE=graceful|abrupt|mixed` selects whether chaos restarts use clean shutdown, task-tree cancellation, or alternating modes. The main client now uses timer-driven local counter checks for payment sizing; the stress recipes still use frequent `GetSessionStatus` polling intentionally to exercise relay control-plane behavior under load.

Ignored but important regression tests can be run explicitly when changing route rebuild or keyset-refresh behavior:

```bash
cargo test -p monad-relay test_configured_client_three_hop_middle_rotation_refreshes_relay_on_channel_link --test integration -- --ignored
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
- client connector with QUIC hop
- configured-client route rebuilds across first, middle, and final hop restarts
- configured-client abrupt relay loss through the chaos stress harness
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

### Relay Keyset Handling

Each relay wallet manager owns one shared in-memory `SpilmanMintCache` populated from configured mint URLs. The cache stores all keysets returned by those mints, active and inactive, for all units the mint reports. The relay applies its configured trusted mint/unit policy when advertising options and accepting first-time channel funding. Stored channels can relink and continue paying after a later policy change. Every configured trusted mint/unit remains an advertisement even when its ordered relay-known preference list is empty.

When a first-time `ChannelLink` uses an unknown keyset for a configured trusted mint/unit, the relay performs metadata-independent structural checks, transparently invokes its bounded refresh coordinator, and retries the immutable link once. A successful refresh that still does not know the keyset produces a permanent `LinkMintOrKeysetUnacceptable` rejection. If cooldown, that relay coordinator's cross-mint capacity, timeout, or mint failure prevents a fresh decision, the relay returns a specific transient link error and the configured client preserves the channel and retries with backoff.

There is no client-requested relay refresh operation. Automatic first-link refresh is limited to configured trusted mint/unit pairs: within one hosted relay, each mint gets at most one actual attempt per cooldown regardless of outcome, concurrent same-mint links share one cancellation-safe attempt, cross-mint saturation fails fast, and mint I/O has a timeout. Hosted relays share the wallet cache but have separate refresh coordinators and budgets. Existing stored channels relink from authoritative persisted funding without requiring the current cache or triggering refresh. Startup discovery still populates the cache. Close and drain operations have separate recovery state machines; both use cache-only selection, can warm an empty mint/unit cache, and allow at most one changed-output-keyset retry after a recognized keyset rejection.

## Payment Code Map

The canonical client funding implementation lives in `monad-client/src/session_driver.rs` and its private modules:

- `runtime` runs the serialized control loop
- `state` holds local driver state and publishing helpers
- `funding` handles channel selection, link, payment, eviction, and recovery
- `payment` holds payment math and relay/client safety checks

Shared protocol helpers used by client, relay, and harness code live in:

- `monad-common/src/control_codec.rs` for newline-delimited control messages
- `monad-common/src/payment_units.rs` for `msat` / `sat` raw-unit conversion

For maintainers, the most focused reference is `docs/payments.md`; `ARCHITECTURE.md`
stays the higher-level protocol overview.

## Transport Identities

MONAD transport now uses secp256k1 identities throughout:

- **TCP MONAD transport** uses secp Noise with 32-byte x-only relay identities
- **QUIC MONAD transport** uses secp attestation plus secp Noise with the same 32-byte x-only relay identities

Configured clients use secp256k1 hop identities from YAML route entries. The
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

| Transport | Route config | Identity | Auth mechanism |
|-----------|-----------|----------|----------------|
| TCP | `addr` + `pubkey` | 32-byte x-only secp256k1 | secp Noise NK |
| QUIC (secp) | `addr` + `pubkey` with QUIC route transport | 32-byte x-only secp256k1 | QUIC attestation + secp Noise NK |

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

Create a `monad.yaml` file. A single file can hold the shared wallets, many relays, and one or more client route definitions. A relay process runs all configured relays by default or one relay selected with `--relay <name>`.

```yaml
relay_wallet:
  db_path: /var/lib/monad/relay.db

client_wallet:
  loose_db_path: /var/lib/monad/client-loose.db
  channel_db_path: /var/lib/monad/client-channels.db
  sender_secret_hex: "${MONAD_CLIENT_SENDER_KEY}"
  channel_funding_token_target_msats: 1000000
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

`channel_policy` is optional. `min_expiry` rejects newly linked channels that do
not have enough time left before expiry. `min_capacity` and
`max_amount_per_output` use explicit `sat` or `msat` suffixes and are converted
to the linked channel's raw unit before validation.
`expiring_channels.close_before_expiry` controls when existing `Open` /
`Closing` relay channels are considered close to expiry for maintenance.
`expiring_channels.auto_close` is disabled by default; when enabled, the running
relay closes its own currently expiring channels once at startup and then every
configured `interval`, continuing after individual failures and logging summary
stats. `close-expiring-channels` runs the same kind of close sweep manually,
continues after individual failures, and exits non-zero if any close fails. Omit
`--relay` / `--wallet-name` on
`expiring-channels` or `close-expiring-channels` to scan all relay identities;
human output is a flat list with a `RELAY` column. Duration fields accept seconds
as numbers or strings such as `3600s`, `60m`, `2h`, and `1d`.

Single selected relay (this process still exclusively owns the configured wallet):

```bash
RUST_LOG=info cargo run -p monad-relay -- run --config monad.yaml --relay hop1
```

All relays in this configuration, including the two-hop example above:

```bash
RUST_LOG=info cargo run -p monad-relay -- run --config monad.yaml
```

Separate relay processes require separate wallet databases/configurations. Do not
run `hop1` and `hop2` as separate processes against the shared `relay_wallet.db_path`
shown above; the second process will correctly fail wallet ownership acquisition.

Alternative two-process shape:

```bash
# terminal 1: config-hop1.yaml has its own relay_wallet.db_path
RUST_LOG=info cargo run -p monad-relay -- run --config config-hop1.yaml --relay hop1
# terminal 2: config-hop2.yaml has a different relay_wallet.db_path
RUST_LOG=info cargo run -p monad-relay -- run --config config-hop2.yaml --relay hop2
```

### 3. Start the client

`monad-client wallet --config monad.yaml ...` exposes configured wallet
inspection and recovery commands; explicit DB/key flags remain available for
manual access. `monad-client run --config monad.yaml --client local` starts the
configured route and binds the configured SOCKS5 listener.

All configured clients:

```bash
RUST_LOG=info cargo run -p monad-client -- run --config monad.yaml
```

One configured client:

```bash
RUST_LOG=info cargo run -p monad-client -- run --config monad.yaml --client local
```

Direct connection route:

```yaml
clients:
  - name: local
    socks: 127.0.0.1:1080
    route:
      - addr: 127.0.0.1:9050
        pubkey: "<SERVER_SECP256K1_PUBKEY>"
```

Three-hop route:

```yaml
clients:
  - name: local
    socks: 127.0.0.1:1080
    route:
      - addr: 127.0.0.1:9051
        pubkey: "<HOP1_SECP_PUB>"
      - addr: 127.0.0.1:9052
        pubkey: "<HOP2_SECP_PUB>"
      - addr: 127.0.0.1:9053
        pubkey: "<HOP3_SECP_PUB>"
```

Each configured client listens locally as a SOCKS5 proxy at its
`clients[].socks` address. If any client leaf or SOCKS listener fails, the
process coordinates shutdown and awaits every managed client before releasing
the shared wallet.

Configured routes currently use QUIC for every hop:

```yaml
clients:
  - name: local
    socks: 127.0.0.1:1080
    route:
      - addr: 127.0.0.1:9051
        pubkey: "<HOP1_SECP_PUB>"
      - addr: 127.0.0.1:9052
        pubkey: "<HOP2_SECP_PUB>"
```

For non-first hops, the previous relay connects via QUIC instead of TCP. The
configured client uses secp256k1 transport identities for QUIC hop
authentication. See `ARCHITECTURE.md` for the full layering model.

When a funded hop fails, the configured client temporarily withdraws the active
route from the SOCKS listener. Existing application streams are not migrated to
the replacement route; they fail if their old route breaks. New SOCKS requests
fail while no route is published, then use the replacement route once it is
connected. A first-hop failure triggers a full reconnect. Later-hop failures
detach only channels tied to the old suffix sessions and try to rebuild from the
failed hop, preserving the unaffected prefix when possible; suffix rebuild
failure falls back to a full route reconnect. Failed or cancelled setup aborts and
awaits its owned payment and H2 tasks before detaching channels or retrying, so a
completed compatible channel can be reused. The default setup budget is five
seconds; cleanup can take longer if an in-flight mint call must finish. Library
embedders can override the budget per instance with
`ConfiguredClientRuntimeOptions::route_setup_timeout` and
`run_configured_client_until_shutdown_with_options`.
The client does not run concurrent rebuilds; failures observed during an in-flight rebuild are treated as stale and
ignored until the rebuilt route is active. Route (re)connects fail fast after a
few attempts before the first successful connect, so startup misconfiguration is
loud; once a route has connected, reconnects retry indefinitely with capped
backoff, and the client recovers when the route (or a refilled wallet) allows.

The configured client connects directly to the first hop via QUIC, then runs
the same Noise+H2 session on top using the secp QUIC path.

Blinded routes are currently exposed through the Rust library route model
(`RouteHop::Blinded`) rather than the YAML client route format.

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

- `DESIGN.md` for the high-level system design and tradeoffs
- `ARCHITECTURE.md` for the protocol and layering model
- `AGENTS.md` for repo-specific development guidance
## Process Funds Lifecycle Tests

`make test-funds-lifecycle` builds the client and relay CLIs and runs opt-in
actual-process wallet lifecycle tests with a retained real CDK HTTP mint.
See [coverage and private failure artifacts](monad-relay/tests/FUNDS_LIFECYCLE.md).
`make test-funds-crashes` includes compile-gated fault injection and real-expiry
refund tests. Both it and `make stress-funds-lifecycle` build their CLIs in
`target/funds-lifecycle/debug`, leaving normal `target/debug` and `target/release`
binaries untouched; no normal-binary rebuild is required afterward. The isolated
instrumented client binary is test-only: never use it with real funds.

`MONAD_FUNDS_SEED=20260921 MONAD_FUNDS_CYCLES=256 make stress-funds-lifecycle`
runs reproducible crash/rotation cycles from one fixed purse, stopping at a
conservative capacity/fee margin rather than replenishing funds.
