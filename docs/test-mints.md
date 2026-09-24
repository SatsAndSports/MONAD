# Managed CDK test mints

`monad-test-mint` hosts persistent CDK mints backed by fake Lightning. They are
demo/test services: invoices are automatically marked paid after roughly one second,
without moving real Lightning funds. No new client wallet funding-management API
is included; tests use the ordinary Cashu HTTP endpoints to bootstrap proofs.

## Configuration and startup

Add the optional `test_mints` section to the existing MONAD YAML:

```yaml
test_mints:
  - name: demo-mint
    listen: 127.0.0.1:3338
    db_path: ./demo/mint.db
    units:
      sat:
        input_fee_ppk: 400
      msat:
        input_fee_ppk: 700

management:
  listen: 127.0.0.1:8090
  test_mint_socket: /tmp/monad-test-mints.sock
```

The same YAML may also contain the existing client/relay sections and their
management socket settings. Mint-only YAML is supported too. Create database parent
directories explicitly; the process does not create them or reset existing data.
When relays trust this local mint, start it before the relays so their startup
keyset discovery can reach it. Client and relay processes do not start mints for you.

```sh
mkdir -p demo
cargo run -p monad-test-mint -- run --config monad.yaml
cargo run -p monad-management -- --config monad.yaml
```

By default one test-mint process hosts all configured test mints. To run only one:

```sh
cargo run -p monad-test-mint -- run --config monad.yaml --mint demo-mint
```

Each mint needs its own name, database, and Cashu HTTP address. The process shares
one Unix management socket across its selected mints. Additional mint processes
need distinct management sockets. Mints bind numeric IPv4/IPv6 loopback addresses;
port zero is supported for tests, with the actual URL exposed in monitoring.
Use stable ports for demos so client/relay mint URLs can be configured normally.
Configured test mints do not automatically become trusted relay mint offers.

The aggregator's default process name is **`test-mints`** when
`management.test_mint_socket` is set. If using an explicit `management.processes`
map, include the test-mint process there as well:

```yaml
management:
  listen: 127.0.0.1:8090
  test_mint_socket: /tmp/monad-test-mints.sock
  processes:
    relays: /tmp/monad-relays.sock
    clients: /tmp/monad-clients.sock
    test-mints: /tmp/monad-test-mints.sock
```

`test_mints` may be omitted/empty in configurations containing clients or relays.
There is then no test-mint process to start. The mint executable rejects an empty
selection or an unknown `--mint` name.

## Initial fees versus runtime rotation

There is **one active keyset per configured unit**, using keyset format v2. SAT and
MSAT keysets rotate independently. You can configure either unit or both.

YAML fee rates initialize a fresh database. Each database stores its own random
signing seed and initial unit configuration atomically. Restart reads the persisted
active keysets' fees and denominations before constructing CDK, avoiding CDK's
normal automatic rotation on configuration mismatch. Editing YAML fees therefore
does not revert a rotation or change an existing keyset, including on restart.
If initial setup was interrupted, missing units use the persisted initial settings.

Persisted mint name and unit set must still match the configuration. Changing the
unit set requires a separate database; it never silently disables existing units.
An unrecognized nonempty database is refused rather than adopted or deleted.

## Rotate with an explicit fee

Use the existing management command protocol. First obtain the current process
generation from `GET /v1/snapshot`, then submit:

```json
{
  "generation": "CURRENT_TEST_MINT_PROCESS_GENERATION",
  "request_id": "rotate-msat-001",
  "instance": "demo-mint",
  "action": "rotate_keyset",
  "arguments": {
    "unit": "msat",
    "input_fee_ppk": 900
  }
}
```

```sh
curl -H 'Content-Type: application/json' --data @rotation.json \
  http://127.0.0.1:8090/v1/processes/test-mints/commands
curl http://127.0.0.1:8090/v1/processes/test-mints/operations/rotate-msat-001
```

The operation returns `unit`, `previous_keyset_id`, `active_keyset_id`, and the new
`input_fee_ppk`. It creates a new keyset even if the requested fee equals the current
fee. The previous keyset becomes inactive and retains its original fee; the other
unit's active keyset is unchanged. Rotations are serialized per mint, so concurrent
commands report an ordered chain of previous/new IDs. Different mints can rotate
independently.

Retries must reuse the identical command envelope and request ID. The existing
management service deduplicates within a process generation. After a restart,
old-generation commands are rejected; inspect persisted keysets instead of blindly
reissuing a command under a new ID. Keyset state is durable; management operation
history and SSE events remain process-local and bounded.

### Fee units and supported range

For MONAD/Spilman compatibility, both initialization and rotation require an integer
`input_fee_ppk` in **0–999**. CDK itself accepts higher rates, but the current Spilman
channel protocol/library does not. Unsupported rates and units are rejected before
rotation. Increasing that range would require a separate channel-library change.

Fees are calculated as `ceil(sum(input proof keyset fee rates) / 1000)` in the
transaction's unit, not as a percentage of transferred value and not per-proof
rounding. For example:

- Two SAT inputs at 400 plus three at 750 cost `ceil(3050 / 1000) = 4 sat`.
- Two MSAT inputs at 700 plus three at 900 cost `ceil(4100 / 1000) = 5 msat`.

The inactive keyset's rate still applies to its old proofs. Inactive does not mean
expired or invalid: old proofs may be spent and established channels remain usable.

## Monitoring and lifecycle

The process snapshot has `kind: "test_mints"`. Each instance reports its name,
actual Cashu `base_url`, `test_only: true`, and public keyset metadata (ID, unit,
active flag, input fee and any final-expiry metadata). `keyset_rotated` events enter
the existing aggregator SSE stream with the unit and old/new keyset IDs. No signing
seed, proof secrets, or private keys are exposed.

Ctrl+C stops HTTP/management serving and awaits CDK background-worker shutdown while
retaining database ownership locks. Cancelling an embedding caller requests the
same cleanup from its owning supervisor. An explicit normal shutdown waits for it.
Concurrent access to a mint database by another managed-mint instance is refused.

After SIGKILL, the database preserves keysets, fees, seed and spent-proof state.
A stale Unix socket can remain; verify the old process has exited before explicitly
removing that socket. Do not delete the database to restart the mint.

## Test coverage

- SAT/MSAT Cashu HTTP minting and swaps with old/new keysets and fee rounding.
- Duplicate rotation commands, per-unit isolation, multiple independent mints,
  concurrent rotation ordering, and SSE delivery through the public TCP aggregator.
- Persistent restart with changed YAML fees, retained inactive-keyset metadata,
  subprocess SIGKILL/restart with spent-proof state and old-proof spending.
- Invalid fees/units, immutable unit set, unknown database preservation, ownership
  locks, cancellation cleanup and socket/port reuse.
- A mixed SAT→MSAT relay route continues using old channels after rotation, makes
  sub-satoshi MSAT payments, provisions fresh channels via normal stale-cache retry
  and relay discovery, then closes/reclaims both old- and new-keyset channels. Sender
  recovery amounts and unit conversions are checked exactly.

Tests bootstrap their own disposable wallets. There is no new token-import or
invoice management action on the client in this change.

Implementation validation: `cargo test` passed with **653 tests, zero failures and
20 ignored**, alongside strict workspace/all-target/all-feature Clippy and formatting.
The new mint tests include real Cashu HTTP, aggregate TCP/SSE commands, subprocess
restart, and mixed-unit channel close/recovery rather than only mocked rotation.
