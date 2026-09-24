# Headless management API

## Single localhost TCP endpoint

Run the configured runtimes, then the aggregator using the same YAML:

```sh
cargo run -p monad-relay -- run --config monad.yaml
cargo run -p monad-client -- run --config monad.yaml
cargo run -p monad-management -- --config monad.yaml
```

The aggregator binds `management.listen` (a numeric IPv4/IPv6 loopback address).
It serves JSON and SSE only; no webpage is included yet. By default it discovers
the configured `relay_socket` as process `relays` and `client_socket` as process
`clients`. For more processes, explicitly name all their sockets:

```yaml
management:
  listen: 127.0.0.1:8090
  processes:
    relays-east: /tmp/monad-east.sock
    relays-west: /tmp/monad-west.sock
    clients: /tmp/monad-clients.sock
```

This block belongs in the full MONAD YAML, alongside the configured runtimes.
The aggregator does not open their wallets or start/stop their OS processes.
It can start before the processes and reconnect after they restart.

Public TCP resources:

| Resource | Purpose |
| --- | --- |
| `GET /v1/snapshot` | Latest cached process views, online/stale status, generation and last successful sample timestamp. |
| `GET /v1/events` | SSE stream of snapshots and discrete runtime events. |
| `GET /v1/events?process=clients` | Filter SSE to one named process. |
| `POST /v1/processes/{name}/commands` | Forward the command envelope below to that process. |
| `GET /v1/processes/{name}/operations/{request_id}` | Read that process's operation result. |

```sh
curl http://127.0.0.1:8090/v1/snapshot
curl -N http://127.0.0.1:8090/v1/events
curl -N -H 'Last-Event-ID: EPOCH:SEQUENCE' http://127.0.0.1:8090/v1/events
curl -H 'Content-Type: application/json' --data @command.json \
  http://127.0.0.1:8090/v1/processes/clients/commands
```

### SSE contract

- Sampling is five times per second **per process**, independent of subscriber
  count. Slow/unavailable processes do not stall other process pollers.
- Every event has an `id: EPOCH:SEQUENCE`. Keep it verbatim for `Last-Event-ID`.
- The first connection receives `event: reset` with a full current snapshot.
  An old epoch, invalid cursor, or replay-history gap also yields `reset`. Replace
  displayed state on reset; do not assume the missed event history was recovered.
- `snapshot` carries `{process, state}`. Replace that process view. Disconnected
  processes retain their last data with `online: false`; it is stale, not live.
- Discrete events carry `{process, instance, generation, event}`. The nested
  event has its source sequence, timestamp, kind, and data.
- `source_gap` means the runtime's own 512-event ring overflowed between samples;
  snapshots remain usable, but individual events were lost.
- The aggregator also retains 512 events. There is no unbounded subscriber queue.
  Slow subscribers resynchronize rather than slowing traffic/payment processing.
- Five-second SSE comments keep otherwise idle streams alive. Subscriber shutdown
  is owned by the HTTP server; even a non-reading subscriber cannot block shutdown.

Stopping the aggregator closes its HTTP streams and process polling connections;
it does not disable clients/relays or cancel commands already accepted by them.
Process-generation validation is performed by the process, including after a
restart between snapshot and command submission. The aggregator never rewrites
generations or automatically retries a command.

## Process endpoints

Both configured runtimes optionally serve HTTP over Unix sockets:

```yaml
management:
  listen: 127.0.0.1:8090
  relay_socket: /tmp/monad-relays.sock
  client_socket: /tmp/monad-clients.sock
  manual_funding_clients: [local]
  disabled_clients: []
```

`monad-relay run --config monad.yaml` serves the relay socket;
`monad-client run --config monad.yaml` serves the client socket. Each endpoint
manages only the instances selected in that process. Use distinct socket paths
when running additional processes. Parent directories must already exist.
Existing socket paths/files are never overwritten or automatically deleted on
startup. Graceful shutdown removes the socket owned by that server. After SIGKILL,
the operator must verify/remove the stale socket before restarting.

Runtime control overrides last until process exit. `manual_funding_clients` and
`disabled_clients` establish client startup defaults. Routes, identities and prices
remain YAML configuration. There is no authentication implementation in this alpha
interface; the public aggregator binds loopback only. Do not configure `auth_token`.

## HTTP resources (v1)

- `GET /v1/snapshot`: `{generation, data}`. `data.kind` is `clients` or `relays`;
  `data.instances` is keyed by configured instance name; `data.wallet` is a shared
  process wallet inventory, not one copy of the wallet per client.
- `POST /v1/commands`: accept a command and return HTTP 202 plus its operation.
- `GET /v1/operations/{request_id}`: read `queued`, `running`, `succeeded`, or
  `failed`, with a public `result` or `error`.

Example snapshot:

```sh
curl --unix-socket /tmp/monad-clients.sock http://localhost/v1/snapshot
```

Command envelope:

```json
{
  "generation": "copy from the current snapshot",
  "request_id": "unique-command-id",
  "instance": "local",
  "action": "provision_channel",
  "arguments": {"session_id": "copy from a waiting hop"}
}
```

Send it with `curl --unix-socket SOCKET -H 'Content-Type: application/json'
--data @command.json http://localhost/v1/commands`. Repeating the same envelope
returns the same operation. Reusing its ID for different contents or supplying a
stale process generation returns 409. A transport timeout is not evidence that a
command failed: query its operation or retry the identical envelope. Never replace
its ID merely because the response was lost.

The executor owns commands independently of HTTP connections. At most 16 execute
concurrently, with 64 queued. Each process retains at most 4096 operation records;
after that, new commands are refused rather than evicting idempotency records and
allowing accidental replay. A process restart creates a fresh generation, does not
replay management commands, and retains the wallet's existing durable recovery.

### Client actions

Administrative refusal/retry state is exposed in client `admission_wait` and
`route_refusal`, and channel admission state in hop `funding_rejection`. Individual
exit failures appear in `last_exit_refusal`. See [structured admission refusals](admission-refusals.md)
for codes, hop attribution, retry timing, policy blockage and cancellation behavior.

| Action | Arguments | Completion |
| --- | --- | --- |
| `set_enabled` | `{"enabled": false}` or `true` | Disable awaits runtime cleanup; enable requests startup. |
| `set_automatic_provisioning` | `{"enabled": false}` or `true` | Changes the provisioning gate, preserving existing-channel payments. |
| `provision_channel` | `{"session_id": "..."}` | Waits for a newly linked channel or reports funding/session failure. |

Provisioning uses the configured budget. A session must be waiting for manual
funding, and automatic provisioning must be off. Pending duplicate and stale-hop
requests are rejected. Relay refusal preserves the funded channel; a new manual
request must not be used to replace it. Inspect hop funding/error state.

### Relay actions

| Action | Arguments | Completion |
| --- | --- | --- |
| `set_controls` | All four booleans: `enabled`, `accept_new_sessions`, `accept_new_tunnels`, `accept_new_channels` | Disable awaits owned work cleanup; admission updates are synchronous. |
| `close_channel` | `{"channel_id": "..."}` | Uses the owning relay's journaled close/recovery path. |

Close results distinguish `closed`, `sender_refunded`, and `unresolved_spent`.
The last is not successful settlement. No proof payloads are returned. A close
failure requires inspecting/recovering the stored channel, not blindly spending
again. Snapshot expiry records include absolute expiry and seconds remaining.

## Monitoring semantics

Snapshots read in-memory session state and cache wallet inventory for one second;
they never ask mints for balances. Client traffic counters are local cleartext
inbound/outbound bytes. Relay traffic counters use the relay's session accounting.
They are not encrypted wire counts. Cumulative counters permit callers to compute
rates without additional runtime accounting on each packet.

Amounts identify their units: `_msats` is millisatoshis; `_raw` uses the adjacent
mint/unit. Relay `remaining_msats` is a decimal string to preserve its signed wide
integer range. Consumers must not add raw amounts across different units or mints.
Available loose proofs, channel records, and relay drain records are separate
inventory categories, not a single spendable-balance total. Reserved/ambiguous
opening funds are not included in available loose proofs. `proof_custody` also
reports available, reserved, and spent proof totals grouped by mint/unit/state;
reserved amounts are locked custody, and spent amounts are historical, not balances
to add to channel holdings.

Each instance retains 512 discrete events with increasing sequence numbers.
`payment_accepted` is recorded after successful relay payment validation;
`payment_observed` is the client's observation of an increased authoritative paid
total. They are two views of the same payment, not additive revenue. Event history
is bounded and process-local, not a durable accounting ledger.
