# Process Funds Lifecycle

Run `make test-funds-lifecycle`. This explicitly builds the real client and relay
CLIs before running the ignored integration target. The parent owns a real CDK
HTTP mint and an echo target; each client, relay, and maintenance invocation is a
separate OS process. Runtime processes are killed and reaped before maintenance
opens their persisted databases. The parent holds no wallet handles across those
transitions. The mint remains alive; mint durability and machine power loss are
not covered.

The purse is funded once. Every completed cycle opens a real channel, pays for a
QUIC/SOCKS echo, kills both runtime processes, closes with a cold relay CLI,
recovers sender funds with a cold client CLI, and drains receiver proofs. A later
cycle spends recovered funds. Recovery is repeated and must not submit again.
The opening response-loss case holds a successful swap response, kills and reaps
the client, then runs restore-only recovery in fresh processes.

The independent oracle checks `initial = client + relay + fees`. It counts only
unique successful input sets, checks every accepted transaction against mint
restore and spent-state evidence, and charges `ceil(sum(input keyset ppk)/1000)`
per transaction. Final custody proofs must be unique, unspent at the mint, and
have valid DLEQs. Receiver drain outputs, not historical channel proof copies,
are final receiver custody. Nonzero fees are enabled from initial funding.

Requests, witnesses, responses, wallet files, and child stderr are private.
Successful runs delete their temporary directory. Failures retain it with a
warning; never upload it. Console events contain only operation names and totals.

## Work Tracking

- [x] Actual CLI processes, persisted cold restart, kill and reap cleanup.
- [x] Baseline lifecycle and committed opening response loss.
- [x] Independent nonzero-fee conservation and idempotent recovery.
- [ ] Request-before-execution crash gates.
- [ ] Refund response loss and signed short-lived channels.
- [ ] Opening/refund offline local-finalization boundary crashes.
- [ ] Rotation before/after preparation and bounded successor crashes.
- [ ] Controlled close/refund winners and concurrent races.
- [ ] Seeded bounded-purse stress and fee exhaustion.

Stale export to an external wallet is explicitly out of scope.
