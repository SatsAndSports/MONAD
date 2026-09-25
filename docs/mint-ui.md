# Mint management page

The loopback management aggregator serves `/mints` (also the destination of `/`).
It displays all discovered `test_mints` processes and their mint instances, grouped
by SAT/MSAT. Active and inactive keysets show IDs, input fees in ppk, and optional
final expiry. Rotate a unit with an integer fee from 0 through 999. Rotating with
the same fee still creates a new keyset.

The embedded HTML/CSS/JavaScript requires no frontend build or external assets.
Browser tabs use the initial SSE `reset` snapshot and subsequent `snapshot` events.
They never fetch a separate initial snapshot. Unavailable sources retain visibly
stale data and disable rotation controls; loss of the stream does the same.

Accepted commands publish `operation_updated` events with queued, running, and
succeeded/failed states. Tabs correlate these by process, generation, and request
ID. Only identifiers and backend-public outcomes are broadcast, never raw command
arguments. Current keysets come from snapshots, not reconstructed command results.
Activity is bounded to 100 commands per tab and starts fresh after a reset/reload.
Missed source history produces an explicit notice. Process restarts do not retain
command history; persisted keysets remain the source of truth.

The browser submits only on a button action and never automatically retries. A
lost HTTP response is reported as unconfirmed, including its request ID; inspect
keysets/activity before issuing another rotation. An accepted operation belongs
to the process even if the initiating tab reloads or closes.

## Disposable demo

From the workspace root, with Node 20 or newer:

```sh
cargo build -p monad-management -p monad-test-mint
node monad-management/ui-tests/demo.mjs
```

Open the printed URL in two tabs. Rotate SAT in one, observe both, reload, and try
MSAT. Two mint instances let you check that other units/mints remain independent.
Ctrl-C stops the processes. Every launch creates a new temporary directory, printed
with the URL, containing configuration, logs, and disposable mint databases. Data is
retained, never silently reset. The helper uses normal `target/debug` binaries.

To use your own configuration, start `monad-test-mint run --config ...` and
`monad-management --config ...` as described in [test-mints.md](test-mints.md), then
open the aggregator's `/mints` page.

## Browser tests

```sh
cargo build -p monad-management -p monad-test-mint
npm ci --prefix monad-management/ui-tests
npm exec --prefix monad-management/ui-tests -- playwright install chromium
npm test --prefix monad-management/ui-tests
```

Playwright uses real disposable mint and aggregator processes. Coverage includes
two-tab rotation visibility while the submitting tab's HTTP response is held,
refresh without resubmission, unit/mint isolation, failure events, narrow-screen
layout, and stale/offline controls. Ordinary `cargo test` also covers asset routes,
ordered command events, duplicate acceptance suppression, and event redaction.
