# Client, relay, and mint management UI

### Tiny-buffer payment regression

The client now keeps payments pending until the relay acknowledges their cumulative
balance and ignores older queued status snapshots. The persisted signed balance
cannot decrease. `payment-burst.spec.js` exercises eight concurrent requests with
the 500-msat mixed-unit setup and checks sampled wallet high-water marks.
The UI surfaces linked-balance validation failures through `session_payment_failed`.

This prevents new corruption; it does not repair wallets whose latest signed
payment was overwritten by older builds. Keep such data for investigation. Do not
raise the local balance merely from an unverified relay claim. The demo launcher
creates a fresh independent directory when restarted, preserving previous runs.

One loopback aggregator serves `/clients`, `/relays`, and `/mints`. Use three tabs
or windows; multiple tabs on the same page are also supported. Each page starts
with the SSE reset snapshot, then follows the same stream for state and command
updates. Browser reload never submits a command. On disconnection, state becomes
stale and controls are disabled; reconnection restores current state. Activity is
bounded and transient, not a durable audit trail.

## Pages

- **Clients:** every configured instance, lifecycle, run/route generations,
  active hop sessions in route order, funding state, linked channel, cleartext
  traffic and msat accounting, and retained diagnostics. Enable/disable, choose
  automatic/manual provisioning, or provision one waiting hop. Partial routes show
  only the sessions established so far. Wallet inventory is process-wide because
  clients in the same process share a wallet. Available proofs are shown by mint
  and raw unit; expandable details include custody and channels. These categories
  are not added together into a fictitious spendable balance.
- **Relays:** every instance, enable/disable and three independent admission
  controls, sessions with pause/accounting/traffic/tunnel counts, and only channels
  linked to those sessions. Paused sessions still count as linked. Below all relay
  sections, **Unlinked channels** combines the rest, newest last-link time first,
  before wallet inventories. A channel moves automatically on unlink/relink; this
  grouping never closes or spends anything. Unavailable processes retain stale
  last-known grouping. Link timestamps are shared server-side for the lifetime of
  the relay process; unknown times after restart sort last with a stable ID tie-break.
  Linked channels offer **Request unlink**, not Close. The relay retires the channel
  (no new links, persisted across restart) and politely asks the owning session to
  release it. While waiting it shows "Unlink requested — waiting for client". Once
  the client confirms, the channel moves to **Unlinked channels**, still Open and
  marked **Retired**, where **Close channel** is a separate operator action. The
  session keeps its remaining credit and keeps working; the client links a
  replacement later according to its provisioning policy. Closing an unlinked
  channel reserves it against concurrent relink. Closing remains explicitly amber
  even if it stalls. Closed channels show compact final paid/capacity amounts
  without red low-capacity styling or a progress bar. Final paid is not a
  net-after-fees earnings figure. Capacity and accepted channel balances use each
  channel's raw unit; session payments/balances are msat. A close request goes
  through the normal wallet close/recovery path.
- **Mints:** inspect keysets and rotate SAT/MSAT independently.

Controls act through existing backend APIs. Runtime/payment decisions remain in
their Rust owners. Relay control commands replace all four flags using the latest
snapshot; competing tabs can supersede one another, and the resulting snapshot is
authoritative. Channel/session identifiers and process generations bind commands
to their original targets. Requests are never automatically retried after a lost
response; inspect state/activity before issuing a new action.

## Combined disposable demo

```sh
cargo build -p monad-management -p monad-client -p monad-relay -p monad-test-mint
cargo build -p monad-test-mint --example demo-fund
node monad-management/ui-tests/network-demo.mjs
```

Requires Node 20+ and curl. No npm install is needed to run the launcher. It starts
normal binaries in separate processes with fresh random keys, disposable SQLite
databases and ephemeral loopback ports. It prints URLs, SOCKS port, a local HTTP
traffic target, and the retained private temporary directory containing config
and logs. The mint uses fake Lightning; initial funds are real signed Cashu test
proofs imported under exclusive wallet authority, not a hard-coded balance.

Both clients share **one** wallet initially funded with 1,000,000 test sats.
The purse is split equally into SAT proofs and MSAT proofs (valued in sats).
`demo-client` starts enabled; `second-client` starts disabled. Both use entry → exit
over QUIC, with a SAT entry channel and an MSAT exit channel. Channel provisioning
starts manual; payments within existing channels remain automatic. Both hops use a
500-msat session credit target and a 500-msat minimum top-up. SAT payments round up
to whole sats; these targets are not hard ceilings on session credit.

Channel funding budgets are 30 sat each, with actual capacity determined by funding
and fees. `traffic-on` requests about 100 KiB per second at 200 bytes/msat, targeting
roughly one minute per channel. Traffic stalls, overhead, and unit rounding affect
the timing. Enable automatic channel provisioning in the UI to replace exhausted
channels without clicking Provision channel each time.

Session credit is displayed separately from cumulative channel payment. SAT channel
capacities are integers; MSAT capacities always include a decimal, with explicit
unit badges. IDs show their first eight bytes (16 hex characters); hover for the
full ID. Accepted payment observations pulse briefly and links get a larger panel
highlight; reset snapshots do not animate historical changes. Capacity below 10%
remaining is red and labeled Low capacity. Reduced-motion preferences suppress
the animations.

The CLI accepts:

- `traffic`: send a local HTTP request through the first client's SOCKS listener;
  observe actual counters and payments on both pages.
- `traffic-on` / `traffic-off`: start/stop paced requests, with at most one request
  in flight. When manual funding pauses the route, requests wait or time out until
  you provision the next channel.
- `topup 100000`: stop the client process, mint/import another 100,000 test sats,
  then restart the client process. Existing wallet/channel data is retained.
  Runtime toggles return to configured defaults on restart (second client disabled).
- `restart-relays`: gracefully restart the relay process using the same persisted
  wallet, then observe client recovery. Existing streams may fail.
- `quit` or Ctrl-C: stop owned processes. Databases/logs are not deleted.

Each launcher invocation creates fresh data. Browser reload and runtime restart
never grant more funds. To test a low/empty balance and manual funding:

```sh
MONAD_DEMO_SATS=0 MONAD_DEMO_MANUAL=1 node monad-management/ui-tests/network-demo.mjs
```

Click Provision channel to see the funding failure; use `topup 100000`, then
provision each hop or switch to automatic funding. The funding helper is a
demo-only Cargo example, restricted to HTTP loopback and bounded test amounts.
Set `MONAD_DEMO_MANUAL=0` to start with automatic channel provisioning instead.

The launcher keeps random ports and `target/debug` binaries by default. Deployment
wrappers may set `MONAD_DEMO_MANAGEMENT_PORT`, `MONAD_DEMO_SOCKS_PORT`, and
`MONAD_DEMO_SOCKS2_PORT` to distinct fixed loopback ports, and
`MONAD_DEMO_BIN_DIR` to a directory containing the four service binaries plus
`examples/demo-fund`. `MONAD_DEMO_FAIL_FAST=1` makes an unexpected service exit
stop the complete demo process tree. Readiness has a bounded overall deadline,
and a failed topup restarts the clients without automatically repeating issuance.
`MONAD_DEMO_LOG_DIR` stores child output and process-limit snapshots in a private
per-run directory separate from the ephemeral wallet and configuration directory.

## Suggested manual experiments

To generate continuous traffic from a separate terminal, pass the SOCKS address
and target URL printed by the launcher:

```sh
./monad-management/ui-tests/traffic.sh 127.0.0.1:12345 http://127.0.0.1:54321
```

An optional third argument sets the delay between requests in seconds (default
`0.1`; use `0` for no delay). Each request reports HTTP status, downloaded bytes,
and elapsed time. Ctrl-C stops the loop. Temporary failures are reported and the
loop continues; automatic channel provisioning is useful for sustained traffic.

1. Open two Clients tabs and one Relays tab; disable/re-enable a client in one tab.
2. Start manually funded and provision each hop in turn.
3. Disable **new channels** on exit before enabling the second client; see it wait,
   then restore admission. Existing stored-channel relinks remain allowed.
4. Disable **new tunnels** on exit and run `traffic`; restore it and try again.
5. Disable **new sessions** on entry before restarting a client; observe admission
   waiting and recovery when allowed again.
6. Disable a client and close its channel on the relay page; inspect the result.
7. Rotate SAT in Mints, then create another client channel.
8. Restart relays, refresh tabs, and observe re-established routes and counters.

## Automated browser validation

Build the binaries/example above, then:

```sh
npm ci --prefix monad-management/ui-tests
npm exec --prefix monad-management/ui-tests -- playwright install chromium
npm test --prefix monad-management/ui-tests
```

Playwright uses real process wallets/mints, actual SOCKS traffic, and API snapshots
alongside DOM assertions. The combined tests cover manual hop provisioning,
shared-tab activity, refresh, automatic funding, all relay admission controls,
enable/disable, channel closure, mint rotation before new funding, aggregator
disconnect/reconnect, relay restart, and empty-wallet top-up recovery. Chromium is
the automated browser target. These tests are separate from ordinary `cargo test`.

The real new-channel admission scenario also found and guards a SQLite-store bug:
upstream default state `Open` must not make an unknown channel count as a stored
relink. The relay now requires stored funding before reporting a channel state.
