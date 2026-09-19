# MONAD Follow-Up TODOs

This is the local, untracked backlog. Current architecture and operator behavior
belong in tracked documentation; this file contains only work not already
implemented.

## Client Wallet UX

- Add mint quote / premint / mint commands for `LooseProofWallet`.
- Expose richer proof-balance inspection.
- Add client close/sweep flows for local change, abandoned channels, and recovered
  established-channel funds.
- Add broader CLI/parser, empty-database, and JSON-output contract tests.

Startup opening-journal recovery is implemented through `ClientWalletManager`.
Do not conflate it with automatic recovery of funds from established channels.

## Established-Channel Recovery

- Decide whether configured-client startup should automatically invoke some or
  all of `recover_channel_funds`; today that entrypoint is available to admin/API
  callers but is separate from opening recovery.
- Cover the `FundingPending` result with a stable pending-state fixture.
- Review whether the post-expiry unknown-output path needs a stronger atomic
  mystery-sweep design across proof import and channel/recovery metadata.
- Define behavior for pre-expiry channels when the client does not know what
  balance the relay exited with.

## Route Failure And Cleanup

Cancellation-safe setup ownership, compatible completed-channel reuse, and
three-hop partial-suffix cleanup regressions are implemented. Remaining work:

- Report wallet-list failure during failed-route cleanup instead of silently
  skipping detachment.
- Consider a graceful connection-close path that lets the control driver perform
  cleanup before bounded fallback abort.
- Replace the fixed unreachable endpoint in the failed-route regression fixture.
- Revisit near-capacity relink behavior. Near-capacity channels are effectively
  single-session because a relink funds from remaining capacity.

## Relay Swaps And Operations

Relay close/drain now use a cacheless HTTP swap/restore adapter and shared wallet
cache. Do not retain that completed adapter replacement as a TODO.

- Review relay close ambiguity separately from drain recovery and client opening.
  In particular, test a successful close whose response is lost across restart.
- Audit mixed-fee post-swap value calculations for duplication.
- Define behavior when close/drain encounters multiple keyset rotations rather
  than one changed-keyset retry.
- Review concurrent first-link ownership around validation, persistence, and
  in-memory session assignment. The owner-map update itself is mutex-protected,
  but it is not one transaction with funding validation/persistence.
- Consider returning active advertisement preferences first, ordered by expiry
  when available.
- Design config reload without killing existing sessions.
- Add process-level tests for sibling-listener failure cleanup and simultaneous
  auto-close/refresh shutdown before wallet lock release.

## Keyset Rotation Coverage

Many client/relay rotation regressions exist, including ignored middle-hop
coverage. Remaining goals:

- Run the ignored three-hop middle-rotation test routinely or in scheduled CI.
- Add an end-to-end matrix for rotation before preparation, first link, payment,
  relay close, and relay drain, asserting each intended keyset is distinct.
- Extend version negotiation when a future keyset format such as v3 arrives.

## Transport And Routing

- Mature blinded-route publication/configuration and decide whether the receive
  payment key is tweaked for blinded hops. Connector integration for one and two
  consecutive blinded hops already exists.
- Re-check hidden-service design and which Tor properties apply to MONAD.
- Revisit the async-I/O issue from the FIPS discussion.
- Review remaining test/harness client paths for duplication now that the old
  manual client path is gone.

## Maintenance

- Keep CDK and Spilman pins current and audit every resulting transitive TLS graph.
- Add scheduled/nightly stress and chaos jobs if suitable runners are available;
  normal fmt, clippy, test, dependency-review, and manual stress workflows already
  exist.
- Narrow remaining restart coverage to the exact case: persist `Closing` or
  `Closed`, restart the relay, and reject a new `ChannelLink`.
