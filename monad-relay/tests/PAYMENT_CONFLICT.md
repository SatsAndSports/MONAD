# Payment-conflict recovery validation

Validation for [MONAD #67](https://github.com/SatsAndSports/MONAD/issues/67).
No production behavior, authorization retry policy, or fault-injection option is
changed. Tests are in `common/payment_conflict.rs`, included by `integration.rs`.

## Deterministic coverage

The test-only `ObservedPayments` adapter delegates to `SpilmanRelayPayments`.
After a configured route is funded and has completed a SOCKS roundtrip, the test
arms one specific Noise session. On its next payment, the adapter releases that
session's channel ownership before forwarding the unmodified signed request.
Real signature validation runs and the real owned-payment CAS returns `Conflict`.
The adapter asserts that exact result and an unchanged authoritative raw balance;
it does not synthesize an error message or bypass the control stream.

This models ownership lost before commit, not a concurrent-thread stress race
inside the CAS. Existing `channel_store` tests cover competing snapshots,
ownership handoff, and close-freeze interleavings. The integration adapter avoids
requiring production test hooks or scheduler-dependent timing.

The three non-ignored tests are:

- `payment_conflict::configured_payment_conflict_rebuilds_first_hop_route`:
  three-hop YAML-configured client, one full reconnect, all old sessions replaced.
- `payment_conflict::configured_payment_conflict_rebuilds_middle_hop_suffix`:
  three-hop YAML-configured client, one successful suffix rebuild, zero fallback,
  exact first-hop session and channel preserved, both suffix sessions replaced.
- `payment_conflict::payment_conflict_wire_error_without_funded_status`:
  explicit QUIC/Noise/H2 control client, real signed first payment rejected;
  decodes every response through EOF/reset and requires exactly one
  `PAYMENT_CONFLICT`, no funded status, zero durable balance, and no later CONNECT.

The configured cases use the existing CDK HTTP test mint and SQLite client/relay
wallets, not `MockWallet`. Test pricing is one byte per millisat so a bounded
1.2 MB transfer forces a topup without exhausting the 11M msat channel budget.
Assertions require an interrupted old stream, resumed uppercase SOCKS traffic,
unchanged channel IDs, open/attached rebuilt channels, relay ownership-release
cleanup and old-session deregistration. Exactly one additional payment reaches
the old session after arming: the rejected one. Relink observes exactly the
pre-conflict durable balance; a subsequent accepted payment advances that balance.

The tests deliberately do not prohibit an equal signed cumulative balance on a
**new** session after authoritative relink. That can be a newly authorized payment;
blind replay on the obsolete session is the prohibited behavior.

Zero rejected credit is checked in layers: the existing reducer test
`payment_conflict_emits_dedicated_error_without_credit` asserts unchanged session
state and no credit effect; the new wire test checks no funded response; the
configured tests check unchanged durable/relink state and interruption rather
than continued use of the rejected session. A terminated session cannot be
queried for a post-rejection status. No assertion relies on log text.

Injection synchronization uses `Notify`, not a timing sleep. Existing fixture
helpers bound route-readiness polling and SOCKS probes to 30 seconds. The conflict
notification has a 30-second deadline; old traffic and client shutdown have
5-second deadlines, relay shutdown 10 seconds, and whole configured cases
90 seconds. The explicit wire case has a 45-second deadline. Client and relay
tasks are awaited on successful completion.

## Reproduction

```bash
cargo test -p monad-relay --test integration payment_conflict -- --test-threads=3
for run in 1 2 3 4 5; do
    cargo test -p monad-relay --test integration payment_conflict -- --test-threads=3 || exit
done
cargo test -- --test-threads=4
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
git diff --check
make stress-payment-buffered
make stress-payment-relink
make stress-chaos-rebuild
make stress-chaos-rebuild-abrupt
```

The payment recipes set `ulimit -n 524288`; the host hard limit must permit it.
No stress duration, concurrency, or payload overrides were used below. The chaos
recipes use three hops and four concurrent probes over their default 60-second
run window. Setup and teardown are additional time. For chaos replay set
`MONAD_CHAOS_SEED=5570757306307527496`.

## Recorded results

2026-09-23, Linux, branch `test/payment-conflict-recovery`, base revision
`89bb271971238f804c1b6b44c87d54b6e30000c4` plus the uncommitted validation changes.
No commit or PR is implied by this record. Existing private logs were preserved;
only counters and reproducible commands are retained here, not keys, proofs,
wallet databases, payment JSON, or raw mint artifacts.

- Full workspace: **584 passed, 0 failed, 20 ignored**. Manual stress tests were
  run separately as listed below; unrelated ignored tests were not run.
- Focused conflict tests: **3/3 passed**, including **five consecutive parallel
  repetitions (15/15)**.
- Strict workspace/all-targets/all-features Clippy, formatting, and diff checks:
  passed.

### Payment stress

| Counter | Buffered | Relink |
| --- | ---: | ---: |
| Relays / circuits / hops | 10 / 25 / 5 | 10 / 10 / 5 |
| Completed streams | 62,500 / 62,500 | 25,000 / 25,000 |
| Total bytes | 32,000,000 | 12,800,000 |
| Harness elapsed seconds | 84.857 | 24.388 |
| Sessions linked | 125 | 50 |
| Channel links / relinks | 125 / 0 | 380 / 330 |
| Sessions relinked | 0 | 50 |
| Maximum links per session | 1 | 10 |
| Initial payments | 125 | 380 |
| Topups total / proactive / reactive | 3,738 / 3,736 / 2 | 708 / 707 / 1 |
| Pause / recovery-unpause events | 2 / 2 | 2 / 2 |
| Status polls / updates | 103,899 / 107,974 | 11,933 / 13,447 |
| Channels abandoned at capacity / below capacity | 0 / 0 | 330 / 0 |
| Failures / control errors / link failures | 0 / 0 / 0 | 0 / 0 / 0 |
| Payment-no-new-funds | 0 | 0 |

Both recipes passed. Proactive topups dominate; buffered mode stays on one channel
per session, while every relink-mode session relinks. The two pause events in each
run recover normally and are consistent with chunk-boundary overshoot.

### Configured-client chaos

Both runs used seed `5570757306307527496`.

| Counter | Graceful | Abrupt |
| --- | ---: | ---: |
| Run-window seconds | 60.211 | 60.850 |
| Restart interval milliseconds | 2,000 | 1,000 |
| Restarts / route failures | 7 / 7 | 25 / 25 |
| Restarts by zero-based hop | [1, 4, 2] | [6, 14, 5] |
| Probes total / successful / failed | 6,385 / 6,273 / 112 | 3,465 / 3,082 / 383 |
| Maximum recovery milliseconds | 1,067 | 1,330 |
| Full reconnects | 1 | 6 |
| Suffix attempts / successes | 6 / 6 | 19 / 19 |
| Suffix failures / fallbacks | 0 / 0 | 0 / 0 |
| Channel records / bound | 3 / 6 | 7 / 21 |

Every restart recovered. Failed in-flight probes during restart are expected:
active streams are not migrated. Channel growth remained below the harness bound.
Abrupt here means in-process relay task-tree cancellation, not process SIGKILL or
a network blackhole. These stress recipes supplement, rather than replace, the
deterministic payment-conflict tests.
