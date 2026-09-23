# Real Mint Keyset Characterization

Recorded 2026-09-23 against MONAD `1c4a4ab09f344c54a32d5debf8ad48a480ac2fd7`,
with the test-only changes in this directory and the shared process fixture.
No production error handling, successor policy, dependencies, or mint validation
were changed. All funds are disposable fake-Lightning funds.

## Versions

| Component | Release / immutable revision |
| --- | --- |
| CDK | `v0.18.1`, `a056e0f0f69e94f431b1aeb90d883f18c61ea4c6` from `Cargo.lock` |
| CDK HTTP fixture | `cdk-spilman-test-mint` at `7eeb3ca54c76ed16b9522ea2a196dfe520d14dc0` |
| Nutmix | `v0.7.0`, `7a2329480b7119d5c2e9e16936462a6e7886e91c` |
| Nutshell | `0.21.0`, `a9749146c6bd7f9ab75375a050e9ba795cee301c` |
| Nutmix database | Docker `postgres:16.8`, disposable anonymous volume |

The release runs used fresh pinned Nutmix and Nutshell clones. The runner verifies
selected backend SHAs and rejects tracked source changes. Nutmix is built in an
owned disposable clone containing only the configured revision and our adapter;
supplied checkouts, including their untracked packages, are never modified.
Candidate results below are separate from the unchanged release expectations.

At original publication on 2026-09-23, Nutmix `master` pointed to the same
`7a2329480b7119d5c2e9e16936462a6e7886e91c` SHA as `v0.7.0`.
GitHub's `v0.7.0...master` comparison is **identical**, with zero commits ahead
or behind. This is source/revision equivalence, not an additional matrix run.

## Ordinary HTTP Results

These are actual `/v1/swap` responses, not inferred from source or broad upstream
`12001 OR 12002` assertions. Every rejection below had HTTP **400**, all submitted
input Ys **UNSPENT**, and exact NUT-09 restore **zero outputs and signatures**.

| Request | CDK | Nutmix | Nutshell |
| --- | --- | --- | --- |
| Active inputs, active outputs | 200 | 200 | 200 |
| Unknown output keyset | 12001 | 12001 | 11000 |
| Unknown input keyset | 12001 | 12001 | 0 |
| Prepared output keyset made inactive by true rotation | 12002 | **12001** | 12002 |
| Inactive inputs, current active outputs | 200 | 200 | 200 |
| Restore accepted outputs after another rotation | Exact match | Exact match | Exact match |

Exact error JSON bodies (no proof material):

| Mint / case | Body |
| --- | --- |
| CDK unknown input or output | `{"code":12001,"detail":"Unknown Keyset"}` |
| CDK inactive output | `{"code":12002,"detail":"Inactive Keyset"}` |
| Nutmix all three rejection cases | `{"code":12001,"detail":"keyset not known","error":"Keyset is not known"}` |
| Nutshell unknown output | `{"detail":"keyset id unknown.","code":11000}` |
| Nutshell unknown input | `{"detail":"keyset 00ababababababab unknown","code":0}` |
| Nutshell inactive output | `{"detail":"keyset is inactive, cannot sign messages","code":12002}` |

The unknown ID is deliberately absent, syntactically valid v1, and public test
data. Requests use freshly HTTP-minted valid proofs, valid blinded points,
supported amounts, matching sat units, balanced totals and zero fees. Only the
target ID changes in unknown-keyset probes. Subsequent successful spends serve
as positive controls. Rotation changes real signing keys; `/v1/keysets` confirms
the old ID inactive and a different new ID active before the inactive probe.
No invalid-signature, fee, or malformed-point error was used as keyset evidence.

NUT-07 checks every requested Y, not just the first proof. NUT-09 compares the
exact B_, keyset IDs, amounts and signed C_ values; optional null fields and
optional restored DLEQs are not treated as different outputs. Recovered proofs
are unblinded and checked UNSPENT. The ordinary script's response-discard case
is restore evidence, **not** network fault injection. Real response gates are
covered separately below.

### Source Cross-Check

Nutmix's [local signer](https://github.com/lescuer97/nutmix/blob/7a2329480b7119d5c2e9e16936462a6e7886e91c/internal/signer/local_signer/signer.go#L284-L295) looks up output IDs in
`activeKeysets` first and returns `ErrKeysetNotKnow` when absent, before checking
`correctKeyset.Active`. This agrees with the observed inactive-output `12001`.
[Issue 237](https://github.com/lescuer97/nutmix/issues/237) was still **OPEN** when
checked with `gh issue view`; its reported unknown-keyset `99999` did **not**
reproduce for these valid requests on this pinned release. This is not a claim
that every path covered by that issue is fixed.

Filed [Nutmix issue 259](https://github.com/lescuer97/nutmix/issues/259) for the
distinct known-inactive-output `12001` behavior, with reproduction steps and
pinned source/specification references. The remote signer was not characterized.

Nutshell's unknown-output `11000` and inactive-output `12002` match the researched
validation behavior. Its unknown-input `0` is a separate observed result.
Neither `12001`, `11000`, `99999`, nor `0` is translated into `12002` or granted
changed-output successor authority.

## Actual MONAD Results

The shared `funds_lifecycle` fixture runs the real isolated client and relay CLIs,
persisted wallets, signed Spilman transactions, QUIC/SOCKS traffic, cold recovery,
and strict custody/conservation checks. Its HTTP proxy forwards to each real
mint without rewriting responses. Bootstrap uses the same HTTP minting code for
all three mints. Each scenario starts with its own 16,384-sat purse; this matrix
is not a single-purse stress run.

`loss` means the mint accepted the request, the existing proxy withheld its
response, and the submitting MONAD process was killed and reaped. The mint then
rotated **before** a fresh recovery process restored the original outputs.
`rotation` means keys rotated after the immutable request was prepared but
before the mint received it. Combined cases lose the accepted successor response
and rotate again before recovery. Refunds wait for actual signed wall-clock expiry.

| Runner case | CDK | Nutmix | Nutshell |
| --- | --- | --- | --- |
| `baseline` (open, close, sender recovery, drain) | Pass | Pass | Pass |
| `opening-loss` | Pass | Pass | Pass |
| `opening-rotation-loss` | Pass | Blocked | Pass |
| `close-loss` | Pass | Pass | Pass |
| `close-rotation` | Pass | Blocked | Pass |
| `close-rotation-loss` | Pass | Blocked | Pass |
| `refund-loss` | Pass | Pass | Pass |
| `refund-rotation` | Pass | Blocked | Pass |
| `refund-rotation-loss` | Pass | Blocked | Pass |
| `drain-loss` | Pass | Pass | Pass |
| `drain-rotation` | Pass | Blocked | Pass |
| `drain-rotation-loss` | Pass | Blocked | Pass |

**36 actual-process cases: 29 passed, 7 failed to complete the requested lifecycle.**
The runner intentionally exits **1**, not a blanket success, for the full matrix.
Each blocked Nutmix Rust test exits **101**. Opening gets one `12001` and times
out waiting for acceptance. Close and drain rotation-only cases fail maintenance;
refund rotation-only fails the fixture's required direct-`12002` assertion.
Combined cases time out waiting for the successful response that never arrives.
Close, refund and drain each observed two `12001` rejections in these cases.
No response-loss recovery result is claimed where there was no accepted response.

Every actual-process keyset rejection was independently checked at the upstream
mint: all inputs UNSPENT and zero exact restored outputs (one funding proof for
opening/close/refund; three inputs for drain). Rejected probes against already
spent funding, encountered during later discovery, instead check unchanged
pre/post state and restore evidence. The proxy does not turn such probes into
transport failures. Handler assertion failures, panics and cancellation latch a
fixture-owned failure; parent custody audits and scenario completion assert this
oracle and require no checks still running. The runner's worker-panic log scan
is defense in depth, not the correctness oracle. Rust custody checks match every
requested Y and exact restored B_/ID/amount and paired C_/ID/amount, ignoring only
optional DLEQ/witness representation. Final proof DLEQ verification is unchanged.

These are **positive signed MONAD interoperability results**, beyond ordinary
swaps. They are not an exhaustive certification of mint spending-condition
enforcement: invalid/missing witnesses, malicious splits, and all signature modes
were not tested in this characterization.

## Nutmix Candidate

[Issue 259](https://github.com/lescuer97/nutmix/issues/259) is addressed by the
separate upstream [PR 260](https://github.com/lescuer97/nutmix/pull/260), still open
when checked. No Nutmix or MONAD production fix is included in this MONAD PR.

| Revision | Meaning | Ordinary observations | MONAD lifecycle |
| --- | --- | --- | --- |
| `7a2329480b7119d5c2e9e16936462a6e7886e91c` | Original v0.7.0 release | 6/6, inactive output 12001 | 5/12, seven actual failures |
| `ef7017157adc78ceb3bf16a03ee78e2060338792` | Upstream production fix | 6/6, inactive output 12002 | 12/12 historical private validation |
| `88cdfb3363f24ae504ed42d3d39487b892dfd251` | Later signer-test consolidation, identical production code | 6/6, inactive output 12002 | 12/12 rerun with this runner's explicit configuration |

The historical `ef70171` run used MONAD `e6b9678` and a private validation wrapper.
That wrapper is neither imported nor needed here. The new `88cdfb3` run uses the
tracked runner directly with full SHA and expected-code arguments. All seven
candidate rotation cases observed HTTP 400/12002, exact requested inputs UNSPENT
and empty restore before the permitted successor. Unknown input/output remain
HTTP 400/12001; accepted restores match after another rotation. Every candidate
process exits zero without worker panics. The release matrix remains 29/36 and
returns nonzero, not an expected-failure success or a skip.

## Reproduction

Requirements: Rust workspace dependencies, Docker, Go, Poetry/Python, jq, available
loopback ports, and network access to fetch pinned dependencies. Run from MONAD's
root; the clone commands are first-time setup and do not overwrite existing clones.

```bash
MONAD="$PWD"
WORK="$(mktemp -d)"
git clone --depth 1 --branch v0.7.0 https://github.com/lescuer97/nutmix.git "$WORK/nutmix"
git clone --depth 1 --branch 0.21.0 https://github.com/cashubtc/nutshell.git "$WORK/nutshell"
poetry -C "$WORK/nutshell" install --with dev
cargo build -p monad-client -p monad-relay --bins --features monad-client/funds-lifecycle-test,monad-relay/funds-lifecycle-test --target-dir target/funds-lifecycle
set -o pipefail
CDK_BIN="$(cargo test -p monad-relay --features funds-lifecycle-test --test mint_characterization --target-dir target/funds-lifecycle --no-run --message-format=json | jq -r 'select(.target.name == "mint_characterization" and .executable != null) | .executable')"
LIFECYCLE_BIN="$(cargo test -p monad-relay --features funds-lifecycle-test --test mint_external_lifecycle --target-dir target/funds-lifecycle --no-run --message-format=json | jq -r 'select(.target.name == "mint_external_lifecycle" and .executable != null) | .executable')"
```

Cargo selects the executable paths, including platform/build-dependent hashes.
All backends use Nutshell's pinned Python crypto helpers for ordinary proof
blinding/unblinding, even when the Nutshell server is not selected. Install that
environment once; `--nutshell` itself is required only when running that backend.
Run the release matrix (expected exit 1 because of the seven Nutmix failures):

```bash
poetry -C "$WORK/nutshell" run python "$MONAD/monad-relay/tests/characterization/run.py" \
  --nutshell "$WORK/nutshell" --nutmix "$WORK/nutmix" \
  --cdk-binary "$CDK_BIN" --lifecycle-binary "$LIFECYCLE_BIN"
```

To reproduce the separately pinned candidate without changing release defaults:

```bash
git clone https://github.com/SatsAndSports/nutmix.git "$WORK/nutmix-candidate"
git -C "$WORK/nutmix-candidate" checkout --detach 88cdfb3363f24ae504ed42d3d39487b892dfd251
poetry -C "$WORK/nutshell" run python "$MONAD/monad-relay/tests/characterization/run.py" \
  --mints nutmix --nutmix "$WORK/nutmix-candidate" \
  --nutmix-revision 88cdfb3363f24ae504ed42d3d39487b892dfd251 \
  --nutmix-inactive-code 12002 --lifecycle-binary "$LIFECYCLE_BIN"
poetry -C "$WORK/nutshell" run python -m unittest discover \
  -s "$MONAD/monad-relay/tests/characterization" -p test_run.py
```

The runner requires a full 40-hex candidate SHA, exact checkout HEAD, clean tracked
source, and an explicit candidate inactive-output expectation. Release expectations
cannot be overridden. Only selected mint backends are checked/built. Override
`--client-binary` and `--relay-binary` for alternate isolated CLI builds; defaults
are repo-relative `target/funds-lifecycle/debug/monad-{client,relay}`. `--temp-dir`
overrides the private artifact parent; otherwise the system temp directory is used.

Omit `--lifecycle-binary` for the ordinary matrix only. `--mints nutshell` or
`--cases refund-loss refund-rotation` narrows the matrix without changing tests.
The runner builds the retained Go adapter inside its own disposable clone. Adapters
expose loopback-only `POST /_test/rotate`, invoking CDK `rotate_sat_keyset`, Nutmix
`Signer.RotateKeyset`, or Nutshell `ledger.rotate_next_keyset`. Cashu endpoints
remain upstream implementations. External scenarios explicitly select zero-fee
rotation and post-commit rotation before opening/refund restore. Calling the
external fixture's rotation API with a nonzero fee fails, rather than silently
ignoring it. Every lifecycle rotation verifies old IDs inactive, different active
IDs and the requested fee through `/v1/keysets`. The separate CDK crash suite
preserves its existing nonzero-fee scenarios and tests fee changes.
Only parsed HTTP loopback IP origins without credentials, paths, queries or
fragments are accepted; fixture HTTP clients disable redirects. Never use public
mints or real funds.

## Validation And Limits

Cleanup reruns on 2026-09-23 (historical results below retained for provenance):

- Full `cargo test`: **581 passed, 0 failed, 20 ignored**; six additional executions
  are the three shared harness regressions included in both integration targets.
- `make test-funds-crashes`: **11 passed, 0 failed** after fixture cleanup.
- Full release ordinary matrix: **18 observations**; process matrix **CDK 12/12,
  Nutmix 5/12, Nutshell 12/12**, overall exit **1** for seven Nutmix failures.
- Candidate `88cdfb3`: **6 ordinary observations, 12/12 lifecycle**, exit **0**,
  using explicit tracked-runner configuration, not a source-replacement wrapper.
- Strict workspace/all-target/all-feature Clippy; Rust fmt/diff checks; Python
  Ruff lint/format and three Python harness tests; Go adapter build, test (no Go
  test files) and vet. Rust regressions cover detached failure propagation, URL
  validation, wrong-Y responses, restore output identity and optional DLEQ.

Original implementation/publication validation:

- `cargo test`: **575 passed, 0 failed, 20 ignored**, including the two new opt-in targets.
- `make test-funds-crashes`: **11 passed, 0 failed**, rerun after fixture changes,
  236.09 seconds. Covers the existing nonzero-fee CDK lifecycle, process-death
  boundaries, close/refund races and persistent CDK mint restart.
- Ordinary HTTP matrix: **18 completed observations**, with rejection and restore
  assertions; the observed numeric codes are now pinned assertions.
- External process matrix: **12/12 CDK, 5/12 Nutmix, 12/12 Nutshell** as above.
- Strict workspace/all-target/all-feature Clippy, Rust/Python formatting checks,
  `gofmt -l`, Python Ruff, `go vet ./cmd/monad-characterization`, and
  `git diff --check` pass.
- Publication checks rerun: `cargo fmt --all -- --check`, `git diff --check`,
  `gofmt -l`, and Python Ruff lint/format checks. The full suite and process
  matrices above are the recorded implementation runs, not publication reruns.
- Publication target check: `cargo test -p monad-relay --test mint_characterization
  --test mint_external_lifecycle` succeeds with both tests ignored as intended;
  this confirms opt-in behavior, not a rerun of their external-mint scenarios.
- No production fixes, error normalization, dependency upgrades, or modifications
  to `AGENTS.md`.

An initial 200-second tool limit interrupted the CDK baseline; subsequent complete
runs passed. Initial harness bring-up also corrected the Python crypto API and
optional restore fields. A preliminary process run exposed the overbroad
already-spent rejection assertion described above; the reported final matrix was
rerun after correcting it, with no worker panics in any passing case.
An additional ordinary-matrix rerun hit PostgreSQL's temporary initialization
server during readiness; the runner now checks TCP readiness rather than the
initial Unix-socket server. The ordinary matrix then passed all 18 observations
again, including the new exact numeric-code assertions.

Not covered: nonzero fees on Nutmix/Nutshell, their mint-process restarts,
long-running purse stress, separate dev-head test runs, all keyset format combinations,
or exhaustive adversarial Spilman enforcement. CDK's existing persistent-mint
test is not evidence of Nutmix/Nutshell restart durability.

## Cleanup

Every launched mint and process-test child is tracked, terminated and reaped;
process groups are terminated even after their leader exits, with a bounded TERM
grace period followed by KILL for surviving descendants. The Python regression
exercises an exited leader with a TERM-ignoring descendant.
Each runner-owned PostgreSQL container and anonymous volume is removed explicitly.
No global Docker cleanup is used. Successful private runner directories are
deleted. Failure directories and failed MONAD wallet fixtures are private and
retained for local investigation only; **never publish or commit them**. The runner
prints their private location locally; individual failure logs identify the
corresponding private wallet directories.
Earlier bring-up failure directories are not authoritative results. Fresh pinned
clones and isolated compiled test binaries remain available for reproduction.
