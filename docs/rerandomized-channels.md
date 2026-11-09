# Dual-mode channel integration

## Agreed policy

- Break the session protocol once, in client and relay together; no old-protocol
  compatibility layer. The bootstrap envelope need not change.
- Relay-wide accepted/preferred commitment-mode policy with per-mint overrides.
- Per-mint/unit advertisements expose the intersection of implementation support,
  operator acceptance and confirmed mint capability. Preferred belongs to accepted;
  an empty intersection produces no usable offer.
- Client capability discovery is independent of relay advertisements. Supported,
  unsupported and unknown/unavailable are distinct. Discovery failure is not
  evidence of lack of support. Capability refresh/cache/error rules belong to the
  protocol/selection implementation and must be documented before activation.
- Session admission policy is fixed for the session. Enforce acceptance on link
  and relink against authenticated parameters, including stored funding on relink.
- Reuse any otherwise eligible accepted-mode channel; preference does not rank
  reusable channels. Prefer the relay's preference only for NEW provisioning.
- Explicit ordinary/rerandomized client overrides remain within relay acceptance.
- Choose one concrete mode before ID/funding derivation. Prepared openings,
  submissions, successor candidates and recovery never reselect or downgrade mode.
- Settlement and recovery remain available when admission policy changes. Mode
  cannot change on an existing channel. New sessions may refuse its relink.
- Opening, sender refund and payout/drain swaps stay ordinary. Both closing
  signers authorize the same mode-selected digest. Mint R is issuance metadata,
  never proof of a receiver close.

## Delivery

1. Wallet, settlement and recovery groundwork, with explicit low-level mode
   selection and real-mint/crash coverage. Normal session admission stays ordinary.
2. Session protocol, effective offers, independent capability discovery, client
   reuse/provisioning policy, configuration and management visibility.

Keep ordinary tests and vectors as the baseline. Add rerandomized variants and
negative cases without weakening ordinary assertions. Any required journal format
break rejects incompatible records intact; never automatically delete wallet data.

## Session activation (`h2-2026-11-08`)

This replaces `h2-2026-10-07` in client and relay together, without fallback. The
bootstrap envelope stays version 1; Cashu Spilman remains `2026-09-14` with keyset
versions `v1` and `v2`. Existing ordinary channel identities are unchanged. This
activation adds no storage migration or reset requirement beyond the financial
groundwork's already established journal versions.
Common wire framing is no longer feature-gated. The client/relay
`funds-lifecycle-test` features remain isolated fault-injection tooling; the
obsolete common-crate feature has been removed.

Channel mode lives only in authenticated upstream parameters: ordinary omits
`commitment_mode`, rerandomized includes `"rerandomized"`. Payments still carry
only channel ID, cumulative balance and signature. A session may accept both
channel modes; there is no redundant session-mode bit or persisted mode column.

Relay defaults accept both modes and prefer rerandomized for new provisioning.
`channel_policy.commitment_modes` sets `{accepted: [...], preferred: ...}`;
`channel_policy.mint_commitment_modes` maps mint URLs to complete overrides.
Accepted modes must be nonempty and unique, and preferred must be accepted.
Mint keys normalize trailing slashes and duplicate normalized overrides reject.
Advertisements carry the effective policy as `commitment_modes` for each unit.

The client follows the relay preference unless `client_wallet.commitment_mode`
explicitly selects `ordinary` or `rerandomized`. An override constrains both reuse
and new provisioning and cannot exceed relay acceptance. Reuse keeps existing
channel ordering and does not rank preferred modes ahead of other accepted modes.
Only new provisioning chooses a concrete mode; low-level explicit-mode wallet
APIs remain caller-policy-controlled and recovery never consults admission policy.

### Independent capability discovery

Ordinary swaps are mandatory baseline Cashu functionality, not an optional NUT-03
extension. Optional rerandomization requires `GET /v1/info` to contain
`nuts["3"].rerandomize: true`. A valid `nuts` object with missing NUT-03/flag, or
an explicit false flag, is known unsupported. Transport/HTTP failures, malformed
JSON or incorrectly typed capability fields are **unknown/unavailable**.

Relay and client caches are independent and memory-only. Discovery is
singleflight per mint, uses a 15-second HTTP timeout and a 64 KiB response limit,
and never logs response bodies.

The relay polls: known supported and unsupported results are rechecked hourly,
unknown results retry after 30 seconds, and expired positives are not reused
after failure. Relay startup primes its cache, and an owned 60-second listener
refresh cycle refreshes expired entries for future sessions. Each established
session freezes its effective policy; later cache/config changes do not alter it.
Startup discovery also includes mints of retained Open rerandomized channels,
even if they are no longer trusted for NEW funding. This preserves stored relinks
after trust changes without advertising removed offers. Ordinary-only operator
policy needs no optional-capability lookup. Refresh targets are captured at
listener startup, keeping wallet scans out of the accept/forwarding loop.

The relay omits unconfirmed rerandomization from offers; ordinary remains usable
if accepted by the operator. Rerandomized-only policy with unknown/unsupported
mint capability produces no offer. Clients independently confirm optional mode
support for eligible stored candidates and new provisioning. An unknown candidate
is temporarily ineligible, not globally invalid. If discovery for NEW preferred
rerandomized provisioning is unknown, that offer is deferred without reserving
funds or silently treating it as unsupported. Confirmed unsupported mode may fall
back to accepted ordinary mode when there is no explicit client override.
Discovery is acquisition work, never part of the 250 ms steady-state credit loop.

The client is event-driven rather than polling, so many clients do not load a
mint. It asks only when a relay advertises rerandomized funding for that mint.
It fetches `/v1/info` on first use in the process; a cached "supported" answer
then never expires, because the relay's own polling withdraws the advertisement
if the mint drops support. A cached "unsupported" or unknown answer contradicts
the advertisement and is refetched, at most once per mint per 60 seconds, so a
misbehaving relay cannot make clients hammer a mint. The advertisement only
triggers a fetch and is never evidence of support. A failed refetch keeps the
last known answer; unknown never becomes unsupported. Residual risk: between a
mint dropping support and the relay's next poll, a client may still provision a
rerandomized channel.

### Rejection and visibility

`LINK_COMMITMENT_MODE_NOT_ACCEPTED` is nonfatal and explains the rejected/accepted
modes. Link/relink checks stored funding where present before ownership or link
changes. Rejection preserves prior credit and funding; the production client
excludes the candidate only within the session and preserves wallet usability.
The fatal keyset-version check retains precedence. Client and relay management
wallet channel summaries expose mode derived from stored parameters after
channel-ID verification; corrupt or missing metadata never invents ordinary mode.

Ordinary fixtures retain explicit ordinary policy where their assertions depend
on it. Additional real-mint tests cover both rejection directions, forged relink
mode fields, prior ownership/credit preservation, accepted non-preferred reuse,
new rerandomized provisioning, client overrides, and independent capability
discovery (including unknown versus unsupported).

Instrumented funds-process fixtures explicitly select both `ordinary` and
`rerandomized` through their test-only environment override. Ordinary is an
override, not an absent preference: it must not follow the production default.
The custody audit checks the actual stored channel parameters in both fixture
modes so a default-selection change cannot silently switch refund expectations.
Because the baseline `make test-funds-lifecycle` uses normal binaries, which
ignore that override, ordinary fixtures also pin `client_wallet.commitment_mode:
ordinary` in their real config; rerandomized fixtures remove that pin.

## Financial invariants

- Stored channel parameters are authoritative for mode; summaries must not invent
  ordinary mode when stored metadata is malformed or missing.
- Retain winner-bound mint randomness with a verified close finalization so the
  complete payout can be reverified offline after restart.
- NUT-07 must cover all funding identities before R-derived NUT-09 restoration.
  Mixed/pending states and missing/inconsistent R remain unresolved.
- Keyset-only close successors retain both signatures and original output points,
  amounts and secrets. Bind finalization to the actual verified candidate.
- The sender restores retained ordinary refunds before discovering close outputs.
  Persist verified recovered proofs before importing and marking completion.
- Funding reservations and opening A/B authority rules remain unchanged.

## First-PR groundwork (before session activation)

- Explicit mode-taking APIs cover funding-value and target-capacity provisioning.
  Mode is persisted in upstream parameters before reservation/submission; A/B
  validation rejects a mode change. Wallet summaries derive mode from those
  parameters and verify the channel ID rather than maintain a second mode column.
- Close journal v6 retains `finalizing_r` and the actual verified winner. Ordinary
  finalization has no R; rerandomized finalization requires it and verifies issued
  points using effective proof blindings offline. v5 and older journals reject
  intact. There is no automatic migration or reset; use matching older binaries
  for existing old journals, or explicitly reset owned disposable fixtures.
- At that stage normal session selection and wire admission remained ordinary. The existing
  `funds-lifecycle-test` feature propagates to common framing solely for isolated
  child-process fixtures; their explicit test environment selects rerandomized
  channels. Production builds ignore that environment variable.
- Ordinary tests retain their behavior. Added coverage includes both opening
  sizing paths under competing candidates, stored mode/identity mismatch,
  complete consistent funding R, SIGKILL and committed-response loss for
  opening/close/refund successors, close/refund races, and offline finalization
  with missing/incorrect/malformed R. The custody and DLEQ oracle uses issued
  restore points for rerandomized transactions.

## Follow-up topics

### Mint metadata coordination and acquisition responsiveness

Client: new-channel selection and provisioning (capability discovery, keyset
refresh, opening swaps) runs in an owned acquisition worker, so a slow mint no
longer delays the session driver's heartbeats, advisories or shutdown handling.
Acquisition still holds the single ordinary slot until its report is applied;
see `ARCHITECTURE.md` (client session driver).

Relay: a first-time `ChannelLink` with an unknown trusted keyset awaits a keyset
refresh inline on the session's control loop, so a Ping or advisory queued behind
it waits too. This is deliberate: the coordinator bounds every caller, including
ones joining an in-flight refresh, by its 5-second timeout, singleflights per
mint, limits concurrency, and applies a 60-second per-mint cooldown. That keeps
the stall well inside the 15-second client heartbeat timeout, which tests
enforce. Relinks use stored funding and payments never contact the mint.
Capability discovery runs off the control loop (startup, then an hourly recheck),
and sessions freeze their mode policy.

Decided under [issue #179](https://github.com/SatsAndSports/MONAD/issues/179):
keyset refresh and capability discovery stay separately coordinated, since a
refreshed capability cannot change a frozen session policy and the client
already performs both inside its acquisition worker. Capability is not
invalidated from mint rejection text. Mints are not expected to withdraw
rerandomization once offered; if one does, retained channel and journal data is
never deleted, preserving later recovery options.

### Expiry policy

Review admission lifetime versus the relay close-ahead threshold, and distinguish
funding-keyset recovery time from the expiry of independently selected payout keys.
This integration does not change expiry policy.
