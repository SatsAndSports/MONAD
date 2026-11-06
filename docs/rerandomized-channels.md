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

## First-PR implementation and checks

- Explicit mode-taking APIs cover funding-value and target-capacity provisioning.
  Mode is persisted in upstream parameters before reservation/submission; A/B
  validation rejects a mode change. Wallet summaries derive mode from those
  parameters and verify the channel ID rather than maintain a second mode column.
- Close journal v6 retains `finalizing_r` and the actual verified winner. Ordinary
  finalization has no R; rerandomized finalization requires it and verifies issued
  points using effective proof blindings offline. v5 and older journals reject
  intact. There is no automatic migration or reset; use matching older binaries
  for existing old journals, or explicitly reset owned disposable fixtures.
- Normal session selection and wire admission remain ordinary. The existing
  `funds-lifecycle-test` feature propagates to common framing solely for isolated
  child-process fixtures; their explicit test environment selects rerandomized
  channels. Production builds ignore that environment variable.
- Ordinary tests retain their behavior. Added coverage includes both opening
  sizing paths under competing candidates, stored mode/identity mismatch,
  complete consistent funding R, SIGKILL and committed-response loss for
  opening/close/refund successors, close/refund races, and offline finalization
  with missing/incorrect/malformed R. The custody and DLEQ oracle uses issued
  restore points for rerandomized transactions.

## Deferred separate topic

Review admission lifetime versus the relay close-ahead threshold, and distinguish
funding-keyset recovery time from the expiry of independently selected payout keys.
This integration does not change expiry policy.
