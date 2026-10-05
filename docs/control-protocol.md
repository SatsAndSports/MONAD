# Established-session control protocol — review draft

**Status: proposed contract, not the protocol currently implemented.**

Tracking issue: [#125](https://github.com/SatsAndSports/MONAD/issues/125).
Implementation baseline inspected: `7212537` (main after PR #118).
This document introduces no runtime changes. In particular, structured
link/payment messages and `Ping`/`Pong` below are **not supported yet**.

The words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** express proposed
requirements for the target protocol, not claims about current conformance.
Items marked **Review decision** remain unresolved. This draft MUST NOT be
treated as a finished interoperability specification until those decisions
are resolved.

### Reading guide

- **§3:** proposed message fields.
- **§5:** link, payment, release and eviction semantics.
- **§6–7:** client-first keyset removal and correlated liveness.
- **§8:** serialized requests and unambiguous response ordering without request IDs.
- **§10–11:** example exchanges and differences from current code.
- **§12:** review decisions and implementation/conformance checklist.

## 1. Scope and principles

This document specifies application messages on the H2 `POST /control` stream
of an already established MONAD session: their contents, meaning, legal timing,
responses, and effect on session/channel state.

Noise handshakes, identity exchange, transport establishment, and bootstrap
negotiation are out of scope. The session is assumed to have established a
compatible control-protocol version, receiver identity, and Cashu Spilman
protocol/keyset-format constraints. These are inputs to this contract, not
additional control messages.

Principles:

1. One operation has one wire representation. Funding belongs only in
   `ChannelLink`; subsequent payments cannot register funding.
2. At most one serialized client request is outstanding per control stream.
3. Relay reports are checked against the client's durable signed-payment history,
   monotonic session-credit record, fixed pricing, and local byte counters. A relay
   report MUST NOT cause the client to pay twice or surrender recorded credit.
4. A state snapshot and a correlated liveness response serve different purposes.
5. Wire rules do not prescribe a reducer, task architecture, database, or language.
6. A failure or lost response is not proof that an operation had no effect.

## 2. Stream lifecycle and framing

### 2.1 Establishment and termination

- A session MUST have at most one accepted control stream. A second control
  stream MUST be rejected without replacing the first.
- The relay's first application message MUST be `SessionStatus`. The client MUST
  wait for it before sending control requests.
- A new session begins unlinked, paused, with zero paid credit and byte counters.
  A stored channel's accepted balance is not automatically credit for a new session.
- Control traffic MUST remain permitted while the session is paused.
- End-of-stream, reset, or loss of the control stream ends the MONAD session;
  control half-close is not a way to keep a data-only session alive.
- Termination MUST release channel ownership held by this session, terminate its
  existing data tunnels, and prevent new tunnels. It MUST NOT erase durable
  channel funding or accepted-payment history or initiate an on-mint close merely
  because control detached.
- Unused credit in a terminated session may be lost; it is not automatically
  transferred to a new session. A previously undelivered payment can indirectly
  produce extra credit on a later session (§5.2), but that is not a refund of
  credit already accepted into the terminated session.
- A fatal error MAY be delivered before termination, but cleanup MUST NOT depend
  on successful delivery to an unresponsive peer.

### 2.2 Encoding

Each message is one UTF-8 JSON object terminated by a single LF byte (`0x0a`).
The required `type` string is case-sensitive. H2 DATA frame boundaries have no
application significance: one message can span frames and a frame can contain
several messages. Senders MUST NOT emit blank lines; receivers MAY ignore them.

Proposed maximum encoded line size: **1,048,576 bytes, excluding the LF**, matching
the current decoder limit. This includes all parameters and funding proofs.
Endpoints MUST bound buffering of incomplete messages as well as complete lines.
Oversize/incomplete input MUST NOT cause an infinite error loop or repeated
processing of the same bytes.

**Proposed strict parsing:** reject duplicate object keys, unknown message types,
wrong-direction messages, missing required fields, unexpected top-level fields,
and invalid field types/ranges. `params` and proof objects have the extension
rules of their referenced Spilman/Cashu schema, not arbitrary MONAD fields.
Forbidden fields remain forbidden even if their JSON value is `null`.

On malformed client input the relay SHOULD send `CONTROL_INVALID_MESSAGE` if
practical and MUST end the session. On malformed relay input the client MUST end
the session. A final partial line is not a message and MUST NOT be executed.
These strictness/termination rules are proposals, not the current decoder's
behavior (see §11 and review decision D4).

### 2.3 Scalar types

| Type | Meaning |
| --- | --- |
| `u64` | JSON integer from 0 through 18,446,744,073,709,551,615 |
| `u32` | JSON integer from 0 through 4,294,967,295 |
| `i64` | JSON integer from −9,223,372,036,854,775,808 through 9,223,372,036,854,775,807 |
| `channel_id` | Canonical channel identifier derived by the established Spilman protocol; currently 32 bytes encoded as 64 lowercase hexadecimal characters |
| `signature` | Spilman balance-commitment BIP-340 signature; currently 64 bytes encoded as 128 lowercase hexadecimal characters |
| `unit` | Cashu unit string; current MONAD offers use `sat` or `msat` |

Integer values MUST be represented and compared exactly; implementations using
JavaScript or floating-point JSON parsers cannot assume all `u64` values fit in
an IEEE-754 number. Senders MUST use integer decimal notation, not fractional
values. Channel balances/capacities are in the channel's raw unit; session credit
is in millisatoshis. No interpretation based on a field's apparent magnitude is
permitted.

JavaScript's ordinary `JSON.parse` uses binary64 numbers: its maximum safe integer
is `2^53 - 1 = 9,007,199,254,740,991`. In millisatoshis that is
**90,071.99254740991 BTC** (100,000,000,000 msat per BTC). Every nonnegative integer
through `2^53` itself is representable, but `2^53 + 1` is not; hence the safe-integer
limit is one less. This is far above normal channel amounts, but does not cover
the full wire range. Implementations using JavaScript MUST preserve integer
tokens losslessly rather than convert an already rounded Number to BigInt.

All fields listed below are required unless explicitly stated otherwise.
Only `SessionStatus.linked_channel` is nullable in these message schemas.

## 3. Message inventory and proposed schemas

### 3.1 Client → relay

| `type` | Additional fields | Purpose |
| --- | --- | --- |
| `ChannelLink` | `channel_id`, `balance_raw: u64` (MUST be 0), `signature`, `params: object`, `funding_proofs: nonempty array` | Register/relink a channel and acquire session ownership |
| `ChannelPayment` | `channel_id`, `balance_raw: u64`, `signature` | Increase the channel's cumulative accepted payment and this session's credit by the accepted delta |
| `ChannelUnlink` | `channel_id`, `final_balance_raw: u64` | Cooperatively finish using a retiring channel |
| `GetSessionStatus` | None | Request a relay-reported state snapshot |
| `Ping` | `nonce: u64` | Request a correlated liveness response |

`ChannelLink` and `ChannelPayment` use structured fields, not `payment_json`.
MONAD's `balance_raw` maps to the Spilman payment's `balance`; this is a wire
field name, not a change to the signed commitment. The established Spilman
signature and channel-ID derivation rules continue to apply.

`params` is a JSON object containing the complete public channel parameters;
`funding_proofs` is a nonempty JSON array of the complete funding proofs, not
JSON-encoded strings. Their contents, signatures, and derivations follow the
[Offline Spilman draft NUT](https://github.com/SatsAndSports/nuts/blob/offline-spillman-channel/XX.md)
and its [published test vectors](https://github.com/SatsAndSports/nuts/blob/offline-spillman-channel/tests/XX-tests.md),
as applicable to the established Spilman version. This document defines their
placement and required presence in MONAD messages, not a second funding schema
or a duplicate set of cryptographic vectors. Internal library objects containing
derived secrets or cached mint metadata are not the public parameters object.

### 3.2 Relay → client

| `type` | Additional fields | Purpose |
| --- | --- | --- |
| `SessionStatus` | See §3.3 | Initial relay state or response to the serialized client request (§8); client validation is required |
| `ChannelEvicted` | `channel_id` | Notify that another session acquired this channel |
| `ChannelReleaseRequested` | `channel_id` | Ask the client to finish outstanding payment work and release a retiring channel |
| `ChannelUnlinked` | `channel_id`, `final_balance_raw: u64` | Confirm cooperative release |
| `Error` | `code: string`, `message: string` | Request rejection or fatal session error (§8–9) |
| `Pong` | `nonce: u64` | Echo the corresponding Ping nonce |

The three channel-specific messages all identify the channel explicitly. A client
MUST NOT apply a delayed notification for channel A to its newer channel B.
`message` in `Error` is diagnostic only; clients MUST NOT parse it for policy.
Nonfatal Error completes the outstanding serialized request. Unsolicited Error
is permitted only for a fatal session error; it ends the session (§8–9).

### 3.3 `SessionStatus`

| Field | Type / meaning |
| --- | --- |
| `receiver_pubkey` | Receiver identity in the established Spilman public-key encoding; must match the expected receiver |
| `advertisements` | Ordered array of mint/unit offers described below |
| `linked_channel` | `null`, or `{channel_id, balance_raw: u64, capacity_raw: u64, unit}` |
| `active_in_rate` | Positive `u64`, inbound bytes per millisatoshi |
| `active_out_rate` | Positive `u64`, outbound bytes per millisatoshi |
| `session_total_in` | `u64`, cleartext bytes flowing from destination toward client |
| `session_total_out` | `u64`, cleartext bytes flowing from client toward destination |
| `total_paid_millisats` | `u64`, relay-reported credit accepted for this session, accumulated across linked channels; larger-than-expected credit is allowed (§5.2) |
| `remaining_milli_sats` | `i64`, signed remaining credit |
| `paused` | Boolean, whether paid data forwarding is paused |
| `open_connects` | `u32`, currently open data CONNECTs |
| `total_connects` | `u64`, cumulative accepted CONNECT count for this session |

The existing `remaining_milli_sats` spelling is retained deliberately. Byte
directions are from the client's perspective, not the relay socket's read/write
perspective. Control-stream bytes do not contribute to these session data counts.

Each advertisement contains exactly:

```text
mint_url: string
unit: string
funding_keyset_recovery_window_secs: u64
in_bytes_per_millisat: positive u64
out_bytes_per_millisat: positive u64
```

There is **no `keyset_ids` field** in the target schema. Offers express relay
mint/unit policy and pricing, not a list of all acceptable funding IDs.
`advertisements` MAY be empty; the control session remains valid.

`linked_channel.balance_raw` is the relay's latest accepted cumulative balance
for that channel, not the last submitted balance and not this session's total
credit. `capacity_raw` is the channel's usable raw capacity. A client MUST check
the returned channel ID, unit, and balance against its own durable channel data.

## 4. Observable session model

Session state has independent dimensions:

- Lifecycle: initializing, active, terminated.
- Channel: unlinked or linked to one channel, optionally release-pending.
- Credit: paused or forwarding, according to remaining credit.
- Client request slot: idle or awaiting link/payment/unlink/status-query outcome.

Being unlinked does not itself discard existing session credit or require an
immediate pause. A session can spend remaining credit after unlink or eviction,
but cannot add credit through a channel it no longer owns.

For fixed session rates:

```text
due_msats = ceil(session_total_in / active_in_rate
               + session_total_out / active_out_rate)
remaining = total_paid_millisats - due_msats
paused = (remaining <= 0)
```

The sum MUST be rounded once using exact arithmetic, not by separately rounding
each direction. Implementations MUST NOT wrap integer counters or amounts.
The wire remaining value is clamped to the `i64` range if necessary, matching
current behavior. Negative credit is permitted because forwarding/accounting
may overshoot at chunk boundaries; it is not grounds to erase accepted payment.

Receiver identity and active rates MUST remain fixed for the session. The client
establishes the rates from the initial SessionStatus and MUST disconnect if a
later status changes either rate. There is no in-session repricing in this
protocol; different rates require a new session or a future protocol upgrade.

New data CONNECTs are rejected while paused (currently HTTP 402); existing
tunnels wait for credit rather than being charged as control traffic. Stream
failure or termination can still end them. The control protocol does not require
one status message per forwarded chunk or a periodic status broadcast.

## 5. State-changing operations

### 5.1 Link and relink

The client MUST send complete `params` and nonempty `funding_proofs` every time,
including relinks. `balance_raw` MUST be zero, and the signature MUST authorize
the Spilman registration commitment. A link MUST NOT be used to submit a payment.

The relay validates channel identity, receiver, signature, funding, unit,
capacity, expiry/recovery constraints, applicable admission policy, and the
session's already-established keyset-format constraints before acquiring ownership.
For unknown funding IDs it may perform bounded mint metadata refresh; this is
on demand, not a promise of periodic refresh or success on the first request.

For a stored channel:

- The relay MUST preserve its stored immutable funding and latest accepted payment.
  The client independently preserves its own signed-payment history (§5.2).
- Supplied funding MUST agree with that record; a conflicting relink MUST be
  rejected rather than rewriting it or silently ignoring the conflict.
- Relinking MUST NOT reset the accepted cumulative balance or credit its
  historical value to the new session.
- Equality must be semantic, not raw JSON byte equality; the precise treatment
  of proof ordering and auxiliary proof metadata is review decision D2.

A session MAY replace its current channel by successfully linking a different
one. Its existing paid credit and byte counters remain. Successful acquisition
releases its previous ownership; a failed acquisition MUST NOT detach the old
channel merely because it was attempted. Channel ownership is exclusive across
sessions: acquiring a channel owned elsewhere evicts the previous owner.

Success is conveyed by `SessionStatus` naming the linked channel and its stored
accepted balance, under §8. Repeating a link is not an idempotency-key replay:
it can reacquire ownership and evict a different session. Clients MUST NOT
automatically replay links in a way that causes ownership ping-pong.

### 5.2 Payment

The channel MUST be linked to and owned by the sending session when the payment
is accepted. `params` and `funding_proofs` MUST NOT appear, even as `null`.

The relay verifies the signed cumulative balance against the stored channel.
For accepted balance `B_old` and proposed `B_new`:

```text
0 <= B_old < B_new <= capacity_raw
credited_msats = raw_to_msats(B_new - B_old, channel_unit)
```

For `sat`, conversion multiplies by 1000; for `msat`, it is identity. The relay
MUST validate representability before committing any transition that depends on
the conversion. Ownership and accepted-balance comparison MUST be protected
against concurrent claims or payments from other sessions.

Persisting a higher accepted balance and crediting its delta MUST NOT result in
double credit. A repeat/lower payment MUST NOT add credit. Current code has a
`PAYMENT_NO_NEW_FUNDS` outcome for no increase, but validation can instead reject
an invalid/lower payment as `PAYMENT_INVALID`; D4 must settle exact precedence.
A failed ownership/balance comparison can report
`PAYMENT_CONFLICT`. Success is reflected in `SessionStatus` under §8, including
both `linked_channel.balance_raw` and `total_paid_millisats`.

#### Client records and ambiguous delivery

The client MUST durably record the signed cumulative channel balance and payment
before handing the payment to the transport. Persistence failure MUST prevent
transmission. Cancellation, a failed write, or a lost response MUST NOT roll back
that record: the relay may already possess the signature. The client MUST NOT
lower its signed channel balance to match the relay's report.

These are two distinct checks:

- **Channel balance:** a relay report above the client's highest signed balance
  for that channel is a protocol violation; the client MUST disconnect. A report
  below the client's signed balance is allowed after ambiguous delivery. A rise
  above the relay's previous report is allowed up to the client's signed balance.
- **Session paid total:** the client maintains a monotonic session-credit record.
  A payment-success response MUST credit at least the client's expected minimum.
  A larger `total_paid_millisats` MUST be accepted as additional session credit,
  raising that record; it MUST NOT be rejected merely for exceeding expectations.
  This does not authorize a higher channel balance or an additional signature.

For a newly signed balance `C_new`, let `C_old` be the client's durable signed
balance before signing. The conservative minimum new credit is
`raw_to_msats(C_new - C_old)`, not a delta calculated from a lower relay report.
Before transmission the client records this increment once against the current
session's expected paid total. Replaying the same signed payment MUST NOT count
that increment twice. Previously signed but undelivered value can yield extra
credit, but is not assumed to be available in the new session before confirmation.

On a successful payment response, the client MUST reject a session paid total
below its expected minimum and MUST NOT compensate by signing another payment.
It updates its session-credit record to the larger reported total otherwise.
Later responses MUST NOT reduce credit already recorded for that session.
A request rejection does not prove that the signature was never received and
MUST NOT roll back either record or trigger compensating payment. An unresolved
or rejected payment cannot be treated as confirmed spendable credit; the client
must reconcile the same payment or end the session before making further payments.

The client sizes payments using fixed pricing, locally observed cleartext byte
counts, and its monotonic session-credit record. Relay-reported byte counts,
remaining balance, or paused state alone MUST NOT authorize additional payment.
All amount conversions and additions MUST use checked exact arithmetic.

Credit belongs to the accepting session; reconnecting does not transfer an old
session's remaining credit. However, if an earlier payment was never accepted,
the relay's lower stored channel balance makes a later cumulative payment credit
more than the client's conservative minimum. The client accepts this bonus (§10).

### 5.3 Cooperative release and unlink

This is a retirement handshake, not a general-purpose on-mint close operation.
The relay's notification does not occupy the client request slot; the unlink
operation starts only when the client sends ChannelUnlink:

1. Relay sends `ChannelReleaseRequested(A)`.
2. Client records release-pending, stops originating new discretionary topups for
   A, and resolves any outstanding serialized request before deciding to unlink.
3. Client sends `ChannelUnlink(A, final_balance_raw)` only once its durable signed
   final balance has been acknowledged by the relay.
4. Relay checks retirement eligibility, ownership and the exact accepted final
   balance, and releases the channel.
5. Relay sends `ChannelUnlinked(A, final_balance_raw)`, then `SessionStatus` with
   no linked channel, as an ordered success pair.

The client MUST NOT send an unlink with a lower invented final balance to get
past unresolved payment history. Missing acknowledgement requires reconciliation
or session termination, not a second conflicting signature.

Unlink preserves session credit. It does not reset channel history, refund
remaining credit, or by itself execute a mint transaction. After the success pair
the client may link a replacement. Retirement prevents later reuse of the retired
channel; ordinary control detach is a different operation.

**Review decision D3:** specify whether an exact duplicate unlink is acknowledged
after release, and how an unsolicited release request racing eviction/relink is
resolved. Clients must already scope each notification to its named channel.

### 5.4 Eviction

On receiving `ChannelEvicted(A)`, a client MUST stop treating A as owned by this
session. If its current channel is B, it MUST NOT clear B. The relay sends the
ChannelEvicted notification without an unsolicited SessionStatus. Eviction alone
does not end the session or erase its remaining credit.

A payment racing a claim by another session must be serialized at the channel
ownership/payment boundary: it is either accepted for its owner or rejected,
never credited twice. The exact wire outcome for a pending operation superseded
by eviction follows §8: the notification cannot substitute for its terminal
response. Release-specific races remain in D3.

## 6. Keyset-independent advertisements

Concrete funding IDs remain inside channel parameters/proofs where they are
needed for validation. Only the redundant advertisement preference list is removed.

Clients select an active output keyset using mint metadata and their own cache,
filtered by mint/unit, established keyset-format constraints, and channel
expiry plus recovery-window requirements. Active output-keyset selection is not
the same as validity of old funding: an inactive keyset does not automatically
invalidate a stored channel.

No client may infer that an unadvertised ID is invalid, or that any ID obtained
from a mint bypasses relay trust/format/expiry checks. The relay's bounded refresh
may be rate-limited, busy, or fail. A retry must remain consistent with immutable
funding and must not provision replacement funds merely to dodge a transient
metadata failure.

### Client-first implementation sequence

1. Keep the existing wire field temporarily, but make **all client selection and
   reuse logic** ignore its values. Test omitted/empty, stale and misleading
   preferences as applicable to that intermediate wire schema.
2. Verify cache-first selection, missing/stale-cache refresh, rotation, inactive
   stored-channel relink, and insufficient-compatible-keyset outcomes. Adapt mock
   wallets/harnesses that currently rely on advertised IDs.
3. Remove `keyset_ids` from the wire and relay, and remove preference plumbing.

Simply passing an empty list through old preference-dependent fallback logic is
not the design goal: review its refresh triggers so every provisioning attempt
does not unnecessarily rediscover the mint. The exact cache TTL/refresh schedule
is implementation policy; correctness on stale-keyset rejection is required.

## 7. Correlated liveness: Ping/Pong

```json
{"type":"Ping","nonce":42}
```

```json
{"type":"Pong","nonce":42}
```

Only the client originates Ping in this draft. While the session remains open,
the relay MUST answer each valid received Ping with one Pong echoing its `nonce`
unchanged. Termination does not guarantee delivery of a pending Pong. The nonce
is a correlation token, not authentication, a timestamp, or a replay/idempotency
credential.

- Client MUST NOT reuse a nonce within the same control stream. A monotonic
  counter is sufficient; it MUST NOT wrap and reuse values.
- Client MUST have at most one live probe outstanding. It MAY send a Ping while
  a serialized client request is outstanding; the two slots are independent.
- Only a Pong matching the outstanding probe completes it. Status responses,
  other messages, and late Pongs for expired probes MUST NOT complete a newer one.
- A client MAY record ordinary received traffic as recent activity and avoid
  unnecessary probes, but cannot call that traffic the response to a sent Ping.
- Paused/unlinked sessions MUST still permit Ping/Pong.
- GetSessionStatus is for snapshots; it MUST NOT be used as the correlated probe.

Permission to send a Ping **does not require preemption**. A relay MAY finish
slow link validation before responding to a later Ping. A client doing slow local
wallet work may likewise delay reading a Pong. No immediate response-time
guarantee or dedicated side channel is implied.

Timeout is a local recovery decision, not proof of permanent peer death or of
non-acceptance of an outstanding payment. The timeout, probe interval, and
whether to defer timeout evaluation around known local work need an explicit
implementation policy (D7). Ping need not be sent periodically: this draft does
not require QUIC keep-alives or maintaining an otherwise idle transport forever.

## 8. Ordering, responses, and the serialized client request slot

ChannelLink, ChannelPayment, and ChannelUnlink each begin with exactly one client
message. GetSessionStatus is read-only but shares their single request slot
because it also returns SessionStatus. The client MUST NOT submit another of
these requests until it has consumed the complete response to the previous one.
A timeout does not free the slot: the client must await the outcome or terminate
the session. In particular, it cannot pipeline GetSessionStatus behind an
unanswered payment to resolve uncertainty. Ping/Pong uses its independent slot.

ChannelReleaseRequested is a notification, not a client operation. It does not
occupy the slot or release ownership. ChannelUnlink begins only when the client
decides to send it after resolving any current request. ChannelEvicted, byte
accounting, and pause/resume changes likewise are not client requests.

The relay MUST finish each request's logical transition and response sequence
before executing the next serialized request. Data forwarding/accounting may
continue concurrently. This is an observable ordering contract, not a mandated
task architecture or a requirement to hold a mutex across I/O.

| Request | Intended success | Rejection / other outcome |
| --- | --- | --- |
| ChannelLink | SessionStatus naming acquired channel and accepted balance | Associated Error; fatal errors terminate |
| ChannelPayment | SessionStatus reflecting accepted cumulative balance and session credit | Associated Error; ownership race may supersede it |
| ChannelUnlink | Matching ChannelUnlinked followed by SessionStatus | Associated Error; release/eviction race needs D3 |
| GetSessionStatus | Freshly generated SessionStatus | Session/protocol failure |
| Ping(n) | Pong(n) | Session/protocol failure or local deadline |

### D1 resolution — response discipline, without request IDs

- The initial SessionStatus is consumed before any client request. After that,
  the relay MUST NOT send unsolicited SessionStatus, including on pause/resume,
  eviction, release requests, or advertisement changes.
- Link/payment/status-query success emits exactly one SessionStatus. Unlink
  success emits the matching ChannelUnlinked followed by one SessionStatus.
  The client MUST keep its slot occupied until that entire pair arrives.
- Nonfatal Error MUST be the single terminal rejection response to the pending
  request; it MUST NOT be followed by a generic status for that request. Fatal
  errors end the session and MAY be unsolicited. Error fatality must be defined
  by machine code, not inferred from diagnostic text or a delayed EOF (D4).
- ChannelReleaseRequested and ChannelEvicted may interleave with a response,
  but MUST NOT complete the request slot. A pending request superseded by eviction
  still needs an explicit terminal response, or session termination. An accepted
  payment must not be described as rejected merely because ownership changed
  afterward.
- Responses and notifications MUST be emitted in logical transition order. A
  snapshot prepared before eviction cannot be emitted after its eviction
  notification and thereby restore obsolete ownership. The unlink success pair
  describes one release transition; later-transition notifications follow it.
- An unexpected response type or extra SessionStatus is a protocol violation;
  the client MUST disconnect. Paused clients can request fresh state when their
  request slot is idle. No periodic status broadcast is required.

Serialization alone would not distinguish a queued unsolicited status from a
request response. Prohibiting those statuses, consuming every complete response,
and giving notifications distinct types removes that ambiguity even for a
same-channel relink. No general request ID or response-role field is needed.
Correlation does not replace the payment-value checks in §5.2.

## 9. Errors, replay, and uncertain outcomes

The following codes exist at the inspected baseline. Grouping below gives
intended treatment to review, not a claim that every current error has a fully
specified causal response contract. Machine codes use the uppercase wire names.

| Codes | Meaning / proposed client action |
| --- | --- |
| `CONTROL_INVALID_MESSAGE` | Framing/schema/direction violation; target draft terminates session (§2) |
| `CHANNEL_ADMISSION_DISABLED` | Administrative rejection; do not provision another channel to bypass policy |
| `LINK_INVALID_PAYMENT`, `LINK_INVALID_CHANNEL`, `LINK_RECEIVER_MISMATCH`, `LINK_NON_ZERO_BALANCE` | Invalid link; correct the request, do not blindly replay |
| `LINK_MINT_OR_KEYSET_UNACCEPTABLE`, `LINK_UNSUPPORTED_UNIT` | Funding/policy incompatibility; do not treat all such errors as temporary metadata lag |
| `LINK_KEYSET_REFRESH_RATE_LIMITED`, `LINK_KEYSET_REFRESH_BUSY`, `LINK_KEYSET_REFRESH_FAILED` | Temporary refresh obstacle; bounded/backed-off retry of unchanged funding may be appropriate |
| `LINK_UNSUPPORTED_CASHU_SPILMAN_PROTOCOL_VERSION` | Incompatible session inputs; reconnection/reconfiguration policy needs D4 |
| `LINK_KEYSET_VERSION_NOT_NEGOTIATED` | Fatal to this MONAD session; must not mark an otherwise valid wallet channel unusable globally |
| `LINK_CHANNEL_RETIRED`, `CHANNEL_CLOSED`, `CHANNEL_EXPIRED` | Channel cannot be used as requested; preserve funds/recovery history |
| `PAYMENT_WRONG_CHANNEL`, `PAYMENT_UNKNOWN_CHANNEL` | Reconcile link/ownership; do not infer accepted credit |
| `PAYMENT_INVALID` | Invalid payment; no blind retry with newly signed funds |
| `PAYMENT_NO_NEW_FUNDS` | No additional delta credited; can occur on replay after a lost response; reconcile status |
| `PAYMENT_CONFLICT` | Ownership/accepted-state race; current client rebuilds the session; final required behavior needs D4 |
| `CHANNEL_UNLINK_REJECTED` | Retirement/ownership/final-balance mismatch; must not pretend release succeeded |
| `INTERNAL_ERROR` | No general no-side-effect guarantee; treat outcome as uncertain and reconcile |

No human-readable error text is a retry instruction. A response timeout,
transport reset, or InternalError MUST NOT authorize new funding or changed
payment history on the assumption that the original request was never accepted.

Payment replay must never add credit twice. Link replay can change ownership.
Unlink replay needs D3. These are separate semantics, not a universal rule that
all control messages are idempotent. This protocol does not specify recovery of
mint HTTP transactions; the wallet's durable recovery obligations still apply.

## 10. Illustrative transcripts

The arrows below abbreviate fields; bracketed outcome labels are explanatory,
not wire fields. Symbols A/B stand for valid channel IDs; signatures/proofs are
omitted here. `paid` means `total_paid_millisats`.

### New session and payment

```text
R -> C  SessionStatus(linked=null, paid=0, remaining=0, paused=true)
C -> R  ChannelLink(A, balance_raw=0, complete params and proofs)
R -> C  [link outcome] SessionStatus(linked=A, balance_raw=0, paused=true)
C -> R  ChannelPayment(A, balance_raw=100)
R -> C  [payment outcome] SessionStatus(linked=A, balance_raw=100, paid=delta)
```

### Relink does not repay history

```text
Stored channel A already has accepted balance 100 raw.
C -> R  ChannelLink(A, balance_raw=0, same immutable funding)
R -> C  [link outcome] SessionStatus(linked=A, balance_raw=100, paid=0, paused=true)
C -> R  ChannelPayment(A, balance_raw=130)
R -> C  [payment outcome] SessionStatus(linked=A, balance_raw=130,
                                       paid=raw_to_msats(30))
```

### Ambiguous old payment yields bonus credit in a new session

```text
Channel A uses msat. Client persisted balance 100 before its previous send.
The connection died; the client keeps 100, but the relay never accepted it (0).
On a new session:
R -> C  SessionStatus(linked=null, paid=0, paused=true)
C -> R  ChannelLink(A, balance_raw=0, same immutable funding)
R -> C  SessionStatus(linked=A, balance_raw=0, paid=0, paused=true)
         Client does NOT lower its durable channel balance from 100 to 0.
         Client persists signed balance 130 and expects at least 30 new msat.
C -> R  ChannelPayment(A, balance_raw=130)
R -> C  SessionStatus(linked=A, balance_raw=130, paid=130)
         Client accepts 130 rather than rejecting it for exceeding 30.
         Its session-credit record rises to 130; the bonus is 100 msat.
```

If the relay had accepted the old 100, the new session would receive only 30.
Neither case permits a channel balance above the client's signed 130. A success
response crediting less than the expected 30 is unacceptable. Repeating a status
reporting 130 adds no further credit: it is a cumulative total, not a delta.

### Liveness while validation is pending

```text
C -> R  ChannelLink(A, ...)
C -> R  Ping(42)
         Relay may still be awaiting mint metadata. Ping is not a preemption demand.
R -> C  [link outcome] SessionStatus(...)
         The status does NOT complete Ping(42).
R -> C  Pong(42)
```

### Release races an already submitted payment

```text
C -> R  ChannelPayment(A, balance_raw=130)
R -> C  ChannelReleaseRequested(A)
         Client stops new discretionary payments, waits for the outstanding result.
R -> C  [payment outcome] SessionStatus(linked=A, balance_raw=130)
C -> R  ChannelUnlink(A, final_balance_raw=130)
R -> C  ChannelUnlinked(A, final_balance_raw=130)
         The request slot is STILL occupied.
R -> C  SessionStatus(linked=null, credit preserved)
         Only now may the client send its next serialized request.
```

## 11. Current implementation versus target

| Topic | Baseline `7212537` | Target draft |
| --- | --- | --- |
| Link/payment encoding | Shared Spilman Payment serialized into `payment_json` string | Distinct structured wire messages |
| Funding on payment | Non-null params/proofs rejected; Option decoding may treat explicit null as absent | Fields forbidden even as null |
| Relink funding | Client sends full funding; relay uses stored data and can ignore missing/conflicting supplied fields | Always require it and reject immutable conflicts |
| Advertised keyset IDs | Relay-known preference list, including inactive IDs; not an acceptance allowlist | Client ignores first, then field removed |
| Liveness | GetSessionStatus heartbeat; any server message clears the outstanding heartbeat | Correlated Ping/Pong; unrelated traffic does not acknowledge Ping |
| Control operation correlation | Client uses local in-flight state and snapshot inference; unsolicited statuses exist | One serialized request including status queries; no unsolicited statuses after initialization; complete response sequences consumed |
| Channel versus session balances | Rejects channel balances above locally signed values and session paid totals above locally authorized totals | Keep the channel upper bound; reject session shortchanging and accept larger session credit |
| Pre-send bookkeeping | Driver increments its local session total after the send; wallet signing is a separate path | Durable signed channel record and expected session increment recorded before transmission; no rollback on uncertain delivery |
| Input errors | Relay attempts Error and continues for decoder errors; client exits on decode failure | Strict fatal malformed-input handling proposed in D4 |
| Execution | Relay reducer + effect interpreter; client imperative loop with inline wallet calls | No mandated architecture; only observable ordering/cleanup obligations |

Relevant source locations for checking this draft:

- `monad-common/src/protocol.rs`: current message/error fields.
- `monad-common/src/control_codec.rs`: line framing and receive size limit.
- `monad-relay/src/session.rs`, `session_fsm.rs`, `control_driver.rs`: control
  sequencing, effects, snapshots, detach.
- `monad-relay/src/payments.rs`: link/relink validation and accepted payment delta.
- `monad-client/src/session_driver/{runtime,state,funding}.rs`: current client
  operation tracking, status reconciliation, heartbeat, and release handling.
- `monad-client/src/sqlite_client_wallet.rs`: registration signing and cached
  keyset selection. Library convenience types are not the wire specification.

## 12. Review decisions and implementation checklist

### Decisions required before declaring this normative

| ID | Question |
| --- | --- |
| D1 — resolved | §8 specifies one serialized request, no unsolicited generic statuses, dedicated notifications, and complete ordered responses without request IDs. |
| D2 | What exact immutable funding equality applies to relinks, including proof ordering and auxiliary metadata? Which error reports a conflict? |
| D3 | What are duplicate unlink, unlinked-session unlink, repeated release requests, and eviction-during-release semantics? |
| D4 | Approve strict JSON parsing/unknown fields/fatal malformed input; specify every error's fatality, association, and whether any accepted state may already have changed. How is prohibited pipelining handled? |
| D5 | Confirm MONAD field sizes, line-size budget, exact integer representation and aggregate buffer limits. Funding structure and cryptographic vectors are referenced from the draft NUT (§3.1), not duplicated here. |
| D6 — partly resolved | Session rates and receiver are fixed. Set advertisement-update rules within solicited responses; distinguish new-channel admission from stored-channel relink when policy changes. |
| D7 | Define operational probe deadlines around slow local work/relay effects, late/unsolicited Pong handling, rate limits, and resource bounds without requiring immediate preemption. |

### Ordered work under #125

- [ ] Review this draft and resolve the remaining decisions; keep target rules distinguishable from current implementation.
- [ ] Change clients to ignore advertised IDs, including mocks and harnesses (#91).
- [ ] Remove the IDs and preference plumbing after that behavior is verified.
- [ ] Implement the approved structured schemas, strict funding rules, and
  operation-outcome ordering/correlation contract.
- [ ] Implement pre-send payment bookkeeping, channel upper-bound checks,
  session-credit lower-bound checks, and monotonic acceptance of bonus credit.
- [ ] Implement Ping/Pong and use it for correlated liveness instead of status queries.
- [ ] Add conformance fixtures/transcripts and adversarial tests for both endpoints.
- [ ] Coordinate the breaking protocol version update outside this document;
  do not silently reinterpret the old wire format as the new one.
- [ ] Mark the specification final only after implementation differences are closed.

### Conformance coverage to require

- Fragmented/coalesced messages, maximum-size lines, overlong incomplete lines,
  duplicate/unknown keys, invalid integers, explicit null funding and wrong direction.
- Initial paused state, second-control rejection, control availability while
  paused, and unconditional cleanup on detach/fatal error.
- Mandatory funding on first link/relink; immutable conflict rejection; no funding
  on payments; no accepted-balance reset or historical credit on relink.
- Duplicate/lower/over-capacity payment; response loss; ownership races; no double
  credit; byte accounting continues during slow control work.
- Reject unsolicited/extra statuses; serialize status queries with payments;
  same-channel relink; notifications before a pending result; no stale ownership
  resurrection; hold the slot through the full unlink pair.
- Crash/write failure after durable signing but before response; lower relay
  channel balance; impossible higher channel balance causes disconnect; session
  shortchanging rejected; bonus session credit accepted without double counting.
- Fixed rates throughout the session; later rate changes cause disconnect;
  relay pause/remaining reports alone cannot induce additional signatures.
- Release with an outstanding payment, mismatched final balance, duplicate unlink,
  eviction during release and retained session credit.
- Matching/late/wrong nonce, paused-session Ping, Ping behind slow validation,
  and cancellation during local work. No false claim that any traffic proves a probe.
- Client-first keyset removal with rotation, inactive stored funding, unavailable
  metadata and refresh rejection, without redundant channel provisioning.

Related investigations: [#119](https://github.com/SatsAndSports/MONAD/issues/119)
(prefix probes), [#121](https://github.com/SatsAndSports/MONAD/issues/121)
(silent failures), [#122](https://github.com/SatsAndSports/MONAD/issues/122)
(deterministic recovery), [#124](https://github.com/SatsAndSports/MONAD/issues/124)
(resource bounds). These do not require a task/reducer redesign as part of this draft.
