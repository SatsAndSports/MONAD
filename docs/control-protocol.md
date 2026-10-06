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

- **§1:** client-driven request/response contract.
- **§3:** proposed message fields.
- **§5:** payment records, optional release, and scoped advisory eviction.
- **§6–7:** client-first keyset removal and correlated liveness.
- **§8:** pipelined requests and FIFO response correlation without request IDs.
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
2. Client requests may be pipelined; the relay executes and answers them in order.
3. Relay reports are checked against the client's durable signed-payment history,
   monotonic session-credit record, fixed pricing, and local byte counters. A relay
   report MUST NOT cause the client to pay twice or surrender recorded credit.
4. A state snapshot and a correlated liveness response serve different purposes.
5. Wire rules do not prescribe a reducer, task architecture, database, or language.
6. A failure or lost response is not proof that an operation had no effect.

### Client-driven exchange

After consuming the initial SessionStatus, the client may send Ping at any time,
including while another request is pending. The relay MUST promptly respond with
the matching Pong without waiting for slow request processing (§7).

The other requests form one ordered pipeline. The client MAY send another
without waiting. Each completes with **exactly one success message or exactly
one Error**, never both, in request order:

| Client request | Success | Failure |
| --- | --- | --- |
| ChannelLink | SessionStatus identifying the linked channel | Error |
| ChannelPayment | SessionStatus reflecting accepted payment and session credit | Error |
| ChannelUnlink | SessionStatus with linked_channel=null and session credit preserved | Error |
| GetSessionStatus | SessionStatus | Error |
| Ping(nonce), independent of the pipeline | Pong(nonce) | Invalid input follows the fatal protocol-error rules |

The client matches each SessionStatus or nonfatal Error to the oldest unanswered
request. Relays MUST support at least five outstanding pipeline requests,
including the request being processed (§8). No window advertisement or negotiation
is needed; normal clients are expected to have only one or two outstanding.
There is no ChannelUnlinked message in the target protocol. Connection loss or
session termination can leave a request unanswered; exactly-one response does
not guarantee delivery across failure.

ChannelReleaseRequested and ChannelEvicted are advisory notifications, not
responses. A client MAY ignore both and rely entirely on request results. Errors
MUST therefore be self-contained, without requiring a previously observed
notification. There are no unsolicited SessionStatus messages after initialization.

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
| `SessionStatus` | See §3.3 | Initial relay state or success response to the oldest unanswered pipeline request (§8); client validation is required |
| `ChannelEvicted` | `channel_id`, `scope: "session" \| "relay"` | Advise that links/payments for this channel will be rejected within the stated scope (§5.4) |
| `ChannelReleaseRequested` | `channel_id` | Optional request to release the channel when convenient |
| `Error` | `code: string`, `message: string` | Request rejection or fatal session error (§8–9) |
| `Pong` | `nonce: u64` | Echo the corresponding Ping nonce |

The two advisory notifications identify the channel explicitly. A client
MUST NOT apply a delayed notification for channel A to its newer channel B.
`message` in `Error` is diagnostic only; clients MUST NOT parse it for policy.
Nonfatal Error completes the oldest unanswered pipeline request. Unsolicited Error
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
- Client request FIFO: unanswered link/payment/unlink/status-query requests in send order.

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
accepted balance, under §8. An evicted channel MUST NOT be reacquired within the
exclusion scope (§5.4). A session-scoped eviction permits use in another session,
subject to normal admission rules; it is not permission to automatically reconnect
and fight another owner. Repeating a link is not an idempotency-key replay.

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

The client keeps three distinct records:

1. **Durable signed channel balance:** the highest cumulative balance it has
   signed for each channel, preserved across sessions and payment rejections.
2. **Confirmed session credit `P`:** the largest validated cumulative
   `total_paid_millisats` for this session. It never decreases and is not reduced
   by consumption; consumption reduces remaining credit, not total paid.
3. **Pending payment expectations:** one entry per outstanding payment, recording
   its channel, signed balance, and minimum credit increment. Entries are attached
   to requests in the client's FIFO, not held in one global pending slot. They
   are not yet confirmed spendable credit.

For a newly signed balance `C_new`, let `C_old` be the client's durable signed
balance before signing. Before transmission, persist the new signed balance and
record its minimum increment `d = raw_to_msats(C_new - C_old)`. The increment
uses the client's signed history, not a lower relay-reported channel balance.
A retransmission MUST NOT attribute the same signed increment twice; retain
its original accounting association rather than manufacture a new increment or
forget an unresolved one. Every wire request still needs its own FIFO entry and
response. Previously signed value from another session can yield bonus credit but is not assumed
available in this session before confirmation.

Process responses in FIFO order. For a successful payment response, its minimum
is `P + d`, where `P` includes the validated responses to earlier requests,
including their bonus credit. The client MUST disconnect if the reported total
is below this minimum. Otherwise it sets `P` to the reported total and resolves
that payment's expectation. Do not include increments of later unanswered
payments when validating an earlier response. A definitive rejection resolves
only its own expectation; it does not pre-credit or cancel later requests.
All later status responses MUST report at least `P`; shortchanging is a protocol
violation, not a reason to sign another payment.

A scoped channel-exclusion rejection (§9) resolves the pending
expectation as rejected without adding it to `P`. This does not roll back the
durable signed channel balance or reduce confirmed session credit. The client
can replace the channel and continue this session, whether or not it processed
an eviction notification. Other payment errors require their code-specific
handling; ambiguous acceptance must be reconciled or the session ended before
originating further payments. Already sent requests remain outstanding and their
responses must still be processed in order. A timeout or notification alone MUST
NOT remove an entry from the FIFO or resolve its payment expectation.

No rejection revokes a signature already disclosed to the relay. Channel rollover
preserves that financial exposure in the durable channel record; it is not a
refund or proof that the signature cannot be redeemed.

The client sizes payments using fixed pricing, locally observed cleartext byte
counts, and its confirmed session credit `P`. It also tracks payments already
in flight so repeated planning does not fund the same target buffer twice; those
pending increments are exposure, not confirmed spendable credit. Relay-reported
byte counts, remaining balance, or paused state alone MUST NOT authorize additional payment.
All amount conversions and additions MUST use checked exact arithmetic.

Credit belongs to the accepting session; reconnecting does not transfer an old
session's remaining credit. However, if an earlier payment was never accepted,
the relay's lower stored channel balance makes a later cumulative payment credit
more than the client's conservative minimum. The client accepts this bonus (§10).

### 5.3 Cooperative release and unlink

ChannelReleaseRequested means **“please unlink this channel when convenient.”**
The client MAY ignore it. Ignoring it is not a protocol violation and does not
itself revoke ownership or invalidate otherwise valid payments. The notification
does not enter or consume the client request FIFO.

The intended initial MONAD client policy is to comply at the first safe
opportunity: mark the named channel release-pending, finish relevant outstanding
requests, reconcile its final signed balance, and then send ChannelUnlink if it
still owns the channel. A per-channel set makes repeated requests harmless.
This is client policy, not a required reaction for interoperable clients.

For a client choosing to comply:

1. Send `ChannelUnlink(A, final_balance_raw)` naming the client's final signed
   balance. A client MAY pipeline it after the final payment; it need not wait
   for that acknowledgement. If the payment fails, unlink is evaluated against
   the actual resulting state and may also fail.
2. The relay checks release eligibility, ownership, and the exact final balance.
3. On success it releases ownership and sends **one SessionStatus**, with
   `linked_channel: null` and session paid credit preserved. On failure it sends
   **one Error**. There is no separate ChannelUnlinked acknowledgement.

The client MUST NOT invent a lower final balance to force unlink success. A
missing payment acknowledgement requires reconciliation, not another conflicting
signature. Unlink does not reset channel history, refund session credit, or
execute an on-mint close. Retirement may prevent subsequent links, but release
request alone is not the relay-wide link-and-payment exclusion defined in §5.4.

If eviction or a successful replacement link already removed ownership, the
client need not issue a deferred unlink. A notification about A must never cause
unlinking B. **Review decision D3:** specify duplicate/unowned unlink outcomes
and unlink racing eviction; all outcomes must obey the single-response rule.

### 5.4 Eviction

ChannelEvicted advises that this channel is excluded from further links and
payments within a required scope:

| `scope` | Exclusion |
| --- | --- |
| `"session"` | This channel cannot be linked or paid again in this session. Other sessions may use it, subject to normal admission rules. |
| `"relay"` | This relay permanently refuses further links and payments for this channel across all sessions, including after restart. |

```json
{"type":"ChannelEvicted","channel_id":"...","scope":"session"}
```

The channel ID above is abbreviated. Scope is required, has no implicit default,
and admits only these two values. “Relay” means the payment-receiving relay
identity, not its hostname, process, or every identity sharing a wallet database.
Relay-scoped exclusion MUST be durable before announcement and enforced across
all sessions for that identity. Session-scoped exclusion lasts until that
session ends. An ownership transfer to another session excludes the old owner
with session scope. Neither scope erases funding/payment history, implies an
on-mint close, or prevents appropriate fund recovery.

The client SHOULD stop trying the excluded channel, but MAY ignore the
notification and learn the same restriction from a request Error. The relay
enforces exclusion and removes affected linked ownership regardless of
notification processing. The notification neither completes an outstanding
request nor proves its financial outcome.
Confirmed session credit remains usable; another channel may fund the session.

**Cutoff rule:** exclusion and request commitment MUST be serialized. A link or
payment not committed when exclusion takes effect MUST be rejected, including
an in-flight request. An already committed request retains its success and
credit, and its success response MUST precede the eviction notification on that
session's stream. Never revoke an accepted payment retroactively. No later link
can reacquire the channel within the excluded scope.

Request errors identify the scope independently (§9). A client that ignores both
notifications can still finish each request, handle its Error, select another
channel, and continue successfully. Notifications about an old channel cannot
cancel a pending request concerning a different one.

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
  pipeline requests are outstanding; the probe and request FIFO are independent.
- Only a Pong matching the outstanding probe completes it. Status responses,
  other messages, and late Pongs for expired probes MUST NOT complete a newer one.
- A client MAY record ordinary received traffic as recent activity and avoid
  unnecessary probes, but cannot call that traffic the response to a sent Ping.
- Paused/unlinked sessions MUST still permit Ping/Pong.
- GetSessionStatus is for snapshots; it MUST NOT be used as the correlated probe.

The relay MUST process Ping and enqueue its Pong promptly, independently of
slow link validation, mint access, or other serialized request work. Such work
MUST NOT block control reads or Pong handling. “Immediately” means no deliberate
wait for that work, not zero network latency or bypassing bytes already queued
on the ordered H2 stream. This requires independent liveness progress, but does
not prescribe a dedicated side channel or a particular task architecture.

Timeout is a local recovery decision, not proof of permanent peer death or of
non-acceptance of an outstanding payment. The timeout, probe interval, and
whether to defer timeout evaluation around known local work need an explicit
implementation policy (D7). Ping need not be sent periodically: this draft does
not require QUIC keep-alives or maintaining an otherwise idle transport forever.

## 8. Ordered request pipelining

ChannelLink, ChannelPayment, ChannelUnlink, and GetSessionStatus each consist of
one message. The client MAY send several without waiting for their responses.
The relay MUST execute them in receive order, finishing each logical operation
and fixing its response before executing the next. Responses MUST be emitted in
the same order. A success snapshot describes its request's resulting state,
before later queued requests mutate it; it is not regenerated from that later
state when eventually written to the wire. Data accounting can continue.

The client maintains a FIFO of unanswered requests. Each SessionStatus or
nonfatal Error consumes exactly its oldest entry. Ping/Pong and advisory
notifications do not enter or consume this FIFO. The client MUST validate each
response against that request, even if it has already sent a replacement link
or a higher payment; an earlier snapshot is not invalid merely because it does
not reflect those later requests.

A failed request does not cancel later ones. Each subsequent request is evaluated
against the state left by preceding operations. For example, failed acquisition
of A followed by Payment(A) normally yields two errors. If the session already
owned A and a failed redundant relink leaves ownership intact, the payment may
still succeed. There is no implicit batch transaction or dependency cancellation.

Timeouts and notifications MUST NOT remove FIFO entries. A status query MAY be
pipelined after a payment, but cannot overtake it or substitute for its missing
response. Fatal termination may leave multiple requests unanswered; preserve all
signed-payment records and treat unconfirmed outcomes conservatively.

### Minimum relay capacity

The relay MUST support at least **five outstanding pipeline requests per session**,
counting the request being processed plus queued requests. It MUST NOT reject an
otherwise valid request merely because another request is still running within
that minimum. Ping is independent and MUST remain serviceable while those
requests await slow work; it does not consume one of the five positions.

This is a minimum implementation capacity, not a negotiated client window or
an advertised SessionStatus field. Clients normally need only one or two
outstanding requests. Relays MAY support more; beyond the guaranteed minimum,
bounded buffering and ordinary transport backpressure are implementation policy.
No unlimited queue is required. If the session remains open, backpressure cannot
silently discard, merge, or reorder requests or their responses. The guarantee
for prompt Pong applies within the supported pipeline capacity and ordinary
transport constraints (§7).

These are observable protocol rules. Queue placement, reducer return values,
and event consumption mechanics are not specified here.

### D1 resolution — response discipline, without request IDs

- The initial SessionStatus is consumed before any client request. After that,
  the relay MUST NOT send unsolicited SessionStatus, including on pause/resume,
  eviction, release requests, or advertisement changes.
- Link/payment/unlink/status-query success emits exactly one SessionStatus, as
  listed in §1. This one message completes the oldest request after validation.
- Nonfatal Error MUST be the single terminal rejection response to its FIFO
  request; it MUST NOT be followed by a generic status for that request. Fatal
  errors end the session and MAY be unsolicited. Error fatality must be defined
  by machine code, not inferred from diagnostic text or a delayed EOF (D4).
- Advisory notifications may interleave with responses but MUST NOT complete
  a FIFO entry or be required to interpret an Error. A client may discard
  both notification types and still follow the same request/response rules.
- Responses and notifications MUST be emitted in logical transition order. A
  snapshot prepared before eviction cannot be emitted after its eviction
  notification and thereby restore obsolete ownership. Link/payment commitment
  races follow the exclusion cutoff in §5.4; no same-scope reacquisition is allowed.
- An unexpected response type or extra SessionStatus is a protocol violation;
  the client MUST disconnect. An extra response means one with no corresponding
  FIFO entry; the protocol relies on the relay honoring response count and order.
  Paused clients can queue status queries. No periodic status broadcast is required.

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
| `LINK_CHANNEL_RETIRED`, `CHANNEL_CLOSED`, `CHANNEL_EXPIRED` | Channel cannot be used as requested; preserve funds/recovery history; payment-time closed/expired rejection follows the replacement rules below |
| `PAYMENT_WRONG_CHANNEL`, `PAYMENT_UNKNOWN_CHANNEL` | Reconcile link/ownership; do not infer accepted credit |
| `PAYMENT_INVALID` | Invalid payment; no blind retry with newly signed funds |
| `PAYMENT_NO_NEW_FUNDS` | No additional delta credited; can occur on replay after a lost response; reconcile status |
| `PAYMENT_CONFLICT` | Baseline conflates ownership loss and accepted-state races; current client rebuilds. Target separates expected eviction from other conflicts as described below |
| `CHANNEL_UNLINK_REJECTED` | Retirement/ownership/final-balance mismatch; must not pretend release succeeded |
| `INTERNAL_ERROR` | No general no-side-effect guarantee; treat outcome as uncertain and reconcile |

### Self-contained exclusion errors

The target adds two nonfatal codes, usable for **both ChannelLink and
ChannelPayment**. Neither exists at the inspected baseline:

| Code | Meaning |
| --- | --- |
| `CHANNEL_EVICTED_FROM_SESSION` | This channel is excluded from this session; another session may use it under normal admission rules. |
| `CHANNEL_RETIRED_AT_RELAY` | This relay identity permanently excludes this channel from links and payments across all sessions and restarts. |

The oldest unanswered request identifies the channel; no notification history or
error-text parsing is required. The relay MUST enforce exclusion at the request
commit boundary and return the scoped rejection for an otherwise valid excluded-channel request;
relay scope takes precedence if both exclusions apply. An already committed
payment MUST NOT be retroactively reclassified as rejected.

The existing LINK_CHANNEL_RETIRED may still describe link-only retirement during
cooperative release. It MUST NOT be confused with relay-scoped exclusion, which
also refuses payments. Malformed requests still follow §2's protocol-error rules.

For a rejected link, either scoped code completes the request and allows selection
of another channel without ending the session. For a rejected payment, the same
continuation preserves signed history and confirmed credit as described below.

### Payment rejection policy

| Payment outcome | Required client handling |
| --- | --- |
| CHANNEL_EVICTED_FROM_SESSION or CHANNEL_RETIRED_AT_RELAY | Resolve the expectation as rejected, preserving signed channel history and confirmed session credit. Record the exclusion scope; select or provision another channel and continue this session. No observed eviction notification is required. |
| CHANNEL_CLOSED or CHANNEL_EXPIRED rejection | Stop using the channel and preserve its signed/recovery history. Resolve the rejected expectation; replacement may continue in the same session without reducing confirmed credit. |
| PAYMENT_NO_NEW_FUNDS | Reconcile with an ordered GetSessionStatus response. Do not blindly sign a larger payment; the same payment may already have been accepted. |
| PAYMENT_CONFLICT, PAYMENT_WRONG_CHANNEL, or PAYMENT_UNKNOWN_CHANNEL | Reconcile ownership and payment state before further payment; do not infer no acceptance or automatically provision a replacement from the code alone. |
| PAYMENT_INVALID | Stop automatic payment attempts and report the validation failure. Fresh channel provisioning is not a repair for an invalid signature or malformed payment. |
| INTERNAL_ERROR or otherwise ambiguous acceptance | Reconcile in FIFO order, accounting for already-sent requests. If the outcome cannot be established safely, end the session. |
| Impossible channel balance, shortchanged success response, or contradictory response ordering | Disconnect for a protocol violation. |

Resolving a rejection removes its FIFO entry, but does not necessarily
resolve financial uncertainty. For errors requiring reconciliation, retain the
signed request and its original expected credit until a fresh status establishes
acceptance with sufficient credit, or end the session. A later status includes
effects of intervening queued requests and MUST NOT be attributed solely to the
earlier uncertain payment. A missing response retains its FIFO entry: a queued
status query is allowed, but cannot bypass it (§8).

Replacement funding is sized from confirmed credit, local usage, and the normal
client payment policy. It MUST NOT blindly repeat the rejected amount as a
compensating payment. Confirmed credit is neither discarded on eviction nor
increased by a rejected pending expectation. If both release and eviction were
observed for A, ownership loss removes the need to originate an unlink for A.
Already queued requests still receive their own responses. The client may have
pipelined a replacement link; it MUST NOT mistake an earlier payment rejection
for that link's response or provision duplicate replacement funding.

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
C -> R  ChannelPayment(A, balance_raw=100)
         Both requests are outstanding; the client does not wait for link success.
R -> C  [link outcome] SessionStatus(linked=A, balance_raw=0, paused=true)
R -> C  [payment outcome] SessionStatus(linked=A, balance_raw=100, paid=delta)
```

The link snapshot MUST NOT include the later payment even if both responses
are buffered together. It completes the first FIFO entry, not the second.

### Failed link followed by payment and a status query

```text
This session does not own A. New channel admission is currently disabled.
C -> R  ChannelLink(A, ...)
C -> R  ChannelPayment(A, balance_raw=100)
C -> R  GetSessionStatus
R -> C  Error(code=CHANNEL_ADMISSION_DISABLED) # link failed
R -> C  Error(code=PAYMENT_WRONG_CHANNEL)      # payment independently failed
R -> C  SessionStatus(linked=null, paid=0)    # status query still succeeds
```

The first error neither answers nor cancels the payment. The second error resolves
the payment request but its signature remains in the wallet's durable history.
A client MUST NOT mistake the final status for a payment acknowledgement. A
failed redundant relink that preserves existing ownership has a different
result: a subsequent otherwise valid payment can succeed.

### Pipelined payments and bonus credit

```text
Channel A uses msat. Client signed balance is 100 from an uncertain old session.
This session starts with confirmed P=0; relay accepted channel balance is 0.
C -> R  ChannelPayment(A, 130)  # persist 130; entry 1 minimum increment d1=30
C -> R  ChannelPayment(A, 150)  # persist 150; entry 2 minimum increment d2=20
R -> C  SessionStatus(linked=A, balance_raw=130, paid=130)
         Validate entry 1 against 0+30, not 0+30+20. Accept bonus; P becomes 130.
R -> C  SessionStatus(linked=A, balance_raw=150, paid=150)
         Validate entry 2 against 130+20, preserving the earlier bonus.
```

The example assumes A was already linked in this session. Later signed balances
do not make earlier response snapshots stale. Each successful payment is checked
against its own increment and credit established by prior FIFO responses.

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
         Link validation remains blocked awaiting mint metadata.
R -> C  Pong(42)
         Pong completes only the probe, not the link request.
R -> C  [link outcome] SessionStatus(...)
```

### Release races an already submitted payment

```text
C -> R  ChannelPayment(A, balance_raw=130)
R -> C  ChannelReleaseRequested(A)
         This client chooses to comply; another client may ignore the request.
         Finish the outstanding payment before unlinking.
R -> C  [payment outcome] SessionStatus(linked=A, balance_raw=130)
C -> R  ChannelUnlink(A, final_balance_raw=130)
R -> C  SessionStatus(linked=null, credit preserved)
         One success message completes the unlink FIFO entry.
```

### Eviction rejects a pending payment; the session continues

```text
Channel A uses msat. Client signed balance is 100; confirmed session paid P=50.
         Client persists balance 130; pending success expectation is 50+30=80.
C -> R  ChannelPayment(A, balance_raw=130)
R -> C  ChannelEvicted(A, scope=session)
         Client ignores this advisory message; the payment remains outstanding.
R -> C  Error(code=CHANNEL_EVICTED_FROM_SESSION)
         Resolve the pending expectation as rejected; confirmed P remains 50.
         A's durable signed balance stays 130. The session remains usable.
         Select an eligible replacement B, provisioning only if necessary.
C -> R  ChannelLink(B, balance_raw=0, complete params and proofs)
R -> C  SessionStatus(linked=B, balance_raw=0, paid=50)
         Future payments use retained credit and local usage, not the rejected
         amount as an automatic retry. Existing data tunnels are not torn down
         merely for this channel rollover; they remain subject to session credit.
```

If payment acceptance had won, the relay would instead send its success status
with `paid >= 80` before ChannelEvicted(A). The client would retain that confirmed
credit while replacing A. Eviction followed by payment success is forbidden.

### Exclusion prevents same-scope reacquisition

```text
This session already owns A and sends ChannelLink(A) again.
C -> R  ChannelLink(A, balance_raw=0, same immutable funding)
         Session exclusion commits before the relink can acquire A.
R -> C  ChannelEvicted(A, scope=session)
R -> C  Error(code=CHANNEL_EVICTED_FROM_SESSION)
         No request for A can reacquire it in this session.
         A new session may use A, subject to normal admission rules.
```

With `scope=relay`, the rejection is CHANNEL_RETIRED_AT_RELAY instead, and even a
new session after relay restart cannot link or pay A at that relay identity.
Neither outcome erases the stored payments or prevents fund recovery.

## 11. Current implementation versus target

| Topic | Baseline `7212537` | Target draft |
| --- | --- | --- |
| Link/payment encoding | Shared Spilman Payment serialized into `payment_json` string | Distinct structured wire messages |
| Funding on payment | Non-null params/proofs rejected; Option decoding may treat explicit null as absent | Fields forbidden even as null |
| Relink funding | Client sends full funding; relay uses stored data and can ignore missing/conflicting supplied fields | Always require it and reject immutable conflicts |
| Advertised keyset IDs | Relay-known preference list, including inactive IDs; not an acceptance allowlist | Client ignores first, then field removed |
| Liveness | GetSessionStatus heartbeat; any server message clears the outstanding heartbeat | Correlated Ping/Pong progressing independently of slow requests; unrelated traffic does not acknowledge Ping |
| Control operation correlation | Client uses local in-flight state and snapshot inference; unsolicited statuses exist | Pipelined requests, FIFO execution/responses, exactly one SessionStatus or Error per request; no unsolicited statuses after initialization |
| Pipeline capacity | Client tracks one control operation; no proposed pipeline guarantee | Relay supports at least five outstanding requests including active work, with independent Ping progress and no negotiated window |
| Unlink success | ChannelUnlinked followed by SessionStatus | One SessionStatus; ChannelUnlinked removed |
| Proactive notifications | Eviction names a channel without scope; client reacts to release requests | Both advisory; required eviction scope and self-contained errors let a client ignore them |
| Channel versus session balances | Rejects channel balances above locally signed values and session paid totals above locally authorized totals | Keep the channel upper bound; reject session shortchanging and accept larger session credit |
| Pre-send bookkeeping | Driver increments its local session total after the send; wallet signing is a separate path | Durable signed history, confirmed credit, and per-request minimum increments recorded before transmission; responses checked in FIFO order |
| Eviction during payment | Client eviction handling clears matching operation state; PAYMENT_CONFLICT rebuilds the session | Request remains outstanding until response; scoped exclusion Error alone permits channel rollover with credit/history preserved |
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
| D1 — resolved | §1/§8 allow pipelining with FIFO execution and exactly one ordered success or Error per request; minimum capacity five, no negotiated window, independent Ping/Pong. |
| D2 | What exact immutable funding equality applies to relinks, including proof ordering and auxiliary metadata? Which error reports a conflict? |
| D3 — partly resolved | Release compliance is optional; §5.4 defines required eviction scope and the commit cutoff. Settle duplicate/unowned unlink and unlink racing eviction, with one response in all cases. |
| D4 — partly resolved | §9 defines self-contained session/relay exclusion errors for links and payments. Complete other error fatality/association rules and approve strict parsing; pipelining itself is permitted. |
| D5 | Confirm MONAD field sizes, line-size budget, exact integer representation and aggregate buffer limits. Funding structure and cryptographic vectors are referenced from the draft NUT (§3.1), not duplicated here. |
| D6 — partly resolved | Session rates and receiver are fixed. Set advertisement-update rules within solicited responses; distinguish new-channel admission from stored-channel relink when policy changes. |
| D7 — partly resolved | Pong must progress promptly despite slow request processing. Define concrete deadlines, client-local work handling, late/unsolicited Pong policy, rate limits, and buffer bounds. |

### Ordered work under #125

- [ ] Review this draft and resolve the remaining decisions; keep target rules distinguishable from current implementation.
- [ ] Change clients to ignore advertised IDs, including mocks and harnesses (#91).
- [ ] Remove the IDs and preference plumbing after that behavior is verified.
- [ ] Implement the approved structured schemas, strict funding rules, and
  FIFO execution/response contract with capacity for at least five requests.
- [ ] Implement pre-send payment bookkeeping, channel upper-bound checks,
  separate confirmed credit and per-request pending increments, session-credit lower-bound
  checks, and monotonic acceptance of bonus credit.
- [ ] Remove ChannelUnlinked; return one SessionStatus on unlink success.
- [ ] Implement optional release handling, scoped exclusion enforcement and
  persistence, self-contained errors, and same-session channel rollover.
- [ ] Implement prompt Ping/Pong independent of slow request processing and use
  it for correlated liveness instead of status queries.
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
- Reject unsolicited/extra statuses; order status queries with other requests;
  one success or Error per request, including unlink; no stale ownership
  resurrection or reacquisition inside an exclusion scope.
- Crash/write failure after durable signing but before response; lower relay
  channel balance; impossible higher channel balance causes disconnect; session
  shortchanging rejected; bonus session credit accepted without double counting.
- Fixed rates throughout the session; later rate changes cause disconnect;
  relay pause/remaining reports alone cannot induce additional signatures.
- Release with an outstanding payment, mismatched final balance, duplicate unlink,
  eviction during release and retained session credit.
- A client ignoring both notifications still handles request responses correctly;
  ignored release requests do not invalidate otherwise valid payments; optional
  release flags are channel-scoped and repeated requests are harmless.
- Exclusion rejection without any client notification history retains its FIFO entry until Error,
  preserves the signed balance and confirmed credit, resolves only the pending
  expectation, and permits a new channel in the same session. Payment success
  before eviction retains credited funds; success after eviction is rejected.
- Required eviction scope; session exclusion permits other sessions but forbids
  same-session relink; relay exclusion survives restart, covers all sessions for
  the receiving identity, and does not affect other identities sharing storage.
- Link/payment committed before exclusion succeeds; uncommitted requests fail
  with the scoped code. Signed history, confirmed credit and recovery survive.
- Generic conflict, missing rejection, and internal error cannot masquerade as a
  scoped exclusion. Notifications alone do not complete requests.
- Matching/late/wrong nonce, paused-session Ping, prompt Pong during blocked validation,
  and cancellation during local work. No false claim that any traffic proves a probe.
- At least five outstanding requests accepted while the first is blocked; Ping
  remains serviceable without queue-window negotiation. Test FIFO success/error
  mixtures, failed link followed by payment, and no implicit batch cancellation.
- Snapshots reflect their own request before later queued mutations; per-payment
  increments preserve prior bonus credit without including later expectations;
  rejected entries do not cancel successors or reduce durable signed balances.
- Pipelined payment then unlink, replacement link then payment, and status queries;
  fatal termination or cancellation retains every unanswered signed payment.
- Client-first keyset removal with rotation, inactive stored funding, unavailable
  metadata and refresh rejection, without redundant channel provisioning.

Related investigations: [#119](https://github.com/SatsAndSports/MONAD/issues/119)
(prefix probes), [#121](https://github.com/SatsAndSports/MONAD/issues/121)
(silent failures), [#122](https://github.com/SatsAndSports/MONAD/issues/122)
(deterministic recovery), [#124](https://github.com/SatsAndSports/MONAD/issues/124)
(resource bounds). These do not require a task/reducer redesign as part of this draft.
