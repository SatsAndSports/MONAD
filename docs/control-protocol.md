# Established-session control protocol — review draft

**Status: proposed contract, not the protocol currently implemented.**

Tracking issue: [#125](https://github.com/SatsAndSports/MONAD/issues/125).
Implementation baseline inspected: `7212537` (main after PR #118).
This document changes no runtime behavior. **MUST**, **MUST NOT**, **SHOULD**, and
**MAY** describe target requirements. Remaining review questions are collected
at the end; this is not yet a finished interoperability specification.

## 1. Scope and client-driven exchange

This contract covers messages on an established H2 `POST /control` stream.
The session-protocol identifier **`h2-2026-10-06`** means HTTP/2 with this MONAD
control contract. The updated client and relay support this identifier only:
**no old `h2` fallback or backward-compatibility path**. Both endpoints must be
updated together. This is a session-protocol selection in the Noise bootstrap,
not a change to HTTP/2 or QUIC TLS ALPN. The bootstrap envelope can remain
version 1; no separate control-protocol version field is needed.

Noise, transport establishment, and bootstrap mechanics are otherwise outside
this document. Authenticated relay identity, negotiated Spilman protocol, and
negotiated keyset versions are inputs. Advisory extensions (§3.4) can evolve
within this contract; new requests/responses or required semantics need explicit
capability negotiation or a new session-protocol identifier.

### Requests and responses

After the initial SessionStatus, the client may send Ping at any time. The relay
MUST promptly return the matching Pong without waiting for slow request work.
The other requests form one ordered pipeline:

| Client request | Exactly one success response | Exactly one failure response |
| --- | --- | --- |
| ChannelLink | SessionStatus identifying the linked channel | Error |
| ChannelPayment | SessionStatus reflecting accepted payment and session credit | Error |
| ChannelUnlink | SessionStatus with linked_channel=null and credit preserved | Error |
| GetSessionStatus | SessionStatus | Error |
| Ping(nonce), independent of the pipeline | Pong(nonce) | Invalid input follows the fatal protocol-error rules |

The client MAY pipeline requests without waiting. The relay MUST execute them
in receive order, finish each logical operation and fix its response before
executing the next, and emit responses in the same order. A status describes
its request's resulting state before later queued requests mutate it; it MUST
NOT be regenerated from that later state when written. Data accounting may
continue concurrently.

The client keeps a FIFO of unanswered requests. Each valid SessionStatus or
nonfatal Error answers its oldest entry. A failure does not cancel successors:
each is evaluated against the state left by earlier operations. A failed link
followed by a payment normally gives two errors; a failed redundant relink that
preserves ownership may still be followed by a successful payment. There is no
implicit batch transaction.

Relays MUST support at least **five outstanding pipeline requests per session**,
including the active request. Ping remains independently serviceable and does
not use one of those positions. There is no advertised or negotiated window;
normal clients are expected to have one or two outstanding requests. Relays may
support more, using bounded buffering/backpressure beyond the minimum. No open
session may silently discard, merge, or reorder requests or their responses.
Queue/reducer implementation mechanics are not part of this contract.

Timeouts and notifications do not remove FIFO entries. A status query can be
queued after a payment, but cannot overtake it or replace its missing response.
Connection loss or fatal termination may leave several requests unanswered;
exactly-one response does not guarantee delivery across failure. Preserve every
signed payment and treat unconfirmed outcomes conservatively.

ChannelReleaseRequested and ChannelEvicted are the two core relay-initiated
advisory notifications. Clients MAY ignore both and rely on request results.
Either endpoint may also send ExtensionNotification. None of these messages
consumes a FIFO entry or requires a reply. Errors are self-contained. Apart
from initialization, the relay MUST NOT send unsolicited SessionStatus or
nonfatal Error. Recognized fatal errors end the session. There is no
ChannelUnlinked message in the target protocol.

## 2. Lifecycle, encoding, and validation

### 2.1 Initial state and termination

- At most one control stream is accepted per session; reject a second without
  replacing the first.
- The relay's first application message MUST be SessionStatus. The client MUST
  consume it before sending any messages, including extensions.
- A new session is unlinked, paused, with zero credit and byte counters. A stored
  channel's historical balance is not automatically credit for this session.
- Control traffic remains available while paused. Control half-close is not a
  way to retain a data-only session: EOF, reset, or loss ends the session.
- Termination MUST release linked ownership, terminate existing data tunnels,
  and prevent new ones. It MUST NOT erase durable funding or accepted-payment
  history or initiate an on-mint close merely because control detached.
- Unused session credit may be lost on termination; it is not transferred on
  reconnect. Previously unaccepted signatures can yield bonus credit later
  (§5.2), which is different from refunding already accepted session credit.
- Fatal-error delivery may precede termination, but cleanup MUST NOT depend on
  delivering that error to an unresponsive peer.

Even though the initial session has no credit, its first status is essential:
it supplies the payment receiver, offered trusted mint/unit combinations and
recovery windows, and session-wide pricing needed to begin funding. Offers are
not an exhaustive allowlist of acceptable stored channels or funding keysets.

### 2.2 Encoding

Each message is one UTF-8 JSON object terminated by LF (`0x0a`), with a required,
case-sensitive `type`. H2 DATA boundaries have no application significance.
Senders MUST NOT emit blank lines; receivers MAY ignore them. A final partial
line is not a message and MUST NOT execute.

Proposed maximum encoded line: **1,048,576 bytes excluding LF**, including
funding data, matching the current decoder limit. Bound incomplete-message
buffering too; oversize input must not cause repeated parsing or error loops.

Reject duplicate keys, unknown top-level types, wrong-direction core messages,
missing required fields, unexpected top-level fields, and invalid types/ranges.
Forbidden fields are forbidden even as `null`. Public parameters/proofs follow
their referenced NUT schemas; extension payloads follow §3.4. An unknown
extension name inside a valid envelope is not an unknown top-level type.

On malformed client input the relay SHOULD send CONTROL_INVALID_MESSAGE if
practical and MUST terminate. Malformed relay input terminates the client
session. These are target rules, not current decoder behavior.

### 2.3 Exact integers and implementation limits

| Type | Wire representation |
| --- | --- |
| `u64` | JSON integer 0 through 18,446,744,073,709,551,615 |
| `u32` | JSON integer 0 through 4,294,967,295 |
| `i64` | JSON integer −9,223,372,036,854,775,808 through 9,223,372,036,854,775,807 |
| `channel_id` | Spilman channel identifier; currently 32 bytes as 64 lowercase hex characters |
| `signature` | Spilman BIP-340 commitment signature; currently 64 bytes as 128 lowercase hex characters |
| `unit` | Cashu unit string; current MONAD usage is `sat` or `msat` |

Integer tokens use decimal integer notation, not fractional values. Channel
balances/capacities use the channel's raw unit; session credit is in millisatoshis.
All supported values, comparisons, conversions, and arithmetic MUST be exact.
No unit inference from magnitude, silent rounding, truncation, or counter wrap.

Implementations MAY impose documented supported ranges smaller than the wire
types. They MUST detect and explicitly reject unsupported values before applying
them or authorizing payment; a local range failure must not alter signed history.
Rejecting an unsupported response may end the session. Validate intermediate
arithmetic too: exact inputs do not guarantee exact multiplication or billing.
There is no requirement that every implementation handle the entire u64 range.

JavaScript's ordinary JSON.parse uses binary64. Number.MAX_SAFE_INTEGER is
`2^53 - 1 = 9,007,199,254,740,991`, or **90,071.99254740991 BTC** in msat.
All nonnegative integers through `2^53` itself are representable, but `2^53 + 1`
is not. A JavaScript implementation may, for example, cap supported monetary
values at **90,000 BTC = 9,000,000,000,000,000 msat**, enforce safe integer/range
checks, and reject larger values rather than use a lossless full-u64 parser.
Counters, nonces, and intermediate results need their own exactness checks.
Converting an already rounded Number to BigInt does not restore precision.

### 2.4 Unexpected messages

After initialization, validate framing/envelopes before applying these rules:

| Incoming relay message | Client handling |
| --- | --- |
| SessionStatus or recognized nonfatal Error with pending requests | Validate against the oldest request; consume exactly that FIFO entry. Earlier snapshots need not reflect later requests already sent. |
| Structurally valid SessionStatus or recognized nonfatal Error with an empty FIFO | Discard without state changes; SHOULD emit a rate-limited warning. Do not update pricing, ownership, credit, counter baselines, pending payments, or heartbeat/probe state. |
| Response failing the oldest request's required checks | Terminate, rather than skip it and guess that the next message is the real response. |
| Recognized fatal Error | Terminate regardless of FIFO state. |
| Core advisory or valid extension notification | Handle or ignore as specified; never consume FIFO entries. |
| Malformed input, unknown top-level type, wrong-direction core message, or unknown Error code | Terminate; unknown errors cannot safely be classified as nonfatal. |

Empty-FIFO tolerance does not authorize unsolicited responses and does not
apply before initialization. Warnings MUST be bounded/rate-limited and MUST NOT
dump payments, extension payloads, or arbitrary peer diagnostic text.
With pending requests, a plausible unsolicited status can be indistinguishable
from a response. Clients check financial/request invariants without heuristic
FIFO repair; correlation relies on relay response count and ordering. Pong uses
its nonce rules, not this FIFO. Optional extensions cannot replace core responses.

## 3. Message schemas

All fields listed are required. Only linked_channel is nullable among the core
fields; extension payload members may contain null according to their schema.

### 3.1 Client → relay

| `type` | Additional fields | Meaning |
| --- | --- | --- |
| ChannelLink | `channel_id`, `zero_balance_signature`, `params: object`, `funding_proofs: nonempty array` | Register/relink funding and acquire ownership |
| ChannelPayment | `channel_id`, `balance_raw: u64`, `signature` | Submit a cumulative signed channel payment |
| ChannelUnlink | `channel_id` | Release linked ownership |
| GetSessionStatus | None | Request a state snapshot |
| Ping | `nonce: u64` | Request correlated liveness evidence |
| ExtensionNotification | `name: string`, `data: object` | Optional advisory extension; no response |

These are structured objects, not payment_json strings. For ChannelLink,
zero_balance_signature signs the **zero-balance Spilman commitment in the
channel's unit**: zero sat or zero msat, as applicable. The zero is implicit;
there is no balance_raw field on a link. For payments, balance_raw maps to the
Spilman commitment's balance without changing the signed construction.
ChannelUnlink has no final_balance_raw field and does not sign anything.

The public parameters object, funding-proof array, signatures, and derivations
follow the [Offline Spilman draft NUT](https://github.com/SatsAndSports/nuts/blob/offline-spillman-channel/XX.md)
and its [published vectors](https://github.com/SatsAndSports/nuts/blob/offline-spillman-channel/tests/XX-tests.md),
as applicable to the negotiated Spilman version. MONAD specifies their placement
and presence, not another funding schema or duplicate cryptographic vectors.
Internal objects containing derived secrets/cached metadata are not the public
parameters object. Funding fields MUST NOT appear on payments, even as null.

### 3.2 Relay → client

| `type` | Additional fields | Meaning |
| --- | --- | --- |
| SessionStatus | §3.3 | Initial state or success response; client validation required |
| ChannelEvicted | `channel_id`, `scope: "session" \| "relay"` | Advisory channel exclusion (§5.4) |
| ChannelReleaseRequested | `channel_id` | Optional request to unlink when convenient |
| Error | `code: string`, `message: string` | Request rejection or fatal session error (§8) |
| Pong | `nonce: u64` | Echo a Ping nonce |
| ExtensionNotification | `name: string`, `data: object` | Optional advisory extension; no response |

Notifications apply only to their named channel; an old-channel message cannot
cancel a request or change ownership for a different channel. Error.message is
diagnostic text, not an instruction to parse. Nonfatal Error completes the
oldest unanswered request; only fatal Error may be unsolicited.

### 3.3 SessionStatus

| Field | Type / meaning |
| --- | --- |
| receiver_pubkey | Current public payment receiver key in the negotiated Spilman encoding; may change (§4) |
| advertisements | Map of mint URL → map of unit → funding_keyset_recovery_window_secs (u64) |
| linked_channel | null or `{channel_id, balance_raw: u64, capacity_raw: u64, unit}` |
| active_in_rate | Positive u64, inbound bytes per millisatoshi, fixed session-wide |
| active_out_rate | Positive u64, outbound bytes per millisatoshi, fixed session-wide |
| session_total_in | u64, cleartext bytes from destination toward client |
| session_total_out | u64, cleartext bytes from client toward destination |
| total_paid_millisats | u64, cumulative credit accepted into this session across channels; bonus credit allowed |
| remaining_milli_sats | i64, signed remaining session credit |
| paused | Boolean, whether paid data forwarding is paused |
| open_connects | u32, currently open accepted H2 data CONNECT tunnels |
| total_connects | u64, cumulative accepted H2 data CONNECT tunnels in this session |

Directions are from the client's perspective. Control bytes are not charged as
data. CONNECT counts include TCP exits and QUIC-forwarded tunnels, regardless
of whether the outer session uses TCP or QUIC. They count logical H2 CONNECTs,
not pooled QUIC connections, packets, or the outer session itself.

For example, the advertisement map can be:

```json
{"https://mint.example":{"sat":3600,"msat":7200}}
```

Each numeric value is that mint/unit's funding-keyset recovery window in seconds.
There are **no per-mint pricing fields or concrete keyset IDs**. Rates exist only
at session level. Map order carries no preference semantics; clients select
among offers using local policy. The map may be empty. It describes offered
trusted mint/unit combinations, not every acceptable stored channel or funding ID.

linked_channel.balance_raw is the relay's accepted cumulative channel balance,
not the client's highest signed balance or the session's total paid credit.
Validate its channel ID, unit, capacity, and balance against local records.
No accepting/draining funding-state field is added; session funding refusal is
communicated by SESSION_FUNDING_DISABLED on a link/payment request (§5.5).

### 3.4 Bidirectional optional extensions

After initialization either endpoint MAY send:

```json
{"type":"ExtensionNotification","name":"example.some_hint","data":{}}
```

The envelope has exactly these required fields. name is a nonempty string and
SHOULD be namespaced; data is an object whose members the extension defines.
Unsupported names/payloads may be ignored after validating the envelope and
framing limits. Malformed envelopes still follow §2's fatal parsing rules.

Extensions MUST be optional: ignoring one must leave the core protocol correct.
They cannot change required pricing, ownership, accounting, payment authorization,
or response semantics. Sender progress must not depend on handling. They create
no FIFO entry, satisfy no Ping, and require no acknowledgement. In particular,
an unsupported client hint MUST NOT cause a relay Error or SessionStatus.

The same rules apply in both directions. Extensions may interleave with the
pipeline and Ping, with bounded resources and preserved liveness progress.
Unsupported-name warnings are optional, rate-limited, and payload-redacted.
Arbitrary unknown top-level types are not extensions. Required behavior changes
need negotiation under §1, not a mandatory instruction hidden in data.

## 4. Session accounting, pricing, and receiver changes

Lifecycle, linked ownership, paid credit, and pending requests are distinct.
Unlink or eviction does not discard credit; an unlinked session can spend what
remains but needs a usable channel to add more.

```text
due_msats = ceil(session_total_in / active_in_rate
               + session_total_out / active_out_rate)
remaining = total_paid_millisats - due_msats
paused = (remaining <= 0)
```

Round the sum once using exact arithmetic, not each direction separately.
Clamp the wire remaining value to i64 range if necessary. Negative credit is
permitted from chunk-boundary overshoot; it does not erase payment history.
New CONNECTs are rejected while paused (currently HTTP 402); existing tunnels
wait for credit. Ordinary transport failure or termination can still end them.

The initial status establishes the two session-wide rates. They MUST NOT change
in a later solicited status; the client disconnects if they do. Discarded
empty-FIFO statuses cannot reprice anything. Different rates require a new
session or a future explicitly negotiated protocol change.

**The advertised payment receiver key MAY change** in later solicited statuses.
It is not the authenticated Noise relay identity, which remains the same for
the session. A receiver-key update guides new channel provisioning; clients
bind each channel to the receiver in its immutable public parameters. Rotation
MUST NOT rewrite an existing channel or by itself invalidate its payments,
accepted history, or relink eligibility. Other explicit admission/exclusion rules
still apply. A pre-provisioned old-receiver channel is not automatically converted
to the new receiver; its admission must be checked normally.

Relay-scoped channel exclusions (§5.4) are keyed by **authenticated relay
identity and channel ID**, not the rotating payment receiver key. Receiver
rotation must not erase those exclusions or affect unrelated hosted identities.

## 5. Channel operations

### 5.1 Link and relink

Every link, including a relink, MUST contain complete public params, nonempty
funding_proofs, and a valid zero_balance_signature. A link cannot submit payment.
The relay validates channel ID, receiver, signature, funding, unit/capacity,
expiry/recovery policy, admission, and negotiated keyset-version constraints
before ownership acquisition. Unknown funding IDs may invoke bounded metadata
refresh, not a promise of immediate or periodic discovery.

Stored immutable funding and accepted payment history MUST be preserved.
Supplied relink funding must agree semantically with that record; conflicts
must be rejected rather than overwritten or ignored. Exact proof-order/auxiliary
metadata equality remains a review question. Relinking never resets accepted
balance or credits historical payments into the new session.

A successful replacement link releases the old ownership, preserving session
credit/counters. Failure alone must not detach the old channel. Only one session
owns a channel at a time; acquisition elsewhere evicts the previous owner.
Excluded channels cannot be reacquired within their exclusion scope. Permitted
use in another session is not an instruction to reconnect and fight another owner.

### 5.2 Payments and client records

Ownership must hold at acceptance. The relay verifies the cumulative signature
against stored channel data, with:

```text
0 <= B_old < B_new <= capacity_raw
credited_msats = raw_to_msats(B_new - B_old)
```

sat conversion multiplies by 1000; msat conversion is identity. Validate
representability before committing. Ownership, accepted-balance comparison, and
crediting must prevent double credit across concurrent sessions. Duplicate/lower
payments add no credit. **PAYMENT_NO_NEW_FUNDS is an Error response**, not a
successful status with a special flag; exact validation-error precedence for
lower/invalid payments remains to be specified.

The client keeps three records:

1. **Durable signed channel balance:** highest cumulative balance signed for
   each channel. Persist the balance and payment before giving the signature to
   transport. Persistence failure prevents transmission. Rejection, failed write,
   cancellation, or lost response MUST NOT roll this record back.
2. **Confirmed session credit P:** largest validated cumulative paid total for
   this session. It never decreases; consumption reduces remaining credit, not P.
3. **Per-request pending increments:** for a newly signed C_new, record
   `d = raw_to_msats(C_new - C_old)`, using the client's prior durable signed
   balance, not a lower relay report. Attach it to that request's FIFO entry.
   It is not yet confirmed spendable credit.

Process responses in FIFO order. Payment success must report at least `P + d`,
where P includes prior validated responses and their bonuses, but not later
pending payments. Otherwise disconnect for shortchanging. Accept a larger total
and raise P to it. All later solicited statuses must report at least P. An
earlier snapshot need not include later requests already transmitted.

The relay's reported channel balance MUST NOT exceed what the client has signed
for that channel; disconnect if it does. A lower relay balance is legitimate
after uncertain delivery and MUST NOT lower the client's signed record. It can
cause a later cumulative payment to credit more than expected, which the client
accepts as a bonus. This does not transfer already accepted credit from a dead
session.

A definitive replacement-eligible or session-funding-disabled rejection (§8)
resolves only that request's pending increment as rejected, without increasing P.
**Only the pending increase is undone, never the durable signed channel balance
or previously confirmed credit.** A rejection cannot revoke a signature the relay possesses.
Unknown acceptance requires reconciliation or session termination before new
payments; already queued responses must still be handled in order.

Retries must retain the original accounting association, neither attributing a
signed increment twice nor forgetting an unresolved one. Each wire request still
gets its own FIFO entry/response. A later reconciliation status includes effects
of intervening requests and cannot be attributed solely to one uncertain payment.

Payment sizing uses fixed rates, local cleartext counts, and P, while tracking
in-flight exposure to avoid funding the same target buffer twice. Relay-reported
pause state, bytes, or remaining balance alone MUST NOT authorize more signatures.

### 5.3 Optional release and unlink

ChannelReleaseRequested means “please unlink when convenient.” The client MAY
ignore it without protocol failure or invalidating otherwise valid payments.
It neither cancels requests nor revokes ownership.

The initial MONAD client policy is to comply at a safe opportunity: remember the
channel ID, finish relevant outstanding work, and unlink if still owned. It may
**provision the replacement channel first**, before unlinking, to reduce the gap;
wallet provisioning is distinct from sending a replacement ChannelLink. Repeated
release hints are harmless; old-channel hints must never unlink a newer channel.

ChannelUnlink carries **only channel_id**. The relay checks ownership and release
eligibility, releases the channel using its stored state, and returns one
SessionStatus with linked_channel=null and paid credit preserved, or one Error.
There is **no final-balance field or final-balance equality check**. Unlink does
not certify agreement about signed payments, settle/refund funds, close on-mint,
or erase history. The client retains and reconciles uncertain signatures through
normal wallet recovery independently of unlink.

Unlink can be pipelined after payment. Both requests execute and receive their
own responses; unlink success cannot substitute for a payment acknowledgement.
If eviction or replacement already released ownership, deferred unlink is not
needed. Duplicate/unowned unlink and unlink-race outcomes remain review questions.

### 5.4 Scoped advisory eviction

| Required scope | Meaning |
| --- | --- |
| `session` | No further links or payments for this channel in this session. Other sessions may use it under normal admission rules. |
| `relay` | Permanent refusal of this channel's links/payments across all sessions for the authenticated relay identity, including after restart. |

There is no default scope. Relay exclusion MUST be durable before announcement
and remain effective across payment receiver-key changes. Session exclusion lasts
until that session ends. Ownership transfer excludes the old owner with session
scope. Neither scope affects other authenticated relay identities, erases channel
history, initiates an on-mint close, or prevents appropriate fund recovery.

Clients SHOULD avoid excluded channels but MAY ignore the notification and learn
the restriction from a self-contained request Error. The relay removes affected
ownership regardless of notification processing; confirmed session credit remains.

Exclusion and request commitment MUST be serialized. An uncommitted link/payment,
including an in-flight one, is rejected once exclusion takes effect. Already
committed requests retain success/credit, with their success responses before
the eviction notification on that session's stream. No retroactive rejection,
stale snapshot resurrection, or subsequent reacquisition within the scope.

### 5.5 Session funding disabled

The relay may permanently disable new funding **for this session** while leaving
it open. An otherwise valid ChannelLink or ChannelPayment not yet committed then
receives **SESSION_FUNDING_DISABLED**, one ordered nonfatal Error per request.
This takes precedence over channel-scoped exclusion when both apply. Already
committed operations retain their success and credit. Disabling funding itself
MUST NOT remove existing linked ownership, discard paid credit, or tear down data
tunnels; new/existing CONNECTs continue under normal credit and transport rules.

Clients stop originating links/payments on this session. Another channel cannot
restore funding here. Ping, GetSessionStatus, extensions, and eligible unlink
remain available. The client may consume remaining credit rather than immediately
abandon it; a different session is needed for further funding. Ordinary failure
can still end delivery, and zero credit still pauses forwarding.

No new proactive notification or funding-state field is introduced. The Error
alone conveys the lifetime restriction and must not be treated as permission to
provision replacement funding in the same session.

## 6. Mint advertisements and keyset selection

Advertisements contain only mint → unit → recovery-window entries (§3.3).
Pricing is fixed session-wide, never attached to those entries. Concrete funding
keyset IDs remain in parameters/proofs; clients select active output keysets
using their own cache/mint metadata and **negotiated keyset-version constraints**,
with appropriate expiry/recovery windows. Inactive funding does not automatically
invalidate stored channels. Missing advertised IDs cannot imply invalidity, and
mint metadata does not bypass relay trust/version/expiry checks.

Relay metadata refresh can be busy, rate-limited, or unavailable. Retries must
preserve immutable funding rather than provision replacement funds just to dodge
a transient metadata error. The implementation sequence remains client-first:

1. Make client selection/reuse ignore existing advertised IDs, including mocks.
2. Verify cache-first behavior, stale/missing cache refresh, rotation, inactive
   relinks, and no-compatible-keyset outcomes without needless rediscovery.
3. Remove keyset_ids/preference plumbing and adopt the mint/unit map. Map order
   does not retain the old array's preference semantics.

## 7. Correlated liveness

Ping and Pong each carry a u64 nonce. The client MUST NOT reuse a nonce within
the stream or wrap its counter. At most one live probe is outstanding, independent
of pipeline requests. Only its matching Pong completes it; status, notifications,
and late/wrong nonces do not. GetSessionStatus is for state, not liveness.

While open, the relay MUST promptly process each valid Ping and enqueue one
matching Pong, independently of slow validation/mint work. Such work must not
block control reads or Pong handling within the supported pipeline capacity.
This does not imply zero latency or bypassing earlier bytes on the H2 stream.
Paused/unlinked sessions still permit probes. Termination may prevent delivery.

**Recommended implementation defaults:** Ping after 5 seconds without valid
relay control activity, with a 15-second deadline for the matching Pong. Ordinary
valid traffic may defer initiating a probe but cannot satisfy one already sent.
Rebuild logic can request fresh responsiveness evidence immediately, reusing a
pending probe only if fresh enough for its purpose. These values are policy, not
mandatory wire timings. Client-local stalls must not be mistaken for peer failure.

Probes can serve as heartbeats/keep-alives for sessions intentionally retained,
including prefix sessions during rebuild. No mandatory periodic Ping or separate
QUIC keep-alive policy is imposed. Pong proves control-path responsiveness, not
successful forwarding to every destination. Timeout authorizes local recovery,
not assumptions that outstanding signatures were never received.

## 8. Error codes and recovery

Every Error has **code** and **message**. The table defines machine meaning and
handling; **exact human-readable message strings are not standardized**. Clients
MUST NOT parse them for retry, scope, or fatality. Core codes must be understood
under the selected contract; unknown codes terminate under §2.4.

Most names below exist at the inspected baseline; scoped exclusions and
SESSION_FUNDING_DISABLED are proposed additions. “Reconcile” means no newly
originated payment until uncertainty is resolved, while preserving already sent
FIFO requests and durable signatures. Nonfatal rejection ends only its request;
fatal failure ends the session. Remaining classification questions are explicit.

| Code(s) | Applies to | Meaning and target handling |
| --- | --- | --- |
| CONTROL_INVALID_MESSAGE | Malformed input | Fatal; bounded error delivery then cleanup. |
| CHANNEL_ADMISSION_DISABLED | Link | Administrative admission refusal; nonfatal. Do not provision another channel to bypass policy. Unlike SESSION_FUNDING_DISABLED, this does not itself prohibit payments on an existing linked channel for the session lifetime. |
| SESSION_FUNDING_DISABLED | Link/payment | Nonfatal lifetime session restriction (§5.5). Resolve rejected expectation without credit, preserve signed history/P, stop funding this session, and permit remaining traffic. |
| CHANNEL_EVICTED_FROM_SESSION | Link/payment | Nonfatal session-scoped channel exclusion. Select another channel and continue; no preceding notification required. |
| CHANNEL_RETIRED_AT_RELAY | Link/payment | Nonfatal permanent exclusion for this authenticated relay identity. Do not reuse the channel there; another channel may fund the session. |
| LINK_INVALID_PAYMENT, LINK_INVALID_CHANNEL, LINK_RECEIVER_MISMATCH | Link | Invalid registration/funding/receiver; nonfatal request rejection. Correct the request, not blind replay. |
| LINK_MINT_OR_KEYSET_UNACCEPTABLE, LINK_UNSUPPORTED_UNIT | Link | Funding/policy incompatibility; nonfatal. Not every such rejection is temporary metadata lag. |
| LINK_KEYSET_REFRESH_RATE_LIMITED, LINK_KEYSET_REFRESH_BUSY, LINK_KEYSET_REFRESH_FAILED | Link | Nonfatal refresh obstacle; bounded/backed-off retry of unchanged funding may be appropriate. |
| LINK_UNSUPPORTED_CASHU_SPILMAN_PROTOCOL_VERSION | Link | Incompatible negotiated inputs; final fatality/reconnect treatment remains under review. |
| LINK_KEYSET_VERSION_NOT_NEGOTIATED | Link | Fatal to this session; do not mark an otherwise valid wallet channel globally unusable. |
| LINK_CHANNEL_RETIRED | Link | Nonfatal link-only retirement; distinct from permanent link-and-payment relay exclusion. |
| CHANNEL_CLOSED, CHANNEL_EXPIRED | Link/payment | Nonfatal unusable-channel rejection. Preserve history/recovery records; another channel may fund this session. |
| PAYMENT_WRONG_CHANNEL, PAYMENT_UNKNOWN_CHANNEL | Payment | Nonfatal rejection; reconcile ownership/payment state, not blind replacement funding. |
| PAYMENT_INVALID | Payment | Nonfatal validation rejection, but stop automatic payment attempts and report it. Fresh funding does not repair an invalid signature. |
| PAYMENT_NO_NEW_FUNDS | Payment | **Error**, no additional credit. May follow replay; reconcile with an ordered status response rather than blindly signing more. |
| PAYMENT_CONFLICT | Payment | Nonfatal state-comparison conflict requiring reconciliation. Scoped ownership loss uses the scoped codes instead. |
| CHANNEL_UNLINK_REJECTED | Unlink | Nonfatal ownership/release-eligibility rejection; no final-balance check exists in the target. Do not pretend release succeeded. |
| INTERNAL_ERROR | Request processing | Acceptance/side effects may be uncertain. Reconcile or terminate; exact fatality taxonomy remains under review. |

When both channel exclusions apply, relay scope takes precedence. These Error
responses identify the channel through the oldest FIFO request, without prior
notification history. Malformed input remains fatal even if funding is disabled.

The old LINK_NON_ZERO_BALANCE code is removed from the target: links have no
balance_raw field. Sending that forbidden field is a schema error; an invalid
zero_balance_signature is an invalid registration signature.

Replacement-eligible rejection resolves only the pending increment. Existing
confirmed credit remains and the signature stays in durable history. Replacement
funding follows local usage/normal policy, not automatic repetition of the rejected
amount. An existing queued replacement link must not cause duplicate provisioning.
SESSION_FUNDING_DISABLED is not replacement-eligible within this session.

PAYMENT_NO_NEW_FUNDS and ambiguous errors require a fresh, ordered snapshot and
careful attribution across intervening requests. A lost response cannot be skipped
by a queued query. If acceptance cannot be established safely, end the session.
Link replay may change ownership, payment replay never adds credit twice, and
unlink replay semantics are still to be finalized. Mint HTTP recovery remains
the wallet's responsibility, not a guarantee supplied by a control error.

## 9. Illustrative transcripts

Fields are abbreviated: A/B are channel IDs, `paid` means total_paid_millisats,
and signatures/proofs are omitted. Outcome labels are explanatory, not wire fields.

### Pipelined link, payment, and failure

```text
R -> C  SessionStatus(linked=null, paid=0, paused=true, receiver, offers, rates)
C -> R  ChannelLink(A, zero_balance_signature, complete params and proofs)
C -> R  ChannelPayment(A, balance_raw=100, signature)
R -> C  [link] SessionStatus(linked=A, balance_raw=0, paid=0, paused=true)
R -> C  [payment] SessionStatus(linked=A, balance_raw=100, paid=raw_to_msats(100))
```

The link snapshot cannot include the later payment. If admission failed and A
was not already owned, the same pipeline instead produces:

```text
R -> C  Error(CHANNEL_ADMISSION_DISABLED) # answers link only
R -> C  Error(PAYMENT_WRONG_CHANNEL)      # independently answers payment
C -> R  GetSessionStatus
R -> C  SessionStatus(linked=null, paid=0)
```

### Ambiguous old payment and pipelined bonus credit

```text
A uses msat. Client persisted/sent 100 in an old session that died.
Relay never accepted it and stores 0; client does not roll its signed 100 back.
In a new session:
C -> R  ChannelLink(A, zero_balance_signature, same immutable funding)
R -> C  SessionStatus(linked=A, balance_raw=0, paid=0)
C -> R  ChannelPayment(A, 130) # persist 130; minimum increment d1=30
C -> R  ChannelPayment(A, 150) # persist 150; minimum increment d2=20
R -> C  SessionStatus(linked=A, balance_raw=130, paid=130)
         Validate against P(0)+30, accept bonus, set P=130.
R -> C  SessionStatus(linked=A, balance_raw=150, paid=150)
         Validate against P(130)+20, preserving the earlier bonus.
```

If the relay had already accepted 100 in the old session, relink would report
balance_raw=100 but paid=0; these new payments would credit 30 then 20. No old
session credit transfers, and no report may exceed the client's signed balance.

### Optional release and simple unlink

```text
C -> R  ChannelPayment(A, 130)
R -> C  ChannelReleaseRequested(A)
         This client chooses to comply; another may ignore the request.
         It may provision B locally while waiting, without linking B yet.
R -> C  SessionStatus(linked=A, balance_raw=130, paid=...)
C -> R  ChannelUnlink(A)
R -> C  SessionStatus(linked=null, credit preserved)
C -> R  ChannelLink(B, zero_balance_signature, complete params and proofs)
R -> C  SessionStatus(linked=B, credit preserved)
```

There is no final balance in unlink, no equality check, and no ChannelUnlinked
message. A client can pipeline unlink after payment; it must still interpret
both responses separately and retain any uncertain signed payment.

### Exclusion versus whole-session funding refusal

```text
Client signed A=100, confirmed P=50; it persists A=130 (pending increment 30).
C -> R  ChannelPayment(A, 130)
R -> C  ChannelEvicted(A, scope=session) # client may ignore
R -> C  Error(CHANNEL_EVICTED_FROM_SESSION)
         Pending increment rejected; P stays 50 and signed A stays 130.
C -> R  ChannelLink(B, zero_balance_signature, complete params and proofs)
R -> C  SessionStatus(linked=B, paid=50)
```

A relink of A in this session also fails. Relay-scoped exclusion uses
CHANNEL_RETIRED_AT_RELAY and survives both restart and payment receiver rotation.
If the response had instead been SESSION_FUNDING_DISABLED, the client would
stop all links/payments here, keep consuming the existing credit, and not try B
on this session. Neither rejection undoes a durable signed channel balance.

### Bidirectional extensions and independent liveness

```text
C -> R  ChannelLink(A, ...)
C -> R  ExtensionNotification(name=example.client_hint, data={})
         Relay ignores the unsupported hint; no Error or response is sent.
C -> R  ChannelPayment(A, 100)
C -> R  Ping(42)
         Link validation is still blocked on mint metadata.
R -> C  Pong(42) # completes only the probe
R -> C  ExtensionNotification(name=example.relay_hint, data={})
         Client ignores it; FIFO still contains link, payment.
R -> C  SessionStatus(linked=A, balance_raw=0)   # link
R -> C  SessionStatus(linked=A, balance_raw=100) # payment
R -> C  SessionStatus(...) # forbidden unsolicited response; FIFO now empty
         Discard, rate-limit warning, change no state.
```

An invalid response while requests remained pending would terminate rather than
be skipped. Unknown top-level types are not ignorable extensions.

## 10. Current implementation versus target

| Topic | Baseline `7212537` | Target |
| --- | --- | --- |
| Session identifier | h2 | h2-2026-10-06 only; coordinated breaking update |
| Link/payment encoding | Shared Payment in payment_json; link balance explicitly zero | Structured messages; link zero_balance_signature and no balance field |
| Funding rules | Full funding sent by client; relay can ignore missing/conflicting relink data | Mandatory on every link; reject immutable conflicts; forbidden on payments even as null |
| Unlink | final_balance_raw plus equality check; ChannelUnlinked then status | channel_id only; stored-state release; one status |
| Advertisements | Ordered mint/unit entries with keyset IDs and rates | Mint → unit → recovery-window map, no IDs or ordering, pricing only at session level |
| Receiver | Captured receiver key for the session | Advertised receiver may rotate; channel receiver immutable; authenticated relay scopes exclusions |
| Client accounting | Rejects session paid above locally authorized total; updates local total after send | Pre-send signed history and per-request increments; accept bonus credit, reject shortchanging |
| Control correlation | One client operation with snapshot inference; unsolicited statuses | FIFO pipelining, five-request minimum, exactly one response; no unsolicited statuses |
| Liveness | GetSessionStatus heartbeat; any server message clears probe | Independent nonce Ping/Pong, prompt despite slow work; 5s idle/15s timeout recommended |
| Proactive messages | Eviction without scope; client acts on release | Ignorable release/eviction, required scope, self-contained errors |
| Funding refusal | Admission controls; no proposed lifetime funding-disabled outcome | SESSION_FUNDING_DISABLED preserves existing credit; no funding-state field |
| Extensions/tolerance | No ExtensionNotification; snapshot updates infer completion | Bidirectional hints; empty-FIFO response discard without state change; invalid pending response fatal |
| Architecture | Relay reducer/effect interpreter, client imperative loop | Only observable ordering/cleanup required; no prescribed queue/reducer redesign |

Source references: monad-common/src/{bootstrap,protocol,control_codec}.rs;
monad-relay/src/{session,session_fsm,control_driver,payments}.rs;
monad-client/src/session_driver/{runtime,state,funding,payment}.rs and
monad-client/src/sqlite_client_wallet.rs. Library convenience types do not define
the proposed wire contract. Current error names are not all final target rules.

## 11. Review decisions and implementation checklist

### Decisions

| ID | Status / remaining question |
| --- | --- |
| D1 — resolved | FIFO requests/responses, five-request minimum, one status/error per request, independent Ping/Pong. |
| D2 — open | Exact semantic equality for relink funding, including proof ordering/auxiliary metadata; conflict error code. |
| D3 — partly resolved | Unlink uses channel ID only and no balance check. Settle duplicate/unowned unlink, eligibility outside a release request, and unlink racing eviction. |
| D4 — partly resolved | Scoped/lifetime funding errors, response tolerance, and extensions defined. Finish ambiguous/internal/version-error fatality, exact validation precedence, and local numeric-limit rejection coding. |
| D5 — partly resolved | Smaller exact implementation ranges permitted; NUT supplies funding schemas/vectors. Confirm field/line/buffer budgets and aggregate limits. |
| D6 — partly resolved | Fixed session pricing, unordered mint/unit map, receiver rotation permitted. Finalize admission policy updates versus stored-channel reuse, including pre-provisioned old-receiver channels. |
| D7 — partly resolved | Prompt Pong and recommended 5s idle/15s timeout. Settle late/unsolicited Pong policy and implementation resource limits. |

### Implementation sequence

- [ ] Resolve remaining questions and retain the current-versus-target distinction.
- [ ] Make clients ignore advertised IDs first, including mocks/harnesses (#91);
  validate cache/rotation/reuse behavior, then remove preference plumbing.
- [ ] Implement the new structured messages, mint/unit map, session-wide pricing,
  receiver updates, ID-only unlink, and self-contained error semantics.
- [ ] Implement durable pre-send accounting, per-request increments, FIFO responses,
  five-request capacity, and correct bonus-credit/rejection handling.
- [ ] Implement optional release, scoped exclusions, lifetime session funding
  refusal, and independent Ping/Pong/extension handling.
- [ ] Coordinate client/relay switch to h2-2026-10-06 only; no legacy fallback.
- [ ] Add conformance coverage; declare the specification final only after
  target/implementation differences are closed.

### Conformance coverage

- Exact protocol selection with old h2 rejected; initial status before any
  messages, second-control rejection, paused control availability, unconditional
  teardown without erasing funding/history or implicitly closing on-mint.
- Fragmentation/coalescing, maximum/overlong partial lines, duplicate/unknown
  fields, malformed JSON, wrong direction, forbidden explicit-null fields.
- Exact supported integers, documented reduced numeric ranges (including the
  90,000 BTC msat example), checked intermediate arithmetic, no rounding/clamping
  of unsupported values. No signed-history rollback on numeric failure.
- Mandatory relink funding and zero_balance_signature; omitted balance field;
  immutable conflict rejection; no funding on payments or historical relink credit.
- Pre-send crash/write failure, duplicate/lower/over-capacity payments, impossible
  relay channel balance, shortchanged success, bonus session credit, no double
  credit, and preserved signatures after all rejections.
- Pipeline mixed success/errors, failed link then payment, redundant relink
  failure preserving ownership, status queries and unlink after payment, snapshot
  timing, prior bonus credit carried into later expectations, five blocked
  outstanding requests with prompt Ping, and fatal loss of multiple responses.
- Empty-FIFO valid response discard without changes to pricing/credit/counters/
  ownership/heartbeat; invalid pending responses and fatal/unknown errors end
  the session; warnings rate-limited and payload-redacted.
- Fixed rates across all mints/units, unordered map semantics, receiver updates
  preserving old channel parameters/history, and exclusions surviving receiver
  rotation. CONNECT counts include TCP and QUIC forwarding, not pooled connections.
- Optional release ignored successfully, replacement provisioning before unlink,
  ID-only unlink despite differing signed/accepted balances without declaring
  payment agreement, and preserved session credit; finalize duplicate/race cases.
- Notifications ignored while self-contained exclusion errors still allow
  rollover; session exclusion forbids same-session reacquisition, relay exclusion
  survives restart across all sessions of the authenticated identity, not others.
- SESSION_FUNDING_DISABLED rejects uncommitted links/payments in order, preserves
  committed credit/linked state/data, permits Ping/query/unlink, and does not cause
  replacement funding attempts in that session or expose a funding-state field.
- Bidirectional unsupported extension hints ignored without replies or FIFO
  effects; malformed envelopes fatal; hint traffic cannot satisfy probes.
- Nonce freshness, paused probes, prompt Pong during blocked work, local stalls,
  cancellation, and fresh rebuild probes; no claim that Pong proves exit reachability.
- Mint/keyset rotation, inactive funding, unavailable metadata, bounded immutable
  retries, and no redundant channel provisioning during preference removal.

Related investigations: [#119](https://github.com/SatsAndSports/MONAD/issues/119)
(prefix probes), [#121](https://github.com/SatsAndSports/MONAD/issues/121)
(silent failures), [#122](https://github.com/SatsAndSports/MONAD/issues/122)
(deterministic recovery), [#124](https://github.com/SatsAndSports/MONAD/issues/124)
(resource bounds).
