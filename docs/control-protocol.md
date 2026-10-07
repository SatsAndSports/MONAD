# Established-session control protocol - review draft

**Status: proposed contract, not the protocol currently implemented.**

Tracking issue: [#125](https://github.com/SatsAndSports/MONAD/issues/125).
Implementation baseline inspected: `7212537` (main after PR #118).
This document changes no runtime behavior. **MUST**, **MUST NOT**, **SHOULD**, and
**MAY** describe target requirements. The client and relay must be updated
together before this contract is selected.

## 1. Scope and lifecycle

This contract covers messages on an established H2 `POST /control` stream. The
session-protocol identifier **`h2-2026-10-06`** selects HTTP/2 with this MONAD
control contract. Endpoints implementing this target MUST select only that
identifier: there is no old `h2` fallback or compatibility path. This is Noise
bootstrap session-protocol selection, not a change to HTTP/2 or QUIC TLS ALPN.
The bootstrap envelope can remain version 1; no separate control version is
needed.

Noise, transport establishment, and bootstrap mechanics are otherwise outside
this document. Authenticated relay identity, negotiated Spilman protocol, and
negotiated keyset versions are inputs. Optional notifications can evolve within
this contract; new requests, responses, or required semantics need explicit
capability negotiation or a new session-protocol identifier.

### 1.1 Initial state

- At most one control stream is accepted per session. A second is rejected
  without replacing the first.
- The relay MUST send one initial `SessionStatus` after the control stream is
  established and before processing any core client request.
  `ExtensionNotification` messages may appear before it, but it is the relay's
  first non-extension message.
- A new session is unlinked and paused, with zero CONNECT counters.
- The initial status supplies the state and funding information defined in §3.3.

### 1.2 Payment channels and payments into a session

A session can have at most one linked payment channel, and a payment channel can
be linked to at most one session at a time. Over time, a session may receive
payments from several successive channels, and a channel may pay into several
successive sessions. Unlinking, replacing, or evicting a channel does not remove
any payments already credited to the session.

The relay's cumulative record of payments into a session,
`total_paid_millisats`, starts at zero for every new session. Linking an existing
channel does not credit its previously accepted payments to that session.

For each valid, increasing payment on the linked channel, the relay advances the
channel's accepted cumulative balance and adds the difference from its previous
accepted balance to the session's paid total, converted to millisatoshis. This
session total is monotonic: payments add to it; nothing subtracts from it.

The client separately records the highest cumulative payment it has signed for
each channel. After successful delivery and acknowledgement, the client's signed
balance and the relay's accepted balance normally agree. An interrupted session
can leave the client's record higher: the client may have signed and sent a
payment that the relay never accepted. The client retains that signed record even
when delivery is uncertain.

If the client reuses that channel in a later session, a subsequent cumulative
payment can therefore credit more than the client's newly signed increment. The
relay calculates the increase from its own previously accepted balance, which
may be lower than the client's previous signed balance.

For example, suppose the client previously signed **100 msat**, but the relay
accepted only **80 msat**. In a new session, linking the channel starts the
session paid total at zero. If the client then signs **130 msat**, its newly
signed increment is **30 msat**, but the relay accepts an increase of **50 msat**
and credits that amount to the new session. For example, the payment that
advanced the signed balance from 80 to 100 msat may have been lost when the old
session terminated.

A successful payment may increase the session paid total by more than the client
expected, but never by less than its expected increment. The client accepts the
larger total and uses it as its confirmed record when validating subsequent
responses. §5.2 defines the precise signed and pending-payment records.

### 1.3 Traffic counters

Traffic directions are measured from the client's perspective:

- **Outbound bytes** travel from the client toward a destination.
- **Inbound bytes** travel from a destination toward the client.

The relay maintains cumulative counters for both directions across all data
CONNECT tunnels in the session. Both counters start at zero and only increase.
Opening or closing a tunnel, or changing the linked payment channel, does not
reset them.

Only payload bytes successfully forwarded through non-control CONNECT streams
count. The control stream does not contribute to either counter. Each forwarded
byte increments the counter for its direction exactly once; bytes that are only
read or buffered but not forwarded do not count.

### 1.4 When data forwarding is enabled

The relay calculates the amount due from the cumulative traffic counters and the
session's fixed directional prices (§4). While the session's cumulative paid
total exceeds that amount, paid data forwarding is unpaused across all its data
CONNECT tunnels, subject to ordinary destination readiness and transport
backpressure.

When the amount due reaches or exceeds the paid total, paid data forwarding
pauses. A subsequent accepted payment that restores positive credit unpauses
forwarding. An unlinked session can continue using its existing credit but needs
a linked channel to add more. The control stream remains available throughout.

### 1.5 Termination

Control EOF, reset, or loss ends the session; half-close is not a way to retain a
data-only session. Termination MUST release linked ownership, terminate existing
data tunnels, and prevent new ones. It MUST NOT erase durable funding or accepted
payment history or initiate an on-mint close merely because control detached.

Unused session credit is not transferred on reconnect. Fatal-error delivery may
precede termination, but cleanup MUST NOT depend on delivery to an unresponsive
peer.

## 2. Framing, validation, and exact values

### 2.1 Encoding and resource bound

Each message is one UTF-8 JSON object terminated by LF (`0x0a`), with a required,
case-sensitive `type`. H2 DATA boundaries have no application significance.
Senders MUST NOT emit blank lines; receivers MAY ignore them. A final partial
line is not a message and MUST NOT execute.

An encoded line MUST NOT exceed **1,048,576 bytes excluding LF**. Senders MUST
enforce the limit before transmission, and receivers MUST bound incomplete-line
buffering to the same limit. Oversize input is a fatal protocol error and must
not cause repeated parsing or error loops.

The bound applies to the complete JSON message, not to an H2 frame, control
stream, or session. `ChannelLink` is normally the largest message because its
`funding_token` contains every funding proof in compact Cashu V4 form. Ordinary
unrestricted power-of-two denominations need few proofs, but a small
`maximum_amount_for_one_output` can make proof count linear in the raw funding
amount. A Spilman construction can therefore be valid under its NUT yet too large
for MONAD. Clients MUST account for the final encoded JSON line, including the
base64url token, while constructing channels and SHOULD conservatively reject
candidates that cannot fit before requesting funding. Encoded size, not a
separate proof-count limit, is authoritative.

Reject duplicate keys, unknown top-level types, wrong-direction core messages,
missing required fields, unexpected top-level fields, and invalid outer field
types or ranges. Forbidden fields are forbidden even as `null`. Senders MUST
encode public parameters and proofs under their referenced NUT schemas. The relay
MUST validate those nested schemas on first registration but MAY rely on its
stored immutable record without parsing them for a known relink under §5.1.
Extension payloads follow §3.5. Unknown extension names inside a valid envelope
are not unknown top-level types.

`Error.message` MUST fit within 4,096 UTF-8 bytes. JSON nesting, counting the root
object as depth one, MUST NOT exceed 64; total object members plus array elements
MUST NOT exceed 65,536. Senders enforce these bounds. A required response that
cannot fit terminates the session rather than truncating structured state.

On malformed client input the relay SHOULD send `CONTROL_INVALID_MESSAGE` if
practical and MUST terminate. Malformed relay input terminates the client. These
are target rules, not current decoder behavior.

### 2.2 Exact integers and supported ranges

| Type | Wire representation |
| --- | --- |
| `u64` | JSON integer 0 through 18,446,744,073,709,551,615 |
| `u32` | JSON integer 0 through 4,294,967,295 |
| `i64` | JSON integer -9,223,372,036,854,775,808 through 9,223,372,036,854,775,807 |
| `channel_id` | Spilman channel identifier; 32 bytes as 64 lowercase hex characters |
| `signature` | Spilman BIP-340 commitment signature; 64 bytes as 128 lowercase hex characters |
| `unit` | Cashu unit string; exactly `sat` or `msat` |

Integer tokens use decimal integer notation, not fractional values. Channel
balances and capacities use the channel's raw unit; session credit uses
millisatoshis. All supported values, comparisons, conversions, and intermediate
arithmetic MUST be exact. There is no unit inference from magnitude, silent
rounding, truncation, saturation, clamping, or counter wrap.

Implementations MAY impose documented supported ranges smaller than the wire
types. They MUST reject unsupported request values before persistence, ownership,
payment, or credit mutation, using `NUMERIC_LIMIT_EXCEEDED`. A local failure must
not alter signed history. Relays MUST set operational limits that keep every
status field, including exact `remaining_milli_sats`, representable. If exact
accounting or a received response becomes unrepresentable despite those checks,
the endpoint terminates rather than emitting or accepting an approximation.

JavaScript's ordinary `JSON.parse` uses IEEE-754 binary64 numbers, whose 53 bits
of integer precision represent every integer only through
`2^53 - 1 = 9,007,199,254,740,991`. Interpreted as millisatoshis, that exact
safe-integer limit is **90,071.99254740991 BTC**. An implementation may therefore
use the round lower cap **90,000 BTC = 9,000,000,000,000,000 msat**, check every
integer and intermediate result, and reject larger values rather than support the
full `u64` range. Some larger integers happen to be representable, but not every
adjacent value is, and converting an already rounded `Number` to `BigInt` does
not restore precision. The cap alone does not make multiplication, addition, or
counters safe; each intermediate result needs its own exactness check.

### 2.3 Sensitive material

Funding tokens contain bearer proofs and secret material. Implementations MUST
NOT log or include in errors, metrics, traces, notifications, or diagnostics a
complete funding token or proof, proof secret, channel secret, private key,
signature, derivation preimage, or complete `ChannelLink` or `ChannelPayment`
message. Diagnostics may identify a channel by `channel_id` and report bounded,
non-secret structural metadata such as a proof count or keyset ID.

## 3. Messages and exchange

All fields listed in the core message tables are required and non-null unless a
field's table entry explicitly says otherwise. Optional extension payload members
may contain null under their schema.

### 3.1 Client to relay

| `type` | Additional fields | Meaning |
| --- | --- | --- |
| `ChannelLink` | `channel_id`, `zero_balance_signature`, `params: object`, `funding_token: string` | Register or relink funding and acquire ownership |
| `ChannelPayment` | `channel_id`, `balance_raw: u64`, `signature` | Submit a cumulative signed channel payment |
| `ChannelUnlink` | `channel_id` | Release linked ownership |
| `GetSessionStatus` | None | Request a state snapshot |
| `Ping` | `nonce: string` | Request correlated liveness evidence |
| `ExtensionNotification` | `name: string`, `data: object` | Optional advisory extension; no response |

A link's `zero_balance_signature` signs the zero-balance Spilman commitment in
the channel's unit; zero is implicit and `balance_raw` is forbidden. A payment's
`balance_raw` maps directly to the Spilman commitment. Funding fields are
forbidden on payments, even as null. Unlink has no final balance and signs
nothing.

`funding_token` is a standard `cashuB` Cashu V4 token containing exactly the
channel's funding proofs. Its mint, unit, keyset ID, amounts, proof order, and
proof contents MUST agree with `params`; it MUST contain exactly one keyset group
and no memo, unrelated proofs, or unknown token fields. For keyset versions `v1`
and `v2`, every proof MUST include its DLEQ data. The token's compact CBOR is
carried in its standard base64url string form, not decoded into a second JSON
proof array. Its encoding follows the pinned
[Cashu V4 token specification](https://github.com/SatsAndSports/nuts/blob/37f03c9c67303d4ae7f2254ff9470c2ecb83565c/00.md#v4-tokens).

For negotiated Spilman protocol `2026-09-14` and keyset versions `v1` and `v2`,
public parameters, decoded proofs, signatures, and derivations follow the pinned
[Offline Spilman draft NUT](https://github.com/SatsAndSports/nuts/blob/37f03c9c67303d4ae7f2254ff9470c2ecb83565c/XX.md)
and its [published vectors](https://github.com/SatsAndSports/nuts/blob/37f03c9c67303d4ae7f2254ff9470c2ecb83565c/tests/XX-tests.md).
MONAD defines their placement and presence, not a second funding schema. Internal
objects containing secrets or cached metadata are not public parameters. Future
versions require an explicit mapping to their immutable specifications and
version-specific validation rules.

Noise bootstrap selects the Spilman protocol and mutually supported keyset
versions; this control protocol uses that result and does not negotiate them.
Today's bootstrap supports `v1` and `v2`. Future `v3` support requires bootstrap
support and a version-specific mapping for any changed proof or signature shape.

### 3.2 Relay to client

| `type` | Additional fields | Meaning |
| --- | --- | --- |
| `SessionStatus` | §3.3 | Initial state or successful request result |
| `ChannelEvicted` | `channel_id`, `scope: "session" \| "relay"` | Advisory exclusion (§5.4) |
| `ChannelReleaseRequested` | `channel_id` | Advisory request to unlink when convenient (§5.3) |
| `Error` | `code: string`, `message: string` | Request rejection or fatal session error (§6) |
| `Pong` | `nonce: string` | Correlated response to Ping (§3.4) |
| `ExtensionNotification` | `name: string`, `data: object` | Optional advisory extension; no response |

`Error.message` is diagnostic text and MUST NOT be parsed for behavior. There is
no `ChannelUnlinked` message.

### 3.3 SessionStatus

| Field | Type and meaning |
| --- | --- |
| `receiver_pubkey` | Current payment receiver key in the negotiated Spilman encoding; may rotate (§4) |
| `advertisements` | Map of mint URL to map of supported unit (`sat` or `msat`) to funding-keyset recovery-window seconds (`u64`) |
| `linked_channel` | Nullable; `null` or `{channel_id, balance_raw: u64, capacity_raw: u64, unit}` |
| `bytes_in_per_msat` | Positive `u64`, bytes from destination toward client per millisatoshi, fixed session-wide |
| `bytes_out_per_msat` | Positive `u64`, bytes from client toward destination per millisatoshi, fixed session-wide |
| `session_total_bytes_in` | `u64`, cleartext bytes from destination toward client |
| `session_total_bytes_out` | `u64`, cleartext bytes from client toward destination |
| `total_paid_millisats` | `u64`, cumulative payments credited to this session (§1.2) |
| `remaining_milli_sats` | `i64`, exact signed remaining session credit |
| `paused` | Boolean, whether paid data forwarding is paused |
| `open_connects` | `u32`, currently open accepted H2 data CONNECT tunnels |
| `total_connects` | `u64`, cumulative accepted H2 data CONNECT tunnels |
| `failed_connects` | `u64`, cumulative H2 data CONNECT requests not accepted by the relay |

CONNECT counts include TCP exits and QUIC-forwarded tunnels and count logical H2
CONNECTs, not packets, pooled QUIC connections, or the outer session.
`total_connects` and `open_connects` increment when the relay commits acceptance
of a CONNECT and submits its successful H2 response. `failed_connects` increments
exactly once when session handling instead commits non-acceptance, including
pause, policy, target, upstream-connect, or pre-acceptance stream failure. Client
receipt of the response is not part of either counter's definition. A tunnel
failure after successful acceptance does not retrospectively increment
`failed_connects`. `open_connects` decrements exactly once when an accepted tunnel
terminates. Each status is one internally consistent snapshot, although
accounting may advance immediately after its linearization point.

An advertisement value is the mint/unit funding-keyset recovery window in
seconds. There are no per-mint rates or concrete keyset IDs. Map order has no
preference semantics and the map may be empty. It describes offered trusted
mint/unit combinations, not every acceptable stored channel or funding ID.
MONAD defines only `sat` and `msat`, but neither endpoint is required to support
both. A relay advertises whichever of those units it accepts for each mint, and a
client uses only a unit it also supports.

`linked_channel.balance_raw` is the relay's accepted cumulative channel balance,
not the client's highest signed balance or total session credit. Clients validate
its ID, unit, capacity, and balance against local records. No accepting/draining
funding-state field exists; §5.5 uses an ordered request error.

### 3.4 Ordered requests and correlated liveness

The relay sends exactly one success or failure response for each request:

| Request | Success | Failure |
| --- | --- | --- |
| `ChannelLink` | `SessionStatus` identifying the linked channel | `Error` |
| `ChannelPayment` | `SessionStatus` reflecting accepted payment and credit | `Error` |
| `ChannelUnlink` | `SessionStatus` with no linked channel and preserved credit | `Error` |
| `GetSessionStatus` | `SessionStatus` | `Error` |

The client MAY pipeline up to five requests. The relay MUST execute them in receive
order, complete each logical operation and fix its response before executing the
next, and emit responses in the same order. A status describes that request's
result before later queued mutations; data accounting may continue concurrently.

The client keeps a FIFO of unanswered requests. Each valid `SessionStatus` or
nonfatal `Error` answers the oldest entry. Failure does not cancel successors;
each is evaluated against the state left by earlier operations. There is no
implicit batch transaction. Relays MUST support at least **five outstanding
requests per session**, including the active request, using bounded buffering or
backpressure beyond that minimum. They MUST NOT silently discard, merge, or
reorder requests or responses.

A client MUST NOT create a sixth unanswered request. If a relay receives one
while five remain unanswered, behavior beyond the guaranteed window is not
interoperable: a relay MAY support it, apply backpressure, or send bounded
`CONTROL_INVALID_MESSAGE` and terminate. The client limit keeps compliant ingress
readable without an unbounded ordinary-request queue.

Apart from the initial status, the relay MUST NOT send an unsolicited
`SessionStatus` or nonfatal `Error`.

Timeouts and notifications do not consume FIFO entries. A queued status request
cannot overtake a payment or replace its missing response. Connection loss or
fatal termination may leave requests unanswered; exactly-one response does not
guarantee delivery across failure. Clients preserve every signed payment and
treat unconfirmed outcomes conservatively.

Ping and Pong are independent of that FIFO. A client MAY send Ping whenever it
wants. Its nonce is an opaque JSON string; a client may encode a timestamp or any
other locally useful value. The relay does not interpret it and MUST return one
Pong containing the same decoded string. It SHOULD do so promptly. Each Pong
answers one Ping occurrence.

Ping consumes none of the five pipeline positions, and multiple Pings are
permitted. A relay MAY process them in receive order with other control messages
or separately. It need not search ahead in buffered input, interrupt active work,
or provide zero-latency preemption. Normal bounded control-stream buffering and
backpressure apply.

Status, notifications, ordinary traffic, and a Pong with a different nonce do
not answer a Ping, update request state, or cancel recovery already selected
after a timeout. Paused and unlinked sessions permit Ping; termination may
prevent Pong delivery.

Recommended policy is Ping after 5 seconds without valid relay control activity
and a 15-second matching-Pong deadline. Ordinary valid traffic may defer creating
a probe but does not answer a Ping already sent. Rebuild logic may demand fresh
evidence. Client-local stalls must not be blamed on the peer. Pong proves only
control-path responsiveness, not destination reachability or nonreceipt of an
outstanding payment. No mandatory periodic Ping or QUIC keep-alive is imposed.

### 3.5 Advisories and extensions

Either endpoint MAY send:

```json
{"type":"ExtensionNotification","name":"example.some_hint","data":{}}
```

The envelope has exactly those fields. `name` is nonempty and SHOULD be
namespaced; `data` is an object. Unsupported names or payloads may be ignored
after envelope and framing validation. Malformed envelopes remain fatal.

Extension notifications may be sent at any time in either direction, including
before the relay's initial `SessionStatus`.

Extensions are optional hints. Ignoring one must leave the core protocol
correct; they cannot change pricing, ownership, accounting, authorization, or
required response semantics. Sender progress cannot depend on handling. They
create no FIFO entry, satisfy no Ping, require no acknowledgement, and may
interleave with requests and probes subject to bounded resources. An unsupported
hint MUST NOT elicit `Error` or `SessionStatus`. Required behavior changes need
negotiation, not a mandatory instruction hidden in extension data.

### 3.6 Unexpected messages

Before the initial status, the client accepts valid extension notifications. The
first non-extension relay message MUST be the initial `SessionStatus`; any other
core relay message at that point is fatal. After initialization, clients apply
these rules after framing validation:

| Incoming relay message | Client handling |
| --- | --- |
| Valid `SessionStatus` or recognized nonfatal `Error` with pending requests | Validate against and consume exactly the oldest FIFO entry. |
| Structurally valid `SessionStatus` or recognized nonfatal `Error` with an empty FIFO | Discard without state changes; SHOULD emit a bounded warning. |
| Response failing the oldest request's required checks | Terminate rather than skip it and guess. |
| Recognized fatal `Error` | Terminate regardless of FIFO state. |
| Core advisory or valid extension | Handle or ignore as specified; never consume FIFO. |
| Malformed input, unknown top-level type, wrong-direction core message, or unknown error code | Terminate. |

Empty-FIFO tolerance applies only after initialization. Discarded messages change
no state. Warnings MUST be rate-limited and redact payments, extension payloads,
and arbitrary peer text. With pending work, clients validate financial invariants
but never heuristically repair the FIFO.

Discovery of fatal input marks the session terminating at one serialized commit
gate: committed operations retain fixed outcomes, while every uncommitted
operation is cancelled and cannot mutate session, ownership, accepted-balance, or
credit state. Harmless validation work or shared metadata-cache refresh may still
finish. Already-fixed responses precede the fatal error when bounded delivery is
practical; cleanup waits for neither.

## 4. Session state, pricing, and advertisements

The accounting and forwarding model in §§1.2-1.4 uses this exact calculation:

```text
due_msats = ceil(session_total_bytes_in / bytes_in_per_msat
               + session_total_bytes_out / bytes_out_per_msat)
remaining_milli_sats = total_paid_millisats - due_msats
paused = (remaining_milli_sats <= 0)
```

Round the sum once using exact arithmetic, not each direction separately. The
wire remaining value is exact and is never clamped. Negative credit is permitted
from chunk-boundary overshoot and does not erase payment history. New CONNECTs
MUST be rejected with HTTP 402 while paused; existing tunnels wait for credit.
Ordinary transport failure or termination may still end them.

For the byte-accounting events defined in §1.3, implementations MUST check counter
and billing representability before each bounded forwarding operation and update
the counter immediately by the number of bytes successfully forwarded.

Implementations choose their forwarding chunk sizes and in-flight limits. Larger
chunks can increase the bytes forwarded after credit reaches zero and therefore
increase the relay's financial exposure; that is a relay implementation and
policy choice, not a wire-protocol violation. Chunking MUST remain bounded and
MUST NOT permit counter overflow, inaccurate accounting, or forwarding to resume
without positive credit.

The initial status fixes both rates. A changed rate in a later solicited status is
fatal; different rates require a new session or future negotiation.

Each status advertises exactly one current payment receiver. It is not the
authenticated Noise identity and MAY change in later solicited statuses. Clients
use the current receiver for new provisioning, while each channel remains bound
to the receiver in its immutable public parameters. Old receiver keys are not
advertised.

A client MAY try a locally stored channel with the same authenticated relay even
when that channel names an older receiver. The relay first looks up `channel_id`:
a channel is known only after successful validation and durable storage, never
merely because a prior link was attempted. Relays SHOULD accept an otherwise
valid known channel under its stored receiver and MUST retain the key material
needed to operate and recover it. Refusing such a relink uses
`LINK_CHANNEL_RETIRED` without erasing its record or recovery path. An unknown
channel bound to a noncurrent receiver gets `LINK_RECEIVER_MISMATCH`.

There is no grace period for unknown channels. Rotation can race local mint
provisioning: if the receiver changes before first successful storage, the client
MUST NOT retry that channel here and instead recovers its funding normally.
Implementations should avoid needless rotation, but an earlier status does not
guarantee later acceptance.

Clients select active output keysets using local cache or mint metadata plus
negotiated keyset-version constraints and the advertised recovery window.
Inactive funding does not invalidate a stored channel. Missing advertised IDs
cannot imply invalidity, and mint metadata cannot bypass relay trust, version,
expiry, or recovery policy. Metadata refresh can be busy, rate-limited, or
unavailable; retry unchanged immutable funding rather than provision replacement
funds merely to avoid a transient refresh error.

For unknown/new funding with channel expiry `E`, advertised recovery window `W`, and the
funding keyset's optional final expiry `K`, admission requires no final expiry or
`K >= E + W` under checked `u64` addition. Final expiry zero is always
unacceptable; equality is acceptable; overflow of `E + W` is unacceptable. This
predicate is for new-funding admission only and MUST NOT block restore, refund,
close, or a valid stored relink.

## 5. Channel operations

### 5.1 Link and relink

Before ownership acquisition, the relay determines known-versus-new status by
`channel_id` and applies the precedence in §6.

For an unknown channel, the relay MUST strictly validate the complete public
parameters and Cashu V4 funding token under the bootstrap-negotiated Spilman
protocol and keyset version before making the channel known. This includes
recomputing the channel ID; validating receiver, unit, capacity, expiry,
admission, mint, keyset, proof structure, and signatures; requiring funding
`witness` and `p2pk_e` to be absent; and, for `v1` and `v2`, requiring DLEQ on
every proof, deriving the expected deterministic `r`, requiring the submitted
`r` to equal it, and verifying `(e,s,r)`. Funding-keyset recovery-window
admission applies only to this first registration. Unknown funding IDs may
invoke bounded metadata refresh. The relay stores the immutable funding only
after all validation succeeds.

For a known channel, the relay's stored, previously validated immutable funding
is authoritative. The client MUST still send the channel's original complete
`params` and `funding_token` to keep one `ChannelLink` shape, but the relay MAY
skip parsing, comparing, or cryptographically revalidating them and SHOULD
normally reuse its stored record without mint I/O. Supplied relink data MUST NOT
overwrite stored funding or accepted balance.

Every relink still validates channel state and policy, bootstrap-negotiated
keyset-version eligibility, exact numeric representability, and the supplied
zero-balance signature against the stored channel before ownership changes. The
signature need not equal the original registration signature and is not evidence
of freshness because its signed message contains no session challenge.

A successful replacement link releases the old ownership. Failure alone does not
detach the old channel. Acquisition elsewhere evicts the previous owner.
Permission to use a channel elsewhere is not an instruction to repeatedly
reacquire it and fight another owner.

### 5.2 Payments and client records

Ownership must hold at acceptance. The relay verifies the cumulative signature
against stored data and atomically enforces:

```text
0 <= B_old < B_new <= capacity_raw
credited_msats = raw_to_msats(B_new - B_old)
```

Sat conversion multiplies by 1000; msat conversion is identity. All conversion
and resulting session totals are checked before mutation. Ownership, accepted
balance, and credit commit prevent double credit across concurrent sessions.
Duplicate or lower payments return `PAYMENT_NO_NEW_FUNDS`, not a successful
status.

The client keeps three records:

1. **Durable signed channel balance:** highest cumulative balance signed for each
   channel. Persist balance and payment before exposing the signature to
   transport. Rejection, write failure, cancellation, or lost response never
   rolls this record back.
2. **Confirmed session paid total P:** largest validated cumulative paid total
   for this session (§1.2).
3. **Per-request pending increment:** for newly signed `C_new`, record
   `d = raw_to_msats(C_new - C_old)` from the prior durable signed balance and
   attach it to that request's FIFO entry. It is not yet spendable credit.

A payment success MUST identify the submitted channel and report
`balance_raw == B_new`. It must report at least `P + d`, where P includes prior
validated responses but excludes later pending payments. A smaller total is
shortchanging and terminates the client. A larger total raises P. Lower channel
balances are allowed only in relink, query, or other reconciliation statuses.
Later solicited statuses must report at least P.

Reported channel balance MUST NOT exceed what the client signed. A lower relay
balance is legitimate after uncertain delivery and never lowers the client's
durable record, as explained in §1.2.

Any definitive payment rejection removes only that request's pending expected
increment. It does not decrease P or the durable signed balance. Unknown
acceptance requires reconciliation or session termination before originating
another payment; already queued responses remain ordered. Retries retain the
original accounting association and never count one signed increment twice.

Replacement funding follows local policy rather than automatically repeating a
rejected amount. An already queued replacement link MUST NOT trigger duplicate
channel provisioning.

Payment sizing uses fixed rates, local cleartext counts, P, and in-flight
exposure. Relay-reported pause, byte counts, or remaining credit alone MUST NOT
authorize another signature.

### 5.3 Release and unlink

`ChannelReleaseRequested` means “please unlink when convenient.” A client MAY
ignore it without protocol failure or invalidating payments. It does not cancel
requests or revoke ownership. A complying client may provision a replacement
locally before unlinking; provisioning is distinct from sending a replacement
link. Repeated hints are harmless, and an old-channel hint never unlinks a newer
channel.

Any current owner may send `ChannelUnlink`; no release hint or other eligibility
condition is required. The relay atomically verifies both session linkage and
authoritative ownership, then releases the channel using stored state. Success is
one `SessionStatus` with `linked_channel=null` and credit preserved. Duplicate,
unowned, already evicted, already released, wrong-channel, or stale unlink gets
nonfatal `CHANNEL_UNLINK_REJECTED`; success is not fabricated for idempotence.

Unlink has no final-balance equality check and does not certify payment agreement,
settle or refund funds, close on-mint, or erase history. Uncertain signatures are
reconciled through wallet recovery independently.

Unlink, replacement, eviction, and exclusion MUST linearize under the same
ownership authority. One unlink commit atomically clears session linkage and
authoritative ownership; it succeeds only if it commits first. Later tunnel/task
cleanup rechecks channel identity and linkage generation, cannot change the
response outcome, and never releases a newer owner.

### 5.4 Scoped eviction

| Scope | Meaning |
| --- | --- |
| `session` | No further links or payments for this channel in this session. Other sessions may use it normally. |
| `relay` | Permanent refusal across all sessions for this authenticated relay identity, including after restart. |

There is no default scope. Relay exclusion is durable before announcement and
survives payment-receiver changes. Session exclusion lasts until session end.
Ownership transfer excludes the old owner with session scope. Neither scope
affects other authenticated relay identities, erases history, initiates an
on-mint close, or prevents appropriate recovery.

Clients SHOULD avoid excluded channels but MAY ignore the advisory and learn the
restriction from the request's self-contained error. The relay removes affected
ownership regardless; confirmed credit remains.

Exclusion and request commitment MUST serialize. An uncommitted link or payment,
including in-flight work, is rejected once exclusion commits. An already
committed request retains success and credit. On one affected session's control
stream, its fixed success response is sent before a later eviction advisory.
Different sessions have no cross-stream delivery order; the serialized ownership
commit determines their outcomes. There is no retroactive rejection, stale
snapshot resurrection, or reacquisition within scope.

### 5.5 Session funding disabled

The relay may permanently disable new funding for one open session. Every
uncommitted link or payment then receives ordered nonfatal
`SESSION_FUNDING_DISABLED`; this takes precedence over channel exclusion. Already
committed operations retain success and credit. Disabling funding does not remove
linked ownership, discard credit, or tear down data tunnels. New and existing
CONNECTs continue under normal credit rules.

The client stops originating links and payments on that session. Another channel
cannot restore funding there. Ping, status queries, extensions, and unlink remain
available. Remaining credit may be consumed; a different session is needed for
more funding. No proactive notification or funding-state field is added, and the
error is not permission to provision a replacement in the same session.

## 6. Error codes and recovery

The table defines each code's machine meaning. Exact diagnostic strings are not
standardized. Unknown codes are fatal. A nonfatal error answers only the oldest
request; a fatal error ends the session and may leave later requests unanswered.

Validation uses this precedence before any request mutation:

1. Malformed envelope, wire type, or wire range is fatal
   `CONTROL_INVALID_MESSAGE`; a valid value beyond a local supported range is
   `NUMERIC_LIMIT_EXCEEDED`.
2. Funding that violates the bootstrap-negotiated keyset-version set uses its
   fatal link code. An internal/configuration failure at any stage is fatal
   `INTERNAL_ERROR`.
3. `SESSION_FUNDING_DISABLED` precedes relay-scoped, then session-scoped,
   exclusion.
4. Channel association and strict ownership precede channel state and policy.
5. A link checks stored terminal state, ownership association, and applicable
   policy first. An unknown channel then checks public parameters/channel ID,
   unit, capacity, ordinary expiry, receiver, admission, mint/keyset trust,
   version and recovery metadata, and funding. A known channel may use its stored
   funding without comparing the submitted copy. Both paths finally check the
   zero-balance signature.
6. A payment checks, in order: terminal state, numeric conversion, signature, and
   monotonicity. `PAYMENT_NO_NEW_FUNDS` applies only after a valid signature; a
   final atomic comparison loss is `PAYMENT_CONFLICT`.

The final commit rechecks every mutable predicate. No lower-priority result may
hide a fatal failure already discovered.

| Code | Applies to | Meaning and handling |
| --- | --- | --- |
| `CONTROL_INVALID_MESSAGE` | Malformed input | Fatal; bounded error delivery then cleanup. |
| `NUMERIC_LIMIT_EXCEEDED` | FIFO request | Definitive nonfatal local-range rejection, valid only before any mutation. |
| `CHANNEL_ADMISSION_DISABLED` | New link | Administrative refusal of unknown channels; nonfatal. Stored relinks and existing-channel payments are not disabled by this code alone. Do not provision another channel to bypass policy. |
| `SESSION_FUNDING_DISABLED` | Link/payment | Nonfatal lifetime session restriction (§5.5); preserve signed history and confirmed credit. |
| `CHANNEL_EVICTED_FROM_SESSION` | Link/payment | Nonfatal session-scoped exclusion; another channel may fund the session. |
| `CHANNEL_RETIRED_AT_RELAY` | Link/payment | Nonfatal permanent exclusion for this authenticated relay identity. |
| `LINK_INVALID_ZERO_BALANCE_SIGNATURE` | Link | The registration signature does not validate at balance zero; nonfatal correction, not blind replay. |
| `LINK_INVALID_CHANNEL` | New link | Public parameters, channel ID, proof structure, capacity, or expiry are invalid and no more specific link code applies; nonfatal. |
| `LINK_RECEIVER_MISMATCH` | New link | Unknown channel is not bound to the current advertised receiver; nonfatal. A failed attempt does not make it known. |
| `LINK_MINT_OR_KEYSET_UNACCEPTABLE`, `LINK_UNSUPPORTED_UNIT` | Link | Nonfatal funding or policy incompatibility; not necessarily transient metadata lag. |
| `LINK_KEYSET_REFRESH_RATE_LIMITED`, `LINK_KEYSET_REFRESH_BUSY`, `LINK_KEYSET_REFRESH_FAILED` | Link | Nonfatal refresh obstacle; bounded retry of unchanged funding may be appropriate. |
| `LINK_KEYSET_VERSION_NOT_NEGOTIATED` | Link | Fatal to this session; do not mark an otherwise valid wallet channel globally unusable. |
| `LINK_CHANNEL_RETIRED` | Link | Nonfatal policy refusing a known channel's relink, including a stored old-receiver channel the relay declines to reuse; preserve its record and recovery path. Distinct from scoped exclusion. |
| `CHANNEL_CLOSED`, `CHANNEL_EXPIRED` | Link/payment | Nonfatal unusable-channel rejection; preserve recovery history. |
| `PAYMENT_WRONG_CHANNEL` | Payment | The session is not linked to the submitted ID; nonfatal. |
| `PAYMENT_INVALID` | Payment | Nonfatal validation rejection; stop automatic payments and report it. Fresh funding does not repair the signature. |
| `PAYMENT_NO_NEW_FUNDS` | Payment | Valid duplicate/lower cumulative payment; no credit. Reconcile with an ordered status before signing more. |
| `PAYMENT_CONFLICT` | Payment | An otherwise valid payment lost the final atomic accepted-balance or ownership comparison; nonfatal reconciliation, with no credit from this request. |
| `CHANNEL_UNLINK_REJECTED` | Unlink | Nonfatal strict-ownership rejection (§5.3). |
| `INTERNAL_ERROR` | Request processing | Fatal because acceptance or side effects may be uncertain; preserve records and reconcile after reconnect. |

Malformed input remains fatal even if funding is disabled. Genuine internal or
configuration failures MUST NOT be disguised as peer-invalid payments. A balance
field on `ChannelLink` is a schema error. A locally linked ID without an
authoritative record violates atomic ownership and is fatal `INTERNAL_ERROR`.

Recovery follows §§3.4 and 5.1-5.3. Mint HTTP recovery remains the wallet's
responsibility, not a guarantee supplied by a control error.

## 7. Review status

Finalization requires coordinated implementations, independent bindings, and
conformance tests. New ambiguities must be resolved here, not with fallback.

## Appendix A. Illustrative transcripts

Fields are abbreviated. Outcome labels are explanatory and are not wire fields.

### A.1 Pipelined link, payment, and failure

```text
R -> C  SessionStatus(linked=null, paid=0, paused=true, receiver, offers, rates)
C -> R  ChannelLink(A, zero_balance_signature, complete params, cashuB funding_token)
C -> R  ChannelPayment(A, balance_raw=100, signature)
R -> C  [link] SessionStatus(linked=A, balance_raw=0, paid=0, paused=true)
R -> C  [payment] SessionStatus(linked=A, balance_raw=100, paid=raw_to_msats(100))
```

The link snapshot cannot include the later payment. If admission failed and A
was not already owned, the same pipeline yields two independent errors:

```text
R -> C  Error(CHANNEL_ADMISSION_DISABLED) # link
R -> C  Error(PAYMENT_WRONG_CHANNEL)      # payment
```

### A.2 Ambiguous old payment and a larger accepted increment

```text
A uses msat. Client persisted and sent 100 in an old session that died.
Relay never accepted it and stores 0; client retains its signed 100.
C -> R  ChannelLink(A, zero_balance_signature, same immutable funding)
R -> C  SessionStatus(linked=A, balance_raw=0, paid=0)
C -> R  ChannelPayment(A, 130) # persist 130; minimum increment d1=30
C -> R  ChannelPayment(A, 150) # persist 150; minimum increment d2=20
R -> C  SessionStatus(linked=A, balance_raw=130, paid=130)
         Validate against P(0)+30, accept the larger total, set P=130.
R -> C  SessionStatus(linked=A, balance_raw=150, paid=150)
         Validate against P(130)+20.
```

If the relay had accepted 100 previously, relink reports `balance_raw=100` but
`paid=0`; the new payments credit 30 then 20. Old session credit does not transfer.

## Appendix B. Migration plan

The baseline below is descriptive; §§1-6 define the target if wording differs.

| Topic | Baseline `7212537` | Target section |
| --- | --- | --- |
| Session identifier | `h2` | §1: coordinated `h2-2026-10-06` switch |
| Link/payment encoding | Shared `payment_json` | §3.1 structured messages and Cashu V4 funding token |
| Relink funding | Funding may be omitted or ignored | §5.1 complete request shape with authoritative stored funding |
| Unlink | Final balance plus `ChannelUnlinked` | §5.3 strict ID-only unlink |
| Advertisements/pricing | Ordered entries with keyset IDs and per-entry rates | §3.3 and §4 |
| Receiver | Fixed for session/runtime identity | §4 stored-channel-safe rotation |
| Client accounting | Local total updated after send | §5.2 pre-send durable accounting |
| Correlation | One operation plus snapshot inference | §3.4 FIFO pipeline |
| Liveness | Status heartbeat cleared by any message | §3.4 correlated Ping/Pong |
| Proactive messages | Unscoped eviction and acted-on release | §3.5 and §5.3-5.4 advisories |
| Funding refusal | Admission controls only | §5.5 lifetime session restriction |
| Extensions/tolerance | No extension envelope; unsolicited statuses | §3.5-3.6 |

Implementation order:

1. Make client keyset selection and reuse independent of advertised IDs, then
   remove preference plumbing and adopt the mint/unit map.
2. Implement structured messages, strict framing, fixed pricing, receiver-key
   retention, stored-funding relinks, ID-only unlink, and the error registry.
3. Implement durable pre-send accounting, per-request increments, FIFO responses,
   five-request capacity, exact numeric bounds, and larger accepted increments.
4. Implement advisories, scoped exclusions, session funding refusal, independent
   Ping/Pong, and extensions without coupling them to FIFO progress.
5. Coordinate the client/relay switch to `h2-2026-10-06`; add conformance coverage
   before declaring the specification final.

Source baseline: `monad-common/src/{bootstrap,protocol,control_codec}.rs`,
`monad-relay/src/{session,session_fsm,control_driver,payments}.rs`,
`monad-client/src/session_driver/{runtime,state,funding,payment}.rs`, and
`monad-client/src/sqlite_client_wallet.rs`. Convenience types do not define this
wire contract.

The contract specifies observable ordering, response, and cleanup behavior. It
does not prescribe a queue, reducer, or client-control-loop architecture.

## Appendix C. Conformance coverage

- §1: exact protocol selection, extensions before initial status, second-control
  rejection, paused control availability, and teardown without erasing funding
  or closing on-mint.
- §2: fragmentation/coalescing; exact 1 MiB inbound/outbound boundary; overlong
  complete and partial lines; proof-heavy Cashu V4 link preflight; parser
  complexity; duplicate, unknown, wrong-direction, and forbidden-null fields;
  exact reduced ranges and checked intermediates; sensitive-data redaction.
- §3: five blocked outstanding requests and a prohibited sixth; mixed
  success/errors; failed redundant relink preserving ownership before a
  successful queued payment; fixed snapshots and successful, failed, and open
  CONNECT count transitions; empty-FIFO discard; fatal input behind pending
  requests; multiple unanswered requests at termination; bounded redacted
  warnings.
- §3.4: opaque string nonces, paused and concurrent Pings, same-nonce Pong
  responses, in-order and independent relay handling, local stalls, timeout
  races, and no claim of destination reachability.
- §3.5: ignored bidirectional extensions and advisories with no response, FIFO,
  accounting, or liveness effect; malformed envelopes remain fatal.
- §4: exact one-round billing; partial forwarding; configured chunk/in-flight
  overshoot exposure; counter exhaustion; fixed rates; TCP/QUIC accounting
  excluding pooled connections; one current receiver; known-channel lookup before receiver checks;
  old-receiver relink or explicit retirement; failed attempts creating no durable
  recognition; rotation during provisioning rejecting and recovering an unknown channel;
  recovery-window equality, zero, absence, and overflow; exclusions surviving
  rotation and relay restart.
- §5.1: strict first-registration Cashu V4 and deterministic DLEQ validation;
  failed attempts creating no durable recognition; known relinks using stored
  immutable funding without mint I/O or redundant cryptographic validation;
  supplied relink data never overwriting stored funding; replayable zero-signature
  semantics and validation before ownership mutation.
- §5.2: pre-send crash/write failure; duplicate, lower, over-capacity, and numeric
  failures; payment success below submitted `B_new`; shortchanging; larger accepted
  increments;
  impossible relay balance; no rollback, duplicate provisioning, or double
  credit; ambiguous acceptance and queued-response attribution.
- §5.3: optional release ignored; replacement provisioning before unlink; strict
  duplicate/unowned behavior; unlink despite differing signed and accepted
  balances; payment then unlink; barrier-tested unlink versus replacement or
  eviction; preserved credit and stale-cleanup safety.
- §5.4-5.5: ignored notifications with self-contained errors; session exclusion;
  durable relay exclusion scoped to authenticated identity; ordered funding
  disablement preserving committed credit, linked state, and data traffic.
- §6: the concrete precedence matrix, unknown codes, fatal negotiated-keyset-
  version or internal errors behind pending work, pre-commit
  `NUMERIC_LIMIT_EXCEEDED`, redacted diagnostics, and recovery that preserves
  every exposed signature.
- Keyset rotation, inactive funding, unavailable metadata, bounded immutable
  retries, and no redundant provisioning during preference removal.

Related investigations: [#91](https://github.com/SatsAndSports/MONAD/issues/91)
(keyset advertisements), [#119](https://github.com/SatsAndSports/MONAD/issues/119)
(prefix probes), [#121](https://github.com/SatsAndSports/MONAD/issues/121)
(silent failures), [#122](https://github.com/SatsAndSports/MONAD/issues/122)
(deterministic recovery), and [#124](https://github.com/SatsAndSports/MONAD/issues/124)
(resource bounds).
