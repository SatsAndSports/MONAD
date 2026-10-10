# Vendored h2 and the paused-tunnel control-starvation fix

This document is the durable reference for why MONAD vendors `h2`, what was
changed, how the vendoring works mechanically, and what we learned while
diagnosing the production failure. It exists so the work can be picked up
later — for example, to prepare an upstream PR.

Contents:

1. HTTP/2 flow control from first principles (the budgets)
2. The bug, exactly as observed in production
3. The fix and its full diff inventory
4. Memory/bounds analysis and tradeoffs
5. Vendoring mechanics (what, how, provenance)
6. MONAD test inventory related to this area
7. Verification record
8. Notes for a future upstream PR and follow-ups

---

## 1. HTTP/2 flow control from first principles

### Capacity is a byte budget

HTTP/2 flow control is a credit system. The receiver advertises "you may send
me up to N bytes before I give you more credit." The sender spends budget as
it sends; the receiver returns budget by sending `WINDOW_UPDATE` frames when
it is done with those bytes.

The invariant on the receiver side:

```text
bytes on the wire + bytes buffered-but-not-yet-consumed  <=  budget
```

So the budget bounds how much the receiver can be forced to hold. In stock
`h2`, the budget is only refunded when the application **consumes** the data
out of the stream's receive buffer.

### There are two budgets

- **Per-stream budget** (default 65,535 bytes). Each stream — the control
  stream and every CONNECT tunnel — has its own. When it is spent, only that
  stream stalls. This is what MONAD uses to pause a tunnel.
- **Connection-wide budget** (default 65,535 bytes). All streams on the same
  HTTP/2 connection also share one combined budget. Every DATA frame on any
  stream is charged to both budgets.

### Why does a connection budget exist at all?

Aggregate memory protection. Without it, worst-case buffering is
`open streams × stream window` — e.g. 25,000 streams × 64 KiB ≈ 1.6 GiB that a
peer can force the receiver to hold. The connection budget caps total
in-flight + unread bytes regardless of stream count, and lets the receiver
throttle the connection as a single pipe.

### How MONAD pauses a session

The relay does not touch any window. It simply **stops reading** the paused
CONNECT streams (`proxy_bidirectional_accounted` waits on the pause watch
before polling `RecvStream::data()`). The stream's own budget drains to zero
as the peer's queued frames arrive, and the tunnel stalls. That is the whole
pause mechanism.

---

## 2. The bug

### Stock h2 couples the refunds

In stock `h2` (through at least 0.4.x), `FlowControl::release_capacity()`
returns **both** budgets at once, and it only runs when the application
consumes a received frame. Before consumption, both budgets stay spent.

Consequence for a paused MONAD session:

1. Relay pauses → proxy stops reading the CONNECT stream.
2. That stream's own budget stays spent → tunnel stops. Correct.
3. But its unread frames **also keep their connection-budget charge**. About
   64 KiB of paused tunnel data consumes the *entire* shared connection
   window.
4. The control stream is not paused and its own stream window is free, but
   every control message also needs connection budget. It gets none.

The control stream is not paused — it is **starved indirectly** through the
shared window. The documented invariant "the control stream is always usable
while paused" was violated.

### Production chronology (16 MiB/s, 1:1, 1,000,000 msat channels, 2 hops)

Timestamps from the release-mode traffic run:

```text
00:29:41.588  hop2 final ChannelPayment confirmed; 67,262 msat session credit left
00:29:41.859  hop2 session pauses (balance -76); exhausted channel retained by client policy
00:29:41.920  hop2 client logs "sending ChannelLink" and send_data() returns
              ... no relay-side receipt, no further hop2 control traffic ...
00:30:02.582  "session payment driver ended with error: control send exceeded
               heartbeat timeout" (15 s) → session torn down
00:30:02.684  suffix rebuild starts; route usable again after 148 ms
```

The rebuild was fast (148 ms end-to-end, 45 ms of rebuild). The outage was
the ~20 s of control starvation before it.

### `send_data()` returning does not mean delivery

`h2::SendStream::send_data` only queues the frame into the connection send
buffer. If the connection send window (the mirror of the peer's receive
window) is exhausted, the frame sits queued. The client-side control send
wraps `send_json_line` in a 15 s heartbeat timeout; that timeout firing is
what tore down the session.

### The fragment-recycle discovery (why naive tests pass)

`h2` batches `WINDOW_UPDATE`s: an update is only emitted once unclaimed
capacity reaches **half the current window**. When the connection window is
fully consumed, that threshold is 0, so *every* tiny release triggers an
immediate update. Control messages can then squeeze through the starved
window fragment-by-fragment (a few bytes per recycle), each fragment consumed
by the peer's control loop, refunding a few more bytes.

So a 19-byte `GetSessionStatus` round trip completes on loopback even in the
broken configuration. The ~700-byte `ChannelLink` (channel params + funding
proofs), crossing **two nested saturated H2 layers** in the production
failure, needs ~150 fragment recycles through both layers — effectively a
stall beyond the 15 s heartbeat timeout. Any regression test must use a
control payload large enough to defeat the fragment recycle (ours uses
~500 KB) or it will pass vacuously.

---

## 3. The fix

### Split the refund timing

| Event | Connection budget | Stream budget |
|---|---|---|
| DATA frame accepted into the stream's bounded buffer | **refunded immediately** | stays spent |
| Application consumes the frame from the stream | (already refunded) | **refunded now** |

A paused tunnel can now fill only its own bounded stream window (buffering
limits unchanged from stock h2), while the shared connection window — and
therefore the control stream — stays alive. Refunding connection capacity
does not forward or authorize the buffered traffic; it only stops counting it
against the shared budget.

Precedent: gRPC's Go transport decouples connection-level flow control from
application reads for exactly this reason ("prevent other active(fast)
streams from starving in presence of slow or inactive streams" —
`internal/transport/http2_server.go` `handleData`).

### Diff inventory vs pristine h2 0.4.16

All changes are opt-in via a new builder flag
`recv_release_connection_on_buffer(bool)`, default `false` (stock behavior).

- `src/client.rs`, `src/server.rs`
  - `Builder::recv_release_connection_on_buffer(bool)` + field, threaded into
    `proto::Config`; rustdoc explaining the semantics and the default.
- `src/proto/connection.rs`
  - `Config.recv_release_connection_on_buffer`, forwarded to `streams::Config`.
- `src/proto/streams/mod.rs`
  - `streams::Config.recv_release_connection_on_buffer` + doc comment.
- `src/proto/streams/recv.rs`
  - `Recv.release_connection_on_buffer` field.
  - `recv_data`: after charging the stream and tracking in-flight data,
    refunds **connection** capacity immediately when the flag is on.
  - Guards so connection capacity is never refunded twice, in:
    `release_capacity` (application consume), `release_closed_capacity`
    (closed-stream auto-release), the `!stream.is_recv` ignore path,
    `clear_recv_buffer` (drop/reset buffer clearing).
  - `releases_connection_on_buffer()` accessor for the streams layer.
  - Unit test `release_connection_on_buffer_keeps_stream_credit_until_consume`
    covering both modes' accounting invariants.
- `src/proto/streams/streams.rs`
  - `recv_data` wrapper: on stream error after receiving DATA, only
    auto-release connection capacity when the flag is off.
  - `proto/streams/counts.rs`: test `Config` updated for the new field.
- `tests/paused_flow_control.rs` (new test target)
  - `blocked_request_body_does_not_starve_another_stream` (flag on: an
    unconsumed full-window request body must not starve another stream's
    connection capacity).
  - `default_receive_accounting_still_blocks_shared_connection_window`
    (flag off: stock behavior preserved).
- `Cargo.toml` — version `0.4.16+monad.1`, empty `[workspace]` table,
  `[[test]]` target, `time`/`io-util` dev features, `futures-core` dev-dep
  (see §5).

### Where MONAD enables it

- Client side: `monad-common/src/session.rs`
  (`RelayConnection::from_transport_stream`, `client::Builder`).
- Relay side: `monad-relay/src/session.rs`
  (`relay_session_from_transport_stream`, `server::Builder`).

Because the flag defaults off, other consumers of the same vendored crate
(hyper/axum via the CDK test mint) keep stock behavior.

---

## 4. Memory/bounds analysis and tradeoffs

The connection budget exists to cap aggregate buffering. The fix relaxes that
cap: a stuck stream may now hold its full stream window *without* counting
against the connection budget, so worst-case receive buffering is again
bounded by `stuck streams × stream window` rather than by the connection
window.

Why this is acceptable for MONAD:

- A MONAD session is control plus a handful of CONNECT tunnels, with the
  default 64 KiB window — the relaxed bound is small and explicit.
- Both peers cap each received uncompressed H2 header list at 32 KiB. MONAD
  rejects all trailing HEADERS blocks, so headers cannot create an additional
  application-level buffering channel after a stream has started.
- Stock behavior is unchanged for peers that do not opt in; the per-stream
  window itself is untouched, so per-stream buffering is exactly as before.
- The 25,000-concurrent-stream stress configuration passes with the fix
  enabled everywhere (see §7).

For general-purpose HTTP servers facing untrusted clients, the stock coupling
(connection refund tied to consumption) is a defensible conservative choice;
that is why the vendored change is opt-in and why any upstream submission
should present it as an opt-in protocol feature rather than a one-line bug
fix.

---

## 5. Vendoring mechanics

### What

- **Base**: the crates.io package `h2 0.4.16` (sha256
  `a9f37a958b41b3b19ee2707c06439c0e9e547e847223eb791ecb0cb821c65e27`, as
  previously recorded in `Cargo.lock`). Copied from the local registry cache.
- **Version**: `0.4.16+monad.1` (build metadata marks provenance; semver
  requirement `h2 = "0.4"` still matches).
- **Location**: `vendor/h2/` in the workspace root (not a workspace member).

### How it is wired in

- Workspace root `Cargo.toml`:
  ```toml
  [patch.crates-io]
  h2 = { path = "vendor/h2" }
  ```
- `cargo update -p h2` re-resolves the graph so every `h2` consumer — direct
  (monad-common, monad-relay, monad-client, monad-test-client) and transitive
  (hyper via axum/cdk) — uses the vendored copy. `Cargo.lock` then contains a
  single `h2` entry (`0.4.16+monad.1`, no checksum: path deps have none).
- `vendor/h2/Cargo.toml` gains an **empty `[workspace]` table** so the crate
  stands alone: `cargo test --manifest-path vendor/h2/Cargo.toml` works
  without absorbing it into the MONAD workspace. The outer workspace lists
  members explicitly, so it is never auto-included, and `cargo test
  --workspace` does not run the vendored crate's own tests.
- The registry metadata file `.cargo-checksum.json` was removed.
- A `[[test]]` target (`tests/paused_flow_control.rs`) and small dev-feature
  additions (`tokio` `time` + `io-util`, `futures-core` dev-dependency) were
  added to the vendored `Cargo.toml` for the regression tests.

### Known noise / caveats

- `cargo update -p h2` also flipped three unrelated `windows-sys` pins
  (`0.61.2 → 0.60.2/0.52.0`) in `Cargo.lock` during re-resolution. These are
  Windows-only transitive deps, not compiled on Linux; left as produced by
  cargo rather than hand-editing the lockfile.
- The packaged crate does **not** ship the upstream hpack fixture corpus
  (`tests/fixtures` is excluded via the upstream `exclude` list), so
  `cargo test -p h2 --lib` inside the vendored copy shows hundreds of
  `hpack::test::fixture` failures from missing files. This is pre-existing
  and also happens on the pristine registry copy; it is unrelated to the
  patch. The relevant suites — `proto::streams::*` unit tests and
  `tests/paused_flow_control.rs` — pass.

---

## 6. MONAD test inventory related to this area

### New regression coverage from this work

- `monad-relay/tests/integration.rs` —
  **`test_control_stream_survives_connection_window_blocked_by_paused_tunnel`**:
  a real relay + real client session is funded with 5 units, a CONNECT tunnel
  spends all credit (relay pauses), then ~65 KB of tunnel DATA is queued
  without waiting for stream capacity (modeling bytes already in flight when
  the pause lands). Asserts (a) the paused tunnel's **stream** window stays
  withheld, and (b) a ~500 KB control `ChannelPayment` round trip completes
  within 2 s. Verified to **fail (timeout) with the flag off** and **pass
  (~0.5 s) with the flag on**. The 500 KB payload is deliberate: small control
  messages survive via the fragment recycle (§2) and would make the test
  vacuous.
- Vendored h2:
  - `vendor/h2/tests/paused_flow_control.rs` — both modes end-to-end over an
    in-memory duplex (see §3).
  - `vendor/h2/src/proto/streams/recv.rs` —
    `release_connection_on_buffer_keeps_stream_credit_until_consume`
    (accounting invariants in both modes); the pre-existing
    `clear_recv_buffer_caps_capacity_before_overflow` covers the overflow cap
    in the buffer-clear path.

### Pre-existing tests whose semantics the fix must (and does) preserve

- Pause/resume billing semantics, `monad-relay/tests/integration.rs`:
  - `test_session_repauses_and_resumes_after_second_payment`
  - `test_session_overshoot_negative_balance_and_resume`
  - `test_session_overshoot_underpayment_stays_paused_until_positive`
  - `test_outbound_bytes_sent_after_pause_are_delivered_after_unpause`
  - `test_inbound_bytes_pushed_after_pause_are_delivered_after_unpause`
    (bytes queued during a pause are delivered intact after unpause)
  - `test_managed_client_exhaustion_waits_then_resumes_same_session`
- Zero-window / control-liveness unit tests:
  - `monad-relay/src/session.rs` —
    `termination_cancels_zero_window_control_bootstrap` and the
    `test_h2_streams` helper used with `initial_window_size(0)`
  - `monad-client/src/session_driver/runtime.rs` —
    `zero_window_control_send_obeys_heartbeat_deadline` (the 15 s control-send
    deadline that fired in production)
- Multiplexing/nesting behavior:
  - concurrent CONNECT tunnels; nested 2-hop and 3-hop routes; QUIC control +
    data over QUIC transport; 1,000 concurrent QUIC streams on one
    connection; 4 MB single-stream payload; `monad-common/src/h2stream.rs`
    and `proxy.rs` unit tests for `H2ConnectStream` read/write/EOF behavior.
- Stress harnesses (exercise the patched h2 under load):
  - `make stress-payment-relink` / `stress-payment-buffered` (channel
    turnover and topups under concurrency; summary showed 0 control errors,
    0 link failures with the fix),
  - `make stress-transport-extreme` (25,000 in-flight streams per circuit),
  - `make stress-chaos-rebuild*` (configured-client route rebuilds).

### Manual verification still expected of the operator

The sustained release-mode browser demo (`network-demo.mjs` with
`MONAD_DEMO_TRAFFIC_SERVER=1`) at high rates — the original reproduction —
is a manual check; automated coverage stops at the 500 KB control-payload
regression and the stress harnesses.

---

## 7. Verification record (as of the fix commit)

| Check | Result |
|---|---|
| New MONAD regression test, flag off | **fails** (2 s timeout — genuine reproduction) |
| New MONAD regression test, flag on | passes (~0.5 s) |
| `cargo test --manifest-path vendor/h2/Cargo.toml --test paused_flow_control` | 2 passed |
| `cargo test --manifest-path vendor/h2/Cargo.toml --lib proto::streams` | 8 passed (hpack fixture failures are the pre-existing packaging caveat, §5) |
| Full `cargo test --workspace` | 742 passed, 0 failed |
| `monad-relay` integration suite | 158 passed, 2 ignored (chaos) |
| `make stress-payment-relink` | 25,000 streams OK, 364 relinks, 0 link failures, 0 pause events, 0 control errors |
| `cargo clippy -p monad-common -p monad-relay --all-targets` | clean |
| `cargo fmt --all -- --check` | clean |
| `cargo build --release --workspace --bins` | clean |

---

## 8. Upstream PR notes and follow-ups

### What an upstream submission would contain

- The opt-in builder flag on both `client::Builder` and `server::Builder`
  (exact name TBD with maintainers; `recv_release_connection_on_buffer` is
  descriptive but clunky).
- The receive-path change with the double-release guards, plus the
  `recv.rs` accounting unit test and the `paused_flow_control.rs` integration
  test (both written upstream-style).
- Motivation: control-channel protocols on top of HTTP/2 (MONAD's paid
  tunnels) need control liveness while data streams are deliberately
  unread; cite the gRPC-Go decoupling as prior art
  (`grpc/internal/transport/http2_server.go#handleData`).

### Likely discussion points

- The memory tradeoff (§4): worst-case buffering moves from the connection
  window to `unread streams × stream window`. Default-off keeps the
  conservative guarantee for general servers.
- Interaction with `Counts`/`max_concurrent_streams` and streams that closed
  with unread buffered data (our `clear_recv_buffer` and
  `release_closed_capacity` guards handle exactly-once refunds).
- Related but distinct upstream issues to reference for context:
  `#2` (flow-control RFC), `#853` (logical deadlock from capacity assigned
  to `pending_open` streams — a different mechanism), `#821` (capacity
  reservation semantics), `#186` (release on DATA stream error).

### MONAD follow-ups (not required for the fix)

- The client session driver still replaces exhausted channels only after the
  relay pauses. With control liveness fixed this is safe (pause → relink →
  resume without rebuild), but a proactive rotation on the capacity-reaching
  payment acknowledgement would remove even the brief pause blip.
- Whether to keep the flag long-term, rename it, or make the behavior
  unconditional once it has soak time.
- Consider contributing the reproducer shape (500 KB control payload vs
  paused full-window data stream) upstream as a regression test.
