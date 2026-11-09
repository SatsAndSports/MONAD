# Single-relay payment capacity experiment

`make stress-payment-capacity` is a **manual-only** test of many independently
funded sessions sharing one relay. It is ignored by normal `cargo test` and CI.
The small configuration/measurement unit tests still run normally.

## Run locally

```bash
# Default: 25 clients, ~one payment/client/10 seconds, 30 measured seconds.
make stress-payment-capacity

# Named one-minute trial with 1,500 sessions and setup concurrency 64.
make stress-payment-capacity-1500

# Fast development check; debug results are not production capacity numbers.
MONAD_CAPACITY_PROFILE=dev MONAD_CAPACITY_SESSIONS=10 \
  MONAD_CAPACITY_PAYMENT_INTERVAL_SECS=5 MONAD_CAPACITY_DURATION_SECS=20 \
  make stress-payment-capacity

# One-minute trial. Raise sessions progressively after checking achieved load.
MONAD_CAPACITY_SESSIONS=500 MONAD_CAPACITY_SETUP_CONCURRENCY=32 \
  MONAD_CAPACITY_DURATION_SECS=60 make stress-payment-capacity

# Ten-minute soak at a previously established healthy session count.
MONAD_CAPACITY_SESSIONS=500 MONAD_CAPACITY_SETUP_CONCURRENCY=32 \
  MONAD_CAPACITY_DURATION_SECS=600 make stress-payment-capacity
```

The Make target defaults to an optimized **release** build, with two Cargo build
jobs to bound compilation memory. A first release build can take several minutes;
subsequent unchanged runs reuse it. `MONAD_CAPACITY_PROFILE=dev` and
`CARGO_BUILD_JOBS` override those choices. Default logging is `error`; `RUST_LOG`
can override it. Avoid verbose logging when comparing performance.

Provisioning, session establishment, and staggered warmup are **additional** to
the measurement duration. Startup concurrency changes setup time, not measured
session count. This first implementation hosts a disposable in-memory CDK mint
for channel creation; the mint is not contacted during measured payments.

## What is real, and what is simulated?

- One relay subprocess runs the production listener/session code,
  `RelayWalletManager`, `SpilmanRelayPayments`, and SQLite storage.
- Each client has an independent QUIC endpoint/connection, Noise/H2 session,
  pre-created real Spilman channel, and one long-lived CONNECT echo tunnel.
- Clients use the production connector and `session_driver`, including ordinary
  payment policy and heartbeat behavior. No custom status-polling payment loop.
- The client wallet is `TestSigningWallet`: real channel creation and payment
  signatures, but in-memory wallet storage. This does not benchmark thousands of
  client SQLite wallets, SOCKS listeners, or full client OS processes.
- This recipe explicitly retains ordinary-channel policy; optional rerandomized
  mint discovery is outside its steady-state payment-capacity workload.
- The generator also runs the local echo target. Both processes compete for the
  laptop's CPU/network resources. A failure to deliver offered load is not alone
  proof that the relay's payment verification or database is saturated.
- The subprocess is a worker in the integration-test executable, not the relay
  CLI. Runtime code is reused without production instrumentation or new APIs.

Each relay direction charges one msat/byte. A minimum topup buys approximately
`PAYMENT_INTERVAL_SECS` of the configured bidirectional echo traffic, rounded up
to whole satoshis. The target buffer is a quarter of that minimum (at least one
sat). Actual payments are still decided by the production driver, not a harness
timer. The seed controls traffic-start phases within one target payment interval.
Channel capacity is sized for warmup and measurement with headroom; replacement
channels are not available, and channel churn during measurement fails the run.

## Configuration

All runtime variables start with `MONAD_CAPACITY_`:

| Suffix | Default | Meaning |
|---|---:|---|
| `SESSIONS` | 25 | Number of independently funded clients |
| `DURATION_SECS` | 30 | Steady-state measurement duration |
| `PAYMENT_INTERVAL_SECS` | 10 | Desired refill cadence, subject to SAT rounding |
| `BYTES_PER_SEC` | 1000 | Echo payload rate **per direction, per client** |
| `TRAFFIC_TICK_MS` | 1000 | Traffic pacing interval; 100–1000 ms |
| `WARMUP_SECS` | payment interval + 2 | Warmup after every client is ready |
| `SETUP_CONCURRENCY` | 8 | Maximum simultaneous provisioning/connection tasks |
| `SETUP_TIMEOUT_SECS` | 300 | Overall provisioning/setup deadline |
| `IO_TIMEOUT_SECS` | 10 | Deadline for each echo and tunnel setup |
| `CLIENT_WORKERS` | 2 | Generator Tokio worker threads |
| `RELAY_WORKERS` | 2 | Relay Tokio worker threads |
| `SEED` | 1 | Reproducible staggering seed |

Measurement must cover two effective payment intervals and ten traffic ticks;
warmup must cover the staggering interval. Rate/tick combinations must yield
whole-byte payloads no larger than 64 KiB. Invalid input fails before starting
the experiment. Duration supports up to one hour, including a 600-second soak.

The relay's open-CONNECT limit is explicitly raised to `max(1024, SESSIONS)`;
the effective limit is printed. Other CONNECT limits retain their production
defaults. Large runs also need sufficient OS file descriptors and UDP ports: each simulated
client owns a UDP endpoint and a TCP echo connection. Before compilation, the Make
target checks that the soft descriptor limit is at least `2 * SESSIONS + 512`
(3,512 for the 1,500-session target), or unlimited. This is a conservative harness
allowance, not an exact descriptor count. It fails with the current/required limits
and an actionable `ulimit -Sn` command; it never changes your limit automatically.
Direct Cargo invocations bypass this Makefile check. The echo-server task is also
monitored throughout setup, warmup and measurement, so an unexpected accept error
is reported instead of being hidden by subsequent TCP connection refusals.
Admission/resource failures are test failures, not silent omissions
from the requested session count.

`TRAFFIC_TICK_MS` separates payment cadence from packet frequency: 1000 clients
at 100 ms generate about 10,000 echo exchanges/sec; at 1000 ms they generate about
1,000, with the **same bytes/sec and intended payments/sec**. Record this setting
when comparing limits. Missed traffic ticks are skipped, not caught up in bursts;
the delivery check detects a generator/transport that cannot sustain the rate.

## Reading results

Five-second progress lines report **successful production payment-backend calls**
within a worker-controlled measurement window, not merely requests sent by the
generator. Initial funding and warmup are excluded. Calls already in progress at
window start, or recorded after window stop, are excluded. The backend has performed
signature validation and its storage update before a success is counted; this is
not a measurement of client-observed response acknowledgement.

The final summary reports accepted payments/sec, rejection/link/unlink counts,
minimum/maximum payments per channel, echo delivery, and backend processing
latency. Latency includes the synchronous payment-backend call (including its
internal lock/storage waits), but not time waiting to be dispatched by the relay,
H2 transit, client signing, or response transit. p50/p95/p99 are **upper bounds from
power-of-two microsecond buckets**. Cadence reports gaps between accepted payments
on the same channel; only pairs inside the measurement window contribute.

A successful run requires:

- every requested session established and remained running through measurement;
- every channel made at least one measured payment;
- zero measured payment rejections, links, or unlinks;
- correct echoes and at least 90% of offered bytes delivered by **each** client;
- successful task/process cleanup.

These criteria establish progress, not a universal latency SLA. Compare achieved
payments/sec with `SESSIONS / effective_payment_interval`, and inspect latency,
cadence and delivery before selecting a soak load. A slow run can keep all clients
connected but still fail the per-client delivery requirement. The test does not
separately count or attribute credit-pause transitions.

Linux resource snapshots report process CPU-tick deltas, RSS, and lifetime RSS
high-water marks separately for relay and generator. The reported clock ticks/sec
convert CPU ticks to CPU seconds (divide again by elapsed seconds for average
cores used). These are not peak CPU samples or measurement-only peak RSS.

Wallet databases and IPC sockets are created in a fresh private temporary
directory and removed after the experiment. No existing wallet is opened or
reset. Child processes are stopped/reaped and tasks cancelled/awaited on ordinary
failure paths. Mint seeds, private keys, signatures, and funding proofs are not
included in metric output.

## Initial laptop observations (2026-11-08)

These are development observations, not portable capacity promises. All runs
below used release builds, two generator workers and two relay workers,
1,000 bytes/sec per direction/client, a ten-second target payment interval,
and seed 1. Setup/warmup are excluded from the measurement durations.

| Sessions | Traffic tick | Measured duration | Accepted payments/sec | Minimum per-client delivery | Result |
|---:|---:|---:|---:|---:|---|
| 100 | 100 ms | 30 s | 10.00 | 100% | Pass |
| 500 | 100 ms | 30 s | 50.00 | 100% | Pass |
| 1,000 | 100 ms | 30 s | 92.96 | 92% | Pass |
| 1,500 | 100 ms | 30 s | 90.50 | 60.3% | Fails delivery criterion |
| 1,500 | 1,000 ms | 30 s | 149.98 | 100% | Pass |
| 2,000 | 1,000 ms | 60 s | 189.20 | 95% | Pass |
| 3,000 | 1,000 ms | 30 s | 204.37 | 66.7% | Fails delivery criterion |
| 1,500 | 1,000 ms | 600 s | 148.39 | 98.7% | Pass |

The ten-minute run accepted 89,032 payments, with zero rejections or channel
churn. Each channel made 59–60 measured payments. Mean observed payment gap was
10.11 seconds, maximum 13.70 seconds; backend p95/p99 upper bounds were
8.192/16.384 ms, maximum 25.713 ms. Relay RSS ended around 511 MiB. Setup took
54 seconds at concurrency 64, followed by 12 seconds of warmup.

The pacing comparison is why the default is one exchange/second rather than ten:
the latter stresses packet scheduling much more heavily at the same payment and
byte rates. The failing trials had zero payment rejections but could not deliver
the offered traffic; they do not isolate a database or signature-verification
ceiling. The 1,500-session soak is a useful starting point for further experiments,
not a substitute for profiling or testing a different machine/worker budget.
