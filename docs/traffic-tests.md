# Managed speed and latency tests

The traffic test engine is owned by each configured MONAD client. Both connections
go through that client's own SOCKS listener. The server must be reachable from the
final relay. Browser controls are under development; the management API is usable.

## Server configuration

Add these entries to your existing YAML (or use a separate server-only file):

```yaml
traffic_servers:
  - name: echo
    listen: 127.0.0.1:9090
management:
  listen: 127.0.0.1:8090
  traffic_server_socket: /tmp/monad-traffic.sock
```

Run `cargo run -p monad-test-traffic -- run --config monad.yaml`.
`--server echo` selects one configured server. Currently server listeners require
numeric loopback addresses; IPv4 and IPv6 are supported. The aggregator discovers
the socket as `traffic-servers` when `management.processes` is empty. When using an
explicit process map, include the socket there. Server snapshots expose
`kind: traffic_servers`, endpoint URLs, connections, and byte counters.

## Client commands

Use the normal generation-bound management command envelope and operation polling.
Read the current `instances.NAME.traffic_test.run_id` before sending a command.
`start_traffic_test` takes exactly:

```json
{
  "expected_run_id": 0,
  "server_url": "http://127.0.0.1:9090",
  "total_rate_bytes_per_second": 1048576,
  "upload_ratio": 1,
  "download_ratio": 5
}
```

`stop_traffic_test` takes exactly `{"expected_run_id": CURRENT_RUN_ID}`. Unknown
fields and stale run IDs are rejected. Accepted starts increment the run ID and
replace the entire run, including its measurements. This currently also applies
to rate-only changes submitted with Start. Stopping preserves totals and latency
history but sets current rates to zero. Client disable stops its test; re-enable
and process restart do not automatically start testing.

**API change from the initial experimental engine:** `expected_run_id` is now
required on Start and Stop, and RTT fields are fractional milliseconds. Update
API callers together with the client binary. No wallet/database reset is needed.

Rates range from 1 KiB/s to 1 GiB/s. Ratios are upload:download, each component
1–100 and at least one component must equal 1. URLs must use HTTP with no credentials,
query, or fragment. An optional base path is supported for an endpoint proxy.

## Wire protocol

Send `GET /v1/stream/UPLOAD/DOWNLOAD HTTP/1.1`, `Connection: Upgrade`, and
`Upgrade: monad-ratio-stream/1`. The server answers 101 with the same upgrade token.
The remaining connection is an unframed duplex byte stream. With N input bytes,
the server owes `floor(N * DOWNLOAD / UPLOAD)` output bytes, independent of input
read boundaries. Equal ratios echo exactly; other ratios produce arbitrary data.
Fractional output remaining at EOF is discarded. The server has no pacing logic.

The client bounds setup to 15 seconds and response headers to 8 KiB, validates the
status and upgrade headers, and rejects output beyond the generated response
allowance. All operations are immediately cancellable by their owner.

## Accounting and measurements

- The ceiling is **combined bulk application payload generated per second**:
  uploaded bytes plus the ratio-implied response bytes. Transport/upgrade overhead
  and the separate latency probes are excluded. A probe sends and echoes 8 bytes
  approximately once per second.
- Tokens start empty. Capacity is 20 ms of selected traffic, with a 101-byte minimum
  so one input byte at 1:100 can progress even at 1 KiB/s. Idle credit is capped;
  reconnect starts empty. Upload chunks shrink to fit the rate and ratio.
- Actual accepted partial writes are counted. Short writes preserve the prepaid
  chunk allowance. Disconnect discards unused allowance rather than refunding
  credit or emitting a catch-up burst.
- Outstanding response work is limited to four measured RTTs of target download
  throughput, with a 250 ms minimum time allowance, 4 MiB minimum and 512 MiB cap.
  The initial RTT estimate is 250 ms. This bounds work, not allocated buffers.
  Routes with bandwidth-delay products above the cap can remain window-limited.
- Because the server is unpaced, delayed responses can arrive in bursts. The
  configured ceiling is not an instantaneous cap on arriving download packets.
- Throughput samples cumulative bulk counters at 5 Hz, retaining 26 samples
  (approximately five seconds). Rates decay to zero during an interruption.
- Latency uses an independent 1:1 connection, a monotonic clock, and one outstanding
  probe. Latest, median, and nearest-rank p95 describe up to 300 **successful** probes.
  The even-sample median averages its middle pair. Timeouts are separately counted
  in `latency_failures` and the aggregate `failures`; they are not successful RTT
  samples. A probe times out after five seconds; bulk inactivity after 30 seconds.
- Bulk and probes retry independently with 250 ms–5 s backoff. Ten seconds of
  connection/session lifetime resets backoff. A run becomes `running` when both
  connections are established and `reconnecting` when either fails.

## Regression tests

`cargo test -p monad-client traffic` covers rate/ratio boundaries, real-server
traffic through an owned SOCKS forwarder, bounded setup and stream cleanup, partial
writes, unsolicited output, independent reconnects, stale commands, and metrics.
`cargo test -p monad-client socks_client` covers SOCKS framing and cancellation.
Runtime tests cover wildcard self-connect addresses and multi-client shutdown
while tests are active during route setup.
