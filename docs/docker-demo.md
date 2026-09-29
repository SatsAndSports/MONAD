# Public demo in Docker

This runs the existing disposable network demo in one container: test mint,
two QUIC relays, two SOCKS clients, management, and a local traffic target.
It uses ordinary bridge networking with unrestricted outbound connectivity.
Container loopback is separate from host loopback; no host networking, Docker
socket, or host data mount is used.

## Start

From the repository root, with Docker Engine and Compose installed:

```sh
docker compose -f compose.demo.yml up --build -d
docker compose -f compose.demo.yml logs -f
```

The first build compiles the Rust release binaries and funding example. No Rust,
Node, or npm installation is needed on the host. Allow several GB of disk and RAM
for compilation. Subsequent starts reuse the image; rebuild after source changes.
Build parallelism defaults to two jobs. Override it with
`docker compose -f compose.demo.yml build --build-arg CARGO_BUILD_JOBS=1` on a
smaller VPS.

| Service | Host address | Container bridge → internal listener |
| --- | --- | --- |
| Management HTTP/SSE | `127.0.0.1:18080` | `8080` → `127.0.0.1:18080` |
| Primary SOCKS5 | public TCP `11080` | `1080` → `127.0.0.1:11080` |
| Second SOCKS5 | public TCP `11081` | `1081` → `127.0.0.1:11081` |

Point your host Nginx HTTPS virtual host at `http://127.0.0.1:18080`.
Serve the UI at the virtual host root, with `/clients`, `/relays`, `/mints`,
`/assets/` and `/v1/` forwarded. Disable proxy buffering for SSE and use an
appropriate streaming read timeout. TLS is handled by your existing Nginx setup.

Only the SOCKS ports need public firewall access. Management stays host-loopback
bound. Visitors use `https://YOUR-DOMAIN/clients` and raw SOCKS5 at
`YOUR-DOMAIN:11080` or `:11081`; SOCKS is not carried over HTTPS.

Host ports are configurable without changing container ports:

```sh
MONAD_DEMO_HTTP_PORT=18090 MONAD_DEMO_PUBLIC_SOCKS_PORT=1090 \
MONAD_DEMO_PUBLIC_SOCKS2_PORT=1091 docker compose -f compose.demo.yml up -d
```

The management headings and default public host mappings both use SOCKS ports
`11080` and `11081`. Compose forwards them through private container bridge ports.

## Use the demo

The primary client starts enabled with automatic channel provisioning. The
second starts disabled; enable it on the Clients page to use the second SOCKS
port. Both clients share one purse, initially 1,000,000 test sats equivalent.

```sh
curl --noproxy '' --socks5-hostname YOUR-DOMAIN:11080 https://example.com/
```

Use `MONAD_DEMO_SATS` to change initial funding and `MONAD_DEMO_MANUAL=1` to start
with manual provisioning. Public management controls and both SOCKS proxies are
unauthenticated, with unrestricted destinations, as intended for this demo.

Interactive commands remain available:

```sh
docker compose -f compose.demo.yml attach monad-demo
```

Enter `traffic`, `traffic-on`, `traffic-off`, `topup 100000`, `restart-relays`, or
`quit`. Detach with **Ctrl-P, Ctrl-Q**; Ctrl-C stops the demo. Topups restore
configured client defaults (including disabling the second client). A failed
topup may have imported one unit already; it does not automatically repeat issuance.

```sh
docker compose -f compose.demo.yml ps
docker compose -f compose.demo.yml down
```

Each start creates fresh keys, wallets, and ports for internal services. Private
configuration, databases, and child logs live in the container's `/tmp` tmpfs;
they are lost when the container stops. There is no persistent volume. The image
runs as a non-root user with a read-only root filesystem and dropped capabilities.
Three socat bridges run **inside** the container. The supervisor handles signals,
reaps children, and shuts down if an essential process exits unexpectedly.

The health check verifies all three managed processes are online; it does not
require clients to remain enabled or funded. No automatic restart policy is set:
restarting grants a new disposable purse, so restarts are explicit.

## Local launcher options and verification

The normal launcher retains random-port/debug-binary defaults. Optional variables:

- `MONAD_DEMO_MANAGEMENT_PORT`, `MONAD_DEMO_SOCKS_PORT`, `MONAD_DEMO_SOCKS2_PORT`:
  internal loopback ports (zero means allocate dynamically).
- `MONAD_DEMO_BIN_DIR`: directory containing service binaries and
  `examples/demo-fund`.
- `MONAD_DEMO_FAIL_FAST=1`: shut down on unexpected service exit; enabled by the
  container supervisor.

After normal debug builds, with socat installed and the six fixed ports free:

```sh
node --test monad-management/ui-tests/container-demo.test.mjs
```

This exercises the same supervisor and forwarding processes locally, checks SSE,
enables the second client via management, carries traffic through both SOCKS
ports, restarts relays, and shuts down. For container verification, additionally
check Compose health, both published SOCKS ports, `docker compose stop`, and a
fresh start with a new wallet.
