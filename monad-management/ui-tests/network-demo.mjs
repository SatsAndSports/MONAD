import { mkdir, mkdtemp, open, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { setTimeout as sleep } from "node:timers/promises";
import { createServer as httpServer, request as httpRequest } from "node:http";
import { createECDH, randomBytes } from "node:crypto";
import { createInterface } from "node:readline";
import {
  reserveRelayPort,
  reserveTcpPort,
} from "./port-reservations.mjs";
const root = fileURLToPath(new URL("../../", import.meta.url));
export async function startNetworkDemo({
  sats = Number(process.env.MONAD_DEMO_SATS ?? 1000000),
  manual = true,
  managementPort = Number(process.env.MONAD_DEMO_MANAGEMENT_PORT ?? 0),
  socksPort = Number(process.env.MONAD_DEMO_SOCKS_PORT ?? 0),
  socks2Port = Number(process.env.MONAD_DEMO_SOCKS2_PORT ?? 0),
  // Small defaults keep imported UI fixtures exercising payment/channel turnover.
  channelFundingMsats = 30000,
  targetTopupMsats = 500,
  minimumTopupMsats = 500,
  mintProxy = false,
  trafficServer = false,
} = {}) {
  if (!Number.isSafeInteger(sats) || sats < 0 || sats > 100000000)
    throw Error("MONAD_DEMO_SATS must be 0..100000000");
  const directory = await mkdtemp(join(tmpdir(), "monad-network-ui-"));
  const configuredLogRoot = process.env.MONAD_DEMO_LOG_DIR;
  if (configuredLogRoot)
    await mkdir(configuredLogRoot, { recursive: true, mode: 0o700 });
  const logDirectory = configuredLogRoot
    ? await mkdtemp(join(configuredLogRoot, "run-"))
    : directory;
  const fixed = [managementPort, socksPort, socks2Port].filter((p) => p !== 0);
  if (new Set(fixed).size !== fixed.length)
    throw Error("Demo ports must be distinct");
  const liveReservations = new Set();
  const reserve = async (factory, requested = 0) => {
    const reservation = await factory(requested);
    liveReservations.add(reservation);
    return reservation;
  };
  const releaseReservation = async (reservation) => {
    if (!reservation) return;
    liveReservations.delete(reservation);
    await reservation.release();
  };
  const releaseReservations = async (reservations) => {
    await Promise.all(reservations.map(releaseReservation));
  };
  const reserveMany = async (ports, factory) => {
    const reservations = [];
    try {
      for (const requested of ports)
        reservations.push(await reserve(factory, requested));
      return reservations;
    } catch (error) {
      await releaseReservations(reservations);
      throw error;
    }
  };
  let apiReservation,
    socksReservation,
    socks2Reservation,
    mintReservation,
    mintBackendReservation,
    trafficReservation;
  try {
    apiReservation = await reserve(reserveTcpPort, managementPort);
    socksReservation = await reserve(reserveTcpPort, socksPort);
    socks2Reservation = await reserve(reserveTcpPort, socks2Port);
    mintReservation = await reserve(reserveTcpPort);
    if (mintProxy) mintBackendReservation = await reserve(reserveTcpPort);
    if (trafficServer) trafficReservation = await reserve(reserveTcpPort);
  } catch (error) {
    await releaseReservations([...liveReservations]);
    throw error;
  }
  const api = apiReservation.port,
    socks = socksReservation.port,
    socks2 = socks2Reservation.port,
    mintPort = mintReservation.port,
    mintBackendPort = mintBackendReservation?.port ?? mintPort,
    trafficPort = trafficReservation?.port;
  const url = `http://127.0.0.1:${api}`,
    mintUrl = `http://127.0.0.1:${mintPort}`;
  const children = [];
  const childExitWaiters = new Set();
  const target = httpServer((req, res) =>
    res.end("MONAD local demo traffic. ".repeat(4096)),
  );
  const mintRequestCounts = new Map();
  let mintGate;
  const mintProxyServer = mintProxy
    ? httpServer((request, response) => {
        const chunks = [];
        let size = 0;
        request.on("data", (chunk) => {
          size += chunk.length;
          if (size > 1024 * 1024) request.destroy(Error("Mint proxy request too large"));
          else chunks.push(chunk);
        });
        request.on("error", (error) => {
          if (!response.headersSent) response.writeHead(502);
          response.end(error.message);
        });
        request.on("end", () => {
          const pathname = new URL(request.url, mintUrl).pathname;
          mintRequestCounts.set(pathname, (mintRequestCounts.get(pathname) ?? 0) + 1);
          const headers = { ...request.headers, host: `127.0.0.1:${mintBackendPort}` };
          delete headers["content-length"];
          const upstream = httpRequest(
            {
              host: "127.0.0.1",
              port: mintBackendPort,
              path: request.url,
              method: request.method,
              headers,
            },
            (upstreamResponse) => {
              const responseChunks = [];
              upstreamResponse.on("data", (chunk) => responseChunks.push(chunk));
              upstreamResponse.on("end", async () => {
                const body = Buffer.concat(responseChunks);
                const gate = mintGate;
                if (
                  gate &&
                  !gate.entered &&
                  pathname === gate.path &&
                  upstreamResponse.statusCode >= 200 &&
                  upstreamResponse.statusCode < 300
                ) {
                  gate.entered = true;
                  gate.resolveEntered();
                  await gate.released;
                  if (mintGate === gate) mintGate = undefined;
                }
                if (response.destroyed) return;
                response.writeHead(upstreamResponse.statusCode, upstreamResponse.headers);
                response.end(body);
              });
            },
          );
          upstream.on("error", (error) => {
            if (!response.headersSent) response.writeHead(502);
            response.end(error.message);
          });
          upstream.end(Buffer.concat(chunks));
        });
      })
    : undefined;
  try {
    await new Promise((resolve, reject) => {
      const failed = (error) => {
        target.off("listening", ready);
        reject(error);
      };
      const ready = () => {
        target.off("error", failed);
        resolve();
      };
      target.once("error", failed);
      target.once("listening", ready);
      target.listen(0, "127.0.0.1");
    });
  } catch (error) {
    await releaseReservations([...liveReservations]);
    throw error;
  }
  const targetUrl = `http://127.0.0.1:${target.address().port}`;
  const childExitError = (entry, status) => {
    const outcome = status.error
      ? `spawn error: ${status.error}`
      : status.signal
        ? `signal ${status.signal}`
        : `code ${status.code}`;
    const error = Error(
      `${entry.binary} exited unexpectedly (${outcome}); private_log=${entry.logPath} limits=${entry.limitsPath}`,
    );
    error.code = "DEMO_CHILD_EXIT";
    return error;
  };
  async function launch(binary, args, reservations = []) {
    const label = binary.replaceAll("/", "-");
    const logPath = join(logDirectory, `${label}.log`);
    const limitsPath = join(logDirectory, `${label}.limits`);
    const binaryDir =
      process.env.MONAD_DEMO_BIN_DIR || resolve(root, "target/debug");
    let child, log;
    try {
      log = await open(logPath, "a", 0o600);
      if (stopping) throw Error("Demo is stopping");
      await releaseReservations(reservations);
      if (stopping) throw Error("Demo is stopping");
      child = spawn(resolve(binaryDir, binary), args, {
        stdio: ["ignore", log.fd, log.fd],
      });
    } catch (error) {
      await releaseReservations(reservations);
      await log?.close();
      throw error;
    }
    const entry = {
      binary,
      child,
      logPath,
      limitsPath,
      expectedExit: binary === "examples/demo-fund",
      status: null,
      done: null,
    };
    entry.done = new Promise((resolve) => {
      let settled = false;
      const finish = (status) => {
        if (settled) return;
        settled = true;
        entry.status = status;
        for (const notify of childExitWaiters) notify(entry, status);
        resolve(status);
      };
      child.once("exit", (code, signal) => finish({ code, signal }));
      child.once("error", (error) =>
        finish({ code: null, signal: null, error: error.message }),
      );
    });
    children.push(entry);
    if (child.pid) {
      try {
        const limits = await readFile(`/proc/${child.pid}/limits`, "utf8");
        await writeFile(limitsPath, limits, { mode: 0o600 });
        const nofile = limits
          .split("\n")
          .find((line) => line.startsWith("Max open files"))
          ?.trim();
        console.log(
          `${binary} started pid=${child.pid}${nofile ? ` ${nofile}` : ""} private_log=${logPath}`,
        );
      } catch (error) {
        console.error(
          `${binary} limits unavailable: ${error.message}; private_log=${logPath}`,
        );
      }
    }
    entry.done.then((status) => {
      if (
        process.env.MONAD_DEMO_FAIL_FAST === "1" &&
        !entry.expectedExit &&
        !stopping
      ) {
        console.error(childExitError(entry, status).message);
        stop().finally(() => process.exit(1));
      }
    });
    await log.close();
    return entry;
  }
  async function stopChild(e) {
    e.expectedExit = true;
    if (e.child.exitCode !== null || e.child.signalCode !== null) return;
    e.child.kill("SIGINT");
    let timer;
    const finished = await Promise.race([
      e.done.then(() => true),
      new Promise((r) => {
        timer = setTimeout(() => r(false), 10000);
      }),
    ]);
    clearTimeout(timer);
    if (!finished) {
      e.child.kill("SIGKILL");
      await e.done;
    }
  }
  let stopping;
  let maintenance = Promise.resolve();
  const shutdown = new AbortController();
  const emergency = () =>
    children.forEach((e) => {
      if (e.child.exitCode === null && e.child.signalCode === null)
        e.child.kill("SIGKILL");
    });
  const stop = () =>
    (stopping ??= (async () => {
      shutdown.abort();
      await releaseReservations([...liveReservations]);
      if (mintGate) mintGate.resolveReleased();
      mintProxyServer?.closeAllConnections();
      if (mintProxyServer?.listening)
        await new Promise((resolve) => mintProxyServer.close(resolve));
      target.closeAllConnections();
      await new Promise((r) => target.close(r));
      for (const e of [...children].reverse()) await stopChild(e);
      await maintenance;
      process.off("exit", emergency);
      process.off("SIGINT", interrupt);
      process.off("SIGTERM", interrupt);
    })());
  const interrupt = () => {
    stop().finally(() => process.exit(0));
  };
  process.on("exit", emergency);
  process.on("SIGINT", interrupt);
  process.on("SIGTERM", interrupt);
  const socket = (name) => join(directory, `${name}.sock`);
  const loose = join(directory, "loose.db"),
    channels = join(directory, "channels.db");
  const config = {
    test_mints: [
      {
        name: "demo-mint",
        listen: `127.0.0.1:${mintBackendPort}`,
        db_path: join(directory, "mint.db"),
        units: { sat: { input_fee_ppk: 0 }, msat: { input_fee_ppk: 0 } },
      },
    ],
    relay_wallet: { db_path: join(directory, "relays.db") },
    client_wallet: {
      loose_db_path: loose,
      channel_db_path: channels,
      sender_secret_hex: randomBytes(32).toString("hex"),
      channel_funding_token_target_msats: channelFundingMsats,
      target_topup_buffer_msats: targetTopupMsats,
      minimum_topup_msats: minimumTopupMsats,
    },
    relays: [],
    clients: [],
    management: {
      listen: `127.0.0.1:${api}`,
      client_socket: socket("clients"),
      relay_socket: socket("relays"),
      test_mint_socket: socket("mints"),
      manual_funding_clients: manual ? ["demo-client", "second-client"] : [],
      disabled_clients: ["second-client"],
    },
  };
  if (trafficServer) {
    config.traffic_servers = [
      { name: "demo-traffic", listen: `127.0.0.1:${trafficPort}` },
    ];
    config.management.traffic_server_socket = socket("traffic");
  }
  const route = [];
  const relayReservations = [];
  try {
    for (const name of ["entry", "exit"]) {
      const key = createECDH("secp256k1");
      key.generateKeys();
      const relayReservation = await reserve(reserveRelayPort);
      relayReservations.push(relayReservation);
      const listen = `127.0.0.1:${relayReservation.port}`;
      route.push(
        `${key.getPublicKey(null, "compressed").subarray(1).toString("hex")}::${listen}`,
      );
      config.relays.push({
        name,
        listen,
        transport_key: key.getPrivateKey().toString("hex").padStart(64, "0"),
        receiver_secret_hex: randomBytes(32).toString("hex"),
        quic_cert_seed: randomBytes(32).toString("hex"),
        trusted_mints: [
          { url: mintUrl, units: [name === "entry" ? "sat" : "msat"] },
        ],
        pricing: {
          in_bytes_per_millisat: 200,
          out_bytes_per_millisat: 200,
        },
      });
    }
  } catch (error) {
    await stop();
    throw error;
  }
  config.clients = [
    { name: "demo-client", socks: `127.0.0.1:${socks}`, route },
    { name: "second-client", socks: `127.0.0.1:${socks2}`, route },
  ];
  const path = join(directory, "demo.json");
  try {
    await writeFile(path, JSON.stringify(config), { mode: 0o600 });
  } catch (error) {
    await stop();
    throw error;
  }
  let mint, clients, relays, management, traffic;
  const essentialChildren = () =>
    [mint, management, relays, clients, traffic].filter(Boolean);
  async function wait(predicate, required) {
    const deadline = Date.now() + 30000;
    const requiredChildren = () => required ?? essentialChildren();
    const throwIfRequiredExited = () => {
      for (const entry of requiredChildren())
        if (entry.status && !entry.expectedExit)
          throw childExitError(entry, entry.status);
    };
    const raceChildExit = (operation) =>
      new Promise((resolve, reject) => {
        let settled = false;
        const finish = (complete, value) => {
          if (settled) return;
          settled = true;
          childExitWaiters.delete(onExit);
          complete(value);
        };
        const onExit = (entry, status) => {
          if (!entry.expectedExit && requiredChildren().includes(entry))
            finish(reject, childExitError(entry, status));
        };
        childExitWaiters.add(onExit);
        try {
          throwIfRequiredExited();
        } catch (error) {
          finish(reject, error);
        }
        operation.then(
          (value) => finish(resolve, value),
          (error) => finish(reject, error),
        );
      });
    const handleWaitError = (error) => {
      if (error.code === "DEMO_CHILD_EXIT") throw error;
      if (shutdown.signal.aborted) throw Error("Demo is stopping");
    };
    while (Date.now() < deadline) {
      if (shutdown.signal.aborted) throw Error("Demo is stopping");
      const remaining = deadline - Date.now();
      try {
        const s = await raceChildExit(
          fetch(`${url}/v1/snapshot`, {
            signal: AbortSignal.any([
              shutdown.signal,
              AbortSignal.timeout(Math.min(2000, remaining)),
            ]),
          }).then((response) => response.json()),
        );
        if (predicate(s)) {
          throwIfRequiredExited();
          return s;
        }
      } catch (error) {
        handleWaitError(error);
      }
      const remainingAfterRequest = deadline - Date.now();
      if (remainingAfterRequest <= 0) break;
      try {
        await raceChildExit(
          sleep(Math.min(100, remainingAfterRequest), undefined, {
            signal: shutdown.signal,
          }),
        );
      } catch (error) {
        handleWaitError(error);
      }
    }
    throw Error(`Demo not ready; inspect private logs in ${logDirectory}`);
  }
  async function fund(amount) {
    const e = await launch("examples/demo-fund", [
      mintUrl,
      loose,
      channels,
      String(amount),
    ]);
    const status = await e.done;
    if (status.code !== 0)
      throw Error(`Funding failed; inspect private log ${e.logPath}`);
  }
  try {
    mint = await launch("monad-test-mint", ["run", "--config", path], [
      mintProxy ? mintBackendReservation : mintReservation,
    ]);
    management = await launch("monad-management", ["--config", path], [
      apiReservation,
    ]);
    await wait((s) => s.processes["test-mints"]?.online);
    if (trafficServer) {
      traffic = await launch(
        "monad-test-traffic",
        ["run", "--config", path],
        [trafficReservation],
      );
      await wait((s) => s.processes["traffic-servers"]?.online);
    }
    if (mintProxy) {
      await releaseReservation(mintReservation);
      await new Promise((resolve, reject) => {
        const failed = (error) => {
          mintProxyServer.off("listening", ready);
          reject(error);
        };
        const ready = () => {
          mintProxyServer.off("error", failed);
          resolve();
        };
        mintProxyServer.once("error", failed);
        mintProxyServer.once("listening", ready);
        mintProxyServer.listen(mintPort, "127.0.0.1");
      });
    }
    await fund(sats);
    relays = await launch("monad-relay", ["run", "--config", path], [
      ...relayReservations,
    ]);
    await wait((s) => s.processes.relays?.online);
    clients = await launch("monad-client", ["run", "--config", path], [
      socksReservation,
      socks2Reservation,
    ]);
    await wait((s) => s.processes.clients?.online);
    const serialized = (fn) => {
      if (stopping) return Promise.reject(new Error("Demo is stopping"));
      const next = maintenance.then(fn);
      maintenance = next.catch(() => {});
      return next;
    };
    return {
      url,
      directory,
      logDirectory,
      socks,
      socks2,
      stop,
      wait,
      targetUrl,
      trafficServerUrl: trafficServer
        ? `http://127.0.0.1:${trafficPort}`
        : undefined,
      mintRequestCount: (pathname) => mintRequestCounts.get(pathname) ?? 0,
      armMintPostCommit(pathname) {
        if (!mintProxy) throw Error("Mint proxy is not enabled");
        if (mintGate) throw Error("Mint proxy gate is already armed");
        let resolveEntered, resolveReleased;
        const entered = new Promise((resolve) => (resolveEntered = resolve));
        const released = new Promise((resolve) => (resolveReleased = resolve));
        mintGate = {
          path: pathname,
          entered: false,
          resolveEntered,
          released,
          resolveReleased,
        };
        return {
          entered,
          release: () => resolveReleased(),
        };
      },
      async command(process, instance, action, args, requestId) {
        const snapshot = await wait((s) => s.processes[process]?.online);
        const request = {
          generation: snapshot.processes[process].generation,
          request_id: requestId,
          instance,
          action,
          arguments: args,
        };
        const response = await fetch(
          `${url}/v1/processes/${encodeURIComponent(process)}/commands`,
          {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify(request),
            signal: AbortSignal.any([
              shutdown.signal,
              AbortSignal.timeout(5000),
            ]),
          },
        );
        return { status: response.status, body: await response.json(), request };
      },
      async waitOperation(process, requestId) {
        const deadline = Date.now() + 30000;
        while (Date.now() < deadline) {
          try {
            const response = await fetch(
              `${url}/v1/processes/${encodeURIComponent(process)}/operations/${encodeURIComponent(requestId)}`,
              {
                signal: AbortSignal.any([
                  shutdown.signal,
                  AbortSignal.timeout(Math.min(5000, deadline - Date.now())),
                ]),
              },
            );
            if (response.ok) {
              const operation = await response.json();
              if (["succeeded", "failed"].includes(operation.state))
                return operation;
            }
          } catch (error) {
            if (shutdown.signal.aborted) throw error;
          }
          await sleep(100);
        }
        throw Error(`Operation ${requestId} did not finish`);
      },
      stopManagement: () => stopChild(management),
      stopMint: () => stopChild(mint),
      restartManagement: () =>
        serialized(async () => {
          await stopChild(management);
          const reservations = await reserveMany([api], reserveTcpPort);
          try {
            if (!stopping)
              management = await launch(
                "monad-management",
                ["--config", path],
                reservations,
              );
          } finally {
            await releaseReservations(reservations);
          }
          await wait((s) => s.processes.clients?.online);
        }),
      traffic: () =>
        promisify(execFile)("curl", [
          "--silent",
          "--show-error",
          "--max-time",
          "10",
          "--noproxy",
          "",
          "--socks5-hostname",
          `127.0.0.1:${socks}`,
          targetUrl,
        ]),
      topup: (amount) =>
        serialized(async () => {
          if (!Number.isSafeInteger(amount) || amount < 0 || amount > 100000000)
            throw Error("Invalid topup");
          const before = await wait((s) => s.processes.clients?.online);
          await stopChild(clients);
          const reservations = await reserveMany(
            [socks, socks2],
            reserveTcpPort,
          );
          try {
            await fund(amount);
          } finally {
            if (!stopping)
              clients = await launch(
                "monad-client",
                ["run", "--config", path],
                reservations,
              );
            else await releaseReservations(reservations);
          }
          await wait(
            (s) =>
              s.processes.clients?.online &&
              s.processes.clients.generation !==
                before.processes.clients.generation,
          );
        }),
      restartRelays: () =>
        serialized(async () => {
          const before = await wait((s) => s.processes.relays?.online);
          await stopChild(relays);
          const reservations = await reserveMany(
            relayReservations.map(({ port }) => port),
            reserveRelayPort,
          );
          try {
            if (!stopping)
              relays = await launch(
                "monad-relay",
                ["run", "--config", path],
                reservations,
              );
          } finally {
            await releaseReservations(reservations);
          }
          await wait(
            (s) =>
              s.processes.relays?.online &&
              s.processes.relays.generation !==
                before.processes.relays.generation,
          );
        }),
      crashRelays: () =>
        serialized(async () => {
          const before = await wait((s) => s.processes.relays?.online);
          relays.expectedExit = true;
          relays.child.kill("SIGKILL");
          await relays.done;
          await rm(socket("relays"), { force: true });
          return before.processes.relays.generation;
        }),
      startRelays: (previousGeneration) =>
        serialized(async () => {
          const reservations = await reserveMany(
            relayReservations.map(({ port }) => port),
            reserveRelayPort,
          );
          try {
            if (!stopping)
              relays = await launch(
                "monad-relay",
                ["run", "--config", path],
                reservations,
              );
          } finally {
            await releaseReservations(reservations);
          }
          return wait(
            (s) =>
              s.processes.relays?.online &&
              s.processes.relays.generation !== previousGeneration,
          );
        }),
    };
  } catch (error) {
    await stop();
    throw error;
  }
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const demo = await startNetworkDemo({
    manual: process.env.MONAD_DEMO_MANUAL !== "0",
    channelFundingMsats: 1000000,
    targetTopupMsats: 100000,
    minimumTopupMsats: 50000,
    trafficServer: process.env.MONAD_DEMO_TRAFFIC_SERVER === "1",
  });
  console.log(
    `Clients: ${demo.url}/clients\nRelays: ${demo.url}/relays\nMints: ${demo.url}/mints${demo.trafficServerUrl ? `\nTraffic servers: ${demo.url}/traffic-servers\nRatio endpoint: ${demo.trafficServerUrl}` : ""}\nSOCKS: 127.0.0.1:${demo.socks}\nTraffic target: ${demo.targetUrl}\nPrivate child logs: ${demo.logDirectory}\nEphemeral data/config: ${demo.directory}\nWallet starts with ${process.env.MONAD_DEMO_SATS ?? 1000000} test sats equivalent, split across SAT/MSAT and shared by both clients. Second client starts disabled.\nSAT entry / MSAT exit · 100-sat credit targets · 50-sat minimum topups · 1,000-sat channel budgets\nCommands: traffic | traffic-on | traffic-off | topup SATS | restart-relays | quit`,
  );
  const input = createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  let trafficTimer,
    trafficBusy = false;
  async function tick() {
    if (trafficBusy) return;
    trafficBusy = true;
    try {
      const result = await demo.traffic();
      console.log(`Received ${result.stdout.length} bytes through SOCKS.`);
    } catch (e) {
      console.log(`Traffic waiting/failed: ${e.message}`);
    } finally {
      trafficBusy = false;
    }
  }
  input.on("close", () => clearInterval(trafficTimer));
  input.on("line", async (line) => {
    try {
      const [cmd, n] = line.trim().split(/\s+/);
      if (cmd === "traffic-on") {
        clearInterval(trafficTimer);
        trafficTimer = setInterval(tick, 1000);
        void tick();
      } else if (cmd === "traffic-off") {
        clearInterval(trafficTimer);
        trafficTimer = undefined;
      } else if (cmd === "traffic") {
        const result = await demo.traffic();
        console.log(`Received ${result.stdout.length} bytes through SOCKS.`);
      } else if (cmd === "topup") {
        await demo.topup(Number(n));
        console.log("Topup complete; clients restarted.");
      } else if (cmd === "restart-relays") {
        await demo.restartRelays();
        console.log("Relays restarted.");
      } else if (cmd === "quit") {
        input.close();
        await demo.stop();
      }
    } catch (e) {
      console.error(e.message);
    }
  });
}
