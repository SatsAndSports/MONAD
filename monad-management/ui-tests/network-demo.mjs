import { mkdir, mkdtemp, open, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { createServer as httpServer } from "node:http";
import { createECDH, randomBytes } from "node:crypto";
import { createInterface } from "node:readline";
import {
  reserveRelayPort,
  reserveTcpPort,
} from "./port-reservations.mjs";
const root = fileURLToPath(new URL("../../", import.meta.url));
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
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
  let apiReservation, socksReservation, socks2Reservation, mintReservation;
  try {
    apiReservation = await reserve(reserveTcpPort, managementPort);
    socksReservation = await reserve(reserveTcpPort, socksPort);
    socks2Reservation = await reserve(reserveTcpPort, socks2Port);
    mintReservation = await reserve(reserveTcpPort);
  } catch (error) {
    await releaseReservations([...liveReservations]);
    throw error;
  }
  const api = apiReservation.port,
    socks = socksReservation.port,
    socks2 = socks2Reservation.port,
    mintPort = mintReservation.port;
  const url = `http://127.0.0.1:${api}`,
    mintUrl = `http://127.0.0.1:${mintPort}`;
  const children = [];
  const target = httpServer((req, res) =>
    res.end("MONAD local demo traffic. ".repeat(4096)),
  );
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
      child,
      logPath,
      limitsPath,
      expectedExit: binary === "examples/demo-fund",
      done: new Promise((r) => {
        child.once("exit", (code, signal) => r({ code, signal }));
        child.once("error", (error) =>
          r({ code: null, signal: null, error: error.message }),
        );
      }),
    };
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
        const outcome = status.error
          ? `spawn error: ${status.error}`
          : status.signal
            ? `signal ${status.signal}`
            : `code ${status.code}`;
        console.error(
          `${binary} exited unexpectedly (${outcome}); private_log=${logPath} limits=${limitsPath}`,
        );
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
  const emergency = () =>
    children.forEach((e) => {
      if (e.child.exitCode === null && e.child.signalCode === null)
        e.child.kill("SIGKILL");
    });
  const stop = () =>
    (stopping ??= (async () => {
      await maintenance;
      await releaseReservations([...liveReservations]);
      target.closeAllConnections();
      await new Promise((r) => target.close(r));
      for (const e of [...children].reverse()) await stopChild(e);
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
        listen: `127.0.0.1:${mintPort}`,
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
  async function wait(predicate) {
    const deadline = Date.now() + 30000;
    while (Date.now() < deadline) {
      if (stopping) throw Error("Demo is stopping");
      try {
        const s = await (
          await fetch(`${url}/v1/snapshot`, {
            signal: AbortSignal.timeout(2000),
          })
        ).json();
        if (predicate(s)) return s;
      } catch {}
      await delay(100);
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
  let clients, relays, management;
  try {
    await launch("monad-test-mint", ["run", "--config", path], [
      mintReservation,
    ]);
    management = await launch("monad-management", ["--config", path], [
      apiReservation,
    ]);
    await wait((s) => s.processes["test-mints"]?.online);
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
      stopManagement: () => stopChild(management),
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
  });
  console.log(
    `Clients: ${demo.url}/clients\nRelays: ${demo.url}/relays\nMints: ${demo.url}/mints\nSOCKS: 127.0.0.1:${demo.socks}\nTraffic target: ${demo.targetUrl}\nPrivate child logs: ${demo.logDirectory}\nEphemeral data/config: ${demo.directory}\nWallet starts with ${process.env.MONAD_DEMO_SATS ?? 1000000} test sats equivalent, split across SAT/MSAT and shared by both clients. Second client starts disabled.\nSAT entry / MSAT exit · 100-sat credit targets · 50-sat minimum topups · 1,000-sat channel budgets\nCommands: traffic | traffic-on | traffic-off | topup SATS | restart-relays | quit`,
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
