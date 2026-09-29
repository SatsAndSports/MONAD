import { mkdir, mkdtemp, open, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { createServer as httpServer } from "node:http";
import { createServer } from "node:net";
import { createECDH, randomBytes } from "node:crypto";
import { createInterface } from "node:readline";
const root = fileURLToPath(new URL("../../", import.meta.url));
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function port(requested = 0) {
  if (!Number.isInteger(requested) || requested < 0 || requested > 65535)
    throw Error("Demo ports must be integers from 0 to 65535");
  const server = createServer();
  await new Promise((r, reject) => {
    server.once("error", reject);
    server.listen(requested, "127.0.0.1", r);
  });
  const p = server.address().port;
  await new Promise((r) => server.close(r));
  return p;
}
export async function startNetworkDemo({
  sats = Number(process.env.MONAD_DEMO_SATS ?? 1000000),
  manual = true,
  managementPort = Number(process.env.MONAD_DEMO_MANAGEMENT_PORT ?? 0),
  socksPort = Number(process.env.MONAD_DEMO_SOCKS_PORT ?? 0),
  socks2Port = Number(process.env.MONAD_DEMO_SOCKS2_PORT ?? 0),
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
  const api = await port(managementPort),
    socks = await port(socksPort),
    socks2 = await port(socks2Port),
    mintPort = await port();
  const url = `http://127.0.0.1:${api}`,
    mintUrl = `http://127.0.0.1:${mintPort}`;
  const children = [];
  const target = httpServer((req, res) =>
    res.end("MONAD local demo traffic. ".repeat(4096)),
  );
  await new Promise((r) => target.listen(0, "127.0.0.1", r));
  const targetUrl = `http://127.0.0.1:${target.address().port}`;
  async function launch(binary, args) {
    const label = binary.replaceAll("/", "-");
    const logPath = join(logDirectory, `${label}.log`);
    const limitsPath = join(logDirectory, `${label}.limits`);
    const log = await open(logPath, "a", 0o600);
    const binaryDir =
      process.env.MONAD_DEMO_BIN_DIR || resolve(root, "target/debug");
    const child = spawn(resolve(binaryDir, binary), args, {
      stdio: ["ignore", log.fd, log.fd],
    });
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
    children.push(entry);
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
      channel_funding_token_target_msats: 30000,
      target_topup_buffer_msats: 500,
      minimum_topup_msats: 500,
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
  for (const name of ["entry", "exit"]) {
    const key = createECDH("secp256k1");
    key.generateKeys();
    const listen = `127.0.0.1:${await port()}`;
    route.push(
      `${key.getPublicKey(null, "compressed").subarray(1).toString("hex")}::${listen}`,
    );
    config.relays.push({
      name,
      listen,
      transport_key: key.getPrivateKey().toString("hex"),
      receiver_secret_hex: randomBytes(32).toString("hex"),
      quic_cert_seed: randomBytes(32).toString("hex"),
      trusted_mints: [
        { url: mintUrl, units: [name === "entry" ? "sat" : "msat"] },
      ],
      pricing: { in_bytes_per_millisat: 200, out_bytes_per_millisat: 200 },
    });
  }
  config.clients = [
    { name: "demo-client", socks: `127.0.0.1:${socks}`, route },
    { name: "second-client", socks: `127.0.0.1:${socks2}`, route },
  ];
  const path = join(directory, "demo.json");
  await writeFile(path, JSON.stringify(config), { mode: 0o600 });
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
    await launch("monad-test-mint", ["run", "--config", path]);
    management = await launch("monad-management", ["--config", path]);
    await wait((s) => s.processes["test-mints"]?.online);
    await fund(sats);
    relays = await launch("monad-relay", ["run", "--config", path]);
    await wait((s) => s.processes.relays?.online);
    clients = await launch("monad-client", ["run", "--config", path]);
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
          management = await launch("monad-management", ["--config", path]);
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
          try {
            await fund(amount);
          } finally {
            if (!stopping)
              clients = await launch("monad-client", ["run", "--config", path]);
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
          relays = await launch("monad-relay", ["run", "--config", path]);
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
  });
  console.log(
    `Clients: ${demo.url}/clients\nRelays: ${demo.url}/relays\nMints: ${demo.url}/mints\nSOCKS: 127.0.0.1:${demo.socks}\nTraffic target: ${demo.targetUrl}\nPrivate child logs: ${demo.logDirectory}\nEphemeral data/config: ${demo.directory}\nWallet starts with ${process.env.MONAD_DEMO_SATS ?? 1000000} test sats equivalent, split across SAT/MSAT and shared by both clients. Second client starts disabled.\nSAT entry / MSAT exit · 500-msat credit targets · 30-sat channel budgets\nCommands: traffic | traffic-on | traffic-off | topup SATS | restart-relays | quit`,
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
