// Container supervisor: retain the interactive demo's stdin, forward fixed ports,
// and stop the entire process tree if any essential child exits.
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const children = [];
let stopping;
function launch(command, args, options = {}) {
  const child = spawn(command, args, { stdio: "inherit", ...options });
  const entry = {
    child,
    group: options.detached,
    bridge: command === "socat",
    done: null,
  };
  entry.done = new Promise((resolve) => {
    child.once("error", (error) => {
      console.error(error.message);
      resolve(1);
    });
    child.once("exit", (code, signal) => resolve(signal ? 1 : code));
  });
  children.push(entry);
  entry.done.then((code) => {
    if (!stopping) void stop(code ?? 1);
  });
}
function signal(entry, sig) {
  try {
    if (entry.group && entry.child.pid && (entry.bridge || sig === "SIGKILL"))
      process.kill(-entry.child.pid, sig);
    else entry.child.kill(sig);
  } catch (error) {
    if (error.code !== "ESRCH") console.error(error.message);
  }
}
function stop(code = 0) {
  return (stopping ??= (async () => {
    // SIGINT follows the demo's graceful path, including its Rust subprocesses.
    for (const entry of children) signal(entry, "SIGINT");
    const deadline = setTimeout(() => {
      for (const entry of children) signal(entry, "SIGKILL");
      process.exit(1);
    }, 45000);
    await Promise.all(children.map((entry) => entry.done));
    clearTimeout(deadline);
    process.exit(code);
  })());
}
process.on("SIGTERM", () => void stop());
process.on("SIGINT", () => void stop());

const mappings = [
  [8080, 18080],
  [1080, 11080],
  [1081, 11081],
];
for (const [external, internal] of mappings)
  launch(
    "socat",
    [
      `TCP4-LISTEN:${external},bind=0.0.0.0,reuseaddr,fork`,
      `TCP4:127.0.0.1:${internal}`,
    ],
    { detached: true },
  );
launch(
  process.execPath,
  [fileURLToPath(new URL("./network-demo.mjs", import.meta.url))],
  {
    detached: true,
    env: {
      ...process.env,
      MONAD_DEMO_MANAGEMENT_PORT: "18080",
      MONAD_DEMO_SOCKS_PORT: "11080",
      MONAD_DEMO_SOCKS2_PORT: "11081",
      MONAD_DEMO_FAIL_FAST: "1",
    },
  },
);
