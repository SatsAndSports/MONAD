// Runs the container supervisor on the host with normal debug binaries.
// Requires socat and free ports 8080, 1080, 1081, 18080, 11080, 11081.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { createServer } from "node:net";
const exec = promisify(execFile);
const root = fileURLToPath(new URL("../../", import.meta.url));
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const base = "http://127.0.0.1:8080";
async function assertPortsFree() {
  for (const port of [8080, 1080, 1081, 18080, 11080, 11081]) {
    const server = createServer();
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(port, "0.0.0.0", resolve);
    });
    await new Promise((resolve) => server.close(resolve));
  }
}
async function waitFor(check) {
  const until = Date.now() + 30000;
  while (Date.now() < until) {
    try {
      const result = await check();
      if (result) return result;
    } catch {}
    await delay(100);
  }
  throw Error("Timed out waiting for supervised demo");
}
test(
  "container supervisor forwards management/SSE and both SOCKS, restarts, and shuts down",
  { timeout: 120000 },
  async () => {
    await assertPortsFree();
    const child = spawn(
      process.execPath,
      [fileURLToPath(new URL("./container-demo.mjs", import.meta.url))],
      {
        env: {
          ...process.env,
          MONAD_DEMO_BIN_DIR: `${root}/target/debug`,
          MONAD_DEMO_MANUAL: "0",
        },
        stdio: ["pipe", "pipe", "pipe"],
      },
    );
    let output = "";
    child.stdout.on("data", (data) => {
      output += data;
    });
    child.stderr.on("data", (data) => {
      output += data;
    });
    const done = new Promise((resolve) =>
      child.once("exit", (code, signal) => resolve({ code, signal })),
    );
    const snapshot = async () =>
      (
        await fetch(`${base}/v1/snapshot`, {
          signal: AbortSignal.timeout(2000),
        })
      ).json();
    try {
      const initial = await waitFor(async () => {
        const s = await snapshot();
        return (
          s.processes.clients?.data?.instances["demo-client"].runtime.lifecycle
            .state === "active" && s
        );
      });
      const controller = new AbortController();
      const events = await fetch(`${base}/v1/events`, {
        signal: controller.signal,
      });
      assert.match(events.headers.get("content-type"), /text\/event-stream/);
      const reader = events.body.getReader();
      assert.match(
        new TextDecoder().decode((await reader.read()).value),
        /event:/,
      );
      controller.abort();
      await reader.cancel().catch(() => {});
      const response = await fetch(`${base}/v1/processes/clients/commands`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          generation: initial.processes.clients.generation,
          request_id: randomUUID(),
          instance: "second-client",
          action: "set_enabled",
          arguments: { enabled: true },
        }),
      });
      assert.equal(response.status, 202);
      await response.json();
      await waitFor(
        async () =>
          (await snapshot()).processes.clients.data.instances["second-client"]
            .runtime.lifecycle.state === "active",
      );
      const target = output.match(/Traffic target: (http:\/\/[^\s]+)/)?.[1];
      assert.ok(target);
      for (const port of [1080, 1081]) {
        const { stdout } = await exec("curl", [
          "--fail",
          "--silent",
          "--show-error",
          "--max-time",
          "10",
          "--noproxy",
          "",
          "--socks5-hostname",
          `127.0.0.1:${port}`,
          target,
        ]);
        assert.match(stdout, /MONAD local demo traffic/);
      }
      child.stdin.write("restart-relays\n");
      await waitFor(async () => {
        const s = await snapshot();
        return (
          s.processes.relays.online &&
          s.processes.relays.generation !== initial.processes.relays.generation
        );
      });
      child.kill("SIGTERM");
      assert.deepEqual(await done, { code: 0, signal: null });
      await assertPortsFree();
    } catch (error) {
      console.error(output);
      throw error;
    } finally {
      if (child.exitCode === null && child.signalCode === null)
        child.kill("SIGTERM");
      await done;
    }
  },
);

test(
  "container supervisor fails and releases bridges when a service cannot start",
  { timeout: 60000 },
  async () => {
    await assertPortsFree();
    const child = spawn(
      process.execPath,
      [fileURLToPath(new URL("./container-demo.mjs", import.meta.url))],
      {
        env: {
          ...process.env,
          MONAD_DEMO_BIN_DIR: "/nonexistent-monad-demo-binaries",
          MONAD_DEMO_MANUAL: "0",
        },
        stdio: "ignore",
      },
    );
    const code = await new Promise((resolve) => child.once("exit", resolve));
    assert.equal(code, 1);
    await assertPortsFree();
  },
);
