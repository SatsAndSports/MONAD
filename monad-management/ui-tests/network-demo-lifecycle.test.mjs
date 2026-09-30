import assert from "node:assert/strict";
import { readFile, rm } from "node:fs/promises";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { setTimeout as sleep } from "node:timers/promises";
import { startNetworkDemo } from "./network-demo.mjs";

test(
  "failed topup restores the client process once and shutdown cancels readiness",
  { timeout: 120000 },
  async () => {
    const previousRustLog = process.env.RUST_LOG;
    process.env.RUST_LOG = "info";
    let demo;
    let stopped = false;
    try {
      demo = await startNetworkDemo({
        manual: false,
        sats: 1000000,
        channelFundingMsats: 1000000,
        targetTopupMsats: 100000,
        minimumTopupMsats: 50000,
      });
      const before = await demo.wait((snapshot) =>
        snapshot.processes.clients?.online ? snapshot : undefined,
      );
      await demo.stopMint();
      await assert.rejects(demo.topup(1), /Funding failed/);
      const recovered = await demo.wait((snapshot) => {
        const client = snapshot.processes.clients;
        return client?.online &&
          client.generation !== before.processes.clients.generation
          ? snapshot
          : undefined;
      });
      assert.notEqual(
        recovered.processes.clients.data.instances["demo-client"].runtime
          .lifecycle.state,
        "disabled",
      );

      const fundingLog = await readFile(
        join(demo.logDirectory, "examples-demo-fund.log"),
        "utf8",
      );
      assert.equal(fundingLog.match(/Imported .* local test sats/g)?.length, 1);
      assert.equal(fundingLog.match(/Connection refused/g)?.length, 1);
      const clientLog = await readFile(
        join(demo.logDirectory, "monad-client.log"),
        "utf8",
      );
      assert.equal(clientLog.match(/connecting configured route/g)?.length, 2);

      const waiting = demo.wait(() => false);
      await sleep(50);
      const started = Date.now();
      const stopping = demo.stop();
      await assert.rejects(waiting, /Demo is stopping/);
      assert.ok(
        Date.now() - started < 500,
        "shutdown should cancel readiness immediately",
      );
      await stopping;
      stopped = true;
    } finally {
      if (demo && !stopped) await demo.stop();
      if (demo) await rm(demo.directory, { recursive: true, force: true });
      if (previousRustLog === undefined) delete process.env.RUST_LOG;
      else process.env.RUST_LOG = previousRustLog;
    }
  },
);

test(
  "readiness reports a required child exit without waiting for its deadline",
  { timeout: 10000 },
  async () => {
    const previousBinaryDirectory = process.env.MONAD_DEMO_BIN_DIR;
    const previousFailFast = process.env.MONAD_DEMO_FAIL_FAST;
    const previousLogDirectory = process.env.MONAD_DEMO_LOG_DIR;
    delete process.env.MONAD_DEMO_LOG_DIR;
    process.env.MONAD_DEMO_BIN_DIR = "/nonexistent-monad-demo-binaries";
    process.env.MONAD_DEMO_FAIL_FAST = "0";
    const started = Date.now();
    let error;
    try {
      await startNetworkDemo({ manual: false });
    } catch (caught) {
      error = caught;
    } finally {
      if (previousBinaryDirectory === undefined)
        delete process.env.MONAD_DEMO_BIN_DIR;
      else process.env.MONAD_DEMO_BIN_DIR = previousBinaryDirectory;
      if (previousFailFast === undefined) delete process.env.MONAD_DEMO_FAIL_FAST;
      else process.env.MONAD_DEMO_FAIL_FAST = previousFailFast;
      if (previousLogDirectory === undefined)
        delete process.env.MONAD_DEMO_LOG_DIR;
      else process.env.MONAD_DEMO_LOG_DIR = previousLogDirectory;
    }

    assert.ok(error);
    assert.match(
      error.message,
      /monad-(?:test-mint|management) exited unexpectedly \(spawn error:/,
    );
    assert.doesNotMatch(error.message, /Demo not ready/);
    assert.ok(
      Date.now() - started < 5000,
      "child exit should fail readiness promptly",
    );
    const logPath = error.message.match(/private_log=([^ ]+)/)?.[1];
    if (logPath) await rm(dirname(logPath), { recursive: true, force: true });
  },
);
