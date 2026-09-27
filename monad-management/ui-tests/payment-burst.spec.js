import {test, expect} from "@playwright/test";
import {readFile} from "node:fs/promises";
import {join} from "node:path";
import {startNetworkDemo} from "./network-demo.mjs";

test("tiny-buffer mixed-unit payments remain monotonic under concurrent traffic", async ({page}) => {
  test.setTimeout(150000);
  const demo = await startNetworkDemo({manual:false});
  console.log(`Burst fixture: ${demo.directory}`);
  try {
    await page.goto(`${demo.url}/clients`);
    await expect(page.locator('[data-instance="demo-client"]')).toContainText("State: active", {timeout:20000});
    let successes = 0;
    const highWater = new Map();
    for(let round=0;round<20;round++) {
      const results = await Promise.allSettled(Array.from({length:8},()=>demo.traffic()));
      successes += results.filter(r=>r.status==="fulfilled").length;
      const state = await (await fetch(`${demo.url}/v1/snapshot`)).json();
      for(const channel of state.processes.clients.data.wallet.channels) {
        expect(channel.signed_balance_msats).toBeGreaterThanOrEqual(highWater.get(channel.channel_id) ?? 0);
        highWater.set(channel.channel_id, channel.signed_balance_msats);
      }
      await new Promise(resolve=>setTimeout(resolve,250));
    }
    expect(successes).toBeGreaterThan(20);
    const log = await readFile(join(demo.directory,"monad-client.log"),"utf8");
    expect(log.includes("above client local signed balance")).toBe(false);
    expect(log.includes("refusing to decrease cumulative")).toBe(false);
    await expect(page.locator('[data-instance="demo-client"]')).toContainText("State: active", {timeout:20000});
  } finally {await demo.stop();}
});
