import {test, expect} from "@playwright/test";
import {startDemo} from "./demo.mjs";
test("real mint rotation is shared across tabs and refresh does not resubmit", async ({browser}) => {
  const demo = await startDemo();
  const context = await browser.newContext();
  try {
    const a = await context.newPage();
    const b = await context.newPage();
    const errors = [];
    for (const page of [a,b]) page.on("pageerror", error => errors.push(error.message));
    await Promise.all([a.goto(`${demo.url}/mints`), b.goto(`${demo.url}/mints`)]);
    const sat = page => page.locator('[data-mint="demo-mint"] [data-unit="sat"]');
    await expect(sat(a).locator("tbody tr")).toHaveCount(1);
    await expect(sat(b).locator("tbody tr")).toHaveCount(1);
    await sat(a).getByLabel("New input fee (ppk)").fill("400");
    // Hold the accepted HTTP response: the other tab must learn through SSE.
    let release;
    const gate = new Promise(resolve => {release = resolve;});
    let accepted;
    const received = new Promise(resolve => {accepted = resolve;});
    let submissions = 0;
    await a.route("**/commands", async route => {
      submissions++;
      const response = await route.fetch(); accepted();
      await gate;
      try {await route.fulfill({response});} catch {}
    });
    await sat(a).getByRole("button", {name: "Rotate SAT"}).click();
    await received;
    await expect(b.locator("#activity")).toContainText("succeeded");
    await expect(sat(b).locator("tbody tr")).toHaveCount(2);
    await a.reload(); release();
    await expect(sat(a).locator("tbody tr")).toHaveCount(2);
    await expect(sat(a).locator("tbody tr").first()).toContainText("400");
    await expect(a.locator('[data-mint="demo-mint"] [data-unit="msat"] tbody tr')).toHaveCount(1);
    await expect(a.locator('[data-mint="second-mint"] [data-unit="sat"] tbody tr')).toHaveCount(1);
    expect(submissions).toBe(1);
    const snapshot = await (await context.request.get(`${demo.url}/v1/snapshot`)).json();
    const rejected = {generation: snapshot.processes["test-mints"].generation,
      request_id: "invalid-rotation", instance: "demo-mint", action: "rotate_keyset",
      arguments: {unit: "sat", input_fee_ppk: 1000}};
    expect((await context.request.post(`${demo.url}/v1/processes/test-mints/commands`, {data: rejected})).status()).toBe(202);
    await expect(a.locator("#activity")).toContainText("failed");
    await expect(b.locator("#activity")).toContainText("failed");
    await expect(sat(a).locator("tbody tr")).toHaveCount(2);
    await a.setViewportSize({width: 390, height: 844});
    expect(await a.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await demo.stopMint();
    await expect(sat(b).getByRole("button")).toBeDisabled({timeout: 10000});
    await expect(b.locator('[data-mint="demo-mint"] .badge')).toContainText("Stale");
    expect(errors).toEqual([]);
  } finally {await context.close(); await demo.stop();}
});
