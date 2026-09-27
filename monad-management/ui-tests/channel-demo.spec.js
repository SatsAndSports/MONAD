import { test, expect } from "@playwright/test";
import { startNetworkDemo } from "./network-demo.mjs";

test("mixed-unit small channels pulse, turn red, pause and replace", async ({
  browser,
}) => {
  test.setTimeout(150000);
  const demo = await startNetworkDemo();
  const page = await browser.newPage();
  try {
    await page.addInitScript(() => {
      window.pulses = [];
      const animate = Element.prototype.animate;
      Element.prototype.animate = function (frames, options) {
        window.pulses.push(options.duration);
        return animate.call(this, frames, options);
      };
    });
    await page.goto(`${demo.url}/clients`);
    const card = page.locator('[data-instance="demo-client"]');
    for (let i = 0; i < 2; i++) {
      await expect(
        card.getByRole("button", { name: "Provision channel" }),
      ).toHaveCount(i + 1);
      await card
        .getByRole("button", { name: "Provision channel" })
        .nth(i)
        .click();
    }
    await expect(card).toContainText("State: active");
    const initial = await demo.wait(
      (s) =>
        s.processes.clients.data.instances["demo-client"].hops.length === 2,
    );
    const hops = initial.processes.clients.data.instances["demo-client"].hops;
    expect(hops.map((h) => h.linked_channel.unit).sort()).toEqual([
      "msat",
      "sat",
    ]);
    await expect(card.locator(".channel-panel")).toHaveCount(2);
    expect(await page.evaluate(() => window.pulses.includes(1500))).toBe(true);
    await page.reload();
    await expect(card).toContainText("State: active");
    expect(await page.evaluate(() => window.pulses.includes(1500))).toBe(false);
    let exhausted = false;
    for (let i = 0; i < 300; i++) {
      try {
        await demo.traffic();
      } catch {}
      // Tiny credit buffers can briefly refuse a burst while payment settles.
      // Allow the real payment loop and 5 Hz snapshot sampler to advance.
      await new Promise(resolve => setTimeout(resolve, 100));
      const s = await (await fetch(`${demo.url}/v1/snapshot`)).json();
      if (
        s.processes.clients.data.instances["demo-client"].hops.some(
          (h) => h.funding.state === "waiting_for_manual_funding",
        )
      ) {
        exhausted = true;
        break;
      }
    }
    expect(exhausted).toBe(true);
    await expect(card.locator(".low-capacity").first()).toBeVisible();
    await expect(card).toContainText("Paused", { timeout: 10000 });
    expect(await page.evaluate(() => window.pulses.includes(700))).toBe(true);
    await card
      .getByRole("button", { name: "Enable automatic channel provisioning" })
      .click();
    await demo.wait((s) =>
      s.processes.clients.data.instances["demo-client"].hops.some(
        (h) =>
          h.linked_channel &&
          !hops.some(
            (old) =>
              old.linked_channel.channel_id === h.linked_channel.channel_id,
          ),
      ),
    );
    expect((await demo.traffic()).stdout).toContain("MONAD local demo traffic");
    await expect
      .poll(() => page.evaluate(() => window.pulses.includes(1500)))
      .toBe(true);
  } finally {
    await page.close();
    await demo.stop();
  }
});
