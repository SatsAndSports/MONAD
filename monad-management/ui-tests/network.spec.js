import { test, expect } from "@playwright/test";
import { startNetworkDemo } from "./network-demo.mjs";
import { createServer } from "node:http";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
const exec = promisify(execFile);
test("clients and relays share commands, fund hops, carry traffic and recover", async ({
  browser,
}) => {
  test.setTimeout(120000);
  const demo = await startNetworkDemo({ manual: true });
  const context = await browser.newContext();
  const target = createServer((req, res) =>
    res.end("MONAD browser test traffic ".repeat(4096)),
  );
  await new Promise((r) => target.listen(0, "127.0.0.1", r));
  const errors = [];
  try {
    const a = await context.newPage(),
      b = await context.newPage(),
      relay = await context.newPage();
    for (const p of [a, b, relay])
      p.on("pageerror", (e) => errors.push(e.message));
    await Promise.all([
      a.goto(`${demo.url}/clients`),
      b.goto(`${demo.url}/clients`),
      relay.goto(`${demo.url}/relays`),
    ]);
    const client = (p) => p.locator('[data-instance="demo-client"]');
    await expect(client(a).getByRole("heading", { level: 2 })).toHaveText(
      `demo-client · SOCKS 127.0.0.1:${demo.socks}`,
    );
    await expect(
      a
        .locator('[data-instance="second-client"]')
        .getByRole("heading", { level: 2 }),
    ).toHaveText(`second-client · SOCKS 127.0.0.1:${demo.socks2}`);
    await expect(
      a.locator('[data-wallet-process="clients"]'),
    ).toContainText("Available loose proofs");
    await expect(
      relay.locator('[data-wallet-process="relays"]'),
    ).toContainText("Drained proofs");
    await expect(client(a)).toContainText("waiting_for_manual_funding");
    for (let hop = 0; hop < 2; hop++) {
      await client(a)
        .getByRole("button", { name: "Provision channel" })
        .filter({ visible: true })
        .nth(hop)
        .click();
      if (hop === 0)
        await expect(
          client(a).getByRole("button", { name: "Provision channel" }),
        ).toHaveCount(2);
    }
    await expect(client(b)).toContainText("State: active");
    await expect(b.locator("#activity")).toContainText(
      "provision_channel · succeeded",
    );
    await a.reload();
    await expect(client(a)).toContainText("State: active");
    await client(a)
      .getByRole("button", { name: "Enable automatic channel provisioning" })
      .click();
    await expect(
      client(b).getByRole("button", {
        name: "Disable automatic channel provisioning",
      }),
    ).toBeVisible();
    const exit = relay.locator('[data-instance="exit"]');
    const mint = await context.newPage();
    await mint.goto(`${demo.url}/mints`);
    const sat = mint.locator('[data-unit="sat"]');
    await sat.getByLabel("New input fee (ppk)").fill("400");
    await sat.getByRole("button", { name: "Rotate SAT" }).click();
    await expect(sat.locator("tbody tr")).toHaveCount(2);
    await mint.close();
    await exit
      .getByRole("button", { name: "Disable new channels", exact: true })
      .click();
    await expect(
      exit.getByRole("button", { name: "Enable new channels", exact: true }),
    ).toBeVisible();
    await demo.wait(
      (s) =>
        s.processes.relays.data.instances.exit.controls.accept_new_channels ===
        false,
    );
    const second = a.locator('[data-instance="second-client"]');
    await second
      .getByRole("button", { name: "Enable automatic channel provisioning" })
      .click();
    await expect(
      second.getByRole("button", {
        name: "Disable automatic channel provisioning",
      }),
    ).toBeVisible();
    await second
      .getByRole("button", { name: "Enable client", exact: true })
      .click();
    await expect(second).toContainText("waiting_for_relay_admission", {
      timeout: 15000,
    });
    await exit
      .getByRole("button", { name: "Enable new channels", exact: true })
      .click();
    await expect(second).toContainText("State: active", { timeout: 15000 });
    await second
      .getByRole("button", { name: "Disable client", exact: true })
      .click();
    await expect(second).toContainText("State: disabled");
    const probe = () =>
      exec("curl", [
        "--silent",
        "--show-error",
        "--max-time",
        "10",
        "--noproxy",
        "",
        "--socks5-hostname",
        `127.0.0.1:${demo.socks}`,
        `http://127.0.0.1:${target.address().port}`,
      ]);
    expect((await probe()).stdout).toContain("MONAD browser test traffic");
    await demo.wait((s) =>
      s.processes.clients.data.instances["demo-client"].hops.some(
        (h) => h.inbound_bytes > 0,
      ),
    );
    await exit
      .getByRole("button", { name: "Disable new tunnels", exact: true })
      .click();
    await expect(
      exit.getByRole("button", { name: "Enable new tunnels", exact: true }),
    ).toBeVisible();
    await expect(probe()).rejects.toThrow();
    await exit
      .getByRole("button", { name: "Enable new tunnels", exact: true })
      .click();
    await expect(
      exit.getByRole("button", { name: "Disable new tunnels", exact: true }),
    ).toBeVisible();
    expect((await probe()).stdout).toContain("MONAD browser test traffic");
    await client(a)
      .getByRole("button", { name: "Disable client", exact: true })
      .click();
    await expect(client(b)).toContainText("State: disabled");
    await expect(exit.locator(".channel-panel")).toHaveCount(0);
    await relay.locator("#unlinked-channels tr").filter({hasText:"exit / relays"}).getByRole("button", {name:"Close channel"}).first().click();
    await expect(relay.locator("#activity")).toContainText(
      "close_channel · succeeded",
    );
    await relay
      .locator('[data-instance="entry"]')
      .getByRole("button", { name: "Disable new sessions", exact: true })
      .click();
    await client(a)
      .getByRole("button", { name: "Enable client", exact: true })
      .click();
    await expect(client(b)).toContainText("waiting_for_admission");
    await relay
      .locator('[data-instance="entry"]')
      .getByRole("button", { name: "Enable new sessions", exact: true })
      .click();
    await expect(client(b)).toContainText("State: active", { timeout: 15000 });
    await exit
      .getByRole("button", { name: "Disable relay", exact: true })
      .click();
    await expect(
      exit.getByRole("button", { name: "Enable relay", exact: true }),
    ).toBeEnabled({ timeout: 15000 });
    await exit
      .getByRole("button", { name: "Enable relay", exact: true })
      .click();
    await expect(client(b)).toContainText("State: active", { timeout: 20000 });
    await demo.stopManagement();
    await expect(
      client(b).getByRole("button", { name: "Disable client", exact: true }),
    ).toBeDisabled({ timeout: 10000 });
    await demo.restartManagement();
    await expect(
      client(b).getByRole("button", { name: "Disable client", exact: true }),
    ).toBeEnabled({ timeout: 15000 });
    await demo.restartRelays();
    await expect
      .poll(
        async () => {
          try {
            return (await probe()).stdout.includes(
              "MONAD browser test traffic",
            );
          } catch {
            return false;
          }
        },
        { timeout: 30000 },
      )
      .toBe(true);
    await relay.setViewportSize({ width: 390, height: 844 });
    expect(
      await relay.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
    expect(errors).toEqual([]);
  } finally {
    await context.close();
    await new Promise((r) => target.close(r));
    await demo.stop();
  }
});

test("empty wallet can be topped up and funded without fabricated balances", async ({
  browser,
}) => {
  test.setTimeout(90000);
  const demo = await startNetworkDemo({ sats: 0, manual: true });
  const page = await browser.newPage();
  try {
    await page.goto(`${demo.url}/clients`);
    const client = page.locator('[data-instance="demo-client"]');
    await expect(client).toContainText("waiting_for_manual_funding");
    await client.getByRole("button", { name: "Provision channel" }).click();
    await expect(page.locator("#activity")).toContainText(
      "provision_channel · failed",
    );
    await demo.topup(100000);
    await expect(client).toContainText("waiting_for_manual_funding");
    await client
      .getByRole("button", { name: "Enable automatic channel provisioning" })
      .click();
    await expect(client).toContainText("State: active", { timeout: 20000 });
  } finally {
    await page.close();
    await demo.stop();
  }
});
