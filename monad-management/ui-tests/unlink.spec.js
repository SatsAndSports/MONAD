import { test, expect } from "@playwright/test";
import { startNetworkDemo } from "./network-demo.mjs";

test("cooperative unlink retires the channel and separate close works", async ({
  browser,
}) => {
  test.setTimeout(120000);
  const demo = await startNetworkDemo({ manual: true });
  const context = await browser.newContext();
  try {
    const client = await context.newPage();
    const relay = await context.newPage();
    const errors = [];
    for (const page of [client, relay])
      page.on("pageerror", (e) => errors.push(e.message));
    await Promise.all([
      client.goto(`${demo.url}/clients`),
      relay.goto(`${demo.url}/relays`),
    ]);
    const clientCard = client.locator('[data-instance="demo-client"]');
    await expect(clientCard).toContainText("waiting_for_manual_funding");
    for (let hop = 0; hop < 2; hop++) {
      await clientCard
        .getByRole("button", { name: "Provision channel" })
        .filter({ visible: true })
        .nth(hop)
        .click();
      if (hop === 0)
        await expect(
          clientCard.getByRole("button", { name: "Provision channel" }),
        ).toHaveCount(2);
    }
    await expect(clientCard).toContainText("State: active");
    const exit = relay.locator('[data-instance="exit"]');
    const linkedChannel = exit.locator(".channel-panel").first();
    await expect(linkedChannel).toBeVisible();
    const channelId = await linkedChannel.getAttribute("data-channel-id");
    expect(channelId).toBeTruthy();
    const short = channelId.slice(0, 16);

    // Request cooperative unlink: the linked channel moves to the retired,
    // unlinked list while remaining Open. The button label changes to the
    // waiting state in the linked section.
    await exit
      .getByRole("button", { name: "Request unlink", exact: true })
      .first()
      .click();
    // The waiting state can be transient when the client unlinks immediately;
    // what must be stable is the channel moving to the retired unlinked list.
    const unlinked = relay.locator("#unlinked-channels");
    await expect(
      unlinked.locator("tbody tr").filter({ hasText: short }),
    ).toHaveCount(1, { timeout: 15000 });
    await expect(
      unlinked.locator("tbody tr").filter({ hasText: short }),
    ).toContainText("Retired");
    await expect(exit.locator(".channel-panel")).toHaveCount(0, {
      timeout: 10000,
    });

    // The retired channel still shows Open in the unlinked list and can now be
    // closed from there.
    const row = unlinked.locator("tbody tr").filter({ hasText: short });
    await expect(row).toContainText("Open");
    await row.getByRole("button", { name: "Close channel" }).click();
    await expect(relay.locator("#activity")).toContainText(
      "close_channel · succeeded",
      { timeout: 10000 },
    );
    await expect(
      unlinked.locator("tbody tr").filter({ hasText: short }),
    ).toContainText("Closed", { timeout: 10000 });

    // With manual provisioning, the session keeps its remaining credit after
    // the unlink. Drive traffic until it runs out; the client then waits for
    // the operator to fund the next channel, and provisioning again restores
    // an active route.
    for (let i = 0; i < 30; i++) {
      const waiting = await clientCard
        .getByRole("button", { name: "Provision channel" })
        .and(clientCard.locator(":not([disabled])"))
        .count();
      if (waiting > 0) break;
      try {
        await demo.traffic();
      } catch {}
    }
    await expect(clientCard).toContainText("waiting_for_manual_funding", {
      timeout: 15000,
    });
    await clientCard
      .getByRole("button", { name: "Provision channel" })
      .and(clientCard.locator(":not([disabled])"))
      .first()
      .click();
    await expect(clientCard).toContainText("State: active", { timeout: 15000 });
    expect(errors).toEqual([]);
  } finally {
    await context.close();
    await demo.stop();
  }
});
