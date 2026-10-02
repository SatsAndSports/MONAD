import { test, expect } from "@playwright/test";
import { startNetworkDemo } from "./network-demo.mjs";

test("online drain survives relay death after mint commit", async ({ browser }) => {
  test.setTimeout(180000);
  const demo = await startNetworkDemo({
    manual: true,
    mintProxy: true,
    sats: 5000,
    channelFundingMsats: 100000,
    targetTopupMsats: 5000,
    minimumTopupMsats: 1000,
  });
  let context;
  try {
    context = await browser.newContext();
    const client = await context.newPage();
    const relay = await context.newPage();
    const errors = [];
    for (const page of [client, relay])
      page.on("pageerror", (error) => errors.push(error.message));
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
    await expect(clientCard).toContainText("State: active", { timeout: 15000 });
    await demo.traffic();

    const exit = relay.locator('[data-instance="exit"]');
    const linkedSnapshot = await demo.wait((snapshot) =>
      snapshot.processes.relays?.data?.wallet?.channels?.find(
        (channel) =>
          channel.relay_name === "exit" && channel.ownership?.state === "linked",
      ),
    );
    const originalChannel = linkedSnapshot.processes.relays.data.wallet.channels.find(
      (channel) =>
        channel.relay_name === "exit" && channel.ownership?.state === "linked",
    ).channel_id;
    const unlink = await demo.command(
      "relays",
      "exit",
      "request_channel_unlink",
      { channel_id: originalChannel },
      "unlink-channel-before-drain-restart",
    );
    expect(unlink.status).toBe(202);
    expect(
      (await demo.waitOperation("relays", unlink.request.request_id)).state,
    ).toBe("succeeded");
    const unlinked = relay.locator("#unlinked-channels");
    const originalRow = unlinked
      .locator("tbody tr")
      .filter({ hasText: originalChannel.slice(0, 16) });
    await expect(originalRow).toContainText("Retired", { timeout: 15000 });

    for (let probe = 0; probe < 30; probe++) {
      const provision = clientCard
        .getByRole("button", { name: "Provision channel" })
        .and(clientCard.locator(":not([disabled])"));
      if ((await provision.count()) > 0) break;
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
    const replacementChannel = await exit
      .locator(".channel-panel")
      .first()
      .getAttribute("data-channel-id");
    expect(replacementChannel).toBeTruthy();
    expect(replacementChannel).not.toBe(originalChannel);

    const trafficDuringClose = Promise.all(
      Array.from({ length: 4 }, () => demo.traffic()),
    );
    await originalRow.getByRole("button", { name: "Close channel" }).click();
    await trafficDuringClose;
    await expect(originalRow).toContainText("Closed", { timeout: 15000 });
    await demo.traffic();

    const swapCount = demo.mintRequestCount("/v1/swap");
    const gate = demo.armMintPostCommit("/v1/swap");
    const drains = relay.locator("#relay-drains");
    await drains
      .getByRole("checkbox", { name: `Select channel ${originalChannel}` })
      .check();
    await drains.getByRole("button", { name: "Drain selected (1)" }).click();
    await gate.entered;
    expect(demo.mintRequestCount("/v1/swap")).toBe(swapCount + 1);
    await expect(relay.locator("#activity")).toContainText("drain_channels");
    await demo.traffic();

    const beforeCrash = await demo.wait((snapshot) =>
      snapshot.processes.relays?.online && snapshot.processes.clients?.online
        ? snapshot
        : undefined,
    );
    const oldRelayGeneration = beforeCrash.processes.relays.generation;
    const clientGeneration = beforeCrash.processes.clients.generation;
    const killedGeneration = await demo.crashRelays();
    expect(killedGeneration).toBe(oldRelayGeneration);
    gate.release();
    await demo.wait((snapshot) => !snapshot.processes.relays?.online, []);
    const restarted = await demo.startRelays(oldRelayGeneration);
    expect(restarted.processes.relays.generation).not.toBe(oldRelayGeneration);
    expect(restarted.processes.clients.generation).toBe(clientGeneration);

    const staleResponse = await fetch(
      `${demo.url}/v1/processes/relays/commands`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          generation: oldRelayGeneration,
          request_id: "stale-drain-after-restart",
          instance: "exit",
          action: "drain_channels",
          arguments: { channel_ids: [originalChannel] },
        }),
      },
    );
    expect(staleResponse.status).toBe(409);
    await expect(relay.locator("#activity")).not.toContainText("drain_channels", {
      timeout: 15000,
    });

    const submittedSnapshot = await demo.wait((snapshot) => {
      const wallet = snapshot.processes.relays?.data?.wallet;
      const drain = wallet?.drains?.find(
        (entry) =>
          entry.state === "Submitted" &&
          entry.channel_ids.length === 1 &&
          entry.channel_ids[0] === originalChannel,
      );
      const channel = wallet?.channels?.find(
        (entry) => entry.channel_id === originalChannel,
      );
      return drain && channel?.drain?.state === "reserved"
        ? { snapshot, drain, channel }
        : undefined;
    });
    const submittedWallet = submittedSnapshot.processes.relays.data.wallet;
    const submitted = {
      drain: submittedWallet.drains.find(
        (entry) =>
          entry.state === "Submitted" &&
          entry.channel_ids.length === 1 &&
          entry.channel_ids[0] === originalChannel,
      ),
      channel: submittedWallet.channels.find(
        (entry) => entry.channel_id === originalChannel,
      ),
    };
    expect(submitted.channel.drain.drain_id).toBe(submitted.drain.drain_id);
    await expect.poll(async () => {
      try {
        await demo.traffic();
        return true;
      } catch {
        return false;
      }
    }, { timeout: 30000 }).toBe(true);

    const restoreCount = demo.mintRequestCount("/v1/restore");
    await drains.getByRole("button", { name: "Resume drain" }).click();
    const completedSnapshot = await demo.wait((snapshot) => {
      const wallet = snapshot.processes.relays?.data?.wallet;
      const drain = wallet?.drains?.find(
        (entry) => entry.drain_id === submitted.drain.drain_id,
      );
      return drain?.state === "Completed" ? { wallet, drain } : undefined;
    });
    const completedWallet = completedSnapshot.processes.relays.data.wallet;
    const completed = {
      wallet: completedWallet,
      drain: completedWallet.drains.find(
        (entry) => entry.drain_id === submitted.drain.drain_id,
      ),
    };
    expect(completed.wallet.drains).toHaveLength(1);
    expect(demo.mintRequestCount("/v1/swap")).toBe(swapCount + 1);
    expect(demo.mintRequestCount("/v1/restore")).toBe(restoreCount + 1);
    await demo.traffic();

    const repeat = await demo.command(
      "relays",
      "exit",
      "recover_drain",
      { drain_id: submitted.drain.drain_id },
      "repeat-completed-drain-recovery",
    );
    expect(repeat.status).toBe(202);
    const repeatOperation = await demo.waitOperation(
      "relays",
      "repeat-completed-drain-recovery",
    );
    expect(repeatOperation.state).toBe("succeeded");
    expect(demo.mintRequestCount("/v1/restore")).toBe(restoreCount + 1);

    const redrain = await demo.command(
      "relays",
      "exit",
      "drain_channels",
      { channel_ids: [originalChannel] },
      "redrain-reserved-channel",
    );
    expect(redrain.status).toBe(202);
    const redrainOperation = await demo.waitOperation(
      "relays",
      "redrain-reserved-channel",
    );
    expect(redrainOperation.state).toBe("failed");
    expect(redrainOperation.error).toContain("already reserved by drain");
    expect(demo.mintRequestCount("/v1/swap")).toBe(swapCount + 1);
    expect(errors).toEqual([]);
  } finally {
    await context?.close();
    await demo.stop();
  }
});
