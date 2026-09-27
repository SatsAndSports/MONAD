import { test, expect } from "@playwright/test";
import { startDemo } from "./demo.mjs";

function processState(kind, summary) {
  return {
    online: true,
    generation: "one",
    last_success_unix_ms: Date.now(),
    data: {
      kind,
      instances: {},
      wallet: {
        summary,
        channels: [],
        available_proofs: [],
        proof_custody: [],
        expiring_channels: [],
        drains: [],
      },
    },
  };
}

async function openWithState(page, demo, path, process, state) {
  await page.route("**/v1/events", (route) =>
    route.fulfill({
      contentType: "text/event-stream",
      body: `event: reset\ndata: ${JSON.stringify({ processes: { [process]: state } })}\n\n`,
    }),
  );
  await page.goto(`${demo.url}/${path}`);
}

test("client wallet summary shows local available proofs and channel states", async ({
  page,
}) => {
  const demo = await startDemo();
  const summary = {
    available_loose_proofs: {
      sat: { amount_raw: "12340", proof_count: 8 },
      msat: { amount_raw: "85000", proof_count: 6 },
    },
    channel_state_counts: { open: 3, closing: 1, closed: 7 },
  };
  const state = processState("clients", summary);
  try {
    await openWithState(page, demo, "clients", "clients", state);
    const card = page.locator('[data-wallet-process="clients"]');
    await expect(card.locator('[data-wallet-category="proofs"]')).toHaveText(
      "Available loose proofs · 12,340 sat · 85,000 msat",
    );
    await expect(card.locator('[data-wallet-category="channels"]')).toHaveText(
      "Channels · Open 3 · Closing 1 · Closed 7",
    );
    summary.available_loose_proofs.sat.amount_raw = "999";
    summary.channel_state_counts.open = 2;
    await page.evaluate(
      ({ process, state }) =>
        stream.dispatchEvent(
          new MessageEvent("snapshot", {
            data: JSON.stringify({ process, state }),
          }),
        ),
      { process: "clients", state },
    );
    await expect(card.locator('[data-wallet-category="proofs"]')).toContainText(
      "999 sat",
    );
    await expect(card.locator('[data-wallet-category="channels"]')).toContainText(
      "Open 2",
    );
  } finally {
    await demo.stop();
  }
});

test("relay wallet summary labels completed drain outputs and all channel states", async ({
  page,
}) => {
  const demo = await startDemo();
  const state = processState("relays", {
    drained_proofs: {
      sat: { amount_raw: "4200" },
      msat: { amount_raw: "0" },
    },
    channel_state_counts: {
      open: 2,
      closing: 0,
      closed: 5,
      sender_refunded_after_expiry: 1,
    },
  });
  try {
    await openWithState(page, demo, "relays", "relays", state);
    const card = page.locator('[data-wallet-process="relays"]');
    await expect(card.locator('[data-wallet-category="proofs"]')).toHaveText(
      "Drained proofs · 4,200 sat · 0 msat",
    );
    await expect(card.locator('[data-wallet-category="channels"]')).toHaveText(
      "Channels · Open 2 · Closing 0 · Closed 5 · Refunded after expiry 1",
    );
    await page.setViewportSize({ width: 390, height: 844 });
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
  } finally {
    await demo.stop();
  }
});
