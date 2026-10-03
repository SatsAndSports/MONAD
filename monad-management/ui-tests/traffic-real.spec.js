import { test, expect } from "@playwright/test";
import { startNetworkDemo } from "./network-demo.mjs";

test("browser speed test drives real traffic through the client's own route", async ({
  browser,
}) => {
  test.setTimeout(120000);
  const demo = await startNetworkDemo({ manual: false, trafficServer: true });
  const context = await browser.newContext();
  const errors = [];
  try {
    const page = await context.newPage();
    page.on("pageerror", (e) => errors.push(e.message));
    await page.goto(`${demo.url}/clients`);
    const client = page.locator('[data-instance="demo-client"]');
    await expect(client).toContainText("State: active", { timeout: 60000 });
    // Server URL is prefilled from the discovered traffic server.
    const url = client.locator('.traffic-form input[type="text"]');
    await expect(url).toHaveValue(demo.trafficServerUrl);
    // Lowest rate keeps route cost negligible for the test duration.
    await client.locator('input[type="range"]').evaluate((range) => {
      range.value = "0";
      range.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await client.getByRole("button", { name: "Start test" }).click();
    await demo.wait((s) => {
      const t =
        s.processes.clients?.data?.instances?.["demo-client"]?.traffic_test;
      return (
        t?.run_id === 1 && t.uploaded_bytes > 0 && t.latency?.samples > 0
      );
    });
    await expect(page.locator("#activity")).toContainText(
      "start_traffic_test · succeeded",
    );
    await expect(client.locator(".traffic-status")).toContainText("Running");
    // Both streams traversed the route and reached the ratio server.
    await demo.wait(
      (s) =>
        s.processes["traffic-servers"]?.data?.instances?.["demo-traffic"]
          ?.total_connections >= 2,
    );
    const servers = await context.newPage();
    await servers.goto(`${demo.url}/traffic-servers`);
    const server = servers.locator('[data-instance="demo-traffic"]');
    await expect(server).toContainText(demo.trafficServerUrl);
    await expect(server).toContainText("Connections active / total");
    await client.getByRole("button", { name: "Stop test" }).click();
    await demo.wait(
      (s) =>
        s.processes.clients?.data?.instances?.["demo-client"]?.traffic_test
          ?.state === "stopped",
    );
    await expect(page.locator("#activity")).toContainText(
      "stop_traffic_test · succeeded",
    );
    await expect(client.locator(".traffic-status")).toContainText("Stopped");
    // Totals are preserved after stop while current rates drop to zero.
    await expect(client.locator(".traffic-metrics")).toContainText("· 0 B/s");
    expect(errors).toEqual([]);
  } finally {
    await context.close();
    await demo.stop();
  }
});
