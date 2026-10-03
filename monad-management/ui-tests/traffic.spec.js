import { test, expect } from "@playwright/test";
import { startDemo } from "./demo.mjs";

const clientsState = () => ({
  online: true,
  generation: "one",
  last_success_unix_ms: Date.now(),
  data: {
    kind: "clients",
    instances: {
      "demo-client": {
        socks_listen: "127.0.0.1:12345",
        controls: { enabled: true, automatic_provisioning: true },
        runtime: {
          lifecycle: { state: "active" },
          run_generation: 1,
          route_generation: 1,
        },
        hops: [],
        events: [],
        traffic_test: {
          revision: 0,
          run_id: 0,
          state: "stopped",
          server_url: "",
          total_rate_bytes_per_second: 1048576,
          upload_ratio: 1,
          download_ratio: 1,
          started_at_unix_ms: null,
          uploaded_bytes: 0,
          downloaded_bytes: 0,
          upload_rate_bytes_per_second: 0,
          download_rate_bytes_per_second: 0,
          latency: { latest_ms: null, median_ms: null, p95_ms: null, samples: 0 },
          failures: 0,
          latency_failures: 0,
          last_error: null,
        },
      },
    },
    wallet: { available_proofs: [], channels: [] },
  },
});
const serversState = () => ({
  online: true,
  generation: "one",
  last_success_unix_ms: Date.now(),
  data: {
    kind: "traffic_servers",
    instances: {
      "demo-traffic": {
        base_url: "http://127.0.0.1:9090",
        active_connections: 1,
        total_connections: 4,
        uploaded_bytes: 65536,
        downloaded_bytes: 1048576,
        events: [],
      },
    },
  },
});

test("speed test controls submit run-bound commands and render live metrics", async ({
  page,
}) => {
  const demo = await startDemo();
  const submissions = [];
  let operationError = null;
  try {
    await page.route("**/v1/events", (route) =>
      route.fulfill({
        contentType: "text/event-stream",
        body: `event: reset\ndata: ${JSON.stringify({ processes: { clients: clientsState(), "traffic-servers": serversState() } })}\n\n`,
      }),
    );
    await page.route("**/commands", async (route) => {
      const request = route.request().postDataJSON();
      submissions.push(request);
      await route.fulfill({
        status: 202,
        json: { request, state: "queued", result: null, error: null },
      });
    });
    await page.route("**/operations/*", (route) =>
      route.fulfill({
        json: {
          request: submissions.at(-1),
          state: operationError ? "failed" : "succeeded",
          result: null,
          error: operationError,
        },
      }),
    );
    await page.goto(`${demo.url}/clients`);
    const client = page.locator('[data-instance="demo-client"]');
    await expect(client.locator(".traffic-panel")).toBeVisible();
    await page.evaluate(() => {
      stream.close();
      live = true;
      for (const state of Object.values(processes))
        state.last_success_unix_ms = Date.now();
      render();
    });

    // Stopped state and server URL prefilled from the discovered server.
    await expect(client.locator(".traffic-status")).toContainText("Stopped");
    await expect(client.locator(".traffic-status")).toContainText("run 0");
    const url = client.locator('.traffic-form input[type="text"]');
    await expect(url).toHaveValue("http://127.0.0.1:9090");

    // Edit URL, rate, and ratio, then start with the current run ID.
    await url.fill("http://custom.example:1234");
    await client.locator('input[type="range"]').evaluate((range) => {
      range.value = "0";
      range.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await expect(client.locator(".traffic-rate-value")).toHaveText("1 KiB/s");
    await client.locator("select").selectOption("1:100");
    await client.getByRole("button", { name: "Start test" }).click();
    await expect(page.locator("#notice")).toContainText(
      "start_traffic_test · queued",
    );
    expect(submissions).toHaveLength(1);
    expect(submissions[0].action).toBe("start_traffic_test");
    expect(submissions[0].instance).toBe("demo-client");
    expect(submissions[0].arguments).toEqual({
      expected_run_id: 0,
      server_url: "http://custom.example:1234",
      total_rate_bytes_per_second: 1024,
      upload_ratio: 1,
      download_ratio: 100,
    });

    // A running snapshot renders formatted live metrics.
    await page.evaluate(() => {
      const t = processes.clients.data.instances["demo-client"].traffic_test;
      Object.assign(t, {
        run_id: 1,
        state: "running",
        server_url: "http://custom.example:1234",
        started_at_unix_ms: Date.now(),
        uploaded_bytes: 1572864,
        downloaded_bytes: 31457280,
        upload_rate_bytes_per_second: 2097152,
        download_rate_bytes_per_second: 1048576,
        failures: 2,
        latency_failures: 1,
      });
      Object.assign(t.latency, {
        latest_ms: 0.5,
        median_ms: 1,
        p95_ms: 2,
        samples: 7,
      });
      render();
    });
    await expect(client.locator(".traffic-status")).toContainText("Running");
    await expect(client.locator(".traffic-status")).toContainText("run 1");
    await expect(client.locator(".traffic-metrics")).toContainText(
      "1.5 MiB · 2 MiB/s",
    );
    await expect(client.locator(".traffic-metrics")).toContainText(
      "0.50 ms / 1.00 ms / 2.00 ms",
    );
    await expect(client.locator(".traffic-metrics")).toContainText("2 (1 latency)");

    // Stop uses the run ID from the latest snapshot, not render-time state.
    await page.evaluate(() => reconcileOperations());
    await client.getByRole("button", { name: "Stop test" }).click();
    await expect(page.locator("#notice")).toContainText(
      "stop_traffic_test · queued",
    );
    expect(submissions).toHaveLength(2);
    expect(submissions[1].action).toBe("stop_traffic_test");
    expect(submissions[1].arguments).toEqual({ expected_run_id: 1 });

    // A stale-run rejection surfaces through operation reconciliation.
    await page.evaluate(() => reconcileOperations());
    operationError = "traffic run changed; refresh before retrying";
    await client
      .getByRole("button", { name: "Restart with these settings" })
      .click();
    await page.evaluate(() => reconcileOperations());
    await expect(page.locator("#notice")).toContainText(
      "traffic run changed; refresh before retrying",
    );

    // Disabled clients cannot start a test.
    await page.evaluate(() => {
      processes.clients.data.instances["demo-client"].controls.enabled = false;
      render();
    });
    await expect(
      client.getByRole("button", { name: "Restart with these settings" }),
    ).toBeDisabled();
  } finally {
    await demo.stop();
  }
});

test("traffic servers page lists endpoints and counters", async ({ page }) => {
  const demo = await startDemo();
  try {
    await page.route("**/v1/events", (route) =>
      route.fulfill({
        contentType: "text/event-stream",
        body: `event: reset\ndata: ${JSON.stringify({ processes: { "traffic-servers": serversState() } })}\n\n`,
      }),
    );
    await page.goto(`${demo.url}/traffic-servers`);
    const server = page.locator('[data-instance="demo-traffic"]');
    await expect(server).toBeVisible();
    await page.evaluate(() => {
      stream.close();
      live = true;
      render();
    });
    await expect(page.locator("#title")).toHaveText("Traffic servers");
    await expect(server.locator("code")).toHaveText("http://127.0.0.1:9090");
    await expect(server).toContainText("1 / 4");
    await expect(server).toContainText("64 KiB");
    await expect(server).toContainText("1 MiB");
    // Read-only page: no wallet inventory or command buttons.
    await expect(page.locator("#instances button")).toHaveCount(0);
    await expect(page.locator("#wallet-summary")).toBeEmpty();
  } finally {
    await demo.stop();
  }
});
