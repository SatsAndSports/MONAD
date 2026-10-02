import { test, expect } from "@playwright/test";
import { readFile } from "node:fs/promises";

async function setup(page) {
  const html = await readFile(new URL("../src/ui/runtime.html", import.meta.url), "utf8");
  const js = await readFile(new URL("../src/ui/runtime.js", import.meta.url), "utf8");
  await page.addInitScript(() => {
    window.EventSource = class extends EventTarget {
      constructor() { super(); window.events = this; }
    };
  });
  await page.route("http://localhost/**", route => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/assets/runtime.js") return route.fulfill({contentType:"text/javascript", body:js});
    if (path === "/relays") return route.fulfill({contentType:"text/html", body:html});
    return route.fulfill({status:404, body:"{}"});
  });
  await page.goto("http://localhost/relays");
}

const channel = (id, unit = "sat", drain = {state:"eligible"}) => ({
  channel_id:id.repeat(64), relay_name:"exit", state:"Closed", mint_url:"http://mint",
  unit, capacity_raw:300, balance_raw:200, ownership:{state:"unlinked"}, drain,
});

async function publish(page, wallet, online = true, generation = "g") {
  await page.evaluate(({wallet, online, generation}) => {
    window.events.dispatchEvent(new MessageEvent("snapshot", {data:JSON.stringify({process:"relays", state:{
      online, generation, last_success_unix_ms:Date.now(),
      data:{kind:"relays", instances:{exit:{controls:{enabled:true,accept_new_sessions:true,
        accept_new_tunnels:true,accept_new_channels:true},sessions:[]}}, wallet},
    }})}));
  }, {wallet, online, generation});
}

test("relay drain controls submit exact groups and resume durable attempts", async ({page}) => {
  await setup(page);
  const channels = [channel("a"), channel("b"), channel("c", "msat"),
    channel("d", "sat", {state:"reserved",drain_id:"reserved-drain"})];
  await publish(page, {channels, drains:[]});
  const drains = page.locator("#relay-drains");
  await expect(drains.getByRole("heading", {name:"Channel drains"})).toBeVisible();
  await expect(drains.getByRole("checkbox")).toHaveCount(3);
  await expect(page.getByText("Drain reserved", {exact:false})).toBeVisible();

  await drains.getByRole("checkbox", {name:`Select channel ${"a".repeat(64)}`}).check();
  await drains.getByRole("checkbox", {name:`Select channel ${"b".repeat(64)}`}).check();
  let submitted;
  await page.route("**/commands", route => {
    submitted = route.request().postDataJSON();
    return route.fulfill({status:202, json:{request:submitted,state:"running"}});
  });
  await drains.getByRole("button", {name:"Drain selected (2)"}).click();
  expect(submitted.action).toBe("drain_channels");
  expect(submitted.arguments).toEqual({channel_ids:["a".repeat(64),"b".repeat(64)]});
  await expect(drains.getByRole("button", {name:"Drain selected (2)"})).toBeDisabled();

  await page.evaluate(request => window.events.dispatchEvent(new MessageEvent("operation_updated", {
    data:JSON.stringify({process:"relays",generation:"g",event:{data:{...request,state:"succeeded",
      result:{drain_id:"drain-1",state:"Submitted",recovery_required:true,channel_ids:request.arguments.channel_ids}}}}),
  })), submitted);
  await publish(page, {channels:[channel("c", "msat")], drains:[{
    drain_id:"drain-1",relay_name:"exit",mint_url:"http://mint",unit:"sat",state:"Submitted",
    input_amount_raw:400,output_amount_raw:400,channel_ids:["a".repeat(64),"b".repeat(64)],
  }]});
  const resume = drains.getByRole("button", {name:"Resume drain"});
  await expect(resume).toBeEnabled();
  await resume.click();
  expect(submitted.action).toBe("recover_drain");
  expect(submitted.arguments).toEqual({drain_id:"drain-1"});

  await publish(page, {channels:[channel("c", "msat")], drains:[{
    drain_id:"drain-1",relay_name:"exit",mint_url:"http://mint",unit:"sat",state:"Completed",
    input_amount_raw:400,output_amount_raw:400,channel_ids:["a".repeat(64),"b".repeat(64)],
  }]});
  await expect(resume).toHaveCount(0);
  await expect(drains.getByRole("cell", {name:"Completed", exact:true}).first()).toBeVisible();
});

test("drain selections clear on generation changes and stale sources disable actions", async ({page}) => {
  await setup(page);
  await publish(page, {channels:[channel("a")],drains:[]});
  const checkbox = page.getByRole("checkbox", {name:`Select channel ${"a".repeat(64)}`});
  await checkbox.check();
  await expect(page.getByRole("button", {name:"Drain selected (1)"})).toBeEnabled();
  await page.route("**/commands", route => {
    const request = route.request().postDataJSON();
    return route.fulfill({status:202, contentType:"application/json", body:JSON.stringify({
      request, state:"queued", result:null, error:null,
    })});
  });
  await page.getByRole("button", {name:"Drain selected (1)"}).click();
  await expect(page.locator("#activity")).toContainText("drain_channels");
  await page.evaluate(() => {
    window.events.dispatchEvent(new MessageEvent("reset", {data:JSON.stringify({processes:{
      relays:{online:false, data:null},
    }})}));
  });
  await expect(page.locator("#activity")).toContainText("drain_channels");
  await publish(page, {channels:[channel("a")],drains:[]}, true, "next");
  await expect(page.locator("#activity")).toContainText("No command activity observed yet.");
  await expect(page.getByRole("button", {name:"Drain selected (0)"})).toBeDisabled();
  await publish(page, {channels:[channel("a")],drains:[]}, false, "next");
  await expect(page.getByRole("checkbox", {name:`Select channel ${"a".repeat(64)}`})).toBeDisabled();
});
