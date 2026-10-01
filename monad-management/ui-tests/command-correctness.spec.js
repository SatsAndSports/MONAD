import { test, expect } from "@playwright/test";
import { readFile } from "node:fs/promises";

async function setup(page, kind) {
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
    if (path === `/${kind}`) return route.fulfill({contentType:"text/html", body:html});
    return route.fulfill({status:404, body:"{}"});
  });
  await page.goto(`http://localhost/${kind}`);
  await page.evaluate(kind => {
    window.events.dispatchEvent(new MessageEvent("reset", {data:JSON.stringify({processes:{[kind]:{
      online:true, generation:"g", last_success_unix_ms:Date.now(),
      data:{kind, instances:{demo:{controls:{enabled:true, automatic_provisioning:true,
        accept_new_channels:true, accept_new_sessions:true, accept_new_tunnels:true},
        runtime:{lifecycle:{state:"active"}}, hops:[], sessions:[]}}}
    }}})}));
  }, kind);
}

for (const classified of [true, false]) {
  test(`503 ${classified ? "pre-admission rejection unlocks" : "ambiguous rejection stays pending"}`, async ({page}) => {
    await setup(page, "clients");
    await page.route("**/commands", route => route.fulfill({status:503, json:{error:"busy",
      ...(classified ? {code:"command_not_admitted"} : {})}}));
    const toggle = page.getByRole("button", {name:"Disable automatic channel provisioning"});
    await toggle.click();
    if (classified) {
      await expect(toggle).toBeEnabled();
      await expect(page.locator("#activity")).toContainText("failed");
    } else {
      await expect(toggle).toBeDisabled();
      await expect(page.locator("#notice")).toContainText("Submission unconfirmed");
    }
  });
}

for (const kind of ["clients", "relays"]) {
  test(`${kind} allow Disable alongside slow work and track both independently`, async ({page}) => {
    await setup(page, kind);
    const slow = kind === "clients" ? "provision_channel" : "close_channel";
    const event = async (request_id, action, state) => page.evaluate(({kind, request_id, action, state}) => {
      window.events.dispatchEvent(new MessageEvent("operation_updated", {data:JSON.stringify({
        process:kind, generation:"g", event:{data:{request_id, instance:"demo", action, state}}
      })}));
    }, {kind, request_id, action, state});
    await event("slow", slow, "running");
    let submitted;
    await page.route("**/commands", route => {
      submitted = route.request().postDataJSON();
      return route.fulfill({status:202, json:{request:submitted, state:"running"}});
    });
    const disable = page.getByRole("button", {name:kind === "clients" ? "Disable client" : "Disable relay", exact:true});
    await expect(disable).toBeEnabled();
    await disable.click();
    await expect(disable).toBeDisabled();
    await expect(page.locator("#activity li")).toHaveCount(2);
    if (kind === "relays") expect(submitted.arguments).toEqual({field:"enabled", enabled:false});
    await event("slow", slow, "succeeded");
    await expect(disable).toBeDisabled();
    await event(submitted.request_id, submitted.action, "succeeded");
    await expect(disable).toBeEnabled();
  });
}

test("relay admission toggle submits only its selected field", async ({page}) => {
  await setup(page, "relays");
  let submitted;
  await page.route("**/commands", route => {
    submitted = route.request().postDataJSON();
    return route.fulfill({status:202, json:{request:submitted, state:"succeeded"}});
  });
  await page.getByRole("button", {name:"Disable new tunnels", exact:true}).click();
  await expect(page.locator("#activity")).toContainText("succeeded");
  expect(submitted.action).toBe("set_control");
  expect(submitted.arguments).toEqual({field:"accept_new_tunnels", enabled:false});
});

for (const kind of ["clients", "relays"]) {
  test(`${kind} wallet retains stale values and distinguishes missing from zero`, async ({page}) => {
    await setup(page, kind);
    const publish = async (online, age, summary) => page.evaluate(({kind, online, age, summary}) => {
      window.events.dispatchEvent(new MessageEvent("snapshot", {data:JSON.stringify({process:kind, state:{
        online, generation:"g", last_success_unix_ms:Date.now() - age,
        data:{kind, instances:{}, wallet:{summary}}
      }})}));
    }, {kind, online, age, summary});
    const summary = {channel_state_counts:{open:0, closing:2},
      [kind === "clients" ? "available_loose_proofs" : "drained_proofs"]:{sat:{amount_raw:"123"}}};
    const card = page.locator(`[data-wallet-process="${kind}"]`);
    await publish(true, 0, summary);
    await expect(card).toContainText("Live · Last successful sample:");
    await expect(card).toContainText("123 sat");
    await expect(card).toContainText("unavailable msat");
    await expect(card).toContainText("Open 0");
    await expect(card).toContainText("Closed unavailable");
    await publish(false, 0, summary);
    await expect(card).toContainText("Stale / unavailable");
    await expect(card).toContainText("123 sat");
    await publish(true, 7000, summary);
    await expect(card).toContainText("Stale / unavailable");
    await publish(true, 0, summary);
    await expect(card).toContainText("Live · Last successful sample:");
    await page.evaluate(() => window.events.onerror());
    await expect(card).toContainText("Stale / unavailable");
    await publish(true, 0, undefined);
    await expect(card).toContainText("Wallet summary unavailable");
    await expect(page.locator("#instances")).not.toContainText("No available loose proofs");
  });
}

test("Resume close uses the existing command and locks on pending or stale state", async ({page}) => {
  await setup(page, "relays");
  const publish = async (online, channelState = "Closing", ownership = "unlinked") => page.evaluate(({online, channelState, ownership}) => {
    window.events.dispatchEvent(new MessageEvent("snapshot", {data:JSON.stringify({process:"relays", state:{
      online, generation:"g", last_success_unix_ms:Date.now(),
      data:{kind:"relays", instances:{}, wallet:{channels:[{channel_id:"channel-1", relay_name:"demo",
        mint_url:"http://mint", unit:"sat", state:channelState, ownership:{state:ownership}, balance_raw:5, capacity_raw:10}]}}
    }})}));
  }, {online, channelState, ownership});
  await publish(false);
  const resume = page.getByRole("button", {name:"Resume close", exact:true});
  await expect(resume).toBeDisabled();
  await publish(true);
  await expect(resume).toBeEnabled();
  let submitted;
  await page.route("**/commands", route => {
    submitted = route.request().postDataJSON();
    return route.fulfill({status:202, json:{request:submitted, state:"running"}});
  });
  await resume.click();
  await expect(resume).toBeDisabled();
  expect(submitted.action).toBe("close_channel");
  expect(submitted.arguments).toEqual({channel_id:"channel-1"});
  await page.evaluate(request => window.events.dispatchEvent(new MessageEvent("operation_updated", {
    data:JSON.stringify({process:"relays", generation:"g", event:{data:{...request, state:"failed", error:"retry recovery"}}})
  })), submitted);
  await expect(resume).toBeEnabled();
  await publish(true, "Closed");
  await expect(resume).toHaveCount(0);
  await expect(page.getByRole("button", {name:"Close channel", exact:true})).toBeDisabled();
  await publish(true, "Closing", "linked");
  await expect(resume).toHaveCount(0);
});
