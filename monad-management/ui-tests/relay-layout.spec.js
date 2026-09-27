import {test, expect} from "@playwright/test";
import {startDemo} from "./demo.mjs";

test("relay channels partition by linkage, preserve Closing, and compact Closed",async({page})=>{
  const demo=await startDemo();
  const channel=(id,state,time)=>({channel_id:id.repeat(64),relay_name:"exit",state,mint_url:"http://mint",unit:"msat",capacity_raw:30000,balance_raw:29500,last_linked_at_unix_ms:time,ownership:id==="a"?{state:"linked",session_id:"session"}:{state:"unlinked"}});
  const data={kind:"relays",instances:{exit:{controls:{enabled:true,accept_new_sessions:true,accept_new_tunnels:true,accept_new_channels:true},disabling:false,sessions:[{session_id:"session",linked_channel_id:"a".repeat(64),paused:true}]}},wallet:{channels:[channel("a","Open",3000),channel("b","Closing",2000),channel("c","Closed",1000)]}};
  const state={online:true,generation:"one",last_success_unix_ms:Date.now(),data};
  try {
    await page.route("**/v1/events",route=>route.fulfill({contentType:"text/event-stream",body:`event: reset\ndata: ${JSON.stringify({processes:{relays:state}})}\n\n`}));
    await page.goto(`${demo.url}/relays`);
    await expect(page.locator('[data-instance="exit"] .channel-panel')).toHaveCount(1);
    await page.evaluate(()=>stream.close());
    const lower=page.locator("#unlinked-channels");
    await expect(lower.locator("tbody tr")).toHaveCount(2);
    await expect(lower.locator("tbody tr").first()).toContainText("Closing");
    await expect(lower.locator(".closing-state")).toHaveText("Closing");
    await expect(lower.locator(".closed-channel")).toContainText("Final paid: 29.5 / 30.0 sat");
    await expect(lower.locator(".low-capacity")).toHaveCount(0);
    await expect(lower.locator("tbody tr").last().locator("progress")).toHaveCount(0);
    // A session link remains visible while its wallet inventory details are absent.
    data.wallet.channels=data.wallet.channels.filter(channel=>channel.channel_id!=="a".repeat(64));
    await page.evaluate(state=>stream.dispatchEvent(new MessageEvent("snapshot",{data:JSON.stringify({process:"relays",state})})),state);
    const missing=page.locator('[data-instance="exit"] table').nth(1).locator("tbody tr");
    await expect(missing).toContainText("a".repeat(16));
    await expect(missing).toContainText("Details unavailable");
    await expect(missing.getByRole("button",{name:"Request unlink"})).toHaveCount(0);
    data.wallet.channels.unshift(channel("a","Open",3000));
    // Paused remains linked; only withdrawing the session moves its channel.
    data.instances.exit.sessions=[];
    await page.evaluate(state=>stream.dispatchEvent(new MessageEvent("snapshot",{data:JSON.stringify({process:"relays",state})})),state);
    await expect(lower.locator("tbody tr")).toHaveCount(2);
    await expect(page.locator('[data-instance="exit"]')).toContainText("session session");
    data.wallet.channels[0].ownership={state:"unlinked"};
    await page.evaluate(state=>stream.dispatchEvent(new MessageEvent("snapshot",{data:JSON.stringify({process:"relays",state})})),state);
    await expect(lower.locator("tbody tr")).toHaveCount(3);
    await expect(lower.locator("tbody tr").first()).toContainText("a".repeat(16));
    await expect(page.locator('[data-instance="exit"] .channel-panel')).toHaveCount(0);
    await expect(page.locator('[data-instance="exit"]')).toContainText("No active relay sessions.");
    await expect(page.locator('[data-instance="exit"]')).toContainText("No linked channels.");
    await page.reload();
    await expect(lower.locator("tbody tr").first()).toContainText("a".repeat(16));
    await page.evaluate(()=>stream.close());
    data.instances.exit.sessions=[{session_id:"replacement",linked_channel_id:"a".repeat(64),paused:false}];
    data.wallet.channels[0].ownership={state:"linked",session_id:"replacement"};
    await page.evaluate(state=>stream.dispatchEvent(new MessageEvent("snapshot",{data:JSON.stringify({process:"relays",state})})),state);
    await expect(lower.locator("tbody tr")).toHaveCount(2);
    await expect(page.locator('[data-instance="exit"] .channel-panel')).toHaveCount(1);
    data.wallet.channels=[];
    await page.evaluate(state=>stream.dispatchEvent(new MessageEvent("snapshot",{data:JSON.stringify({process:"relays",state})})),state);
    await expect(page.locator('[data-instance="exit"]')).toContainText("Details unavailable");
    await expect(page.getByText("No wallet channels.",{exact:true})).toBeVisible();
    expect(await page.locator("#instances > section, #instances > article").evaluateAll(nodes=>nodes.map(n=>n.querySelector("h2").textContent))).toEqual(["exit","Unlinked channels","relays · wallet inventory"]);
  } finally {await demo.stop();}
});
