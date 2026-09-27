import {test, expect} from "@playwright/test";
import {startDemo} from "./demo.mjs";

test("accepted commands stay locked and lost events reconcile to a visible failure", async ({page}) => {
  const demo = await startDemo();
  const channelId = "a".repeat(64);
  const state = {online:true,generation:"one",last_success_unix_ms:Date.now(),data:{kind:"relays",instances:{exit:{controls:{enabled:true,accept_new_sessions:true,accept_new_tunnels:true,accept_new_channels:true},sessions:[]}},wallet:{channels:[{channel_id:channelId,relay_name:"exit",state:"Open",unit:"sat",mint_url:"http://mint",capacity_raw:30,balance_raw:1,ownership:{state:"unlinked"}}]}}};
  let request, submissions = 0, finished = false;
  try {
    await page.route("**/v1/events", route => route.fulfill({contentType:"text/event-stream",body:`event: reset\ndata: ${JSON.stringify({processes:{relays:state}})}\n\n`}));
    await page.route("**/commands", async route => {
      submissions++;
      request = route.request().postDataJSON();
      await route.fulfill({status:202,json:{request,state:"queued",result:null,error:null}});
    });
    await page.route("**/operations/*", route => route.fulfill({json:{request,state:finished?"failed":"running",result:null,error:finished?"channel is linked; request unlink first":null}}));
    await page.goto(`${demo.url}/relays`);
    await expect(page.locator('[data-instance="exit"]')).toBeVisible();
    await page.evaluate(() => { stream.close(); live = true; processes.relays.last_success_unix_ms = Date.now(); render(); });
    const close = page.getByRole("button", {name:"Close channel",exact:true});
    await close.click();
    await expect(close).toBeDisabled();
    await expect(page.locator("#notice")).toContainText("queued");
    await page.evaluate(() => reconcileOperations());
    await expect(page.locator("#notice")).toContainText("running");
    await expect(close).toBeDisabled();
    expect(submissions).toBe(1);
    finished = true;
    await expect(page.locator("#notice")).toContainText("channel is linked; request unlink first");
    await expect(page.locator("#notice")).toContainText(channelId);
    await expect(close).toBeEnabled();
    // A delayed acceptance cannot regress an already-terminal operation.
    await page.evaluate(request => observeOperation({...request,process:"relays",state:"queued"}), request);
    await expect(close).toBeEnabled();
    await expect(page.locator("#notice")).toContainText("failed");
    // Concurrent commands observed from two tabs must both finish before unlock.
    await page.evaluate(request => {
      observeOperation({...request,process:"relays",request_id:"other-a",state:"running"});
      observeOperation({...request,process:"relays",request_id:"other-b",state:"running"});
      observeOperation({...request,process:"relays",request_id:"other-a",state:"succeeded"});
    }, request);
    await expect(close).toBeDisabled();
    await page.evaluate(request => observeOperation({...request,process:"relays",request_id:"other-b",state:"succeeded"}), request);
    await expect(close).toBeEnabled();
  } finally { await demo.stop(); }
});
