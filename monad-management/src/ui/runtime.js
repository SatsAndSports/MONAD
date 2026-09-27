"use strict";
const kind = location.pathname === "/clients" ? "clients" : "relays";
document.title = `${kind === "clients" ? "Clients" : "Relays"} · MONAD`;
document.querySelector("#title").textContent =
  kind === "clients" ? "Clients & routes" : "Relays & sessions";
document
  .querySelector(`nav a[href="/${kind}"]`)
  .setAttribute("aria-current", "page");
const root = document.querySelector("#instances"),
  notice = document.querySelector("#notice"),
  activity = document.querySelector("#activity");
let processes = {},
  live = false;
const pending = new Map(),
  commands = new Map(),
  cards = new Map();
function el(tag, text, cls) {
  const n = document.createElement(tag);
  if (text != null) n.textContent = text;
  if (cls) n.className = cls;
  return n;
}
const value = (v) =>
  v == null ? "—" : typeof v === "object" ? JSON.stringify(v) : String(v);
const healthy = (s) =>
  live && s?.online && Date.now() - s.last_success_unix_ms < 6000;
function update(old, next) {
  if (old.nodeName !== next.nodeName) {
    old.replaceWith(next);
    return next;
  }
  if (old.nodeType === Node.TEXT_NODE) {
    if (old.textContent !== next.textContent)
      old.textContent = next.textContent;
    return old;
  }
  for (const attr of [...old.attributes])
    if (!next.hasAttribute(attr.name) && attr.name !== "open")
      old.removeAttribute(attr.name);
  for (const attr of next.attributes) old.setAttribute(attr.name, attr.value);
  if (old instanceof HTMLButtonElement) {
    old.disabled = next.disabled;
    old.onclick = next.onclick;
  }
  const children = [...next.childNodes];
  children.forEach((child, i) => {
    if (old.childNodes[i]) update(old.childNodes[i], child);
    else old.append(child);
  });
  while (old.childNodes.length > children.length) old.lastChild.remove();
  return old;
}
function table(headers, rows) {
  const t = el("table"),
    head = el("tr"),
    body = el("tbody");
  headers.forEach((h) => head.append(el("th", h)));
  const th = el("thead");
  th.append(head);
  t.append(th);
  rows.forEach((row) => {
    const tr = el("tr");
    row.forEach((cell) => {
      const td = el("td");
      if (cell instanceof Node) td.append(cell);
      else td.textContent = value(cell);
      tr.append(td);
    });
    body.append(tr);
  });
  t.append(body);
  const wrap = el("div", null, "table-scroll");
  wrap.append(t);
  return wrap;
}
function button(text, process, name, action, args, enabled = true) {
  const b = el("button", text);
  b.type = "button";
  b.disabled =
    !healthy(processes[process]) ||
    pending.has(JSON.stringify([process, name])) ||
    !enabled;
  const generation = processes[process].generation;
  b.onclick = () => submit(process, name, generation, action, args);
  return b;
}
async function submit(process, name, generation, action, args) {
  const key = JSON.stringify([process, name]);
  if (
    !healthy(processes[process]) ||
    processes[process].generation !== generation ||
    pending.has(key)
  )
    return;
  const request_id = crypto.randomUUID();
  const controller = new AbortController(),
    timer = setTimeout(() => controller.abort(), 10000);
  const tracked = {process, instance:name, generation, request_id, action, channel_id:args.channel_id, state:"submitting"};
  pending.set(key, tracked);
  render();
  try {
    const response = await fetch(
      `/v1/processes/${encodeURIComponent(process)}/commands`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          generation,
          request_id,
          instance: name,
          action,
          arguments: args,
        }),
        signal: controller.signal,
      },
    );
    const result = await response.json();
    if ([400, 409, 429].includes(response.status)) {
      observeOperation({...tracked, state:"failed", error:result.error || `HTTP ${response.status}`});
      return;
    }
    if (!response.ok) throw Error(result.error || `HTTP ${response.status}`);
    observeOperation({...result.request, ...result, process, generation, request_id, instance:name, action, channel_id:args.channel_id});
  } catch (e) {
    if (pending.get(key) === tracked)
      notice.textContent = `Submission unconfirmed: ${e.message}. Request ${request_id}. Checking operation status; do not resubmit.`;
  } finally {
    clearTimeout(timer);
    render();
  }
}

function observeOperation(c) {
  if (processes[c.process]?.generation !== c.generation) return;
  const id = JSON.stringify([c.process, c.generation, c.request_id]);
  const previous = commands.get(id);
  if (["succeeded", "failed"].includes(previous?.state)) return;
  const key = JSON.stringify([c.process, c.instance]);
  const local = pending.get(key);
  c = {...previous, ...c, channel_id:c.channel_id || previous?.channel_id || (local?.request_id === c.request_id ? local.channel_id : undefined)};
  commands.set(id, c);
  const terminal = ["succeeded", "failed"].includes(c.state);
  if (terminal) {
    if (local?.request_id === c.request_id) pending.delete(key);
  } else if (!local || local.request_id === c.request_id) pending.set(key, c);
  notice.textContent = `${c.instance}: ${c.action}${c.channel_id ? " · channel " + c.channel_id : ""} · ${c.state} (${c.request_id})${c.error ? ": " + c.error : ""}${c.action === "request_channel_unlink" && c.state === "succeeded" ? " — check channel ownership for release completion" : ""}`;
  while (commands.size > 100) commands.delete(commands.keys().next().value);
  renderActivity();
  render();
}

let reconciling = false;
async function reconcileOperations() {
  if (reconciling) return;
  reconciling = true;
  try {
    await Promise.all([...pending.values()].map(async c => {
      if (processes[c.process]?.generation !== c.generation) {
        pending.delete(JSON.stringify([c.process, c.instance]));
        notice.textContent = `${c.instance}: process restarted; prior command outcome is unknown. Inspect current state.`;
        return;
      }
      try {
        const response = await fetch(`/v1/processes/${encodeURIComponent(c.process)}/operations/${encodeURIComponent(c.request_id)}`, {signal:AbortSignal.timeout(5000)});
        if (!response.ok) return;
        const op = await response.json();
        if (op.request.generation === c.generation)
          observeOperation({...c, ...op, ...op.request});
      } catch { /* Keep uncertain commands locked until lookup succeeds. */ }
    }));
  } finally { reconciling = false; render(); }
}
setInterval(reconcileOperations, 2000);
function controls(process, name, instance) {
  const box = el("div", null, "controls");
  const c = instance.controls;
  if (kind === "clients") {
    box.append(
      button(
        c.enabled ? "Disable client" : "Enable client",
        process,
        name,
        "set_enabled",
        { enabled: !c.enabled },
        instance.runtime.lifecycle.state !== "disabling",
      ),
    );
    box.append(
      button(
        c.automatic_provisioning
          ? "Disable automatic channel provisioning"
          : "Enable automatic channel provisioning",
        process,
        name,
        "set_automatic_provisioning",
        { enabled: !c.automatic_provisioning },
      ),
    );
  } else {
    for (const [field, label] of [
      ["enabled", "relay"],
      ["accept_new_sessions", "new sessions"],
      ["accept_new_tunnels", "new tunnels"],
      ["accept_new_channels", "new channels"],
    ]) {
      box.append(
        button(
          `${c[field] ? "Disable" : "Enable"} ${label}`,
          process,
          name,
          "set_controls",
          { ...c, [field]: !c[field] },
          !instance.disabling,
        ),
      );
    }
  }
  return box;
}
function sats(msat) {
  return (Number(msat) / 1000).toFixed(3);
}
function channelAmount(raw, unit) {
  if (unit === "sat") return String(raw);
  return sats(raw)
    .replace(/(\.\d*?[1-9])0+$/, "$1")
    .replace(/\.000$/, ".0");
}
function shortId(id) {
  const node = el("code", `${id.slice(0, 16)}…`);
  node.title = id;
  return node;
}
function channelPanel(c, session) {
  if (!c) return el("span", "No linked channel");
  const state = String(c.state || "open").toLowerCase();
  if (state === "closed") {
    const summary = el("span", `Final paid: ${channelAmount(c.balance_raw,c.unit)} / ${channelAmount(c.capacity_raw,c.unit)} sat`, "closed-channel");
    summary.dataset.channelId = c.channel_id;
    return summary;
  }
  const panel = el("section", null, "channel-panel");
  if (session) panel.dataset.channelSession = session;
  panel.dataset.channelId = c.channel_id;
  const left = Math.max(0, c.capacity_raw - c.balance_raw);
  const low = state === "open" && c.capacity_raw > 0 && left / c.capacity_raw < 0.1;
  panel.classList.toggle("low-capacity", low);
  panel.classList.toggle("closing-channel", state === "closing");
  panel.append(shortId(c.channel_id), el("strong", ` ${c.unit.toUpperCase()}`));
  const amount = el(
    "p",
    `${channelAmount(c.balance_raw, c.unit)} / ${channelAmount(c.capacity_raw, c.unit)} sat paid`,
    "channel-amount",
  );
  panel.append(amount);
  const bar = el("progress");
  bar.max = c.capacity_raw || 1;
  bar.value = c.balance_raw;
  bar.setAttribute("aria-label", "Channel capacity used");
  panel.append(
    bar,
    el(
      "p",
      `${channelAmount(left, c.unit)} sat capacity left${low ? " · Low capacity" : ""}`,
    ),
  );
  return panel;
}
function channelState(c) {
  const state = String(c.state).toLowerCase();
  const box = el("span");
  box.append(el("strong", value(c.state), state === "closing" ? "closing-state" : ""));
  if (c.retired) box.append(el("strong", " · Retired", "retired-state"));
  return box;
}
function unlinkedChannels() {
  const section = el("section", null, "mint"); section.id = "unlinked-channels";
  section.append(el("h2","Unlinked channels"), el("p","Most recently linked first. Paused sessions still count as linked. Unknown link times sort last."));
  const entries = [];
  for (const [process,state] of Object.entries(processes)) {
    if (state.data?.kind !== "relays") continue;
    for (const c of state.data.wallet?.channels || []) {
      if (c.ownership?.state === "linked") continue;
      entries.push({process,state,c});
    }
  }
  entries.sort((a,b)=>(b.c.last_linked_at_unix_ms || 0)-(a.c.last_linked_at_unix_ms || 0)
    || a.process.localeCompare(b.process) || a.c.channel_id.localeCompare(b.c.channel_id));
  section.append(table(["Relay / process","Channel","State","Mint / unit","Paid / capacity","Last linked","Action"],entries.map(({process,state,c})=>[
    `${c.relay_name} / ${process}${healthy(state) ? "" : " · Stale / unavailable"}`,
    shortId(c.channel_id), channelState(c), `${c.mint_url} / ${c.unit}`, channelPanel(c),
    c.last_linked_at_unix_ms ? new Date(c.last_linked_at_unix_ms).toLocaleString() : "Unknown (before this process run)",
    c.ownership?.state === "unlinked"
      ? button("Close channel",process,c.relay_name,"close_channel",{channel_id:c.channel_id},String(c.state).toLowerCase()==="open")
      : el("span", "Ownership unavailable")
  ])));
  if(!entries.length) section.append(el("p","No unlinked channels."));
  return section;
}
function sessionPanel(h) {
  const panel = el("section");
  panel.dataset.creditSession = h.session_id;
  panel.append(
    el("strong", `${sats(h.remaining_msats)} sat available`),
    el("p", h.paused ? "Paused" : "Running"),
    el(
      "small",
      `${sats(h.total_paid_msats)} sat credited · ${sats(Number(h.total_paid_msats) - Number(h.remaining_msats))} sat charged`,
    ),
  );
  return panel;
}
function pulseChanges(process, before, after) {
  if (
    !before ||
    before.generation !== after.generation ||
    after.data?.kind !== "clients"
  )
    return;
  for (const [name, instance] of Object.entries(after.data.instances)) {
    const old = before.data?.instances?.[name];
    if (!old) continue;
    const card = cards.get(JSON.stringify(["instance", process, name]));
    if (!card) continue;
    for (const hop of instance.hops) {
      const previous = old.hops.find(
        (h) => h.session_id === hop.session_id,
      ) || { total_paid_msats: 0 };
      const linked =
        hop.linked_channel?.channel_id &&
        hop.linked_channel.channel_id !== previous.linked_channel?.channel_id;
      const paid =
        Number(hop.total_paid_msats) > Number(previous.total_paid_msats);
      const panel = [...card.querySelectorAll("[data-channel-session]")].find(
        (n) => n.dataset.channelSession === hop.session_id,
      );
      const credit = [...card.querySelectorAll("[data-credit-session]")].find(
        (n) => n.dataset.creditSession === hop.session_id,
      );
      const animate = (node, color, duration) => {
        if (!node || matchMedia("(prefers-reduced-motion: reduce)").matches)
          return;
        node.getAnimations().forEach((a) => a.cancel());
        node.animate(
          [
            { backgroundColor: color, boxShadow: `0 0 16px ${color}` },
            { backgroundColor: "transparent", boxShadow: "none" },
          ],
          { duration, easing: "ease-out" },
        );
      };
      if (linked) animate(panel, "#357d91", 1500);
      else if (paid)
        animate(panel?.querySelector(".channel-amount"), "#397b60", 700);
      if (paid) animate(credit, "#397b60", 700);
    }
  }
}
function instanceCard(process, name, state, instance) {
  const card = el("article", null, "mint");
  card.dataset.instance = name;
  card.append(
    el("h2", name),
    el(
      "p",
      `${process} · ${healthy(state) ? "Live" : "Stale / unavailable"} · sampled ${new Date(state.last_success_unix_ms).toLocaleTimeString()}`,
    ),
  );
  card.append(controls(process, name, instance));
  if (kind === "clients") {
    const runtime = instance.runtime;
    card.append(
      el("h3", `State: ${runtime.lifecycle.state}`),
      el(
        "p",
        `Run ${runtime.run_generation} · route ${runtime.route_generation}`,
      ),
    );
    if (Object.keys(runtime.lifecycle).length > 1)
      card.append(el("pre", JSON.stringify(runtime.lifecycle, null, 2)));
    if (runtime.last_failure)
      card.append(el("p", `Latest failure: ${value(runtime.last_failure)}`));
    if (runtime.last_exit_failure)
      card.append(
        el("p", `Latest exit refusal: ${value(runtime.last_exit_failure)}`),
      );
    const hops = [...instance.hops].sort((a, b) =>
      a.label.localeCompare(b.label, undefined, { numeric: true }),
    );
    card.append(
      table(
        [
          "Hop / session",
          "Funding",
          "Channel",
          "Session credit",
          "Inbound / outbound (bytes)",
          "Action",
        ],
        hops.map((h) => [
          `${h.label} · ${h.session_id.slice(0, 16)}…`,
          value(h.funding),
          channelPanel(h.linked_channel, h.session_id),
          sessionPanel(h),
          `${h.inbound_bytes} / ${h.outbound_bytes}`,
          button(
            "Provision channel",
            process,
            name,
            "provision_channel",
            { session_id: h.session_id },
            !instance.controls.automatic_provisioning &&
              h.funding.state === "waiting_for_manual_funding",
          ),
        ]),
      ),
    );
    if (!hops.length) card.append(el("p", "No active hop sessions."));
  } else {
    const sessions = instance.sessions || [];
    card.append(
      el(
        "h3",
        instance.disabling
          ? "Disabling"
          : instance.controls.enabled
            ? "Enabled"
            : "Disabled",
      ),
    );
    card.append(
      table(
        [
          "Session / channel",
          "Paused",
          "Session credit available / credited (sat)",
          "Inbound / outbound (bytes)",
          "Tunnels active / total",
        ],
        sessions.map((s) => [
          `${s.session_id.slice(0, 16)}… / ${s.linked_channel_id?.slice(0, 16) || "—"}…`,
          s.paused,
          `${sats(s.remaining_msats)} / ${sats(s.total_paid_msats)}`,
          `${s.inbound_bytes} / ${s.outbound_bytes}`,
          `${s.active_tunnels} / ${s.total_tunnels}`,
        ]),
      ),
    );
    if (!sessions.length) card.append(el("p", "No active relay sessions."));
    card.append(el("h3", "Linked channels"));
    const inventory = new Map(
      (state.data.wallet?.channels || [])
        .filter((channel) => channel.relay_name === name)
        .map((channel) => [channel.channel_id, channel]),
    );
    const linkedChannels = [
      ...new Set([
        ...[...inventory.values()].filter(channel => channel.ownership?.state === "linked").map(channel => channel.channel_id),
        ...sessions.map(session => session.linked_channel_id).filter(id => id && !inventory.has(id)),
      ]),
    ].map((channelId) => ({ channelId, channel: inventory.get(channelId) }));
    card.append(
      table(
        ["Channel", "State", "Mint / unit", "Paid / capacity (sat)", "Action"],
        linkedChannels.map(({ channelId, channel }) =>
          channel
            ? [
                el("span", `${channel.channel_id.slice(0, 16)}… · session ${channel.ownership.session_id}`),
                channelState(channel),
                `${channel.mint_url} / ${channel.unit}`,
                channelPanel(channel),
                channel.retired
                  ? el(
                      "span",
                      "Unlink requested — waiting for client",
                      "unlink-pending",
                    )
                  : button(
                      "Request unlink",
                      process,
                      name,
                      "request_channel_unlink",
                      { channel_id: channel.channel_id },
                      String(channel.state).toLowerCase() === "open",
                    ),
              ]
            : [
                shortId(channelId),
                el("span", "Details unavailable", "missing-channel"),
                "—",
                "—",
                el("span", "Waiting for wallet inventory", "missing-channel"),
              ],
        ),
      ),
    );
    if (!linkedChannels.length) card.append(el("p", "No linked channels."));
  }
  return card;
}
function render() {
  const seen = new Set();
  for (const [process, state] of Object.entries(processes)) {
    if (state.data?.kind !== kind) continue;
    for (const [name, instance] of Object.entries(state.data.instances)) {
      const key = JSON.stringify(["instance", process, name]);
      seen.add(key);
      const old = cards.get(key);
      const card = instanceCard(process, name, state, instance);
      if (old) cards.set(key, update(old, card));
      else {
        root.append(card);
        cards.set(key, card);
      }
    }
    const key = JSON.stringify(["wallet", process]);
    seen.add(key);
    const wallet = el("section", null, "mint");
    wallet.append(el("h2", `${process} · wallet inventory`));
    const walletData = state.data.wallet;
    if (kind === "clients") {
      wallet.append(
        el(
          "p",
          "Shared by this process’s clients. Available loose proofs, reserved custody, and channel capacity are separate categories—not an additive spendable balance.",
        ),
      );
      wallet.append(
        table(
          ["Mint", "Unit", "Available (raw unit)", "Proofs"],
          (walletData?.available_proofs || []).map((p) => [
            p.mint_url,
            p.unit,
            p.amount_raw,
            p.proof_count,
          ]),
        ),
      );
      if (!walletData?.available_proofs?.length)
        wallet.append(el("p", "No available loose proofs."));
    }
    if (!walletData) wallet.append(el("p", "Wallet inventory unavailable."));
    else {
      if (!walletData.channels?.length)
        wallet.append(el("p", "No wallet channels."));
      const details = el("details"),
        summary = el("summary", "Wallet details (channels and custody)");
      details.append(summary, el("pre", JSON.stringify(walletData, null, 2)));
      wallet.append(details);
    }
    const old = cards.get(key);
    if (old?.querySelector("details")?.open && wallet.querySelector("details"))
      wallet.querySelector("details").open = true;
    if (old) cards.set(key, update(old, wallet));
    else {
      root.append(wallet);
      cards.set(key, wallet);
    }
  }
  if (kind === "relays") {
    const key = "unlinked"; seen.add(key);
    const next = unlinkedChannels(), old = cards.get(key);
    if(old) cards.set(key,update(old,next)); else {root.append(next); cards.set(key,next);}
    const order = [];
    for(const [process,state] of Object.entries(processes)) {
      if(state.data?.kind!=="relays") continue;
      for(const name of Object.keys(state.data.instances)) order.push(cards.get(JSON.stringify(["instance",process,name])));
    }
    order.push(cards.get(key));
    for(const [process,state] of Object.entries(processes)) if(state.data?.kind==="relays") order.push(cards.get(JSON.stringify(["wallet",process])));
    order.forEach((card,index)=>{if(root.children[index]!==card) root.insertBefore(card,root.children[index] || null);});
  }
  for (const [key, card] of cards)
    if (!seen.has(key)) {
      card.remove();
      cards.delete(key);
    }
  for (const child of [...root.childNodes])
    if (![...cards.values()].includes(child)) child.remove();
  if (!cards.size)
    root.append(
      el(
        "p",
        `No ${kind} process is available yet. Start the configured runtime.`,
      ),
    );
}
function renderActivity() {
  activity.replaceChildren();
  if (!commands.size)
    activity.append(el("li", "No command activity observed yet."));
  for (const c of [...commands.values()].reverse())
    activity.append(
      el(
        "li",
        `${c.process} / ${c.instance} · ${c.action} · ${c.state} · ${c.request_id}${c.channel_id ? " · channel " + c.channel_id : ""}${c.error ? " · " + c.error : ""}${c.result ? " · " + JSON.stringify(c.result) : ""}`,
      ),
    );
}
const stream = new EventSource("/v1/events");
stream.addEventListener("reset", (e) => {
  processes = JSON.parse(e.data).processes;
  live = true;
  reconcileOperations();
  renderActivity();
  render();
});
stream.addEventListener("snapshot", (e) => {
  const u = JSON.parse(e.data);
  const before = processes[u.process];
  const previous = processes[u.process]?.generation;
  if (previous && previous !== u.state.generation) {
    for (const [key, c] of commands)
      if (c.process === u.process && c.generation !== u.state.generation)
        commands.delete(key);
    renderActivity();
  }
  processes[u.process] = u.state;
  live = true;
  render();
  pulseChanges(u.process, before, u.state);
});
stream.addEventListener("operation_updated", (e) => {
  const u = JSON.parse(e.data),
    c = u.event.data;
  if (
    ![
      "set_enabled",
      "set_automatic_provisioning",
      "provision_channel",
      "set_controls",
      "close_channel",
      "request_channel_unlink",
    ].includes(c.action)
  )
    return;
   observeOperation({
    ...c,
    process: u.process,
    generation: u.generation,
  });
});
stream.addEventListener("source_gap", () => {
  reconcileOperations();
  notice.textContent =
    "Some activity was missed; snapshots still restore current state.";
});
stream.addEventListener("session_payment_failed", (e) => {
  const update = JSON.parse(e.data);
  notice.textContent = `${update.process} / ${update.instance}: ${update.event.data.message}`;
});
stream.onerror = () => {
  live = false;
  render();
};
setInterval(() => {
  document.querySelector("#connection").textContent = live
    ? "● Connected"
    : "Reconnecting…";
  render();
}, 1000);
