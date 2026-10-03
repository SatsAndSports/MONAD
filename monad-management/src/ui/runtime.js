"use strict";
const PAGES = {
  "/clients": ["clients", "Clients", "Clients & routes"],
  "/relays": ["relays", "Relays", "Relays & sessions"],
  "/traffic-servers": ["traffic_servers", "Traffic servers", "Traffic servers"],
};
const [kind, pageName, pageHeading] =
  PAGES[location.pathname] || PAGES["/relays"];
document.title = `${pageName} · MONAD`;
document.querySelector("#title").textContent = pageHeading;
document
  .querySelector(`nav a[href="${location.pathname}"]`)
  .setAttribute("aria-current", "page");
const root = document.querySelector("#instances"),
  summaryRoot = document.querySelector("#wallet-summary"),
  notice = document.querySelector("#notice"),
  activity = document.querySelector("#activity"),
  drainSelectionWarning = document.querySelector("#drain-selection-warning"),
  drainSelectionWarningMessage = document.querySelector("#drain-selection-warning-message"),
  clearDrainSelection = document.querySelector("#clear-drain-selection");
let processes = {},
  live = false;
const pending = new Map(),
  commands = new Map(),
  cards = new Map(),
  summaryCards = new Map(),
  drainSelections = new Map();
const MAX_DRAIN_CHANNELS = 1024;
function clearSelectedDrainChannels() {
  for (const selected of drainSelections.values()) selected.clear();
}
clearDrainSelection.onclick = () => {
  clearSelectedDrainChannels();
  drainSelectionWarning.close();
  render();
};
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
  if (old instanceof HTMLInputElement) {
    old.checked = next.checked;
    old.disabled = next.disabled;
    old.onchange = next.onchange;
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
    instancePending(process, name, action, args) ||
    !enabled;
  const generation = processes[process].generation;
  b.onclick = () => submit(process, name, generation, action, args);
  return b;
}
function instancePending(process, instance, action, args) {
  const disabling = (action === "set_enabled" ||
    (action === "set_control" && args.field === "enabled")) && args.enabled === false;
  return [...pending.values()].some(c => c.process === process && c.instance === instance &&
    c.generation === processes[process]?.generation &&
    (!disabling || c.action === "set_enabled" || c.action === "set_control"));
}
const operationKey = c => JSON.stringify([c.process, c.generation, c.request_id]);
async function submit(process, name, generation, action, args) {
  if (
    !healthy(processes[process]) ||
    processes[process].generation !== generation ||
    instancePending(process, name, action, args)
  )
    return;
  const request_id = crypto.randomUUID();
  const controller = new AbortController(),
    timer = setTimeout(() => controller.abort(), 10000);
  const tracked = {process, instance:name, generation, request_id, action,
    channel_id:args.channel_id, drain_id:args.drain_id,
    channel_count:args.channel_ids?.length, state:"submitting"};
  const key = operationKey(tracked);
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
    if ([400, 409, 413, 429].includes(response.status) ||
        (response.status === 503 && result.code === "command_not_admitted")) {
      observeOperation({...tracked, state:"failed", error:result.error || `HTTP ${response.status}`});
      return;
    }
    if (!response.ok) throw Error(result.error || `HTTP ${response.status}`);
    observeOperation({...result.request, ...result, process, generation, request_id,
      instance:name, action, channel_id:args.channel_id, drain_id:args.drain_id,
      channel_count:args.channel_ids?.length});
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
  const id = operationKey(c);
  const previous = commands.get(id);
  if (["succeeded", "failed"].includes(previous?.state)) return;
  const key = id;
  const local = pending.get(key);
  c = {...previous, ...c,
    channel_id:c.channel_id || previous?.channel_id || (local?.request_id === c.request_id ? local.channel_id : undefined),
    drain_id:c.drain_id || c.result?.drain_id || previous?.drain_id || (local?.request_id === c.request_id ? local.drain_id : undefined),
    channel_count:c.channel_count || c.result?.channel_ids?.length || previous?.channel_count || (local?.request_id === c.request_id ? local.channel_count : undefined)};
  commands.set(id, c);
  const terminal = ["succeeded", "failed"].includes(c.state);
  if (terminal) {
    if (local?.request_id === c.request_id) pending.delete(key);
  } else if (!local || local.request_id === c.request_id) pending.set(key, c);
  notice.textContent = `${c.instance}: ${c.action}${c.channel_id ? " · channel " + c.channel_id : ""}${c.drain_id ? " · drain " + c.drain_id : ""}${c.channel_count ? " · " + c.channel_count + " channels" : ""} · ${c.state} (${c.request_id})${c.error ? ": " + c.error : ""}${c.action === "request_channel_unlink" && c.state === "succeeded" ? " — check channel ownership for release completion" : ""}`;
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
        pending.delete(operationKey(c));
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
          "set_control",
          { field, enabled: !c[field] },
          !instance.disabling,
        ),
      );
    }
  }
  return box;
}
const TRAFFIC_RATES = [
  1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576,
  2097152, 4194304, 8388608, 16777216, 33554432, 67108864, 134217728, 268435456,
  536870912, 1073741824,
];
const TRAFFIC_RATIOS = [
  [1, 100], [1, 50], [1, 20], [1, 10], [1, 5], [1, 2], [1, 1], [2, 1], [5, 1],
  [10, 1], [20, 1], [50, 1], [100, 1],
];
// Form state survives re-renders; keyed by process + client name. Snapshot
// values only seed the initial form.
const trafficForms = new Map();
function binaryUnits(v, suffix) {
  const units = ["", "Ki", "Mi", "Gi", "Ti"];
  let n = Number(v) || 0,
    i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  const rounded =
    n >= 100 || Number.isInteger(n) ? String(Math.round(n)) : n.toFixed(1);
  return `${rounded} ${units[i]}${suffix}`;
}
const fmtMs = (v) =>
  v == null ? "—" : `${v < 10 ? v.toFixed(2) : v.toFixed(1)} ms`;
function trafficServerUrls() {
  const urls = [];
  for (const state of Object.values(processes))
    if (state.data?.kind === "traffic_servers")
      for (const instance of Object.values(state.data.instances || {}))
        if (instance.base_url) urls.push(instance.base_url);
  return urls.sort();
}
function trafficRateIndex(rate) {
  let best = 0;
  TRAFFIC_RATES.forEach((r, i) => {
    if (
      Math.abs(Math.log2(r / rate)) <
      Math.abs(Math.log2(TRAFFIC_RATES[best] / rate))
    )
      best = i;
  });
  return best;
}
function trafficForm(process, name, t) {
  const key = `${process}\n${name}`;
  let form = trafficForms.get(key);
  if (!form) {
    const valid = new Set(TRAFFIC_RATIOS.map(([u, d]) => `${u}:${d}`));
    const snapRatio = `${t?.upload_ratio}:${t?.download_ratio}`;
    form = {
      url: t?.server_url || trafficServerUrls()[0] || "",
      rateIndex:
        t?.total_rate_bytes_per_second > 0
          ? trafficRateIndex(t.total_rate_bytes_per_second)
          : trafficRateIndex(1048576),
      ratio: valid.has(snapRatio) ? snapRatio : "1:1",
    };
    trafficForms.set(key, form);
  }
  return form;
}
// Like button(), but arguments are built lazily at click time from the latest
// snapshot so expected_run_id is never stale from a re-render race.
function trafficButton(text, process, name, action, argsFor, enabled = true) {
  const b = el("button", text);
  b.type = "button";
  b.disabled =
    !healthy(processes[process]) ||
    instancePending(process, name, action, {}) ||
    !enabled;
  b.onclick = () => {
    const state = processes[process];
    const args = argsFor(state?.data?.instances?.[name]?.traffic_test);
    if (state?.generation && args)
      submit(process, name, state.generation, action, args);
  };
  return b;
}
function trafficPanel(process, name, instance) {
  const t = instance.traffic_test || {};
  const form = trafficForm(process, name, t);
  const panel = el("section", null, "traffic-panel");
  panel.append(el("h3", "Speed test"));
  const stateName = t.state || "stopped";
  const status = el("p", null, "traffic-status");
  status.append(
    el(
      "strong",
      stateName[0].toUpperCase() + stateName.slice(1),
      `traffic-state-${stateName}`,
    ),
    ` · run ${t.run_id ?? 0}`,
  );
  if (t.started_at_unix_ms)
    status.append(
      ` · started ${new Date(t.started_at_unix_ms).toLocaleTimeString()}`,
    );
  panel.append(status);
  const metrics = el("div", null, "traffic-metrics");
  const metric = (label, text) => {
    const box = el("div");
    box.append(el("small", label), el("div", text, "traffic-metric-value"));
    return box;
  };
  metrics.append(
    metric(
      "Uploaded",
      `${binaryUnits(t.uploaded_bytes, "B")} · ${binaryUnits(t.upload_rate_bytes_per_second, "B/s")}`,
    ),
    metric(
      "Downloaded",
      `${binaryUnits(t.downloaded_bytes, "B")} · ${binaryUnits(t.download_rate_bytes_per_second, "B/s")}`,
    ),
    metric(
      "Latency latest / median / p95",
      `${fmtMs(t.latency?.latest_ms)} / ${fmtMs(t.latency?.median_ms)} / ${fmtMs(t.latency?.p95_ms)}`,
    ),
    metric("Probes", `${t.latency?.samples ?? 0}`),
    metric(
      "Failures",
      `${t.failures ?? 0}${t.latency_failures ? ` (${t.latency_failures} latency)` : ""}`,
    ),
  );
  panel.append(metrics);
  if (t.last_error)
    panel.append(el("p", `Latest error: ${t.last_error}`, "traffic-error"));
  const formRow = el("div", null, "traffic-form");
  const listId = `traffic-urls-${`${process}-${name}`.replace(/[^a-zA-Z0-9_-]/g, "_")}`;
  const urlInput = el("input");
  urlInput.type = "text";
  urlInput.setAttribute("list", listId);
  urlInput.placeholder = "http://host:port";
  urlInput.spellcheck = false;
  urlInput.value = form.url;
  urlInput.oninput = (e) => {
    form.url = e.currentTarget.value.trim();
  };
  const urlLabel = el("label");
  urlLabel.append(el("span", "Server URL"), urlInput);
  const urlList = el("datalist");
  urlList.id = listId;
  for (const u of trafficServerUrls()) {
    const option = el("option");
    option.value = u;
    urlList.append(option);
  }
  const rateInput = el("input");
  rateInput.type = "range";
  rateInput.min = 0;
  rateInput.max = TRAFFIC_RATES.length - 1;
  rateInput.step = 1;
  rateInput.value = form.rateIndex;
  rateInput.oninput = (e) => {
    form.rateIndex = Number(e.currentTarget.value);
    render();
  };
  const rateLabel = el("label");
  rateLabel.append(
    el("span", "Rate (up + down)"),
    rateInput,
    el(
      "span",
      binaryUnits(TRAFFIC_RATES[form.rateIndex], "B/s"),
      "traffic-rate-value",
    ),
  );
  const ratioSelect = el("select");
  for (const [u, d] of TRAFFIC_RATIOS) {
    const option = el("option", `${u}:${d}`);
    option.value = `${u}:${d}`;
    if (form.ratio === option.value) option.selected = true;
    ratioSelect.append(option);
  }
  ratioSelect.onchange = (e) => {
    form.ratio = e.currentTarget.value;
  };
  const ratioLabel = el("label");
  ratioLabel.append(el("span", "Upload : download"), ratioSelect);
  const running = stateName !== "stopped";
  const clientEnabled = instance.controls?.enabled === true;
  const start = trafficButton(
    running ? "Restart with these settings" : "Start test",
    process,
    name,
    "start_traffic_test",
    (current) => {
      // Built at click time: renders only happen once per second and must not
      // capture stale form values.
      const [u, d] = form.ratio.split(":").map(Number);
      return {
        expected_run_id: current?.run_id ?? 0,
        server_url: form.url,
        total_rate_bytes_per_second: TRAFFIC_RATES[form.rateIndex],
        upload_ratio: u,
        download_ratio: d,
      };
    },
    clientEnabled && form.url.trim().length > 0,
  );
  if (!clientEnabled) start.title = "Enable the client to run a speed test";
  else if (!form.url.trim()) start.title = "Enter a traffic server URL";
  const stop = trafficButton(
    "Stop test",
    process,
    name,
    "stop_traffic_test",
    (current) => (current ? { expected_run_id: current.run_id } : null),
    running,
  );
  formRow.append(urlLabel, rateLabel, ratioLabel, start, stop);
  panel.append(formRow, urlList);
  return panel;
}
function trafficServerCard(process, name, state, instance) {
  const card = el("article", null, "mint");
  card.dataset.instance = name;
  card.append(
    el("h2", name),
    el(
      "p",
      `${process} · ${healthy(state) ? "Live" : "Stale / unavailable"} · sampled ${new Date(state.last_success_unix_ms).toLocaleTimeString()}`,
    ),
  );
  const endpoint = el("p");
  endpoint.append("Endpoint ", el("code", instance.base_url || "unavailable"));
  card.append(
    el("h3", "Ratio stream server"),
    endpoint,
    table(
      ["Connections active / total", "Uploaded", "Downloaded"],
      [
        [
          `${instance.active_connections ?? 0} / ${instance.total_connections ?? 0}`,
          binaryUnits(instance.uploaded_bytes, "B"),
          binaryUnits(instance.downloaded_bytes, "B"),
        ],
      ],
    ),
  );
  return card;
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
  if (c.drain?.state === "reserved")
    box.append(el("strong", ` · Drain ${c.drain.drain_id?.slice(0, 12) || "reserved"}`, "drain-reserved"));
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
      ? button(String(c.state).toLowerCase()==="closing" ? "Resume close" : "Close channel",
          process,c.relay_name,"close_channel",{channel_id:c.channel_id},
          ["open", "closing"].includes(String(c.state).toLowerCase()))
      : el("span", "Ownership unavailable")
  ])));
  if(!entries.length) section.append(el("p","No unlinked channels."));
  return section;
}
function drainGroupKey(process, state, channel) {
  return JSON.stringify([process, state.generation, channel.relay_name, channel.mint_url, channel.unit]);
}
function relayDrains() {
  const section = el("section", null, "mint");
  section.id = "relay-drains";
  section.append(
    el("h2", "Channel drains"),
    el("p", "Select eligible Closed channels from one relay, mint, and unit. Every selection is revalidated atomically before mint submission."),
  );
  const groups = new Map(), attempts = [];
  for (const [process, state] of Object.entries(processes)) {
    if (state.data?.kind !== "relays") continue;
    for (const channel of state.data.wallet?.channels || []) {
      if (channel.drain?.state !== "eligible") continue;
      const key = drainGroupKey(process, state, channel);
      if (!groups.has(key)) groups.set(key, {key, process, state, channels:[]});
      groups.get(key).channels.push(channel);
    }
    for (const drain of state.data.wallet?.drains || []) attempts.push({process, state, drain});
  }
  for (const key of [...drainSelections.keys()]) {
    const group = groups.get(key);
    if (!group) {
      drainSelections.delete(key);
      continue;
    }
    const eligible = new Set(group.channels.map(channel => channel.channel_id));
    const selected = drainSelections.get(key);
    for (const id of [...selected]) if (!eligible.has(id)) selected.delete(id);
  }
  const selectedGroups = [...drainSelections.entries()].filter(([, selected]) => selected.size);
  const [activeEntry, ...conflictingEntries] = selectedGroups;
  for (const [, selected] of conflictingEntries) selected.clear();
  const activeKey = activeEntry?.[0], activeGroup = groups.get(activeKey),
    activeSelection = activeEntry?.[1] || new Set();
  const groupLabel = group => {
    const channel = group.channels[0];
    return `${channel.relay_name} · ${channel.mint_url} · ${channel.unit}`;
  };
  const toolbar = el("div", null, "drain-toolbar");
  toolbar.append(el(
    "p",
    activeGroup
      ? `${activeSelection.size} selected · Active group: ${groupLabel(activeGroup)}`
      : "0 selected · Choose channels from one relay, mint, and unit",
    "drain-selection-summary",
  ));
  const drainButton = activeGroup
    ? button(
        `Drain selected (${activeSelection.size})`,
        activeGroup.process,
        activeGroup.channels[0].relay_name,
        "drain_channels",
        {channel_ids:[...activeSelection].sort()},
        activeSelection.size > 0 && activeSelection.size <= MAX_DRAIN_CHANNELS,
      )
    : el("button", "Drain selected (0)");
  drainButton.type = "button";
  if (!activeGroup) drainButton.disabled = true;
  const clearButton = el("button", "Clear selection");
  clearButton.type = "button";
  clearButton.disabled = !activeGroup;
  clearButton.onclick = () => {
    clearSelectedDrainChannels();
    render();
  };
  toolbar.append(drainButton, clearButton);
  section.append(toolbar);
  for (const group of groups.values()) {
    group.channels.sort((a,b)=>a.channel_id.localeCompare(b.channel_id));
    const first = group.channels[0], selected = drainSelections.get(group.key) || new Set();
    drainSelections.set(group.key, selected);
    const heading = el("h3", `${first.relay_name} · ${first.mint_url} · ${first.unit}`);
    const rows = group.channels.map(channel => {
      const checkbox = el("input");
      checkbox.type = "checkbox";
      checkbox.checked = selected.has(channel.channel_id);
      checkbox.disabled = !healthy(group.state) ||
        (!checkbox.checked && group.key === activeKey && activeSelection.size >= MAX_DRAIN_CHANNELS) ||
        instancePending(group.process, channel.relay_name, "drain_channels", {});
      checkbox.setAttribute("aria-label", `Select channel ${channel.channel_id}`);
      checkbox.onchange = event => {
        if (event.currentTarget.checked) {
          if (activeGroup && activeKey !== group.key) {
            event.currentTarget.checked = false;
            drainSelectionWarningMessage.textContent =
              `A drain must contain channels from the same relay, mint, and unit. ` +
              `Your current selection is for ${groupLabel(activeGroup)}. ` +
              `Clear the current selection before selecting channels from ${groupLabel(group)}.`;
            if (typeof drainSelectionWarning.showModal === "function")
              drainSelectionWarning.showModal();
            else notice.textContent = drainSelectionWarningMessage.textContent;
            return;
          }
          if (selected.size >= MAX_DRAIN_CHANNELS) return;
          selected.add(channel.channel_id);
        } else selected.delete(channel.channel_id);
        render();
      };
      return [checkbox, shortId(channel.channel_id), channelAmount(channel.balance_raw, channel.unit), channelAmount(channel.capacity_raw, channel.unit)];
    });
    const groupSection = el("section", null, group.key === activeKey ? "drain-group-active" : "");
    groupSection.append(heading, table(["Select", "Channel", `Paid (${first.unit})`, `Capacity (${first.unit})`], rows));
    section.append(groupSection);
  }
  if (!groups.size) section.append(el("p", "No eligible Closed channels."));
  section.append(el("h3", "Drain attempts"));
  attempts.sort((a,b)=>a.process.localeCompare(b.process) || a.drain.drain_id.localeCompare(b.drain.drain_id));
  section.append(table(
    ["Relay / process", "Drain", "State", "Mint / unit", "Input / output", "Channels", "Action"],
    attempts.map(({process,state,drain})=>[
      `${drain.relay_name} / ${process}${healthy(state) ? "" : " · Stale / unavailable"}`,
      shortId(drain.drain_id),
      drain.state,
      `${drain.mint_url} / ${drain.unit}`,
      `${wholeNumber(drain.input_amount_raw)} / ${wholeNumber(drain.output_amount_raw)}`,
      drain.channel_ids?.length ?? "unavailable",
      ["Prepared","Submitted","Finalizing"].includes(drain.state)
        ? button("Resume drain", process, drain.relay_name, "recover_drain", {drain_id:drain.drain_id})
        : el("span", "Completed"),
    ]),
  ));
  if (!attempts.length) section.append(el("p", "No drain attempts."));
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
  if (kind === "traffic_servers")
    return trafficServerCard(process, name, state, instance);
  const card = el("article", null, "mint");
  card.dataset.instance = name;
  const heading =
    kind === "clients" && instance.socks_listen
      ? `${name} · SOCKS ${instance.socks_listen}`
      : name;
  card.append(
    el("h2", heading),
    el(
      "p",
      `${process} · ${healthy(state) ? "Live" : "Stale / unavailable"} · sampled ${new Date(state.last_success_unix_ms).toLocaleTimeString()}`,
    ),
  );
  card.append(controls(process, name, instance));
  if (kind === "clients") {
    card.append(trafficPanel(process, name, instance));
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
function wholeNumber(value) {
  if (value == null || value === "") return "unavailable";
  try {
    return BigInt(value).toLocaleString("en-US");
  } catch {
    return "unavailable";
  }
}
function summarizedAmount(summary, category, unit) {
  return wholeNumber(summary?.[category]?.[unit]?.amount_raw);
}
function summarizedCount(summary, state) {
  return wholeNumber(summary?.channel_state_counts?.[state]);
}
function walletSummary(process, state) {
  const card = el("section", null, "mint wallet-summary-card");
  card.dataset.walletProcess = process;
  card.append(el("h2", `${process} · wallet summary`));
  card.append(el("p", `${healthy(state) ? "Live" : "Stale / unavailable"} · Last successful sample: ${
    state.last_success_unix_ms != null
      ? new Date(state.last_success_unix_ms).toLocaleString()
      : "unavailable"
  }`));
  const summary = state.data.wallet?.summary;
  if (!summary) {
    card.append(el("p", "Wallet summary unavailable."));
    return card;
  }
  const proofs = el("p");
  proofs.dataset.walletCategory = "proofs";
  const proofLabel = kind === "clients" ? "Available loose proofs" : "Drained proofs";
  proofs.append(
    el("strong", proofLabel),
    ` · ${summarizedAmount(summary, kind === "clients" ? "available_loose_proofs" : "drained_proofs", "sat")} sat`,
    ` · ${summarizedAmount(summary, kind === "clients" ? "available_loose_proofs" : "drained_proofs", "msat")} msat`,
  );
  const channels = el("p");
  channels.dataset.walletCategory = "channels";
  channels.append(
    el("strong", "Channels"),
    ` · Open ${summarizedCount(summary, "open")}`,
    ` · Closing ${summarizedCount(summary, "closing")}`,
    ` · Closed ${summarizedCount(summary, "closed")}`,
  );
  if (kind === "relays")
    channels.append(
      ` · Refunded after expiry ${summarizedCount(summary, "sender_refunded_after_expiry")}`,
    );
  card.append(proofs, channels);
  return card;
}
function renderWalletSummaries() {
  if (kind === "traffic_servers") return;
  const seen = new Set();
  for (const [process, state] of Object.entries(processes)) {
    if (state.data?.kind !== kind) continue;
    seen.add(process);
    const next = walletSummary(process, state);
    const old = summaryCards.get(process);
    if (old) summaryCards.set(process, update(old, next));
    else {
      summaryRoot.append(next);
      summaryCards.set(process, next);
    }
  }
  for (const [process, card] of summaryCards)
    if (!seen.has(process)) {
      card.remove();
      summaryCards.delete(process);
    }
}
function render() {
  renderWalletSummaries();
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
    if (kind === "traffic_servers") continue;
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
      if (Array.isArray(walletData?.available_proofs) && !walletData.available_proofs.length)
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
    const drainKey = "drains"; seen.add(drainKey);
    const drains = relayDrains(), oldDrains = cards.get(drainKey);
    if(oldDrains) cards.set(drainKey,update(oldDrains,drains)); else {root.append(drains); cards.set(drainKey,drains);}
    const order = [];
    for(const [process,state] of Object.entries(processes)) {
      if(state.data?.kind!=="relays") continue;
      for(const name of Object.keys(state.data.instances)) order.push(cards.get(JSON.stringify(["instance",process,name])));
    }
    order.push(cards.get(key), cards.get(drainKey));
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
        kind === "traffic_servers"
          ? "No traffic server process is available yet. Start monad-test-traffic."
          : `No ${kind} process is available yet. Start the configured runtime.`,
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
        `${c.process} / ${c.instance} · ${c.action} · ${c.state} · ${c.request_id}${c.channel_id ? " · channel " + c.channel_id : ""}${c.drain_id ? " · drain " + c.drain_id : ""}${c.channel_count ? " · " + c.channel_count + " channels" : ""}${c.error ? " · " + c.error : ""}${c.result ? " · " + JSON.stringify(c.result) : ""}`,
      ),
    );
}
function discardStaleOperations() {
  for (const collection of [commands, pending]) {
    for (const [key, command] of collection) {
      const generation = processes[command.process]?.generation;
      if (generation && generation !== command.generation)
        collection.delete(key);
    }
  }
}
const stream = new EventSource("/v1/events");
stream.addEventListener("reset", (e) => {
  processes = JSON.parse(e.data).processes;
  discardStaleOperations();
  live = true;
  reconcileOperations();
  renderActivity();
  render();
});
stream.addEventListener("snapshot", (e) => {
  const u = JSON.parse(e.data);
  const before = processes[u.process];
  const previous = processes[u.process]?.generation;
  if (previous !== u.state.generation) {
    processes[u.process] = u.state;
    discardStaleOperations();
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
      "set_control",
      "close_channel",
      "request_channel_unlink",
      "drain_channels",
      "recover_drain",
      "start_traffic_test",
      "stop_traffic_test",
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
