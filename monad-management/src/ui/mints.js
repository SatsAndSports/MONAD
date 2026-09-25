"use strict";
const mints = document.querySelector("#mints");
const notice = document.querySelector("#notice");
const connection = document.querySelector("#connection");
const activity = document.querySelector("#activity");
let processes = {};
let live = false;
const cards = new Map();
const commands = new Map();
const pending = new Set();
const generations = new Map();
function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}
function usable(state) {
  return live && state.online && Date.now() - state.last_success_unix_ms < 6000;
}
function renderActivity() {
  activity.replaceChildren();
  if (!commands.size) {
    activity.append(element("li", "No command activity observed yet."));
    return;
  }
  for (const command of [...commands.values()].reverse()) {
    const item = element("li", `${command.instance} · ${command.state === "queued" ? "accepted" : command.state}`);
    item.append(element("small", `${command.process} · ${command.request_id}`));
    if (command.result) item.append(element("small", `${command.result.unit?.toUpperCase()} · fee ${command.result.input_fee_ppk} ppk · ${command.result.active_keyset_id}`));
    if (command.error) item.append(element("p", command.error));
    activity.append(item);
  }
}
function render() {
  const retained = new Set();
  for (const [process, state] of Object.entries(processes)) {
    if (state.data?.kind !== "test_mints") continue;
    for (const [name, mint] of Object.entries(state.data.instances)) {
      const key = JSON.stringify([process, name]);
      retained.add(key);
      let card = cards.get(key);
      const signature = JSON.stringify([state.generation, [...mint.keysets].sort((a,b) => a.id.localeCompare(b.id))]);
      if (!card || card.dataset.signature !== signature) {
        const replacement = element("article", undefined, "mint");
        replacement.dataset.signature = signature;
        replacement.dataset.mint = name;
        const head = element("div", undefined, "mint-head");
        const title = element("div");
        title.append(element("h2", name), element("p", `${process} · ${mint.base_url}`));
        head.append(title, element("span", "", "badge"));
        replacement.append(head);
        const units = element("div", undefined, "units");
        for (const unit of ["sat", "msat"]) {
          const keysets = mint.keysets.filter(k => k.unit === unit);
          if (!keysets.length) continue;
          const section = element("section", undefined, "unit");
          section.dataset.unit = unit;
          section.append(element("h3", unit.toUpperCase()));
          const table = element("table");
          const tr = element("tr");
          for (const label of ["Keyset ID", "Status", "Fee (ppk)"]) tr.append(element("th", label));
          const thead = element("thead"); thead.append(tr); table.append(thead);
          const tbody = element("tbody");
          keysets.sort((a,b) => Number(b.active)-Number(a.active) || a.id.localeCompare(b.id));
          for (const k of keysets) {
            const row = element("tr");
            const id = element("td"); id.append(element("code", k.id));
            if (k.final_expiry != null) id.append(element("p", `Expiry: ${new Date(k.final_expiry * 1000).toLocaleString()}`));
            row.append(id, element("td", k.active ? "Active" : "Inactive"), element("td", String(k.input_fee_ppk)));
            tbody.append(row);
          }
          table.append(tbody); section.append(table);
          const form = element("form");
          const label = element("label", "New input fee (ppk)");
          const input = element("input");
          input.type = "number"; input.min = "0"; input.max = "999"; input.step = "1"; input.required = true;
          input.value = String(keysets.find(k => k.active)?.input_fee_ppk ?? 0);
          label.append(input);
          const button = element("button", `Rotate ${unit.toUpperCase()}`);
          form.append(label, button);
          const generation = state.generation;
          form.addEventListener("submit", async event => {
            event.preventDefault();
            if (!usable(processes[process]) || processes[process].generation !== generation || pending.has(key)) return;
            const fee = Number(input.value);
            if (!Number.isInteger(fee) || fee < 0 || fee > 999) return;
            const requestId = globalThis.crypto?.randomUUID?.()
              || `rotation-${Date.now()}-${Math.random().toString(16).slice(2)}`;
            const request = {generation, request_id: requestId, instance: name,
              action: "rotate_keyset", arguments: {unit, input_fee_ppk: fee}};
            pending.add(key); render();
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 10000);
            try {
              const response = await fetch(`/v1/processes/${encodeURIComponent(process)}/commands`, {
                method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(request),
                signal: controller.signal,
              });
              const body = await response.json();
              if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
              notice.textContent = `Rotation accepted for ${name} / ${unit.toUpperCase()}. Request ${request.request_id}.`;
            } catch (error) {
              notice.textContent = `Submission could not be confirmed: ${error.message}. Request ${request.request_id}. Inspect keysets and live activity before issuing another rotation. Refresh never retries a command.`;
            } finally { clearTimeout(timeout); pending.delete(key); render(); }
          });
          section.append(form); units.append(section);
        }
        replacement.append(units);
        if (card) card.replaceWith(replacement); else mints.append(replacement);
        card = replacement; cards.set(key, card);
      }
      const badge = card.querySelector(".badge");
      const online = usable(state);
      badge.textContent = online ? "● Live" : `● Stale / unavailable · last sample ${new Date(state.last_success_unix_ms).toLocaleTimeString()}`;
      badge.classList.toggle("offline", !online);
      card.querySelectorAll("button").forEach(button => { button.disabled = !online || pending.has(key); });
    }
  }
  for (const [key, card] of cards) if (!retained.has(key)) {card.remove(); cards.delete(key);}
  for (const child of [...mints.children]) if (!child.matches("article")) child.remove();
  if (!cards.size) mints.append(element("p", "No managed test mints are available yet. Start monad-test-mint with the configured management socket."));
}
const stream = new EventSource("/v1/events");
stream.addEventListener("reset", event => {
  processes = JSON.parse(event.data).processes;
  commands.clear(); generations.clear();
  for (const [process, state] of Object.entries(processes)) generations.set(process, state.generation);
  renderActivity();
  live = true; connection.textContent = "● Connected"; render();
});
stream.addEventListener("snapshot", event => {
  const update = JSON.parse(event.data);
  const previous = generations.get(update.process);
  if (previous && update.state.generation && previous !== update.state.generation) {
    for (const [key, command] of commands) if (command.process === update.process) commands.delete(key);
    renderActivity();
  }
  if (update.state.generation) generations.set(update.process, update.state.generation);
  processes[update.process] = update.state;
  live = true; connection.textContent = "● Connected"; render();
});
stream.addEventListener("operation_updated", event => {
  const update = JSON.parse(event.data);
  const op = update.event.data;
  if (op.action !== "rotate_keyset") return;
  const key = JSON.stringify([update.process, update.generation, op.request_id]);
  commands.set(key, {process: update.process, ...op});
  while (commands.size > 100) commands.delete(commands.keys().next().value);
  renderActivity();
});
stream.addEventListener("source_gap", () => {notice.textContent = "Some activity events were missed. Keysets continue to follow current snapshots.";});
stream.onerror = () => {live = false; connection.textContent = "Reconnecting…"; render();};
setInterval(render, 1000);
