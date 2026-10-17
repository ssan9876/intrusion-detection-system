/* Signature NIDS dashboard — a packet-analyzer style workbench.
   This module owns live state (WebSocket + REST), the toolbar, view tabs,
   display-filter bar and status bar; each view lives in js/views/. */
import {
  $, api, esc, fmtAgo, fmtBytes, fmtDuration, fmtNum, store, SEV_RANK, SEVERITIES,
} from "./js/util.js";
import { compile, suggest } from "./js/filter.js";
import { closeMenu, confirmDialog, contextMenu, toast } from "./js/ui.js";
import alertsView from "./js/views/alerts.js";
import packetsView from "./js/views/packets.js";
import endpointsView from "./js/views/endpoints.js";
import conversationsView from "./js/views/conversations.js";
import signaturesView from "./js/views/signatures.js";
import iographView from "./js/views/iograph.js";
import reportsView from "./js/views/reports.js";

const ALERT_CAP = 2000;

// ---------- state + events ----------
const bus = new EventTarget();
const state = {
  status: null,
  snapshot: null,
  alerts: [],              // newest first, list fields only (no payload)
  alertsLoaded: false,
  paused: false,
  pendingWhilePaused: 0,
  connected: false,
  view: store("view") || "alerts",
  filters: store("filters") || {},
};

const app = {
  state,
  on: (type, fn) => bus.addEventListener(type, (e) => fn(e.detail)),
  emit: (type, detail) => bus.dispatchEvent(new CustomEvent(type, { detail })),
  toast, confirmDialog, contextMenu,
  show: (id) => showView(id),
  setFilter: (viewId, text, { apply = true } = {}) => setFilter(viewId, text, apply),
  get currentView() { return views[state.view]; },
  updateAlerts(ids, status) {
    const set = new Set(ids);
    for (const a of state.alerts) if (set.has(a.id)) { a.status = status; a.status_ts = Date.now() / 1000; }
    app.emit("alerts", { reason: "status", ids });
  },
  async setAlertStatus(ids, status) {
    if (!ids.length) return;
    try {
      const r = await api("/api/alerts/status", { method: "POST", body: { ids, status } });
      app.updateAlerts(ids, status);
      if (state.snapshot) state.snapshot.totals.untriaged = r.untriaged;
      renderChrome();
      return r;
    } catch (e) {
      toast({ title: "Couldn't update the alert", body: e.message });
      return null;
    }
  },
  async setRuleState(ruleId, body) {
    try {
      const r = await api(`/api/rules/${encodeURIComponent(ruleId)}/state`, { method: "POST", body });
      app.emit("rules-changed", { ruleId });
      loadStatus();
      return r;
    } catch (e) {
      toast({ title: "Couldn't change the signature", body: e.message });
      return null;
    }
  },
  setStatusMessage,
};

const views = Object.fromEntries([
  alertsView, packetsView, endpointsView, conversationsView, signaturesView, iographView, reportsView,
].map((v) => [v.id, v]));
const order = ["alerts", "packets", "endpoints", "conversations", "signatures", "iograph", "reports"];

// ---------- data ----------
async function loadStatus() {
  try {
    state.status = await api("/api/status");
    renderChrome();
  } catch { /* retried on the next tick */ }
}

async function loadAlerts() {
  try {
    state.alerts = await api(`/api/alerts?limit=${ALERT_CAP / 2}`);
    state.alertsLoaded = true;
    app.emit("alerts", { reason: "load" });
    renderChrome();
  } catch (e) {
    setStatusMessage("Couldn't load alerts: " + e.message, true);
  }
}

function addAlert(a) {
  if (state.alerts.length && state.alerts[0].id === a.id) return;
  state.alerts.unshift(a);
  if (state.alerts.length > ALERT_CAP) state.alerts.length = ALERT_CAP;
  if (state.paused) state.pendingWhilePaused++;
  app.emit("alert", a);
  if (a.status === "new" && (a.severity === "critical" || a.severity === "high")) {
    toast({
      sev: a.severity, title: a.rule_name,
      body: `${a.src} → ${a.dst}${a.dport ? ":" + a.dport : ""}`,
      onClick: () => { showView("alerts"); views.alerts.selectAlert(a.id); },
    });
  }
}

function connect() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws`);
  ws.onopen = () => {
    state.connected = true;
    loadStatus();
    if (state.alertsLoaded) loadAlerts(); // catch up on anything missed while disconnected
    renderChrome();
  };
  ws.onclose = () => { state.connected = false; renderChrome(); setTimeout(connect, 1500); };
  ws.onerror = () => ws.close();
  ws.onmessage = (ev) => {
    let msg; try { msg = JSON.parse(ev.data); } catch { return; }
    if (msg.type === "snapshot") {
      state.snapshot = msg.data;
      renderChrome();
      if (!state.paused) app.emit("snapshot", msg.data);
    } else if (msg.type === "alert") {
      addAlert(msg.alert);
    } else if (msg.type === "alert_status") {
      if (state.snapshot) state.snapshot.totals.untriaged = msg.untriaged;
      app.updateAlerts(msg.ids, msg.status);
      renderChrome();
    } else if (msg.type === "rollover") {
      toast({ title: "Day archived", body: `Saved ${msg.file}; live stats reset.` });
      app.emit("rollover", msg);
    } else if (msg.type === "rules") {
      loadStatus();
      app.emit("rules-changed", {});
    }
  };
}

// ---------- chrome: toolbar state, overview, status bar ----------
function worstUntriaged() {
  let worst = 0;
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  let oldest = null;
  for (const a of state.alerts) {
    if (a.status !== "new") continue;
    counts[a.severity] = (counts[a.severity] || 0) + 1;
    worst = Math.max(worst, SEV_RANK[a.severity] || 0);
    if (oldest == null || a.ts < oldest) oldest = a.ts;
  }
  const sev = Object.keys(SEV_RANK).find((k) => SEV_RANK[k] === worst) || null;
  return { sev, counts, oldest };
}

function setStatusMessage(text, bad = false) {
  const el = $("filter-msg");
  el.textContent = text || "";
  el.classList.toggle("is-bad", bad);
}

let faviconState = "";
function setFavicon(sev) {
  if (faviconState === (sev || "")) return;
  faviconState = sev || "";
  const color = { critical: "#d42c22", high: "#e3730e", medium: "#c99a00", low: "#4a82d8" }[sev];
  const dot = color ? `<circle cx='25' cy='7' r='6' fill='${color}' stroke='#fff' stroke-width='2'/>` : "";
  const svg = `<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><path d='M16 2.5 5 7v8.2c0 6.9 4.6 12.2 11 14.3 6.4-2.1 11-7.4 11-14.3V7L16 2.5z' fill='#2a62b8'/><path d='M9.5 17h3.2l2-5 2.6 9 2-4h3.2' stroke='#fff' stroke-width='2.2' fill='none' stroke-linecap='round' stroke-linejoin='round'/>${dot}</svg>`;
  $("favicon").href = "data:image/svg+xml," + encodeURIComponent(svg);
}

function renderChrome() {
  const s = state.status, snap = state.snapshot;
  if (s && s.version) $("version").textContent = "v" + s.version;

  // capture indicator
  const led = $("capture-led"), text = $("capture-text");
  led.className = "led";
  if (!state.connected) { led.classList.add("is-down"); text.innerHTML = "<b>Disconnected</b> — retrying"; }
  else if (state.paused) { led.classList.add("is-paused", s && s.mode === "live" ? "is-live" : "is-demo"); text.innerHTML = "<b>Paused</b> — capture continues in the background"; }
  else if (s && s.mode === "live") { led.classList.add("is-live"); text.innerHTML = `<b>Live capture</b> on ${esc(s.interface)}`; }
  else if (s && s.mode === "demo") { led.classList.add("is-demo"); text.innerHTML = "<b>Demo mode</b> — synthetic traffic"; }
  else text.textContent = "Connecting…";

  const untriaged = snap ? snap.totals.untriaged : state.alerts.filter((a) => a.status === "new").length;
  const w = worstUntriaged();

  // tab counts
  const ca = $("count-alerts");
  ca.textContent = untriaged ? fmtNum(untriaged) : "";
  ca.classList.toggle("is-hot", untriaged > 0);
  ca.title = untriaged ? `${untriaged} untriaged` : "";
  if (snap) {
    $("count-endpoints").textContent = fmtNum(snap.totals.hosts);
    $("count-flows").textContent = fmtNum(snap.totals.flows);
  }
  if (s) $("count-rules").textContent = fmtNum(s.rules_loaded);

  // expert info (status bar) + document title + favicon
  const dot = $("expert-dot");
  dot.className = "expert-dot" + (!state.connected ? " is-off" : untriaged ? ` is-${w.sev || "low"}` : "");
  const parts = SEVERITIES.filter((k) => w.counts[k]).map((k) => `${w.counts[k]} ${k}`);
  $("expert-text").innerHTML = untriaged
    ? `${fmtNum(untriaged)} untriaged${parts.length ? `<span class="expert-extra"> · ${esc(parts.join(", "))}</span>` : ""}`
    : "No untriaged alerts";
  document.title = (untriaged ? `(${untriaged}) ` : "") + "Signature NIDS";
  setFavicon(untriaged ? w.sev || "low" : null);

  // overview strip
  const word = $("state-word"), detail = $("state-detail");
  if (!state.connected && !snap) { word.textContent = "Connecting"; word.className = "state-word"; detail.textContent = ""; }
  else if (untriaged) {
    word.textContent = `${fmtNum(untriaged)} alert${untriaged === 1 ? "" : "s"} to triage`;
    word.className = `state-word is-${w.sev || "low"}`;
    detail.textContent = w.oldest ? `oldest ${fmtAgo(w.oldest)}` : "";
  } else {
    word.textContent = "All quiet";
    word.className = "state-word is-calm";
    const last = state.alerts[0];
    detail.textContent = last ? `nothing waiting · last alert ${fmtAgo(last.ts)}` : "nothing waiting · no alerts yet";
  }
  if (snap) {
    const bw = snap.bandwidth[snap.bandwidth.length - 2] || snap.bandwidth[snap.bandwidth.length - 1] || { bps: 0, pps: 0 };
    const today = state.alerts.filter((a) => a.ts >= snap.started_at).length;
    const facts = [
      ["Throughput", fmtBytes(bw.bps) + "/s"],
      ["Packets/s", fmtNum(bw.pps)],
      ["Packets", fmtNum(snap.totals.packets)],
      ["Data", fmtBytes(snap.totals.bytes)],
      ["Hosts", fmtNum(snap.totals.hosts)],
      ["Flows", fmtNum(snap.totals.flows)],
      ["Alerts today", (today >= state.alerts.length && state.alerts.length >= ALERT_CAP / 2 ? "≥ " : "") + fmtNum(today)],
      ["Since", fmtDuration(snap.uptime)],
    ];
    $("facts").innerHTML = facts.map(([k, v]) => `<span class="fact">${k} <b>${esc(v)}</b></span>`).join("");
  }

  // status bar cells
  const v = views[state.view];
  const shown = v && v.counts ? v.counts() : null;
  const cells = [];
  if (shown) cells.push(`Displayed: <b>${fmtNum(shown.shown)}</b>${shown.total !== shown.shown ? ` of ${fmtNum(shown.total)}` : ""}`);
  if (snap) cells.push(`Packets: <b>${fmtNum(snap.totals.packets)}</b>`);
  if (s) cells.push(`Rules: <b>${fmtNum(s.rules_loaded)}</b>${s.rules_disabled ? ` (${s.rules_disabled} off)` : ""}`);
  if (snap) cells.push(`Up ${fmtDuration(snap.uptime)}`);
  $("status-cells").innerHTML = cells.map((c) => `<span>${c}</span>`).join("");

  if (state.paused && state.pendingWhilePaused) {
    setStatusMessage(`Paused — ${state.pendingWhilePaused} new alert${state.pendingWhilePaused === 1 ? "" : "s"} waiting. Press Space to resume.`);
  }
}

// ---------- views ----------
function showView(id) {
  if (!views[id]) id = "alerts";
  const prev = views[state.view];
  if (prev && prev.id !== id && prev.hide) prev.hide();
  state.view = id;
  store("view", id);
  document.querySelectorAll(".tab").forEach((t) => t.setAttribute("aria-selected", String(t.dataset.view === id)));
  document.querySelectorAll(".view").forEach((v) => { v.hidden = v.dataset.view !== id; });
  renderPresets();
  loadFilterText();
  views[id].show();
  renderChrome();
}

document.querySelector(".tabs").addEventListener("click", (e) => {
  const t = e.target.closest(".tab"); if (t) showView(t.dataset.view);
});
document.querySelector(".tabs").addEventListener("keydown", (e) => {
  if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
  const i = order.indexOf(state.view) + (e.key === "ArrowRight" ? 1 : -1);
  const id = order[(i + order.length) % order.length];
  showView(id);
  document.querySelector(`.tab[data-view="${id}"]`).focus();
});

// ---------- display filter ----------
const input = $("filter"), field = $("filter-field"), sugBox = $("filter-suggest");
let sugIndex = -1, sugItems = [];

function placeholderFor(v) {
  return v.placeholder || "Apply a display filter…";
}

function loadFilterText() {
  const v = views[state.view];
  const hasFilter = Boolean(v.fields);
  $("filterbar").hidden = !hasFilter;
  if (!hasFilter) return;
  input.placeholder = placeholderFor(v);
  input.value = state.filters[v.id] || "";
  validate(true);
}

function validate(applyIfOk = false) {
  const v = views[state.view]; if (!v.fields) return;
  const r = compile(input.value, v.fields);
  field.classList.toggle("is-ok", r.ok && !r.empty);
  field.classList.toggle("is-bad", !r.ok);
  input.setAttribute("aria-invalid", String(!r.ok));
  if (!r.ok) setStatusMessage(r.error, true);
  else setStatusMessage(r.empty ? "" : "Filter: " + input.value.trim());
  if (r.ok && applyIfOk) v.applyFilter(r.fn, !r.empty);
  return r;
}

function setFilter(viewId, text, apply) {
  state.filters[viewId] = text;
  store("filters", state.filters);
  if (viewId === state.view) {
    input.value = text;
    validate(apply);
    renderPresets();
  } else if (apply && views[viewId].fields) {
    const r = compile(text, views[viewId].fields);
    if (r.ok) views[viewId].applyFilter(r.fn, !r.empty);
  }
}

function applyInput() {
  const r = validate(false);
  hideSuggest();
  if (!r.ok) return;
  setFilter(state.view, input.value.trim(), true);
  renderChrome();
}

input.addEventListener("input", () => { validate(false); showSuggest(); });
input.addEventListener("keydown", (e) => {
  if (!sugBox.hidden && sugItems.length) {
    if (e.key === "ArrowDown") { e.preventDefault(); sugIndex = (sugIndex + 1) % sugItems.length; paintSuggest(); return; }
    if (e.key === "ArrowUp") { e.preventDefault(); sugIndex = (sugIndex - 1 + sugItems.length) % sugItems.length; paintSuggest(); return; }
    if ((e.key === "Tab" || e.key === "Enter") && sugIndex >= 0) { e.preventDefault(); acceptSuggest(sugIndex); return; }
  }
  if (e.key === "Enter") { e.preventDefault(); applyInput(); }
  if (e.key === "Escape") {
    e.preventDefault();
    if (!sugBox.hidden) { hideSuggest(); return; }
    input.value = state.filters[state.view] || ""; validate(false); input.blur();
  }
});
input.addEventListener("blur", () => setTimeout(hideSuggest, 120));
$("filter-apply").addEventListener("click", applyInput);
$("filter-clear").addEventListener("click", () => { input.value = ""; applyInput(); input.focus(); });

function showSuggest() {
  const v = views[state.view];
  const { items } = suggest(input.value, input.selectionStart, v.fields);
  sugItems = items; sugIndex = items.length ? 0 : -1;
  if (!items.length) { hideSuggest(); return; }
  paintSuggest();
  sugBox.hidden = false;
  input.setAttribute("aria-expanded", "true");
}
function paintSuggest() {
  sugBox.innerHTML = sugItems.map((it, i) => `<li role="option" id="sg-${i}" data-i="${i}" aria-selected="${i === sugIndex}"><b>${esc(it.name)}</b><span>${esc(it.help)}</span></li>`).join("");
  input.setAttribute("aria-activedescendant", sugIndex >= 0 ? `sg-${sugIndex}` : "");
}
function hideSuggest() { sugBox.hidden = true; sugItems = []; input.setAttribute("aria-expanded", "false"); }
function acceptSuggest(i) {
  const it = sugItems[i]; if (!it) return;
  const caret = input.selectionStart;
  const before = input.value.slice(0, caret).replace(/[a-z0-9_.]*$/i, "");
  const after = input.value.slice(caret);
  input.value = before + it.name + " " + after.replace(/^[a-z0-9_.]*/i, "");
  const pos = (before + it.name + " ").length;
  input.setSelectionRange(pos, pos);
  hideSuggest(); validate(false);
}
sugBox.addEventListener("pointerdown", (e) => {
  const li = e.target.closest("li"); if (!li) return;
  e.preventDefault(); acceptSuggest(+li.dataset.i);
});

function renderPresets() {
  const v = views[state.view];
  const box = $("presets");
  const cur = (state.filters[v.id] || "").trim();
  box.innerHTML = (v.presets || []).map((p, i) =>
    `<button type="button" class="preset" data-i="${i}" aria-pressed="${p.expr === cur}" title="${esc(p.expr)}">${esc(p.label)}</button>`).join("");
}
$("presets").addEventListener("click", (e) => {
  const b = e.target.closest(".preset"); if (!b) return;
  const p = views[state.view].presets[+b.dataset.i];
  const cur = (state.filters[state.view] || "").trim();
  setFilter(state.view, cur === p.expr ? "" : p.expr, true);
  renderChrome();
});

/* Context menu for table cells and tree rows: "Apply as Filter" and friends. */
export function filterMenu(viewId, expr, copyText) {
  const cur = (state.filters[viewId] || "").trim();
  const wrap = (s) => (/\|\||\bor\b/i.test(s) ? `(${s})` : s);
  const items = [{ label: "Apply as filter" },
    { text: "Selected", code: expr, icon: "filter", run: () => { show(viewId); setFilter(viewId, expr, true); } },
    { text: "Not selected", code: `!(${expr})`, run: () => { show(viewId); setFilter(viewId, `!(${expr})`, true); } }];
  if (cur) {
    items.push(
      { text: "…and selected", code: `${wrap(cur)} && ${expr}`, run: () => { show(viewId); setFilter(viewId, `${wrap(cur)} && ${expr}`, true); } },
      { text: "…or selected", code: `${cur} || ${expr}`, run: () => { show(viewId); setFilter(viewId, `${cur} || ${expr}`, true); } },
    );
  }
  items.push("-",
    { text: "Copy value", icon: "copy", run: () => navigator.clipboard?.writeText(copyText) },
    { text: "Copy as filter", icon: "copy", run: () => navigator.clipboard?.writeText(expr) });
  return items;
  function show(id) { if (state.view !== id) showView(id); }
}
app.filterMenu = filterMenu;

// ---------- toolbar ----------
function setPaused(p) {
  state.paused = p;
  if (!p) {
    state.pendingWhilePaused = 0;
    setStatusMessage("");
    if (state.snapshot) app.emit("snapshot", state.snapshot);
    app.emit("alerts", { reason: "resume" });
  }
  const b = $("btn-pause");
  b.setAttribute("aria-pressed", String(p));
  b.querySelector("use").setAttribute("href", p ? "#i-play" : "#i-pause");
  b.querySelector(".tool-label").textContent = p ? "Resume" : "Pause";
  b.title = p ? "Resume live updates (Space)" : "Pause live updates (Space)";
  renderChrome();
}
$("btn-pause").addEventListener("click", () => setPaused(!state.paused));

$("btn-reload").addEventListener("click", async () => {
  const b = $("btn-reload");
  b.disabled = true; b.classList.add("is-busy");
  try {
    const r = await api("/api/rules/reload", { method: "POST" });
    toast({ title: "Rules reloaded", body: `${r.rules_loaded} signatures active from disk.` });
    loadStatus(); app.emit("rules-changed", {});
  } catch (e) {
    toast({ sev: "high", title: "Rules not reloaded — the old set stays active", body: e.message, ms: 12000 });
  } finally { b.disabled = false; b.classList.remove("is-busy"); }
});

async function rollover() {
  const ok = await confirmDialog({
    title: "Roll over now?",
    body: "Today's activity is written to a daily report and the live counters reset. Alerts and their triage status are kept.",
    ok: "Roll over",
  });
  if (!ok) return;
  try {
    const r = await api("/api/rollover", { method: "POST" });
    toast({ title: "Day archived", body: `Saved ${r.log}.` });
    app.emit("rollover", r);
  } catch (e) { toast({ sev: "high", title: "Roll over failed", body: e.message }); }
}
$("btn-rollover").addEventListener("click", rollover);
app.rollover = rollover;

// theme: system → light → dark
const THEMES = ["system", "light", "dark"];
function applyTheme(t) {
  const root = document.documentElement;
  if (t === "system") delete root.dataset.theme; else root.dataset.theme = t;
  store("theme", t);
  const b = $("btn-theme");
  b.querySelector("use").setAttribute("href", { system: "#i-auto", light: "#i-sun", dark: "#i-moon" }[t]);
  b.title = `Theme: ${t === "system" ? "follows system" : t} (t)`;
  app.emit("theme", t);
}
$("btn-theme").addEventListener("click", () => {
  const cur = store("theme") || "system";
  applyTheme(THEMES[(THEMES.indexOf(cur) + 1) % THEMES.length]);
});
matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => app.emit("theme", "system"));

function openHelp() {
  const v = views[state.view];
  const fields = v.fields ? Object.entries(v.fields).filter(([, f]) => !f.alias) : [];
  $("field-help").innerHTML = fields.length
    ? fields.map(([n, f]) => `<code>${esc(n)}</code><span>${esc(f.help || "")}</span>`).join("")
    : `<span>This view has no display filter.</span>`;
  $("dlg-help").showModal();
}
$("btn-help").addEventListener("click", openHelp);
$("expert").addEventListener("click", () => {
  showView("alerts");
  setFilter("alerts", "status == new", true);
  renderChrome();
});

// ---------- keyboard ----------
document.addEventListener("keydown", (e) => {
  // a focused table / tree already handled its own navigation keys
  if (e.defaultPrevented || document.querySelector("dialog[open]")) return;
  const t = e.target;
  const typing = t.closest && t.closest("input, textarea, select, [contenteditable]");
  if ((e.ctrlKey || e.metaKey) && e.key === "/") { e.preventDefault(); input.focus(); input.select(); return; }
  if (typing || e.ctrlKey || e.metaKey || e.altKey) return;
  if (e.key === "Escape") { closeMenu(); return; }
  if (e.key === "/") { e.preventDefault(); if (!$("filterbar").hidden) { input.focus(); input.select(); } return; }
  if (e.key === "?") { e.preventDefault(); openHelp(); return; }
  if (/^[1-7]$/.test(e.key)) { e.preventDefault(); showView(order[+e.key - 1]); return; }
  if (e.key === " " && !t.closest("button, a, .tree, [role=separator]")) { e.preventDefault(); setPaused(!state.paused); return; }
  if (e.key === "t") { e.preventDefault(); $("btn-theme").click(); return; }
  const v = views[state.view];
  if (v.onKey && v.onKey(e)) e.preventDefault();
});

// ---------- boot ----------
for (const v of Object.values(views)) v.init(app);
applyTheme(store("theme") || "system");
showView(state.view);
loadStatus();
loadAlerts();
connect();
setInterval(loadStatus, 15000);
setInterval(renderChrome, 5000); // keeps "x ago" texts honest between snapshots
