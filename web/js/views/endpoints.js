/* Endpoints: every host seen today, with a drill-down into its peers, ports
   and alert history. */
import {
  $, api, esc, fmtAgo, fmtBytes, fmtClock, fmtDateTime, fmtNum, icon, portLabel, sevMark, STATUS_LABEL,
} from "../util.js";
import { hostFields } from "../fields.js";
import { Table } from "../table.js";
import { splitters } from "../ui.js";

let app, table, timer = null, filterActive = false, total = 0;
let current = null;   // selected host address
let pendingOpen = null;

const view = {
  id: "endpoints",
  fields: hostFields,
  placeholder: "Filter endpoints… e.g.  internal   ·   alerts > 0   ·   bytes > 1m   ·   ip.addr contains 192.168",
  presets: [
    { label: "Internal", expr: "internal" },
    { label: "External", expr: "!internal" },
    { label: "Raised alerts", expr: "alerts > 0" },
    { label: "Untriaged", expr: "untriaged > 0" },
    { label: "Many ports", expr: "ports >= 15" },
  ],

  init(a) {
    app = a;
    app.openHost = openHost;
    table = new Table($("host-list"), {
      ariaLabel: "Endpoints",
      rowKey: (r) => r.host,
      rowClass: (r) => (r.untriaged ? "zebra is-new" : "zebra"),
      sort: { key: "bytes", dir: -1 },
      empty: () => (filterActive ? "<b>No endpoints match this filter.</b>" : "<b>No hosts seen yet.</b><br>Every address the sensor sees appears here with its traffic and alert counts."),
      columns: [
        { key: "host", label: "Address", cls: "mono w-ip", render: (r) => `${esc(r.host)}<span class="scope">${r.internal ? "internal" : "external"}</span>`, sort: (r) => r.host, filter: (r) => `ip.addr == ${r.host}` },
        { key: "packets", label: "Packets", cls: "num w-num", render: (r) => fmtNum(r.packets) },
        { key: "bytes", label: "Bytes", cls: "num w-num", render: (r) => fmtBytes(r.bytes), filter: (r) => `bytes >= ${r.bytes}` },
        { key: "tx", label: "Sent", cls: "num w-num", render: (r) => fmtBytes(r.bytes_tx), sort: (r) => r.bytes_tx },
        { key: "rx", label: "Received", cls: "num w-num", render: (r) => fmtBytes(r.bytes_rx), sort: (r) => r.bytes_rx },
        { key: "peers", label: "Peers", cls: "num w-sm", render: (r) => fmtNum(r.peers), filter: (r) => `peers >= ${r.peers}` },
        { key: "ports", label: "Ports", cls: "num w-sm", render: (r) => fmtNum(r.ports), filter: (r) => `ports >= ${r.ports}` },
        { key: "alerts", label: "Alerts", cls: "num w-sm", render: (r) => fmtNum(r.as_src + r.as_dst), sort: (r) => r.as_src + r.as_dst, filter: () => "alerts > 0" },
        { key: "untriaged", label: "Untriaged", cls: "num w-num", render: (r) => (r.untriaged ? fmtNum(r.untriaged) : `<span class="dim">0</span>`), filter: () => "untriaged > 0" },
        { key: "last", label: "Last seen", cls: "wide dim", render: (r) => fmtAgo(r.last_seen), sort: (r) => r.last_seen },
      ],
      onSelect: (r) => { if (r) loadHost(r.host); },
    });
    $("host-list").addEventListener("contextmenu", (e) => {
      const c = table.cellFilter(e.target); if (!c) return;
      e.preventDefault(); table.select(c.row.host);
      app.contextMenu(e.clientX, e.clientY, [
        ...app.filterMenu("endpoints", c.expr, c.text),
        "-",
        { text: "Alerts involving this host", icon: "apply", run: () => { app.show("alerts"); app.setFilter("alerts", `ip.addr == ${c.row.host}`); } },
        { text: "Packets involving this host", icon: "apply", run: () => { app.show("packets"); app.setFilter("packets", `ip.addr == ${c.row.host}`); } },
      ]);
    });
    $("host-detail").addEventListener("click", (e) => {
      const t = e.target.closest("[data-host],[data-alert],[data-rule]"); if (!t) return;
      if (t.dataset.host) openHost(t.dataset.host);
      else if (t.dataset.alert) app.openAlert(+t.dataset.alert);
      else if (t.dataset.rule) { app.show("alerts"); app.setFilter("alerts", `ip.addr == ${current} && rule.id == ${t.dataset.rule}`); }
    });
    $("host-actions").addEventListener("click", (e) => {
      const b = e.target.closest("[data-act]"); if (!b || !current) return;
      const f = `ip.addr == ${current}`;
      if (b.dataset.act === "alerts") { app.show("alerts"); app.setFilter("alerts", f); }
      if (b.dataset.act === "packets") { app.show("packets"); app.setFilter("packets", f); }
      if (b.dataset.act === "flows") { app.show("conversations"); app.setFilter("conversations", f); }
      if (b.dataset.act === "copy") navigator.clipboard?.writeText(current);
    });
    splitters($("host-panes"), "endpoints", [1.2, 1]);
    app.on("rollover", () => load());
    renderEmpty();
  },

  show() {
    load();
    timer = setInterval(() => { if (!app.state.paused) { load(); if (current) loadHost(current, true); } }, 4000);
  },
  hide() { clearInterval(timer); timer = null; },
  applyFilter(fn, active) { filterActive = active; table.filterFn = active ? fn : null; table.render(); },
  counts() { return { shown: table.view.length, total }; },
  onKey(e) {
    if (["j", "k"].includes(e.key)) { table.move(e.key === "j" ? 1 : -1); return true; }
    return false;
  },
};

async function load() {
  try {
    const rows = await api("/api/hosts");
    total = rows.length;
    table.setRows(rows);
    if (pendingOpen) { const h = pendingOpen; pendingOpen = null; table.select(h, { silent: true }); }
  } catch { /* next tick */ }
}

function openHost(host) {
  if (app.state.view !== "endpoints") app.show("endpoints");
  if (table.filterFn && !table.view.some((r) => r.host === host)) app.setFilter("endpoints", "");
  pendingOpen = host;
  table.select(host, { focus: true, silent: true });
  loadHost(host);
}

function renderEmpty() {
  $("host-actions").innerHTML = "";
  $("host-detail").innerHTML = `<div class="pane-empty"><b>Select an endpoint</b><p>See who it talks to, which ports it touched, and every alert it raised or received. Hosts with untriaged alerts are shown in bold.</p></div>`;
}

let seq = 0;
async function loadHost(host, quiet = false) {
  const my = ++seq;
  current = host;
  if (!quiet) $("host-actions").innerHTML = `<span class="pane-title">${esc(host)}</span>`;
  try {
    const d = await api(`/api/hosts/${encodeURIComponent(host)}`);
    if (my !== seq) return;
    render(d);
  } catch (e) {
    if (my !== seq) return;
    $("host-detail").innerHTML = `<div class="pane-empty"><b>${esc(host)} isn't in today's traffic</b><p>${esc(e.message)}. Hosts reset at the daily rollover; its alerts are still in the Alerts view.</p></div>`;
  }
}

function render(d) {
  const s = d.stats;
  $("host-actions").innerHTML = `
    <span class="pane-title">${esc(d.host)} <span class="mono">${d.internal ? "internal" : "external"}</span></span>
    <button class="btn" data-act="alerts" type="button">${icon("filter")}Alerts (${fmtNum(d.alert_count)})</button>
    <button class="btn" data-act="packets" type="button">${icon("filter")}Packets</button>
    <button class="btn" data-act="flows" type="button">${icon("filter")}Conversations</button>
    <span class="pane-spacer"></span>
    <button class="btn" data-act="copy" type="button">${icon("copy")}Copy address</button>`;

  const summary = s ? `
    <dl class="kv">
      <dt>Scope</dt><dd>${d.internal ? "internal (private network)" : "external"}</dd>
      <dt>First seen</dt><dd class="mono">${esc(fmtDateTime(s.first_seen))}</dd>
      <dt>Last seen</dt><dd>${esc(fmtAgo(s.last_seen))}</dd>
      <dt>Sent</dt><dd class="mono">${fmtNum(s.packets_tx)} pkts · ${esc(fmtBytes(s.bytes_tx))}</dd>
      <dt>Received</dt><dd class="mono">${fmtNum(s.packets_rx)} pkts · ${esc(fmtBytes(s.bytes_rx))}</dd>
      <dt>Peers</dt><dd>${fmtNum(s.peers)}</dd>
      <dt>Alerts</dt><dd>${fmtNum(d.alert_count)}${d.first_alert ? ` · first ${esc(fmtAgo(d.first_alert))}` : ""}</dd>
    </dl>` : `<p class="dim">No traffic from this host since the last rollover.</p>`;

  const byRule = d.alerts_by_rule.length ? `<table class="mini-table">
      <thead><tr><th>Signature</th><th>Severity</th><th class="num">Hits</th><th class="num">Last</th></tr></thead>
      <tbody>${d.alerts_by_rule.map((r) => `<tr class="is-link" data-rule="${esc(r.rule_id)}" title="Show these alerts">
        <td>${esc(r.rule_name)}</td><td>${sevMark(r.severity)}</td><td class="num">${fmtNum(r.hits)}</td><td class="num">${esc(fmtAgo(r.last_hit))}</td></tr>`).join("")}</tbody></table>`
    : `<p class="dim">No alerts involve this host.</p>`;

  const peers = d.peers.length ? `<table class="mini-table">
      <thead><tr><th>Peer</th><th class="num">Packets</th><th class="num">Bytes</th></tr></thead>
      <tbody>${d.peers.map((p) => `<tr class="is-link" data-host="${esc(p.host)}" title="Open ${esc(p.host)}">
        <td class="mono">${esc(p.host)}</td><td class="num">${fmtNum(p.packets)}</td><td class="num">${esc(fmtBytes(p.bytes))}</td></tr>`).join("")}</tbody></table>`
    : `<p class="dim">No active conversations.</p>`;

  const ports = d.ports.length
    ? `<ul class="port-list">${d.ports.slice(0, 120).map((p) => `<li title="${esc(portLabel(p))}">${esc(portLabel(p))}</li>`).join("")}</ul>${d.ports.length > 120 ? `<p class="dim">…and ${d.ports.length - 120} more</p>` : ""}`
    : `<p class="dim">This host hasn't initiated any TCP/UDP connections.</p>`;

  const recent = d.alerts.length ? `<table class="mini-table">
      <thead><tr><th>Time</th><th>Severity</th><th>Signature</th><th>Direction</th><th>Status</th></tr></thead>
      <tbody>${d.alerts.slice(0, 15).map((a) => `<tr class="is-link" data-alert="${a.id}" title="Open alert ${a.id}">
        <td class="mono">${esc(fmtClock(a.ts, false))}</td><td>${sevMark(a.severity)}</td><td>${esc(a.rule_name)}</td>
        <td class="mono">${a.src === d.host ? "→ " + esc(a.dst) : "← " + esc(a.src)}</td>
        <td>${esc(STATUS_LABEL[a.status] || a.status)}</td></tr>`).join("")}</tbody></table>`
    : "";

  $("host-detail").innerHTML = `<div class="detail-grid">
      <section class="detail-block"><h3>Summary</h3>${summary}</section>
      <section class="detail-block"><h3>Alerts by signature</h3>${byRule}</section>
      <section class="detail-block"><h3>Top peers</h3>${peers}</section>
      <section class="detail-block"><h3>Destination ports contacted (${fmtNum(d.ports.length)})</h3>${ports}</section>
      ${recent ? `<section class="detail-block" style="grid-column:1/-1"><h3>Recent alerts</h3>${recent}</section>` : ""}
    </div>`;
}

export default view;
