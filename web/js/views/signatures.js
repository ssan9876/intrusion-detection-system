/* Signatures: every loaded rule with its hit counts; enable, disable or mute
   from here. Changes are stored in the alert database, never in the rules file. */
import { $, api, esc, fmtAgo, fmtClock, fmtDateTime, fmtNum, icon, portLabel, sevMark, STATUS_LABEL } from "../util.js";
import { ruleFields } from "../fields.js";
import { Table } from "../table.js";
import { splitters } from "../ui.js";

let app, table, timer = null, filterActive = false;
let rules = [];
let current = null;

const matchOf = (r) => (r.detector ? r.detector_info
  : r.content != null ? JSON.stringify(r.content)
    : r.content_hex != null ? "hex " + r.content_hex
      : r.regex != null ? "/" + r.regex + "/" : "header only");

const muteLeft = (r) => (r.muted_until ? r.muted_until - Date.now() / 1000 : 0);

const view = {
  id: "signatures",
  fields: ruleFields,
  placeholder: "Filter signatures… e.g.  hits24 > 0   ·   !enabled   ·   category == web-attack   ·   sev >= high",
  presets: [
    { label: "Fired today", expr: "hits24 > 0" },
    { label: "Never fired", expr: "hits == 0" },
    { label: "Disabled", expr: "!enabled" },
    { label: "Muted", expr: "muted" },
    { label: "High & critical", expr: "sev >= high" },
  ],

  init(a) {
    app = a;
    table = new Table($("rule-list"), {
      ariaLabel: "Signatures",
      rowKey: (r) => r.id,
      rowClass: (r) => `zebra${r.enabled ? "" : " is-muted"}`,
      sort: { key: "h24", dir: -1 },
      empty: () => (filterActive ? "<b>No signatures match this filter.</b>" : "Loading signatures…"),
      columns: [
        {
          key: "on", label: "On", cls: "w-toggle", sort: (r) => (r.enabled ? 1 : 0),
          render: (r) => (r.detector ? `<span class="dim" title="Built-in detector: it can be muted, not disabled">built-in</span>`
            : `<label class="switch" title="${r.enabled ? "Disable" : "Enable"} ${esc(r.id)}"><input type="checkbox" data-toggle="${esc(r.id)}" ${r.enabled ? "checked" : ""} aria-label="${esc(r.id)} enabled"><span></span></label>`),
          filter: (r) => (r.enabled ? "enabled" : "!enabled"),
        },
        { key: "id", label: "ID", cls: "mono w-rule", render: (r) => esc(r.id), filter: (r) => `rule.id == ${r.id}` },
        { key: "sev", label: "Severity", cls: "w-sev", render: (r) => sevMark(r.severity), sort: (r) => ({ low: 1, medium: 2, high: 3, critical: 4 }[r.severity]), filter: (r) => `sev == ${r.severity}` },
        { key: "cat", label: "Category", cls: "w-num", render: (r) => esc(r.category), sort: (r) => r.category, filter: (r) => `category == ${r.category}` },
        { key: "proto", label: "Proto", cls: "w-proto", render: (r) => esc(String(r.protocol).toUpperCase()) },
        { key: "port", label: "Port", cls: "num w-sm", render: (r) => (r.dst_port != null ? r.dst_port : r.src_port != null ? `src ${r.src_port}` : `<span class="dim">any</span>`), sort: (r) => r.dst_port ?? -1 },
        { key: "name", label: "Name / match", cls: "wide", render: (r) => `${esc(r.name)} <span class="dim mono">${esc(matchOf(r))}</span>`, sort: (r) => r.name, title: (r) => matchOf(r) },
        { key: "h24", label: "24 h", cls: "num w-sm", render: (r) => (r.hits_24h ? fmtNum(r.hits_24h) : `<span class="dim">0</span>`), sort: (r) => r.hits_24h, filter: () => "hits24 > 0" },
        { key: "hits", label: "Total", cls: "num w-sm", render: (r) => fmtNum(r.hits), sort: (r) => r.hits },
        { key: "last", label: "Last hit", cls: "w-num dim", render: (r) => (r.last_hit ? fmtAgo(r.last_hit) : "never"), sort: (r) => r.last_hit || 0 },
        { key: "state", label: "State", cls: "w-status", render: (r) => (!r.enabled ? "Disabled" : muteLeft(r) > 0 ? `Muted ${fmtLeft(muteLeft(r))}` : `<span class="dim">Active</span>`), sort: (r) => (!r.enabled ? 2 : muteLeft(r) > 0 ? 1 : 0), filter: (r) => (r.muted_until ? "muted" : "!muted") },
      ],
      onSelect: (r) => { current = r ? r.id : null; renderDetail(); },
    });
    $("rule-list").addEventListener("change", async (e) => {
      const cb = e.target.closest("[data-toggle]"); if (!cb) return;
      const id = cb.dataset.toggle;
      const ok = await app.setRuleState(id, { enabled: cb.checked });
      if (!ok) cb.checked = !cb.checked;
    });
    $("rule-list").addEventListener("contextmenu", (e) => {
      const c = table.cellFilter(e.target); if (!c) return;
      e.preventDefault(); table.select(c.row.id);
      app.contextMenu(e.clientX, e.clientY, [
        ...app.filterMenu("signatures", c.expr, c.text),
        "-",
        { text: "Alerts from this signature", icon: "apply", run: () => { app.show("alerts"); app.setFilter("alerts", `rule.id == ${c.row.id}`); } },
      ]);
    });
    $("rule-actions").addEventListener("click", async (e) => {
      const b = e.target.closest("[data-act]"); if (!b || !current) return;
      const { act, arg } = b.dataset;
      if (act === "toggle") await app.setRuleState(current, { enabled: arg === "on" });
      if (act === "mute") await app.setRuleState(current, { mute_minutes: +arg });
      if (act === "alerts") { app.show("alerts"); app.setFilter("alerts", `rule.id == ${current}`); }
    });
    $("rule-detail").addEventListener("click", (e) => {
      const t = e.target.closest("[data-alert]"); if (t) app.openAlert(+t.dataset.alert);
    });
    splitters($("rule-panes"), "signatures", [1.5, 1]);
    app.on("rules-changed", () => { if (app.state.view === "signatures") load(); });
    renderDetail();
  },

  show() { load(); timer = setInterval(() => !app.state.paused && load(), 10000); },
  hide() { clearInterval(timer); timer = null; },
  applyFilter(fn, active) { filterActive = active; table.filterFn = active ? fn : null; table.render(); },
  counts() { return { shown: table.view.length, total: rules.length }; },
  onKey(e) {
    if (["j", "k"].includes(e.key)) { table.move(e.key === "j" ? 1 : -1); return true; }
    if (e.key === "m" && current) { app.setRuleState(current, { mute_minutes: 60 }); return true; }
    return false;
  },
};

function fmtLeft(s) {
  if (s >= 86400) return Math.round(s / 86400) + " d";
  if (s >= 3600) return Math.round(s / 3600) + " h";
  return Math.max(1, Math.round(s / 60)) + " min";
}

async function load() {
  try {
    rules = await api("/api/rules");
    table.setRows(rules);
    if (current) renderDetail();
  } catch (e) {
    $("rule-list").querySelector("tbody").innerHTML = `<tr class="empty-row"><td colspan="11"><b>Couldn't load signatures.</b><br>${esc(e.message)}</td></tr>`;
  }
}

let seq = 0;
async function renderDetail() {
  const r = rules.find((x) => x.id === current);
  const head = $("rule-actions"), box = $("rule-detail");
  if (!r) {
    head.innerHTML = "";
    box.innerHTML = `<div class="pane-empty"><b>Select a signature</b><p>See exactly what it looks for, how often it fires, and its latest alerts. Switch noisy ones off, or mute them: muted alerts are still logged but don't ask for triage.</p></div>`;
    return;
  }
  const muted = muteLeft(r) > 0;
  head.innerHTML = `
    <span class="pane-title">${esc(r.id)} <span class="mono">${esc(r.category)}</span></span>
    ${r.detector ? "" : r.enabled
      ? `<button class="btn" data-act="toggle" data-arg="off" type="button">${icon("power")}Disable</button>`
      : `<button class="btn btn-primary" data-act="toggle" data-arg="on" type="button">${icon("power")}Enable</button>`}
    <span class="btn-group">
      ${muted ? `<button class="btn" data-act="mute" data-arg="0" type="button">${icon("bell")}Unmute (${fmtLeft(muteLeft(r))} left)</button>`
      : `<button class="btn" data-act="mute" data-arg="60" type="button">${icon("mute")}Mute 1 h</button>
         <button class="btn" data-act="mute" data-arg="1440" type="button">24 h</button>
         <button class="btn" data-act="mute" data-arg="10080" type="button">7 d</button>`}
    </span>
    <button class="btn" data-act="alerts" type="button">${icon("filter")}Show alerts (${fmtNum(r.hits)})</button>`;

  const def = r.detector ? { id: r.id, detector: "port scan", fires_when: r.detector_info, severity: r.severity, category: r.category }
    : Object.fromEntries(Object.entries({
      id: r.id, name: r.name, severity: r.severity, category: r.category, protocol: r.protocol,
      src_port: r.src_port, dst_port: r.dst_port, content: r.content, content_hex: r.content_hex,
      regex: r.regex, nocase: r.nocase || undefined, references: r.references && r.references.length ? r.references : undefined,
    }).filter(([, v]) => v != null));
  const json = esc(JSON.stringify(def, null, 2))
    .replace(/^(\s*)(&quot;[^&]+&quot;):/gm, '$1<span class="k">$2</span>:')
    .replace(/: (&quot;.*?&quot;)(,?)$/gm, ': <span class="s">$1</span>$2');

  box.innerHTML = `<div class="detail-grid">
      <section class="detail-block"><h3>Definition</h3><pre class="rule-def">${json}</pre></section>
      <section class="detail-block"><h3>Activity</h3>
        <dl class="kv">
          <dt>State</dt><dd>${!r.enabled ? "disabled — packets aren't checked" : muted ? `muted until ${esc(fmtDateTime(r.muted_until))}` : "active"}</dd>
          <dt>Last 24 h</dt><dd>${fmtNum(r.hits_24h)} alert${r.hits_24h === 1 ? "" : "s"}</dd>
          <dt>All time</dt><dd>${fmtNum(r.hits)}</dd>
          <dt>Last hit</dt><dd class="mono">${r.last_hit ? esc(fmtDateTime(r.last_hit)) + " · " + esc(fmtAgo(r.last_hit)) : "never"}</dd>
          ${r.dst_port != null ? `<dt>Port</dt><dd>${esc(portLabel(r.dst_port))}</dd>` : ""}
        </dl>
        <h3 style="margin-top:14px">Latest alerts</h3><div id="rule-recent"><p class="dim">Loading…</p></div>
      </section>
    </div>`;

  const my = ++seq;
  try {
    const recent = await api(`/api/alerts?rule_id=${encodeURIComponent(r.id)}&limit=10`);
    if (my !== seq) return;
    $("rule-recent").innerHTML = recent.length ? `<table class="mini-table"><thead><tr><th>Time</th><th>Source</th><th>Destination</th><th>Status</th></tr></thead><tbody>
      ${recent.map((a) => `<tr class="is-link" data-alert="${a.id}" title="Open alert ${a.id}"><td class="mono">${esc(fmtClock(a.ts, false))}</td><td class="mono">${esc(a.src)}</td><td class="mono">${esc(a.dst)}${a.dport ? ":" + a.dport : ""}</td><td>${esc(STATUS_LABEL[a.status] || a.status)}</td></tr>`).join("")}
      </tbody></table>` : `<p class="dim">This signature hasn't fired yet.</p>`;
  } catch { /* leave the loading note */ }
}

export default view;
