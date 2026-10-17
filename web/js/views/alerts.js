/* Alerts: list / dissection tree / hex bytes, linked the way a packet
   analyzer links them — selecting the matched-content field lights up the
   exact bytes that fired the rule, and clicking those bytes selects the field. */
import {
  $, api, clean, esc, endpoint, fmtAgo, fmtClock, fmtDateTime, fmtNum, icon, isInternal, portLabel,
  sevMark, STATUS_LABEL, store,
} from "../util.js";
import { alertFields } from "../fields.js";
import { Table } from "../table.js";
import { splitters, Tree } from "../ui.js";
import { drawThroughput } from "../charts.js";

let app, table, tree;
let filterFn = null;
let detail = null;          // the selected alert's full record
const cache = new Map();    // id -> detail
const fresh = new Set();    // ids that arrived since the last render
let timeMode = store("alerts.time") || "clock";
let dirty = false;

const scopeTag = (h) => `<span class="scope">${isInternal(h) ? "internal" : "external"}</span>`;

const view = {
  id: "alerts",
  fields: alertFields,
  placeholder: "Filter alerts… e.g.  sev >= high && ip.src == 203.0.113.66   ·   status == new   ·   sql",
  presets: [
    { label: "Untriaged", expr: "status == new" },
    { label: "High & critical", expr: "sev >= high" },
    { label: "From outside", expr: "!ip.src.internal" },
    { label: "Port scans", expr: "rule.id == RECON-PORTSCAN" },
    { label: "Web attacks", expr: "category == web-attack" },
    { label: "Last hour", expr: "age < 3600" },
  ],

  init(a) {
    app = a;
    app.openAlert = (id) => { app.show("alerts"); selectAlert(id); };
    table = new Table($("alert-list"), {
      ariaLabel: "Alerts",
      rowKey: (r) => r.id,
      rowClass: (r) => `c-${r.severity} is-${r.status}${fresh.has(r.id) ? " is-fresh" : ""}${detail && r.src === detail.src && r.id !== detail.id ? " is-related" : ""}`,
      sort: { key: "no", dir: -1 },
      empty: () => app.state.alertsLoaded
        ? (filterFn
          ? `<b>No alerts match this filter.</b><br>Clear it with <kbd>Esc</kbd> in the filter box, or pick another saved filter.`
          : `<b>No alerts yet.</b><br>Every packet is checked against the loaded signatures; matches land here with the bytes that triggered them.`)
        : "Loading alerts…",
      columns: [
        { key: "no", label: "No.", cls: "num w-no", render: (r) => r.id, sort: (r) => r.id, filter: (r) => `alert.id == ${r.id}` },
        {
          key: "time", label: "Time", cls: "mono w-time",
          render: (r) => (timeMode === "clock" ? fmtClock(r.ts) : fmtAgo(r.ts)),
          title: (r) => fmtDateTime(r.ts) + " — click the column header to switch clock / relative",
          sort: (r) => r.ts,
          onHeader: () => { timeMode = timeMode === "clock" ? "rel" : "clock"; store("alerts.time", timeMode); },
        },
        { key: "sev", label: "Severity", cls: "w-sev", render: (r) => sevMark(r.severity), sort: (r) => ({ low: 1, medium: 2, high: 3, critical: 4 }[r.severity]), filter: (r) => `sev == ${r.severity}` },
        { key: "src", label: "Source", cls: "mono w-ip", render: (r) => esc(endpoint(r.src, r.sport)), sort: (r) => r.src, filter: (r) => `ip.src == ${r.src}` },
        { key: "dst", label: "Destination", cls: "mono w-ip", render: (r) => esc(endpoint(r.dst, r.dport)), sort: (r) => r.dst, filter: (r) => `ip.dst == ${r.dst}` },
        { key: "proto", label: "Protocol", cls: "w-proto", render: (r) => esc(String(r.proto).toUpperCase()), filter: (r) => `proto == ${r.proto}` },
        { key: "rule", label: "Signature", cls: "w-rule", render: (r) => esc(r.rule_name), title: (r) => r.rule_id, sort: (r) => r.rule_name, filter: (r) => `rule.id == ${r.rule_id}` },
        { key: "info", label: "Info", cls: "wide", render: (r) => esc(clean(r.detail)), title: (r) => clean(r.detail), sort: (r) => r.detail || "", filter: (r) => `detail contains "${String(r.detail || "").slice(0, 24).replace(/"/g, "")}"` },
        { key: "status", label: "Status", cls: "w-status", render: (r) => `<span class="status-pill s-${esc(r.status)}">${esc(STATUS_LABEL[r.status] || r.status)}</span>`, filter: (r) => `status == ${r.status}` },
      ],
      onSelect: (r) => select(r ? r.id : null),
      onActivate: (r) => r && $("alert-tree").focus(),
    });
    table.filterFn = null;

    tree = new Tree($("alert-tree"), {
      persistKey: "alert",
      onHover: (n) => hotBytes(n && n.bytes),
      onSelect: (n) => {
        hotBytes(n && n.bytes, true);
        if (n && n.filter) app.setStatusMessage(`${n.filter}   — right-click to apply as filter`);
      },
      onContext: (n, e) => {
        if (!n || !n.filter) return;
        app.contextMenu(e.clientX, e.clientY, app.filterMenu("alerts", n.filter, n.copy ?? n.filter));
      },
    });

    $("alert-list").addEventListener("contextmenu", (e) => {
      const c = table.cellFilter(e.target); if (!c) return;
      e.preventDefault();
      table.select(c.row.id);
      app.contextMenu(e.clientX, e.clientY, app.filterMenu("alerts", c.expr, c.text));
    });

    // tree row chips (Host, Filter, open alert)
    $("alert-tree").addEventListener("click", (e) => {
      const b = e.target.closest("[data-act]"); if (!b) return;
      const { act, arg } = b.dataset;
      if (act === "host") app.openHost(arg);
      if (act === "filter") app.setFilter("alerts", arg);
      if (act === "alert") selectAlert(+arg);
    });

    $("alert-hex").addEventListener("click", (e) => {
      const i = e.target.closest("i[data-o]"); if (!i || !detail) return;
      const o = +i.dataset.o;
      const inMatch = detail.match_start != null && o >= detail.match_start && o < detail.match_end;
      tree.select(inMatch ? "sig.match" : "payload");
    });
    $("alert-hex").addEventListener("pointerover", (e) => {
      const i = e.target.closest("i[data-o]"); if (!i || !detail) return;
      const o = +i.dataset.o;
      const inMatch = detail.match_start != null && o >= detail.match_start && o < detail.match_end;
      const li = $("alert-tree").querySelector('.tn[data-id="sig.match"] > .tn-row');
      if (li) li.classList.toggle("is-linked", inMatch);
    });
    $("alert-hex").addEventListener("pointerleave", () => {
      $("alert-tree").querySelector(".tn-row.is-linked")?.classList.remove("is-linked");
    });

    $("alert-actions").addEventListener("click", (e) => {
      const b = e.target.closest("[data-act]"); if (!b) return;
      act(b.dataset.act, b.dataset.arg);
    });

    splitters($("alert-panes"), "alerts", [1.6, 1, 0.55]);

    app.on("alerts", () => schedule());
    app.on("alert", (a) => { fresh.add(a.id); schedule(); });
    app.on("snapshot", (s) => drawMini(s));
    app.on("theme", () => { app.state.snapshot && drawMini(app.state.snapshot); });
    app.on("rules-changed", () => { cache.clear(); if (detail) loadDetail(detail.id); });
    new ResizeObserver(() => app.state.snapshot && drawMini(app.state.snapshot)).observe($("io-mini"));
    renderDetail();
  },

  show() { render(); if (app.state.snapshot) drawMini(app.state.snapshot); },
  hide() {},

  applyFilter(fn, active) {
    filterFn = active ? fn : null;
    table.filterFn = filterFn;
    render();
  },

  counts() { return { shown: table.view.length, total: app.state.alerts.length }; },

  onKey(e) {
    const k = e.key;
    if (k === "a") return act("ack"), true;
    if (k === "f") return act("fp"), true;
    if (k === "u") return act("new"), true;
    if (k === "m") return act("mute", "60"), true;
    if (k === "h" && detail) return act("host"), true;
    if (["j", "k", "ArrowDown", "ArrowUp"].includes(k) && document.activeElement !== $("alert-tree")) {
      table.move(k === "j" || k === "ArrowDown" ? 1 : -1); return true;
    }
    return false;
  },

  selectAlert,
};

function schedule() {
  if (dirty) return;
  dirty = true;
  requestAnimationFrame(() => {
    dirty = false;
    if (app.state.view !== "alerts" || app.state.paused) return;
    render();
  });
}

function render() {
  table.setRows(app.state.alerts);
  fresh.clear();
  // keep the detail header in sync with status changes made elsewhere
  if (detail) {
    const row = app.state.alerts.find((a) => a.id === detail.id);
    if (row && row.status !== detail.status) { detail.status = row.status; detail.status_ts = row.status_ts; renderDetail(); }
  }
}

function drawMini(s) {
  if (app.state.view !== "alerts") return;
  const t0 = s.bandwidth[0]?.t || 0;
  const ticks = [];
  for (const a of app.state.alerts) { if (a.ts < t0) break; ticks.push(a); }
  drawThroughput($("io-mini"), s.bandwidth, ticks, { compact: true });
}

async function selectAlert(id) {
  if (!app.state.alerts.some((a) => a.id === id)) {
    // not in the loaded window (e.g. from host history): load it on its own
    await loadDetail(id);
    return;
  }
  if (filterFn && !table.view.some((r) => r.id === id)) app.setFilter("alerts", "");
  table.select(id, { focus: true });
}

function select(id) {
  if (id == null) { detail = null; renderDetail(); return; }
  if (detail && detail.id === id) return;
  loadDetail(id);
}

let loadSeq = 0;
async function loadDetail(id) {
  const seq = ++loadSeq;
  if (cache.has(id)) { detail = cache.get(id); renderDetail(); return; }
  try {
    const d = await api(`/api/alerts/${id}`);
    cache.set(id, d);
    if (cache.size > 200) cache.delete(cache.keys().next().value);
    if (seq !== loadSeq) return;
    detail = d;
    renderDetail();
  } catch (e) {
    if (seq !== loadSeq) return;
    detail = null;
    $("alert-tree").innerHTML = `<div class="pane-empty"><b>Couldn't load alert ${id}</b><p>${esc(e.message)}</p></div>`;
  }
}

// ---------- actions ----------
async function act(kind, arg) {
  if (!detail && kind !== "ack-shown") return;
  const d = detail;
  if (kind === "ack" || kind === "fp" || kind === "new") {
    if (d.status === kind) return;
    const r = await app.setAlertStatus([d.id], kind);
    if (!r) return;
    d.status = kind; d.status_ts = Date.now() / 1000;
    renderDetail();
    if (kind !== "new") table.move(1); // triage flow: on to the next one
  } else if (kind === "ack-shown") {
    const ids = table.view.filter((r) => r.status === "new").map((r) => r.id);
    if (!ids.length) return;
    const ok = await app.confirmDialog({
      title: `Acknowledge ${ids.length} alert${ids.length === 1 ? "" : "s"}?`,
      body: "Every untriaged alert in the current list is marked acknowledged. You can reopen any of them later.",
      ok: "Acknowledge",
    });
    if (ok) await app.setAlertStatus(ids, "ack");
  } else if (kind === "mute") {
    const mins = +arg;
    const r = await app.setRuleState(d.rule_id, { mute_minutes: mins });
    if (r) app.toast({ title: mins ? `Muted ${d.rule_id}` : `Unmuted ${d.rule_id}`, body: mins ? `New alerts are still logged, marked muted, for ${mins >= 1440 ? mins / 1440 + " d" : mins / 60 + " h"}.` : "New alerts will need triage again." });
  } else if (kind === "disable" || kind === "enable") {
    const r = await app.setRuleState(d.rule_id, { enabled: kind === "enable" });
    if (r) app.toast({ title: `${kind === "enable" ? "Enabled" : "Disabled"} ${d.rule_id}`, body: kind === "enable" ? "The signature is checked again on every packet." : "Packets are no longer checked against this signature." });
  } else if (kind === "host") {
    app.openHost(d.src);
  } else if (kind === "related") {
    app.setFilter("alerts", `ip.src == ${d.src}`);
  }
}

// ---------- detail rendering ----------
function renderDetail() {
  const head = $("alert-actions");
  if (!detail) {
    head.innerHTML = "";
    tree.render([], `<div class="pane-empty"><b>Select an alert</b><p>Its dissection appears here: addresses, ports, the signature that fired, the matched bytes and the history of the source. <kbd>j</kbd>/<kbd>k</kbd> move, <kbd>a</kbd> acknowledges.</p></div>`);
    renderHex();
    return;
  }
  const d = detail;
  const st = d.rule_state || {};
  const muted = st.muted_until && st.muted_until > Date.now() / 1000;
  const isDetector = !d.rule;
  const untriagedShown = table.view.filter((r) => r.status === "new").length;
  head.innerHTML = `
    <span class="pane-title">Alert ${d.id} <span class="mono">${esc(d.rule_id)}</span></span>
    ${d.status === "new"
      ? `<button class="btn btn-primary" data-act="ack" type="button">${icon("check")}Acknowledge <kbd>A</kbd></button>`
      : `<button class="btn btn-primary" data-act="new" type="button">${icon("undo")}Reopen <kbd>U</kbd></button>`}
    <div class="pane-more">
    ${d.status === "new" ? `<button class="btn" data-act="fp" type="button">${icon("fp")}False positive <kbd>F</kbd></button>` : ""}
    <span class="btn-group">
      ${muted
        ? `<button class="btn" data-act="mute" data-arg="0" type="button">${icon("bell")}Unmute signature</button>`
        : `<button class="btn" data-act="mute" data-arg="60" type="button" title="Mute this signature for 1 hour (m)">${icon("mute")}Mute 1 h</button>
           <button class="btn" data-act="mute" data-arg="1440" type="button" title="Mute for 24 hours">24 h</button>`}
    </span>
    ${isDetector ? "" : st.enabled === false
      ? `<button class="btn" data-act="enable" type="button">${icon("power")}Enable signature</button>`
      : `<button class="btn" data-act="disable" type="button" title="Stop checking packets against this signature">${icon("power")}Disable</button>`}
    <button class="btn" data-act="host" type="button" title="Open ${esc(d.src)} in Endpoints (h)">${icon("host")}Source host <kbd>H</kbd></button>
    <span class="pane-spacer"></span>
    <button class="btn" data-act="ack-shown" type="button" ${untriagedShown ? "" : "disabled"} title="Acknowledge every untriaged alert in the list">${icon("check")}Acknowledge shown (${fmtNum(untriagedShown)})</button>
    </div>`;

  tree.render(buildTree(d));
  table.render(); // refresh the related-alert marks
  if (!tree.selected) tree.select(d.match_start != null ? "sig.match" : "frame", { silent: true, scroll: false });
  renderHex();
  hotBytes(tree.nodes.get(tree.selected)?.bytes, true);
}

function chip(act, arg, label, ic = "filter") {
  return `<button type="button" class="chip-act" data-act="${act}" data-arg="${esc(arg)}">${icon(ic)}${esc(label)}</button>`;
}

function bytesOf(d) {
  const h = d.payload_hex || "";
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}
const printable = (b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : ".");

function buildTree(d) {
  const r = d.rule;
  const rel = d.related || {};
  const bytes = bytesOf(d);
  const prev = (rel.recent_from_src || []).find((x) => x.ts < d.ts);
  const proto = String(d.proto).toLowerCase();
  const nodes = [];

  nodes.push({
    id: "frame", head: true, open: true,
    label: `Alert ${d.id}: ${esc(d.rule_name)}`,
    kids: [
      { id: "frame.time", label: "Arrival time", val: esc(fmtDateTime(d.ts) + "." + String(Math.floor((d.ts % 1) * 1000)).padStart(3, "0")), filter: `age < ${Math.ceil(Date.now() / 1000 - d.ts) + 60}`, copy: String(d.ts) },
      { id: "frame.prev", label: "Time since previous alert from this source", val: prev ? esc(((d.ts - prev.ts)).toFixed(3) + " s") : `<span class="tn-dim">first alert from this source in the database</span>` },
      { id: "frame.sev", label: "Severity", val: sevMark(d.severity), filter: `sev == ${d.severity}`, copy: d.severity },
      { id: "frame.cat", label: "Category", val: esc(d.category), filter: `category == ${d.category}`, copy: d.category },
      { id: "frame.status", label: "Triage status", val: esc(STATUS_LABEL[d.status] || d.status) + (d.status_ts && d.status !== "new" ? ` <span class="tn-dim">${esc(fmtAgo(d.status_ts))}</span>` : ""), filter: `status == ${d.status}`, copy: d.status },
    ],
  });

  nodes.push({
    id: "ip", head: true, open: true,
    label: `Internet Protocol, Src: <span class="tn-val mono">${esc(d.src)}</span>, Dst: <span class="tn-val mono">${esc(d.dst)}</span>`,
    filter: `ip.addr == ${d.src} && ip.addr == ${d.dst}`,
    kids: [
      { id: "ip.src", label: "Source address", val: esc(d.src) + scopeTag(d.src), filter: `ip.src == ${d.src}`, copy: d.src, act: chip("host", d.src, "Host", "host") },
      { id: "ip.dst", label: "Destination address", val: esc(d.dst) + scopeTag(d.dst), filter: `ip.dst == ${d.dst}`, copy: d.dst, act: chip("host", d.dst, "Host", "host") },
    ],
  });

  if (proto === "tcp" || proto === "udp") {
    const name = proto === "tcp" ? "Transmission Control Protocol" : "User Datagram Protocol";
    nodes.push({
      id: "l4", head: true,
      label: `${name}, Src Port: <span class="tn-val mono">${d.sport ?? "—"}</span>, Dst Port: <span class="tn-val mono">${esc(portLabel(d.dport))}</span>`,
      filter: `${proto}.port == ${d.dport}`,
      kids: [
        { id: "l4.sport", label: "Source port", val: esc(portLabel(d.sport)), filter: `sport == ${d.sport}`, copy: String(d.sport) },
        { id: "l4.dport", label: "Destination port", val: esc(portLabel(d.dport)), filter: `dport == ${d.dport}`, copy: String(d.dport) },
      ],
    });
  } else if (proto === "icmp") {
    nodes.push({ id: "l4", head: true, label: "Internet Control Message Protocol", filter: "icmp" });
  }

  // the signature, and the evidence
  const sigKids = [];
  if (r) {
    sigKids.push(
      { id: "sig.id", label: "Rule ID", val: esc(r.id), filter: `rule.id == ${r.id}`, copy: r.id },
      { id: "sig.name", label: "Name", val: esc(r.name), copy: r.name },
      { id: "sig.constraint", label: "Applies to", val: esc([r.protocol.toUpperCase(), r.src_port != null ? `src port ${r.src_port}` : "", r.dst_port != null ? `dst port ${portLabel(r.dst_port)}` : "any port"].filter(Boolean).join(" · ")) },
    );
    const cond = r.content != null ? ["content", JSON.stringify(r.content)]
      : r.content_hex != null ? ["hex", r.content_hex]
        : r.regex != null ? ["regex", "/" + r.regex + "/"] : ["header", "protocol / port only"];
    sigKids.push({ id: "sig.cond", label: `Looks for (${cond[0]}${r.nocase ? ", case-insensitive" : ""})`, val: esc(cond[1]), copy: cond[1] });
  } else if (d.rule_id === "RECON-PORTSCAN") {
    sigKids.push(
      { id: "sig.id", label: "Detector", val: "stateful port-scan detector", filter: `rule.id == ${d.rule_id}` },
      { id: "sig.cond", label: "Fires when", val: "one source probes many distinct ports within a short window" },
    );
  } else {
    sigKids.push({ id: "sig.id", label: "Rule ID", val: `${esc(d.rule_id)} <span class="tn-dim">no longer in the loaded rules file</span>`, filter: `rule.id == ${d.rule_id}` });
  }
  if (d.match_start != null && d.match_end > d.match_start) {
    const ms = d.match_start, me = d.match_end;
    const txt = Array.from(bytes.slice(ms, me), printable).join("");
    sigKids.push({
      id: "sig.match", bytes: [ms, me],
      label: "Matched content",
      val: `"${esc(txt.length > 64 ? txt.slice(0, 64) + "…" : txt)}" <span class="tn-dim">at offset ${d.payload_offset + ms}, ${me - ms} byte${me - ms === 1 ? "" : "s"}</span>`,
      copy: txt,
      filter: `detail contains "${txt.slice(0, 20).replace(/"/g, "")}"`,
    });
  }
  if (r && r.references && r.references.length) {
    sigKids.push({
      id: "sig.refs", label: `References (${r.references.length})`, open: true,
      kids: r.references.map((u, i) => ({
        id: `sig.ref.${i}`,
        label: `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(u.replace(/^https?:\/\//, ""))} ${icon("external")}</a>`,
      })),
    });
  }
  const st = d.rule_state || {};
  const mutedUntil = st.muted_until && st.muted_until > Date.now() / 1000 ? st.muted_until : null;
  sigKids.push({
    id: "sig.state", label: "Signature state",
    val: st.enabled === false ? "disabled — packets are not checked"
      : mutedUntil ? `muted until ${esc(fmtDateTime(mutedUntil))}` : "enabled",
  });
  nodes.push({ id: "sig", head: true, open: true, label: `Signature match: <span class="tn-val mono">${esc(d.rule_id)}</span>`, filter: `rule.id == ${d.rule_id}`, kids: sigKids });

  if (bytes.length) {
    nodes.push({
      id: "payload", head: true, bytes: [0, bytes.length],
      label: `Payload <span class="tn-dim">(${bytes.length} byte${bytes.length === 1 ? "" : "s"} kept${d.payload_offset ? `, from offset ${d.payload_offset}` : ""})</span>`,
      kids: [{ id: "payload.text", label: "As text", val: esc(Array.from(bytes.slice(0, 96), printable).join("") + (bytes.length > 96 ? "…" : "")) }],
    });
  }

  if (d.detail) nodes.push({ id: "detail", head: true, label: "Detection detail", val: esc(clean(d.detail)), copy: d.detail });

  const recent = rel.recent_from_src || [];
  nodes.push({
    id: "hist", head: true, open: true, label: "History",
    kids: [
      { id: "hist.src", label: `Alerts from ${esc(d.src)}`, val: `${fmtNum(rel.same_src)}${rel.first_from_src ? ` <span class="tn-dim">since ${esc(fmtAgo(rel.first_from_src))}</span>` : ""}`, filter: `ip.src == ${d.src}`, act: chip("filter", `ip.src == ${d.src}`, "Show") },
      { id: "hist.rule", label: "Alerts for this signature", val: fmtNum(rel.same_rule), filter: `rule.id == ${d.rule_id}`, act: chip("filter", `rule.id == ${d.rule_id}`, "Show") },
      { id: "hist.pair", label: `Alerts ${esc(d.src)} → ${esc(d.dst)}`, val: fmtNum(rel.same_pair), filter: `ip.src == ${d.src} && ip.dst == ${d.dst}`, act: chip("filter", `ip.src == ${d.src} && ip.dst == ${d.dst}`, "Show") },
      ...(recent.length ? [{
        id: "hist.recent", label: `Recent from this source (${recent.length})`,
        kids: recent.map((x) => ({
          id: `hist.r.${x.id}`,
          label: `${sevMark(x.severity)} <span class="tn-val mono">${esc(fmtClock(x.ts, false))}</span> ${esc(x.rule_name)} <span class="tn-dim">→ ${esc(endpoint(x.dst, x.dport))}</span>`,
          act: chip("alert", x.id, "Open", "apply"),
        })),
      }] : []),
    ],
  });
  return monoize(nodes, new Set([
    "frame.time", "frame.prev", "ip.src", "ip.dst", "l4.sport", "l4.dport",
    "sig.id", "sig.cond", "sig.match", "payload.text", "detail",
  ]));
}

// monospace is for addresses, ports, bytes and timestamps only
function monoize(nodes, ids) {
  for (const n of nodes) {
    if (ids.has(n.id) || [...ids].some((p) => p.endsWith("*") && n.id.startsWith(p.slice(0, -1)))) n.mono = true;
    if (n.kids) monoize(n.kids, ids);
  }
  return nodes;
}

// ---------- hex ----------
function renderHex() {
  const box = $("alert-hex");
  if (!detail) { box.innerHTML = ""; return; }
  const bytes = bytesOf(detail);
  if (!bytes.length) {
    box.innerHTML = `<div class="hex-note">${detail.rule_id === "RECON-PORTSCAN"
      ? "No payload for this alert: the port-scan detector fires on the pattern of many probes, not on one packet's bytes."
      : "No payload bytes were kept for this alert. It matched on protocol and port alone, or was recorded before evidence capture existed."}</div>`;
    return;
  }
  const ms = detail.match_start, me = detail.match_end, base = detail.payload_offset || 0;
  const lines = [];
  for (let off = 0; off < bytes.length; off += 16) {
    const row = bytes.slice(off, off + 16);
    let hx = "", as = "";
    row.forEach((b, j) => {
      const o = off + j;
      const m = ms != null && o >= ms && o < me ? " is-match" : "";
      hx += `<i data-o="${o}" class="${m}">${b.toString(16).padStart(2, "0")}</i>`;
      const ch = printable(b);
      as += `<i data-o="${o}" class="${m}${ch === "." && b !== 46 ? " np" : ""}">${esc(ch)}</i>`;
    });
    lines.push(`<div class="hex-line"><span class="hex-off">${(base + off).toString(16).padStart(4, "0")}</span><span class="hex-bytes">${hx}</span><span class="hex-ascii">${as}</span></div>`);
  }
  box.innerHTML = lines.join("");
}

function hotBytes(range, scroll = false) {
  const box = $("alert-hex");
  box.querySelectorAll("i.is-hot").forEach((i) => i.classList.remove("is-hot"));
  if (!range) return;
  const [s, e] = range;
  let first = null;
  box.querySelectorAll("i[data-o]").forEach((i) => {
    const o = +i.dataset.o;
    if (o >= s && o < e) { i.classList.add("is-hot"); first ??= i; }
  });
  if (scroll && first) first.scrollIntoView({ block: "nearest" });
}

export default view;
