/* I/O Graph & statistics: alert timeline by severity, live throughput, and
   the summary tables an analyzer keeps under its Statistics menu. */
import { $, api, esc, fmtBytes, fmtNum, sevMark, SEVERITIES, store, STATUS_LABEL } from "../util.js";
import { drawThroughput, drawTimeline } from "../charts.js";

let app, timer = null;
let hours = store("io.hours") || 24;
let timeline = null, geom = null, hover = -1;
let analytics = null;

const BUCKETS = { 1: 60, 6: 72, 24: 48, 168: 56 };

const view = {
  id: "iograph",
  init(a) {
    app = a;
    $("sev-legend").innerHTML = SEVERITIES.map((s) => sevMark(s)).join("");
    $("range").addEventListener("click", (e) => {
      const b = e.target.closest("[data-hours]"); if (!b) return;
      hours = +b.dataset.hours; store("io.hours", hours); paintRange(); load();
    });
    const cv = $("timeline");
    cv.addEventListener("pointermove", (e) => {
      if (!geom || !timeline) return;
      const r = cv.getBoundingClientRect();
      const x = e.clientX - r.left;
      const i = Math.floor((x - geom.L) / geom.bw);
      const next = i >= 0 && i < geom.n ? i : -1;
      if (next !== hover) { hover = next; paintTimeline(); }
      tip(e, r);
    });
    cv.addEventListener("pointerleave", () => { hover = -1; paintTimeline(); $("timeline-tip").hidden = true; });
    cv.addEventListener("click", () => {
      if (hover < 0 || !timeline) return;
      const b = timeline.series[hover];
      const age = Math.ceil(Date.now() / 1000 - b.t);
      const until = Math.max(0, Math.floor(Date.now() / 1000 - (b.t + timeline.bucket)));
      app.show("alerts");
      app.setFilter("alerts", until > 0 ? `age <= ${age} && age >= ${until}` : `age <= ${age}`);
    });
    $("stat-tables").addEventListener("click", (e) => {
      const t = e.target.closest("[data-filter]"); if (!t) return;
      app.show(t.dataset.view || "alerts");
      app.setFilter(t.dataset.view || "alerts", t.dataset.filter);
    });
    app.on("snapshot", (s) => { if (app.state.view === "iograph") { paintIO(s); paintProto(s); } });
    app.on("theme", () => { if (app.state.view === "iograph") { paintTimeline(); app.state.snapshot && paintIO(app.state.snapshot); } });
    new ResizeObserver(() => { if (app.state.view === "iograph") { paintTimeline(); app.state.snapshot && paintIO(app.state.snapshot); } }).observe($("timeline"));
    paintRange();
  },
  show() {
    load();
    timer = setInterval(() => !app.state.paused && load(), 15000);
    if (app.state.snapshot) paintIO(app.state.snapshot);
  },
  hide() { clearInterval(timer); timer = null; },
};

function paintRange() {
  $("range").querySelectorAll("button").forEach((b) => b.setAttribute("aria-checked", String(+b.dataset.hours === hours)));
}

async function load() {
  try {
    const [t, an] = await Promise.all([
      api(`/api/alerts/timeline?hours=${hours}&buckets=${BUCKETS[hours] || 48}`),
      api(`/api/analytics?hours=${hours}`),
    ]);
    timeline = t; analytics = an;
    paintTimeline();
    paintTables();
  } catch (e) {
    $("stat-tables").innerHTML = `<p class="dim">Couldn't load statistics: ${esc(e.message)}</p>`;
  }
}

function paintTimeline() {
  if (!timeline) return;
  geom = drawTimeline($("timeline"), timeline.series, timeline.bucket, hover);
}

function tip(e, rect) {
  const box = $("timeline-tip");
  if (hover < 0) { box.hidden = true; return; }
  const b = timeline.series[hover];
  const total = SEVERITIES.reduce((n, k) => n + b[k], 0);
  const from = new Date(b.t * 1000), to = new Date((b.t + timeline.bucket) * 1000);
  const f = (d) => d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", hour12: false });
  const day = hours > 24 ? from.toLocaleDateString("en-GB", { weekday: "short", day: "numeric" }) + " " : "";
  box.innerHTML = `<b>${esc(day + f(from))}–${esc(f(to))} · ${fmtNum(total)} alert${total === 1 ? "" : "s"}</b>
    ${SEVERITIES.filter((s) => b[s]).map((s) => `<div class="row">${sevMark(s)}<span>${fmtNum(b[s])}</span></div>`).join("")}
    ${total ? `<div class="row dim" style="margin-top:3px"><span>Click to list them</span></div>` : ""}`;
  box.hidden = false;
  const x = e.clientX - rect.left, y = e.clientY - rect.top;
  const w = box.offsetWidth;
  box.style.left = Math.min(rect.width - w - 6, x + 14) + "px";
  box.style.top = Math.max(6, y - 20) + "px";
}

function paintIO(s) { drawThroughput($("io-big"), s.bandwidth, app.state.alerts.filter((a) => a.ts >= s.bandwidth[0].t)); }

function bars(rows, key, label, filter, view = "alerts") {
  const max = Math.max(1, ...rows.map((r) => r[key]));
  return rows.map((r) => `<tr class="is-link" data-filter="${esc(filter(r))}" data-view="${view}">
      ${label(r)}
      <td class="num bar-cell" style="width:38%"><span class="bar" style="width:${(r[key] / max) * 100}%"></span><span>${fmtNum(r[key])}</span></td></tr>`).join("");
}

function table(title, head, body, empty) {
  return `<section><h3>${title}</h3>${body ? `<table class="mini-table"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>` : `<p class="dim">${empty}</p>`}</section>`;
}

function paintTables() {
  const a = analytics; if (!a) return;
  const span = hours >= 168 ? "7 days" : hours + " h";
  const none = `No alerts in the last ${span}.`;
  const statuses = Object.entries(a.by_status || {}).sort((x, y) => y[1] - x[1]).map(([k, n]) => ({ k, n }));
  $("stat-tables").innerHTML = [
    table(`Top signatures · ${fmtNum(a.total)} alerts in ${span}`, `<th>Signature</th><th>Severity</th><th class="num">Alerts</th>`,
      bars(a.top_rules, "n", (r) => `<td title="${esc(r.rule_id)}">${esc(r.rule_name)}</td><td>${sevMark(r.severity)}</td>`, (r) => `rule.id == ${r.rule_id}`), none),
    table("Top sources", `<th>Address</th><th class="num">Alerts</th>`,
      bars(a.top_sources, "n", (r) => `<td class="mono">${esc(r.host)}</td>`, (r) => `ip.src == ${r.host}`), none),
    table("Top targets", `<th>Address</th><th class="num">Alerts</th>`,
      bars(a.top_targets, "n", (r) => `<td class="mono">${esc(r.host)}</td>`, (r) => `ip.dst == ${r.host}`), none),
    table("Categories", `<th>Category</th><th class="num">Alerts</th>`,
      bars(a.categories, "n", (r) => `<td>${esc(r.category)}</td>`, (r) => `category == ${r.category}`), none),
    table("Triage", `<th>Status</th><th class="num">Alerts</th>`,
      bars(statuses, "n", (r) => `<td>${esc(STATUS_LABEL[r.k] || r.k)}</td>`, (r) => `status == ${r.k}`), none),
    `<section id="proto-hier"></section>`,
  ].join("");
  if (app.state.snapshot) paintProto(app.state.snapshot);
}

function paintProto(s) {
  const el = $("proto-hier"); if (!el) return;
  const rows = Object.entries(s.proto_counts || {}).map(([k, n]) => ({ k, n })).sort((x, y) => y.n - x.n);
  const total = rows.reduce((t, r) => t + r.n, 0);
  el.outerHTML = `<section id="proto-hier">${table(`Protocol hierarchy · ${fmtNum(total)} packets, ${esc(fmtBytes(s.totals.bytes))} today`,
    `<th>Protocol</th><th class="num">Share</th><th class="num">Packets</th>`,
    rows.map((r) => `<tr class="is-link" data-view="packets" data-filter="proto == ${esc(r.k)}"><td>${esc(r.k.toUpperCase())}</td>
      <td class="num bar-cell" style="width:30%"><span class="bar" style="width:${total ? (r.n / total) * 100 : 0}%"></span><span>${total ? ((r.n / total) * 100).toFixed(1) : 0}%</span></td>
      <td class="num">${fmtNum(r.n)}</td></tr>`).join(""), "No packets yet.").replace(/^<section>|<\/section>$/g, "")}</section>`;
}

export default view;
