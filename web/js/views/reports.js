/* Reports: the archived daily reports, read in place. */
import { $, api, esc, fmtBytes, icon } from "../util.js";

let app, logs = [], meta = null, current = null;

const view = {
  id: "reports",
  init(a) {
    app = a;
    $("report-list").addEventListener("click", (e) => {
      const b = e.target.closest("[data-name]"); if (b) open(b.dataset.name);
    });
    $("report-list").addEventListener("keydown", (e) => {
      if (!["ArrowDown", "ArrowUp", "j", "k"].includes(e.key)) return;
      e.preventDefault();
      const i = logs.findIndex((l) => l.name === current);
      const n = logs[Math.max(0, Math.min(logs.length - 1, i + (e.key === "ArrowDown" || e.key === "j" ? 1 : -1)))];
      if (n) { open(n.name); $("report-list").querySelector(`[data-name="${CSS.escape(n.name)}"]`)?.focus(); }
    });
    $("reports-head").addEventListener("click", (e) => { if (e.target.closest("[data-act=rollover]")) app.rollover(); });
    app.on("rollover", () => load(true));
  },
  show() { load(); },
};

async function load(selectNewest = false) {
  try {
    const d = await api("/api/logs");
    meta = d; logs = d.logs;
    // the server's timestamp can land a fraction of a second before the hour
    const next = new Date(Math.round(new Date(d.next_rollover) / 60000) * 60000);
    $("reports-head").innerHTML = `
      <div class="reports-info">Daily at ${String(d.rollover_hour).padStart(2, "0")}:00 · next ${esc(next.toLocaleString("en-GB", { weekday: "short", hour: "2-digit", minute: "2-digit", hour12: false }))}${d.retention_days ? ` · kept ${d.retention_days} days` : " · kept forever"}</div>
      <span class="pane-spacer"></span>
      <button class="btn" type="button" data-act="rollover">${icon("rollover")}Roll over now</button>`;
    $("report-list").innerHTML = logs.length ? logs.map((l) => `
      <button type="button" class="report-item" data-name="${esc(l.name)}" aria-current="${l.name === current}">
        <span class="mono">${esc(l.name.replace(/^nids-|\.txt$/g, "").replace("_", " · "))}</span>
        <span class="dim">${esc(fmtBytes(l.size))}</span>
      </button>`).join("")
      : `<div class="pane-empty"><b>No reports yet</b><p>A report is written at each daily rollover, or when you click “Roll over now”.</p></div>`;
    if (logs.length && (selectNewest || !current || !logs.some((l) => l.name === current))) open(logs[0].name);
    if (!logs.length) { $("report-actions").innerHTML = ""; $("report-text").textContent = ""; }
  } catch (e) {
    $("report-list").innerHTML = `<div class="pane-empty"><b>Couldn't list reports</b><p>${esc(e.message)}</p></div>`;
  }
}

async function open(name) {
  current = name;
  $("report-list").querySelectorAll(".report-item").forEach((b) => b.setAttribute("aria-current", String(b.dataset.name === name)));
  const l = logs.find((x) => x.name === name);
  const n = encodeURIComponent(name);
  $("report-actions").innerHTML = `<span class="pane-title">${esc(name)}</span><span class="pane-spacer"></span>
    <a class="btn" href="/api/logs/${n}?download=1">${icon("download")}Download .txt</a>
    ${l && l.json ? `<a class="btn" href="/api/logs/${encodeURIComponent(l.json)}?download=1">${icon("download")}.json</a>` : ""}`;
  $("report-text").textContent = "Loading…";
  try {
    const txt = await api(`/api/logs/${n}`);
    if (current === name) $("report-text").textContent = txt;
  } catch (e) { $("report-text").textContent = "Couldn't load this report: " + e.message; }
}

export default view;
