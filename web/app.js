/* Signature NIDS dashboard — live WebSocket client + canvas charts (no deps). */
(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const PROTO_COLORS = { tcp: "#38bdf8", udp: "#a78bfa", icmp: "#34d399", ip: "#fbbf24", other: "#7c8aa0" };
  const SEV_ORDER = ["critical", "high", "medium", "low"];

  let severityFilter = "";
  let seenAlertKeys = new Set();
  let lastTotals = null;

  function fmtBytes(n) {
    if (n < 1024) return n + " B";
    const u = ["KB", "MB", "GB", "TB"]; let i = -1;
    do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
    return n.toFixed(1) + " " + u[i];
  }
  function fmtTime(ts) {
    const d = new Date(ts * 1000);
    return d.toLocaleTimeString("en-US", { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0").slice(0, 2);
  }
  function fmtUptime(s) {
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
    return (h ? h + "h " : "") + (m ? m + "m " : "") + sec + "s";
  }
  function ep(host, port) { return port ? `${host}:${port}` : host; }

  // ---- status ----
  async function loadStatus() {
    try {
      const s = await (await fetch("/api/status")).json();
      $("rules-count").textContent = s.rules_loaded;
      $("iface-text").textContent = s.mode === "demo" ? "demo data" : s.interface;
      const pill = $("mode-pill"), dot = pill.querySelector(".dot");
      $("mode-text").textContent = s.mode === "live" ? "LIVE CAPTURE" : (s.mode === "demo" ? "DEMO MODE" : s.mode);
      dot.className = "dot" + (s.mode === "live" ? "" : " dot-amber");
    } catch (e) { /* retry on next snapshot */ }
  }

  // ---- charts ----
  function drawBandwidth(series) {
    const c = $("bw-chart"); const ctx = c.getContext("2d");
    const w = c.width = c.clientWidth, h = c.height;
    ctx.clearRect(0, 0, w, h);
    if (!series || !series.length) return;
    const max = Math.max(1, ...series.map((p) => p.bps));
    $("chart-peak").textContent = "peak " + fmtBytes(max) + "/s";
    const step = w / (series.length - 1);
    // grid
    ctx.strokeStyle = "rgba(31,42,58,.6)"; ctx.lineWidth = 1;
    for (let i = 1; i < 4; i++) { const y = (h / 4) * i; ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke(); }
    // area + line
    const pts = series.map((p, i) => [i * step, h - (p.bps / max) * (h - 8) - 4]);
    const grad = ctx.createLinearGradient(0, 0, 0, h);
    grad.addColorStop(0, "rgba(56,189,248,.35)"); grad.addColorStop(1, "rgba(56,189,248,0)");
    ctx.beginPath(); ctx.moveTo(0, h);
    pts.forEach(([x, y]) => ctx.lineTo(x, y));
    ctx.lineTo(w, h); ctx.closePath(); ctx.fillStyle = grad; ctx.fill();
    ctx.beginPath(); pts.forEach(([x, y], i) => i ? ctx.lineTo(x, y) : ctx.moveTo(x, y));
    ctx.strokeStyle = "#38bdf8"; ctx.lineWidth = 2; ctx.stroke();
  }

  function drawProtocols(counts) {
    const c = $("proto-chart"); const ctx = c.getContext("2d");
    const w = c.width = c.clientWidth, h = c.height;
    ctx.clearRect(0, 0, w, h);
    const entries = Object.entries(counts || {}).sort((a, b) => b[1] - a[1]);
    const total = entries.reduce((s, [, v]) => s + v, 0);
    const cx = w / 2, cy = h / 2, r = Math.min(w, h) / 2 - 6, inner = r * 0.6;
    const legend = $("proto-legend"); legend.innerHTML = "";
    if (!total) { ctx.fillStyle = "#7c8aa0"; ctx.fillText("no traffic", cx - 24, cy); return; }
    let a0 = -Math.PI / 2;
    for (const [proto, v] of entries) {
      const frac = v / total, a1 = a0 + frac * Math.PI * 2;
      const col = PROTO_COLORS[proto] || PROTO_COLORS.other;
      ctx.beginPath(); ctx.moveTo(cx, cy); ctx.arc(cx, cy, r, a0, a1); ctx.closePath();
      ctx.fillStyle = col; ctx.fill();
      a0 = a1;
      const item = document.createElement("div"); item.className = "item";
      item.innerHTML = `<span class="swatch" style="background:${col}"></span>${proto.toUpperCase()} ${(frac * 100).toFixed(0)}%`;
      legend.appendChild(item);
    }
    ctx.beginPath(); ctx.arc(cx, cy, inner, 0, Math.PI * 2); ctx.fillStyle = "#0f1520"; ctx.fill();
    ctx.fillStyle = "#e6edf6"; ctx.font = "600 14px monospace"; ctx.textAlign = "center"; ctx.textBaseline = "middle";
    ctx.fillText(total.toLocaleString(), cx, cy - 6); ctx.fillStyle = "#7c8aa0"; ctx.font = "10px sans-serif";
    ctx.fillText("packets", cx, cy + 10); ctx.textAlign = "start";
  }

  function renderSeverity(counts) {
    const box = $("severity-bars"); const max = Math.max(1, ...Object.values(counts || {}));
    box.innerHTML = SEV_ORDER.map((s) => {
      const v = counts[s] || 0;
      return `<div class="sev-row"><span class="name">${s}</span><span class="track"><span class="fill ${s}" style="width:${(v / max) * 100}%"></span></span><span class="count">${v}</span></div>`;
    }).join("");
  }

  function renderTalkers(talkers) {
    const box = $("talkers-list");
    const max = Math.max(1, ...talkers.map((t) => t.bytes));
    box.innerHTML = talkers.map((t) =>
      `<div class="bar-row"><div class="bar-top"><span>${t.host}</span><span class="val">${fmtBytes(t.bytes)}</span></div><div class="track"><span class="fill" style="width:${(t.bytes / max) * 100}%"></span></div></div>`
    ).join("") || `<div class="muted">no traffic yet</div>`;
  }

  function renderPackets(packets) {
    const tb = $("packets-table").querySelector("tbody");
    tb.innerHTML = packets.slice().reverse().map((p) =>
      `<tr><td>${fmtTime(p.ts)}</td><td class="proto-tag">${p.proto.toUpperCase()}</td><td>${ep(p.src, p.sport)}</td><td>${ep(p.dst, p.dport)}</td><td>${p.length}</td><td class="detail">${escapeHtml(p.summary || "")}</td></tr>`
    ).join("");
  }

  function alertKey(a) { return `${a.ts}|${a.rule_id}|${a.src}|${a.dst}`; }

  function renderAlerts(alerts) {
    const tb = $("alerts-table").querySelector("tbody");
    const filtered = alerts.filter((a) => !severityFilter || a.severity === severityFilter);
    tb.innerHTML = filtered.slice().reverse().map((a) => {
      const isNew = !seenAlertKeys.has(alertKey(a));
      return `<tr class="${isNew ? "new-alert" : ""}"><td>${fmtTime(a.ts)}</td><td><span class="badge ${a.severity}">${a.severity}</span></td><td title="${escapeHtml(a.rule_id)}">${escapeHtml(a.rule_name)}</td><td>${ep(a.src, a.sport)}</td><td>${ep(a.dst, a.dport)}</td><td class="detail" title="${escapeHtml(a.detail || "")}">${escapeHtml(a.detail || "")}</td></tr>`;
    }).join("") || `<tr><td colspan="6" class="muted" style="text-align:center;padding:20px">no alerts${severityFilter ? " at this severity" : ""}</td></tr>`;
    alerts.forEach((a) => seenAlertKeys.add(alertKey(a)));
    if (seenAlertKeys.size > 5000) seenAlertKeys = new Set(alerts.map(alertKey));
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  }

  // ---- snapshot apply ----
  let latestAlerts = [];
  function applySnapshot(d) {
    $("stat-packets").textContent = d.totals.packets.toLocaleString();
    $("stat-bytes").textContent = fmtBytes(d.totals.bytes);
    $("stat-flows").textContent = d.totals.flows.toLocaleString();
    $("stat-alerts").textContent = d.totals.alerts.toLocaleString();
    $("stat-uptime").textContent = "up " + fmtUptime(d.uptime);

    const last = d.bandwidth[d.bandwidth.length - 1] || { pps: 0, bps: 0 };
    $("stat-pps").textContent = last.pps + " pps";
    $("stat-bps").textContent = fmtBytes(last.bps) + "/s";

    drawBandwidth(d.bandwidth);
    drawProtocols(d.proto_counts);
    renderSeverity(d.severity_counts);
    renderTalkers(d.top_talkers || []);
    renderPackets(d.recent_packets || []);
    latestAlerts = d.recent_alerts || [];
    renderAlerts(latestAlerts);
  }

  // ---- daily logs ----
  async function loadLogs() {
    try {
      const d = await (await fetch("/api/logs")).json();
      const nxt = new Date(d.next_rollover);
      $("rollover-info").textContent =
        `Rolls over daily at ${String(d.rollover_hour).padStart(2, "0")}:00 — next ${nxt.toLocaleString("en-US", { hour12: false })}`;
      const box = $("logs-list");
      box.innerHTML = d.logs.map((l) =>
        `<div class="log-item"><a href="/api/logs/${encodeURIComponent(l.name)}" target="_blank">${escapeHtml(l.name)}</a><span class="log-size">${fmtBytes(l.size)}</span></div>`
      ).join("") || `<div class="muted">no archived days yet</div>`;
    } catch (e) { /* ignore */ }
  }

  $("rollover-btn").addEventListener("click", async () => {
    if (!confirm("Archive today's activity to a log file and reset live stats now?")) return;
    const btn = $("rollover-btn");
    btn.disabled = true; btn.textContent = "rolling…";
    try {
      const r = await (await fetch("/api/rollover", { method: "POST" })).json();
      btn.textContent = "saved ✓";
      await loadLogs();
    } catch (e) { btn.textContent = "failed"; }
    setTimeout(() => { btn.disabled = false; btn.textContent = "Roll over now"; }, 2000);
  });

  // ---- websocket ----
  function connect() {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.host}/ws`);
    const connPill = $("conn-pill"); const connDot = connPill.querySelector(".dot");
    ws.onopen = () => { connDot.className = "dot"; loadStatus(); };
    ws.onclose = () => { connDot.className = "dot dot-red"; setTimeout(connect, 1500); };
    ws.onerror = () => ws.close();
    ws.onmessage = (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.type === "snapshot") applySnapshot(msg.data);
      else if (msg.type === "alert") { /* snapshot will refresh within 1s; flash handled there */ }
      else if (msg.type === "rollover") { seenAlertKeys = new Set(); loadLogs(); }
    };
  }

  // ---- filter buttons ----
  $("sev-filter").addEventListener("click", (e) => {
    const btn = e.target.closest("button"); if (!btn) return;
    severityFilter = btn.dataset.sev;
    $("sev-filter").querySelectorAll("button").forEach((b) => b.classList.toggle("active", b === btn));
    renderAlerts(latestAlerts);
  });

  loadStatus();
  loadLogs();
  connect();
  setInterval(loadStatus, 10000);
  setInterval(loadLogs, 60000);
})();
