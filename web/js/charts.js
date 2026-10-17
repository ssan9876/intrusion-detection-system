/* Canvas charts in the analyzer's I/O-graph style: plain plot area, hairline
   grid, labelled axes. Colours come from CSS custom properties so both themes
   redraw correctly. */
import { cssVar, fmtBytes, SEVERITIES } from "./util.js";

function prep(c) {
  const dpr = window.devicePixelRatio || 1;
  const w = c.clientWidth, h = c.clientHeight;
  if (!w || !h) return null;
  if (c.width !== Math.round(w * dpr) || c.height !== Math.round(h * dpr)) {
    c.width = Math.round(w * dpr); c.height = Math.round(h * dpr);
  }
  const ctx = c.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);
  return { ctx, w, h };
}

function niceMax(v) {
  if (v <= 0) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  const n = v / p;
  return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * p;
}

function niceBytesMax(v) {
  // round up on a 1024 ladder so the axis reads 4 KB / 8 KB rather than 5120 B
  if (v <= 0) return 1024;
  let unit = 1;
  while (v / unit >= 1024 && unit < 1024 ** 4) unit *= 1024;
  return niceMax(v / unit) * unit;
}

function font(px, weight = 400) {
  return `${weight} ${px}px ${cssVar("--font-ui") || "system-ui"}`;
}

function axes(ctx, x0, y0, w, h, ticks, fmtY, labels) {
  const grid = cssVar("--plot-grid"), axis = cssVar("--plot-axis"), text = cssVar("--text-3");
  ctx.lineWidth = 1;
  ctx.font = font(10.5);
  ctx.fillStyle = text;
  ctx.textAlign = "right"; ctx.textBaseline = "middle";
  for (let i = 0; i <= ticks.n; i++) {
    const y = Math.round(y0 + h - (h * i) / ticks.n) + 0.5;
    ctx.strokeStyle = i === 0 ? axis : grid;
    ctx.beginPath(); ctx.moveTo(x0, y); ctx.lineTo(x0 + w, y); ctx.stroke();
    ctx.fillText(fmtY((ticks.max * i) / ticks.n), x0 - 6, y);
  }
  ctx.textAlign = "center"; ctx.textBaseline = "top";
  for (const [x, label] of labels) {
    const xx = Math.round(x) + 0.5;
    ctx.strokeStyle = axis;
    ctx.beginPath(); ctx.moveTo(xx, y0 + h); ctx.lineTo(xx, y0 + h + 3); ctx.stroke();
    ctx.fillText(label, xx, y0 + h + 5);
  }
}

/* Throughput over the last 60 s, with alert instants as ticks along the floor. */
export function drawThroughput(canvas, series, alertTimes = [], { compact = false } = {}) {
  const p = prep(canvas); if (!p || !series.length) return;
  const { ctx, w, h } = p;
  const L = compact ? 52 : 60, R = 10, T = 8, B = compact ? 18 : 22;
  const pw = w - L - R, ph = h - T - B;
  const max = niceBytesMax(Math.max(...series.map((s) => s.bps)) * 1.1);
  const t0 = series[0].t, t1 = series[series.length - 1].t;
  const xOf = (t) => L + ((t - t0) / Math.max(1, t1 - t0)) * pw;
  const labels = [];
  for (let s = 60; s >= 0; s -= compact ? 15 : 10) labels.push([xOf(t1 - s), s ? `-${s}s` : "now"]);
  axes(ctx, L, T, pw, ph, { n: compact ? 2 : 4, max }, (v) => (v ? fmtBytes(v) + "/s" : "0"), labels);

  const line = cssVar("--plot-line");
  ctx.beginPath();
  series.forEach((s, i) => {
    const x = xOf(s.t), y = T + ph - (s.bps / max) * ph;
    i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
  });
  ctx.lineTo(xOf(t1), T + ph); ctx.lineTo(xOf(t0), T + ph); ctx.closePath();
  ctx.fillStyle = cssVar("--plot-fill"); ctx.fill();
  ctx.beginPath();
  series.forEach((s, i) => {
    const x = xOf(s.t), y = T + ph - (s.bps / max) * ph;
    i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
  });
  ctx.strokeStyle = line; ctx.lineWidth = 1.5; ctx.lineJoin = "round"; ctx.stroke();

  for (const a of alertTimes) {
    if (a.ts < t0 || a.ts > t1 + 1) continue;
    const x = Math.round(xOf(a.ts)) + 0.5;
    ctx.strokeStyle = cssVar(`--sev-${a.severity}-mark`);
    ctx.lineWidth = 2;
    ctx.beginPath(); ctx.moveTo(x, T + ph - 7); ctx.lineTo(x, T + ph); ctx.stroke();
  }
}

/* Alerts per bucket, stacked by severity. Returns geometry for hover hit-testing. */
export function drawTimeline(canvas, series, bucket, hover = -1) {
  const p = prep(canvas); if (!p) return null;
  const { ctx, w, h } = p;
  const L = 44, R = 10, T = 10, B = 24;
  const pw = w - L - R, ph = h - T - B;
  const totals = series.map((s) => SEVERITIES.reduce((n, k) => n + s[k], 0));
  const max = niceMax(Math.max(1, ...totals));
  const n = series.length || 1;
  const bw = pw / n;
  const labels = [];
  const every = Math.max(1, Math.ceil(n / Math.max(2, Math.floor(pw / 70))));
  const longSpan = bucket * n > 86400 * 1.5;
  series.forEach((s, i) => {
    if (i % every) return;
    const d = new Date(s.t * 1000);
    const lab = longSpan
      ? d.toLocaleDateString("en-GB", { weekday: "short", day: "numeric" })
      : d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", hour12: false });
    labels.push([L + i * bw + bw / 2, lab]);
  });
  axes(ctx, L, T, pw, ph, { n: 4, max }, (v) => (Number.isInteger(v) ? String(v) : v.toFixed(1)), labels);

  const gap = bw > 6 ? 1.5 : 0.5;
  series.forEach((s, i) => {
    let y = T + ph;
    const x = L + i * bw + gap / 2;
    if (i === hover) {
      ctx.fillStyle = cssVar("--plot-hover");
      ctx.fillRect(L + i * bw, T, bw, ph);
    }
    for (const sev of ["low", "medium", "high", "critical"]) {
      if (!s[sev]) continue;
      const bh = (s[sev] / max) * ph;
      ctx.fillStyle = cssVar(`--sev-${sev}-mark`);
      ctx.fillRect(x, y - bh, Math.max(1, bw - gap), bh);
      y -= bh;
    }
  });
  return { L, T, pw, ph, bw, n };
}
