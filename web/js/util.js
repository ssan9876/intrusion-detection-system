/* Shared helpers: escaping, formatting, API calls, small DOM utilities. */

export const $ = (id) => document.getElementById(id);

export const SEVERITIES = ["critical", "high", "medium", "low"];
export const SEV_RANK = { low: 1, medium: 2, high: 3, critical: 4 };
export const STATUS_LABEL = { new: "New", ack: "Acknowledged", fp: "False positive", muted: "Muted" };

// Every dynamic value goes through this before touching innerHTML.
export function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));
}

// Payload previews carry raw bytes; show control characters as a middle dot.
export function clean(s) {
  return String(s ?? "").replace(/[\x00-\x1f\x7f-\x9f\ufffd]/g, "\u00b7");
}

export function icon(name, cls = "") {
  return `<svg class="ic ${cls}" aria-hidden="true"><use href="#i-${name}"/></svg>`;
}

export function sevMark(sev) {
  const s = SEV_RANK[sev] ? sev : "low";
  return `<span class="sev sev-${s}"><svg class="sev-mark" aria-hidden="true"><use href="#sev-${s}"/></svg>${esc(s)}</span>`;
}

export function fmtBytes(n) {
  n = Number(n) || 0;
  if (n < 1024) return n + " B";
  const u = ["KB", "MB", "GB", "TB"]; let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return (n >= 100 ? n.toFixed(0) : n.toFixed(1)) + " " + u[i];
}

export function fmtNum(n) { return (Number(n) || 0).toLocaleString("en-US"); }

export function fmtClock(ts, ms = true) {
  const d = new Date(ts * 1000);
  const t = d.toLocaleTimeString("en-GB", { hour12: false });
  return ms ? t + "." + String(d.getMilliseconds()).padStart(3, "0") : t;
}

export function fmtDateTime(ts) {
  const d = new Date(ts * 1000);
  return d.toLocaleDateString("en-CA") + " " + d.toLocaleTimeString("en-GB", { hour12: false });
}

export function fmtAgo(ts, now = Date.now() / 1000) {
  const s = Math.max(0, Math.round(now - ts));
  if (s < 60) return s + "s ago";
  if (s < 3600) return Math.floor(s / 60) + "m ago";
  if (s < 86400) return Math.floor(s / 3600) + "h " + Math.floor((s % 3600) / 60) + "m ago";
  return Math.floor(s / 86400) + "d ago";
}

export function fmtDuration(s) {
  s = Math.max(0, Math.round(s));
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${s % 60}s`;
  return `${s}s`;
}

// Well-known ports, for "Dst Port: 80 (http)" style labels.
const SERVICES = {
  20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 67: "dhcp", 68: "dhcp",
  80: "http", 110: "pop3", 123: "ntp", 137: "netbios-ns", 139: "netbios", 143: "imap", 161: "snmp",
  389: "ldap", 443: "https", 445: "smb", 465: "smtps", 587: "submission", 993: "imaps", 995: "pop3s",
  1337: "waste", 1389: "ldap-alt", 1433: "mssql", 1900: "ssdp", 3306: "mysql", 3333: "stratum",
  3389: "rdp", 4444: "metasploit", 5353: "mdns", 5432: "postgres", 5900: "vnc", 6379: "redis",
  8080: "http-alt", 8443: "https-alt", 9001: "tor-orport",
};
export const service = (p) => SERVICES[p] || "";
export function portLabel(p) {
  if (p == null) return "";
  const s = service(p);
  return s ? `${p} (${s})` : String(p);
}
export function endpoint(host, port) { return port != null && port !== "" ? `${host}:${port}` : host; }

// RFC 1918 / CGNAT / loopback / link-local / ULA, mirrored from ids/store.py:is_internal
export function isInternal(h) {
  if (!h) return false;
  if (h.includes(":")) return /^(fe8|fc|fd|::1$)/i.test(h);
  const p = h.split(".").map(Number);
  if (p.length !== 4 || p.some((x) => Number.isNaN(x))) return false;
  return p[0] === 10 || p[0] === 127 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31)
    || (p[0] === 192 && p[1] === 168) || (p[0] === 169 && p[1] === 254)
    || (p[0] === 100 && p[1] >= 64 && p[1] <= 127);
}

export async function api(path, opts = {}) {
  const init = { ...opts, headers: { ...(opts.headers || {}) } };
  if (opts.body && typeof opts.body !== "string") {
    init.body = JSON.stringify(opts.body);
    init.headers["Content-Type"] = "application/json";
  }
  const res = await fetch(path, init);
  const isJson = (res.headers.get("content-type") || "").includes("json");
  const data = isJson ? await res.json() : await res.text();
  if (!res.ok) {
    let msg = (data && data.detail) || res.statusText || "request failed";
    if (Array.isArray(msg)) msg = msg.map((d) => d.msg).join("; ");
    throw new Error(msg);
  }
  return data;
}

export function store(key, value) {
  try {
    if (value === undefined) return JSON.parse(localStorage.getItem("nids." + key));
    localStorage.setItem("nids." + key, JSON.stringify(value));
  } catch { return null; }
  return value;
}

export function debounceFrame(fn) {
  let queued = false;
  return () => {
    if (queued) return;
    queued = true;
    requestAnimationFrame(() => { queued = false; fn(); });
  };
}

export function cssVar(name, el = document.documentElement) {
  return getComputedStyle(el).getPropertyValue(name).trim();
}
