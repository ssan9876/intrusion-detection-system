/* Packets: the live packet list, coloured by protocol, newest at the bottom. */
import { $, esc, endpoint, fmtAgo, fmtClock, fmtDateTime, fmtNum, icon, isInternal, portLabel } from "../util.js";
import { packetFields } from "../fields.js";
import { Table } from "../table.js";
import { splitters, Tree } from "../ui.js";

const CAP = 1000;
let app, table, tree;
let rows = [];
let seq = 0;
const seen = new Set();
let filterActive = false;

const keyOf = (p) => `${p.ts}|${p.src}|${p.sport}|${p.dst}|${p.dport}|${p.length}`;

const view = {
  id: "packets",
  fields: packetFields,
  placeholder: "Filter packets… e.g.  tcp && dport == 22   ·   ip.addr == 192.168.88.20   ·   len > 500",
  presets: [
    { label: "TCP", expr: "tcp" },
    { label: "UDP", expr: "udp" },
    { label: "DNS", expr: "port == 53" },
    { label: "Web", expr: "port == 80 || port == 443" },
    { label: "SSH", expr: "port == 22" },
    { label: "Inbound", expr: "!ip.src.internal && ip.dst.internal" },
  ],

  init(a) {
    app = a;
    table = new Table($("packet-list"), {
      ariaLabel: "Packets",
      rowKey: (r) => r.no,
      rowClass: (r) => `p-${["tcp", "udp", "icmp"].includes(r.proto) ? r.proto : "other"}`,
      empty: () => (filterActive ? "<b>No packets match this filter.</b>" : "<b>Waiting for traffic…</b><br>Packets appear here as the sensor sees them."),
      columns: [
        { key: "no", label: "No.", cls: "num w-no", render: (r) => r.no },
        { key: "time", label: "Time", cls: "mono w-time", render: (r) => fmtClock(r.ts), sort: (r) => r.ts },
        { key: "src", label: "Source", cls: "mono w-ip", render: (r) => esc(r.src), filter: (r) => `ip.src == ${r.src}` },
        { key: "dst", label: "Destination", cls: "mono w-ip", render: (r) => esc(r.dst), filter: (r) => `ip.dst == ${r.dst}` },
        { key: "proto", label: "Protocol", cls: "w-proto", render: (r) => esc(r.proto.toUpperCase()), filter: (r) => r.proto },
        { key: "len", label: "Length", cls: "num w-len", render: (r) => r.length, sort: (r) => r.length, filter: (r) => `len == ${r.length}` },
        { key: "info", label: "Info", cls: "wide", render: (r) => esc(info(r)), sort: (r) => r.dport ?? 0, filter: (r) => (r.dport != null ? `dport == ${r.dport}` : r.proto) },
      ],
      onSelect: (r) => renderTree(r),
    });
    table.followable = true;
    table.follow = true;

    tree = new Tree($("packet-tree"), {
      persistKey: "packet",
      onContext: (n, e) => n?.filter && app.contextMenu(e.clientX, e.clientY, app.filterMenu("packets", n.filter, n.copy ?? n.filter)),
    });
    $("packet-tree").addEventListener("click", (e) => {
      const b = e.target.closest("[data-act]"); if (!b) return;
      if (b.dataset.act === "host") app.openHost(b.dataset.arg);
      if (b.dataset.act === "alerts") { app.show("alerts"); app.setFilter("alerts", `ip.addr == ${b.dataset.arg}`); }
    });
    $("packet-list").addEventListener("contextmenu", (e) => {
      const c = table.cellFilter(e.target); if (!c) return;
      e.preventDefault(); table.select(c.row.no, { silent: false });
      app.contextMenu(e.clientX, e.clientY, app.filterMenu("packets", c.expr, c.text));
    });
    splitters($("packet-panes"), "packets", [2, 1]);
    app.on("snapshot", (s) => ingest(s.recent_packets || []));
    app.on("rollover", () => { rows = []; seen.clear(); table.setRows(rows); });
    renderTree(null);
  },

  show() { table.render(); },
  applyFilter(fn, active) { filterActive = active; table.filterFn = active ? fn : null; table.render(); },
  counts() { return { shown: table.view.length, total: rows.length }; },
  onKey(e) {
    if (["j", "k"].includes(e.key)) { table.move(e.key === "j" ? 1 : -1); return true; }
    return false;
  },
};

function info(p) {
  const s = p.summary || "";
  // demo/scapy summaries repeat the addresses already shown in their own columns
  const tail = s.replace(/^\S+\s+\S+\s*->\s*\S+\s*/, "");
  const ports = p.sport != null || p.dport != null ? `${p.sport ?? "?"} → ${portLabel(p.dport)}` : "";
  return [ports, tail].filter(Boolean).join("  ");
}

function ingest(list) {
  let added = 0;
  for (const p of list) {
    const k = keyOf(p);
    if (seen.has(k)) continue;
    seen.add(k);
    rows.push({ ...p, no: ++seq });
    added++;
  }
  if (rows.length > CAP) {
    for (const r of rows.splice(0, rows.length - CAP)) seen.delete(keyOf(r));
  }
  if (seen.size > CAP * 4) { seen.clear(); rows.forEach((r) => seen.add(keyOf(r))); }
  if (added && app.state.view === "packets") table.setRows(rows);
  else table.rows = rows;
}

function renderTree(p) {
  if (!p) {
    tree.render([], `<div class="pane-empty"><b>Select a packet</b><p>Its header fields appear here. The list keeps following new packets while you're scrolled to the bottom; scroll up or press <kbd>Space</kbd> to hold it still.</p></div>`);
    return;
  }
  const proto = p.proto;
  const scope = (h) => `<span class="scope">${isInternal(h) ? "internal" : "external"}</span>`;
  const chip = (act, arg, label, ic) => `<button type="button" class="chip-act" data-act="${act}" data-arg="${esc(arg)}">${icon(ic)}${esc(label)}</button>`;
  const nodes = [
    {
      id: "frame", head: true, open: true, label: `Frame ${p.no}: ${p.length} bytes captured`,
      kids: [
        { id: "f.time", label: "Arrival time", val: esc(fmtDateTime(p.ts)) + ` <span class="tn-dim">${esc(fmtAgo(p.ts))}</span>` },
        { id: "f.len", label: "Frame length", val: `${p.length} bytes`, filter: `len == ${p.length}` },
      ],
    },
    {
      id: "ip", head: true, open: true,
      label: `Internet Protocol, Src: <span class="tn-val mono">${esc(p.src)}</span>, Dst: <span class="tn-val mono">${esc(p.dst)}</span>`,
      filter: `ip.addr == ${p.src} && ip.addr == ${p.dst}`,
      kids: [
        { id: "ip.src", label: "Source address", val: esc(p.src) + scope(p.src), filter: `ip.src == ${p.src}`, copy: p.src, act: chip("host", p.src, "Host", "host") + chip("alerts", p.src, "Alerts", "filter") },
        { id: "ip.dst", label: "Destination address", val: esc(p.dst) + scope(p.dst), filter: `ip.dst == ${p.dst}`, copy: p.dst, act: chip("host", p.dst, "Host", "host") + chip("alerts", p.dst, "Alerts", "filter") },
      ],
    },
  ];
  if (proto === "tcp" || proto === "udp") {
    nodes.push({
      id: "l4", head: true, open: true,
      label: `${proto === "tcp" ? "Transmission Control Protocol" : "User Datagram Protocol"}, Src Port: <span class="tn-val mono">${p.sport}</span>, Dst Port: <span class="tn-val mono">${esc(portLabel(p.dport))}</span>`,
      filter: `${proto}.port == ${p.dport}`,
      kids: [
        { id: "l4.s", label: "Source port", val: esc(portLabel(p.sport)), filter: `sport == ${p.sport}` },
        { id: "l4.d", label: "Destination port", val: esc(portLabel(p.dport)), filter: `dport == ${p.dport}` },
      ],
    });
  } else if (proto === "icmp") nodes.push({ id: "l4", head: true, label: "Internet Control Message Protocol", filter: "icmp" });
  if (p.summary) nodes.push({ id: "sum", head: true, label: "Summary", val: esc(p.summary), mono: true });
  for (const n of nodes) for (const k of n.kids || []) if (k.id !== "f.len") k.mono = true;
  tree.render(nodes);
}

export default view;
