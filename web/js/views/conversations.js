/* Conversations: one row per src → dst → protocol flow, biggest first. */
import { $, api, esc, fmtAgo, fmtBytes, fmtClock, fmtDuration, fmtNum } from "../util.js";
import { flowFields } from "../fields.js";
import { Table } from "../table.js";

let app, table, timer = null, filterActive = false, total = 0;

const view = {
  id: "conversations",
  fields: flowFields,
  placeholder: "Filter conversations… e.g.  ip.addr == 192.168.88.20   ·   bytes > 1m   ·   udp",
  presets: [
    { label: "TCP", expr: "tcp" },
    { label: "UDP", expr: "udp" },
    { label: "Over 100 KB", expr: "bytes > 100k" },
    { label: "Internal ↔ internal", expr: "ip.src.internal && ip.dst.internal" },
    { label: "To the internet", expr: "ip.src.internal && !ip.dst.internal" },
  ],

  init(a) {
    app = a;
    table = new Table($("flow-list"), {
      ariaLabel: "Conversations",
      rowKey: (r) => `${r.src}|${r.dst}|${r.proto}`,
      rowClass: (r) => `p-${["tcp", "udp", "icmp"].includes(r.proto) ? r.proto : "other"}`,
      sort: { key: "bytes", dir: -1 },
      empty: () => (filterActive ? "<b>No conversations match this filter.</b>" : "<b>No conversations yet.</b><br>Each source → destination pair appears here with its packet and byte counts."),
      columns: [
        { key: "src", label: "Address A", cls: "mono w-ip", render: (r) => esc(r.src), filter: (r) => `ip.src == ${r.src}` },
        { key: "dst", label: "Address B", cls: "mono w-ip", render: (r) => esc(r.dst), filter: (r) => `ip.dst == ${r.dst}` },
        { key: "proto", label: "Protocol", cls: "w-proto", render: (r) => esc(r.proto.toUpperCase()), filter: (r) => r.proto },
        { key: "packets", label: "Packets", cls: "num w-num", render: (r) => fmtNum(r.packets), filter: (r) => `packets >= ${r.packets}` },
        { key: "bytes", label: "Bytes", cls: "num w-num", render: (r) => fmtBytes(r.bytes), filter: (r) => `bytes >= ${r.bytes}` },
        { key: "start", label: "Started", cls: "mono w-time", render: (r) => fmtClock(r.first_seen, false), sort: (r) => r.first_seen },
        { key: "dur", label: "Duration", cls: "num w-num", render: (r) => fmtDuration(r.last_seen - r.first_seen), sort: (r) => r.last_seen - r.first_seen },
        { key: "last", label: "Last packet", cls: "wide dim", render: (r) => fmtAgo(r.last_seen), sort: (r) => r.last_seen },
      ],
      onActivate: (r) => {
        if (!r) return;
        app.show("packets");
        app.setFilter("packets", `ip.addr == ${r.src} && ip.addr == ${r.dst}`);
      },
    });
    $("flow-list").addEventListener("contextmenu", (e) => {
      const c = table.cellFilter(e.target); if (!c) return;
      e.preventDefault();
      const pair = `ip.addr == ${c.row.src} && ip.addr == ${c.row.dst}`;
      app.contextMenu(e.clientX, e.clientY, [
        ...app.filterMenu("conversations", c.expr, c.text),
        "-",
        { text: "Show these packets", icon: "apply", run: () => { app.show("packets"); app.setFilter("packets", pair); } },
        { text: "Show alerts between them", icon: "apply", run: () => { app.show("alerts"); app.setFilter("alerts", pair); } },
      ]);
    });
    app.on("rollover", () => load());
  },

  show() { load(); timer = setInterval(() => !app.state.paused && load(), 2000); },
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
    const rows = await api("/api/flows");
    total = rows.length;
    table.setRows(rows);
  } catch { /* next tick */ }
}

export default view;
