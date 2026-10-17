---
version: 1
slug: "web-index-html"
primary_target: "web/index.html"
related_targets: ["web/style.css","web/app.js"]
---

## Scope

The Signature NIDS dashboard (`web/`), the single surface of the product. Mode: Operate.
Audience: the homelab owner, glancing to confirm calm and digging in when something fires.
Task: triage alerts to a conclusion (what fired, on which bytes, from which host, is it
recurring), drill alert → host → rule, control noisy rules, read history and reports.

## Direction contract

THESIS: The dashboard is the packet analyzer the owner already knows: a toolbar, a display
filter, and stacked list / dissection tree / hex panes, with severity as coloring rules. It
refuses the dark SOC card grid of KPI tiles and glowing dots.

OWN-WORLD: Light analyzer chrome (#f4f4f2 toolbars, white panes, hairline #d4d4d0 splitters)
with a matching dark theme. Wireshark-style pastel row tints carry severity and protocol.
The display filter field turns green when valid and red when invalid. Selection is solid
blue with white text. Disclosure-tree rows, offset | hex | ASCII dumps, drawn 16px stroke
icons, system UI type, and monospace only for addresses, ports, bytes and timestamps.

STORY: The owner sees at once whether anything is untriaged (status bar expert-info dot plus
summary line). They select an alert and read it dissected down to the matched bytes. They
pivot by "Apply as filter", acknowledge it, and move on with j/k.

FIRST VIEWPORT: Toolbar row (capture state, pause, reload rules, roll over, export, theme),
then view tabs (Alerts · Packets · Endpoints · Conversations · Signatures · I/O Graph ·
Reports), then the display-filter bar with filter buttons. Below that, a one-line capture
summary over an axis-labelled I/O graph strip, then the Alerts list pane (≈45%), the
dissection tree, and the hex pane split by draggable splitters, with the status bar
pinned at the bottom. The primary action, triage of the selected alert, sits in the
tree pane header.

FORM: Packet Analyzer (Wireshark three-pane grammar), position 1 of the ordered list,
taken as IMPECCABLE'S PICK; seed key cd60bd43. Signature interaction: hovering or
selecting the tree's "Matched content" node highlights the exact matched bytes in the
hex pane, and clicking a byte selects its tree node. Motion grammar: 150–200 ms
state-only transitions, and new rows flash their tint once.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance

## Unresolved

- Whether to add browser notifications for critical alerts (not requested).
