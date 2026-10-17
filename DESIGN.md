---
name: Signature NIDS
description: A self-hosted network intrusion detection dashboard built as a packet analyzer workbench.
colors:
  accent: "#2a62b8"
  accent-hover: "#2357a5"
  accent-ink: "#ffffff"
  accent-soft: "#e3ecfa"
  chrome: "#f2f2ef"
  chrome-2: "#e7e7e3"
  chrome-3: "#dcdcd7"
  pane: "#ffffff"
  pane-alt: "#f7f7f5"
  line: "#d5d5cf"
  line-strong: "#b9b9b2"
  text: "#1d1e20"
  text-2: "#4d5056"
  text-3: "#686c73"
  row-hover: "#eef3fb"
  sev-critical-bg: "#ffd9d7"
  sev-critical-fg: "#8c1212"
  sev-critical-mark: "#d42c22"
  sev-high-bg: "#ffe5cb"
  sev-high-fg: "#853b00"
  sev-high-mark: "#e3730e"
  sev-medium-bg: "#fff3bd"
  sev-medium-fg: "#6a4f00"
  sev-medium-mark: "#c99a00"
  sev-low-bg: "#e1ecff"
  sev-low-fg: "#1c4686"
  sev-low-mark: "#4a82d8"
  proto-tcp: "#e8e6ff"
  proto-udp: "#dbeeff"
  proto-icmp: "#fbe1fc"
  proto-other: "#f1f1ee"
  filter-ok: "#d5f3cf"
  filter-bad: "#ffd9d7"
  live: "#1f9d45"
  warn: "#c78a00"
  down: "#c8352b"
  hex-hover: "#c9dbf7"
typography:
  headline:
    fontFamily: "Segoe UI Variable Text, Segoe UI, system-ui, -apple-system, Helvetica Neue, Arial, sans-serif"
    fontSize: "15px"
    fontWeight: 600
    lineHeight: 1.4
  title:
    fontFamily: "Segoe UI Variable Text, Segoe UI, system-ui, -apple-system, Helvetica Neue, Arial, sans-serif"
    fontSize: "13.5px"
    fontWeight: 600
    lineHeight: 1.4
  state:
    fontFamily: "Segoe UI Variable Text, Segoe UI, system-ui, -apple-system, Helvetica Neue, Arial, sans-serif"
    fontSize: "14px"
    fontWeight: 650
    lineHeight: 1.4
  body:
    fontFamily: "Segoe UI Variable Text, Segoe UI, system-ui, -apple-system, Helvetica Neue, Arial, sans-serif"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.4
  grid:
    fontFamily: "Segoe UI Variable Text, Segoe UI, system-ui, -apple-system, Helvetica Neue, Arial, sans-serif"
    fontSize: "12.5px"
    fontWeight: 400
    lineHeight: "22px"
    fontFeature: "tnum"
  label:
    fontFamily: "Segoe UI Variable Text, Segoe UI, system-ui, -apple-system, Helvetica Neue, Arial, sans-serif"
    fontSize: "11.5px"
    fontWeight: 400
    lineHeight: 1.4
  mono:
    fontFamily: "ui-monospace, Cascadia Mono, SF Mono, Menlo, Consolas, DejaVu Sans Mono, monospace"
    fontSize: "12px"
    fontWeight: 400
    lineHeight: "20px"
    fontFeature: "tnum"
rounded:
  inset: "3px"
  control: "4px"
  menu: "5px"
  dialog: "6px"
spacing:
  xxs: "2px"
  xs: "4px"
  sm: "6px"
  md: "8px"
  lg: "10px"
  xl: "12px"
  xxl: "16px"
  row: "22px"
components:
  button:
    backgroundColor: "{colors.pane}"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
    padding: "0 10px"
    height: "26px"
  button-hover:
    backgroundColor: "{colors.chrome-2}"
  button-primary:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.accent-ink}"
    rounded: "{rounded.control}"
    padding: "0 10px"
    height: "26px"
  button-primary-hover:
    backgroundColor: "{colors.accent-hover}"
  tool:
    backgroundColor: "transparent"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
    padding: "0 9px"
    height: "28px"
  tool-hover:
    backgroundColor: "{colors.chrome-2}"
  preset:
    backgroundColor: "{colors.pane}"
    textColor: "{colors.text-2}"
    rounded: "{rounded.control}"
    padding: "0 9px"
    height: "24px"
  preset-pressed:
    backgroundColor: "{colors.accent-soft}"
    textColor: "{colors.text}"
  filter-field:
    backgroundColor: "{colors.pane}"
    textColor: "{colors.text}"
    typography: "{typography.mono}"
    rounded: "{rounded.control}"
    height: "28px"
  filter-field-valid:
    backgroundColor: "{colors.filter-ok}"
  filter-field-invalid:
    backgroundColor: "{colors.filter-bad}"
  tab:
    backgroundColor: "transparent"
    textColor: "{colors.text-2}"
    padding: "0 12px"
    height: "31px"
  tab-count-hot:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.accent-ink}"
    rounded: "{rounded.inset}"
    padding: "0 5px"
  grid-row:
    backgroundColor: "{colors.pane}"
    textColor: "{colors.text}"
    typography: "{typography.grid}"
    padding: "0 8px"
    height: "{spacing.row}"
  grid-row-critical:
    backgroundColor: "{colors.sev-critical-bg}"
    textColor: "{colors.sev-critical-fg}"
  grid-row-triaged:
    backgroundColor: "{colors.pane}"
    textColor: "{colors.text-2}"
  grid-row-selected:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.accent-ink}"
  pane-head:
    backgroundColor: "{colors.pane-alt}"
    padding: "3px 8px"
    height: "34px"
---

# Design System: Signature NIDS

## Overview

**Creative North Star: "The Packet Analyzer"**

The dashboard is the packet analyzer the owner already knows: a toolbar, a display filter, view tabs, and stacked list / dissection tree / hex panes divided by draggable hairline splitters, with a status bar pinned to the bottom. Severity and protocol arrive the way they do in Wireshark, as pastel coloring-rule row tints, not as cards, tiles, or glowing indicators. Light analyzer chrome is the default; a matching dark theme follows `prefers-color-scheme` and can be forced with `data-theme`.

Density is that of a desktop tool: 13px system UI type, 22px grid rows, 24 to 28px controls, hairline borders everywhere and no ornament. Calm looks calm because the chrome is neutral grey and white; an untriaged alert is impossible to miss because only untriaged rows carry colour. The signature interaction links the tree to the bytes: hovering or selecting the "Matched content" node highlights the exact matched bytes in the hex pane, and clicking a byte selects its tree node.

The world rejects the dark SOC card grid: no KPI tile wall, no glowing or pulsing status dots, no decorative gradients.

**Key Characteristics:**
- Three-pane analyzer grammar: list, dissection tree, offset | hex | ASCII dump.
- Severity as row tint plus a fixed shape ramp, never colour alone.
- One blue accent for selection, focus, and primary actions.
- System UI type; monospace reserved for wire data.
- Flat, hairline-divided surfaces; shadows only on floating layers.
- State-only motion of 150 to 200ms; new rows flash their tint once.

## Colors

A neutral warm-grey analyzer chrome with white panes, one working blue, and a four-step pastel severity ramp borrowed from packet-analyzer coloring rules. Every colour token has a dark-theme counterpart on `:root` (see the sidecar).

### Primary
- **Analyzer Selection Blue** (accent): the solid fill of the selected row, selected tree node, selected report, highlighted hex bytes, active segmented-control option, hot tab-count badge, primary button, and the 2px active-tab underline. It is also the focus ring colour and the I/O plot line.
- **Pressed Selection Blue** (accent-hover): hover state of primary buttons only.
- **Selection Wash** (accent-soft): pressed filter presets, splitter hover, and the bar fills behind counts in mini tables.

### Neutral
- **Toolbar Grey** (chrome): toolbar, tabs, filter bar, table headers, splitters, status bar.
- **Hover Grey / Press Grey** (chrome-2, chrome-3): hover and active fills for toolbar tools and buttons; the off track of the switch.
- **Pane White** (pane) and **Pane Header Grey** (pane-alt): pane bodies and pane header strips; pane-alt also backs code blocks, port tags, and kbd keys.
- **Hairline** (line) and **Strong Hairline** (line-strong): every divider, splitter edge, and control border; strong hairline for input and button borders and floating-layer borders.
- **Ink, Secondary Ink, Tertiary Ink** (text, text-2, text-3): primary labels; secondary copy and triaged rows; column dims, offsets, captions, placeholders.
- **Row Hover Blue** (row-hover): hover on tree rows, report items, and linked mini-table rows.

### Severity coloring rules
- **Critical Rose / High Apricot / Medium Butter / Low Sky** (sev-*-bg with sev-*-fg): untriaged alert row tints and their text.
- **Severity marks** (sev-*-mark): the saturated colour of each severity shape, the expert-info dot, and the summary state word for critical and high.

### Protocol and state
- **Protocol tints** (proto-tcp lavender, proto-udp ice, proto-icmp orchid, proto-other grey): packet-list coloring rules.
- **Filter Valid Green / Filter Invalid Rose** (filter-ok, filter-bad): the display filter background as it parses.
- **Live / Demo / Down** (live, warn, down): the capture LED; live green is also the calm state word.

### Named Rules
**The One Accent Rule.** Blue is the only interactive colour. Selection, focus, and primary actions use the accent; nothing else does.

**The Untriaged-Only Tint Rule.** Only untriaged alert rows carry severity tint. Acknowledged, false-positive, and muted rows drop to Pane White with Secondary Ink (false positives also strike through the rule name; muted rows dim to 78%). The colour on screen is the work left to do.

**The Shape-Plus-Colour Rule.** Severity is always a fixed mark plus colour: low is a hollow circle, medium a filled dot, high a filled triangle, critical a filled diamond. Never signal severity by colour alone, and never change the shape mapping.

## Typography

**Body Font:** Segoe UI Variable Text (with Segoe UI, system-ui, -apple-system, Helvetica Neue, Arial)
**Mono Font:** ui-monospace (with Cascadia Mono, SF Mono, Menlo, Consolas, DejaVu Sans Mono)

**Character:** The platform's own UI face at desktop-tool sizes, so the dashboard reads as a native utility; monospace appears only where the data is wire data. No web fonts are loaded (the product forbids external calls).

### Hierarchy
- **Headline** (600, 15px): dialog titles only.
- **State** (650, 14px): the summary state word ("76 alerts to triage", calm in live green).
- **Title** (600, 13.5px): brand name, statistics section titles, empty-state headings.
- **Body** (400, 13px, 1.4): all UI copy, tree rows, buttons at 12.5px, pane titles at 600.
- **Grid** (400, 12.5px, 22px rows, tabular numerals): packet, alert, host, and rule lists. Headers are 600 at 12px in Secondary Ink.
- **Label** (400, 11 to 11.5px): captions, context-menu labels, mini-table headers, scope tags.
- **Mono** (400, 12px, 20px in the hex pane, tabular numerals): addresses, ports, byte counts, timestamps, the display filter input, hex dumps, rule definitions, and matched-pattern fields.

### Named Rules
**The Wire Data Rule.** Monospace is only for addresses, ports, bytes, timestamps, and byte or pattern fields. Signature names, severity, status, counts of things, and all prose stay in the UI face.

## Layout

A full-viewport grid of five rows: toolbar (28px tools), view tabs (31px), display-filter bar with preset buttons, the view area, and a 25px status bar. Views stack panes vertically (list about 45%, dissection tree, hex) with 5px draggable splitters; Reports uses a side list (240 to 300px) beside the text pane. Pane headers are 34px strips that hold the pane title and the pane's actions, including the primary triage action in the tree pane.

The Alerts view opens with an overview: one summary line (state word, oldest-untriaged age, then dot-separated facts) over a full-width, axis-labelled I/O strip (74px, 80px on mobile) with severity ticks along its baseline. Statistics pages cap at 1500px and lay tables in an auto-fit grid (min 300px).

Spacing is a tight 2 / 4 / 6 / 8 / 10 / 12 / 16px rhythm; cell padding is 0 8px.

Responsive: at 1100px toolbar labels collapse to icons; at 760px the app becomes a scrolling page, panes stack with fixed list heights (52vh), splitters disappear, the status bar becomes sticky, the primary triage button stretches full width, and secondary pane actions move to a horizontally scrolling row. Grids keep a minimum width (680px) and scroll horizontally rather than reflow.

### Named Rules
**The Summary Line Rule.** The overview is one summary line over a full-width axis-labelled I/O strip. Never a KPI tile grid.

## Elevation & Depth

Flat by default. Depth is tonal: grey chrome around white panes, separated by hairlines. Shadows exist only on layers that float above the workbench.

### Shadow Vocabulary
- **Menu shadow** (`box-shadow: 0 6px 24px rgba(20, 22, 26, .16), 0 1px 3px rgba(20, 22, 26, .12)`; dark `0 8px 28px rgba(0,0,0,.5), 0 1px 3px rgba(0,0,0,.4)`): context menu, filter suggestions, plot tooltip, toasts, dialogs.
- **Focus halo** (`box-shadow: 0 0 0 2px` accent at 22%): the display filter field while focused.

### Named Rules
**The Flat Dot Rule.** Status dots (capture LED, expert-info dot, status pill) are flat filled circles: no glow halos, no pulsing.

## Shapes

Rectangular and small-radiused. Controls (buttons, tools, presets, filter field, segmented control, suggestion list, plot frame, rule definition block) use 4px corners. Small inset elements use 3px: the tab-count badge, in-field filter buttons, kbd keys, port tags, tree action chips, and the status-bar expert button. Floating layers step up slightly: menus and toasts 5px, dialogs 6px. Circles are reserved for status dots and severity marks; the rule-enable switch is the single rounded control. Grouped buttons butt together with shared hairlines and squared inner corners.

### Named Rules
**The Rectangular Vocabulary Rule.** Every control is a 4px rectangle (3px for inset badges and keys). No pill buttons, no large-radius cards.

## Components

### Buttons
- **Shape:** gently squared (4px), 26px tall, 0 10px padding, 12.5px label with optional 15px stroke icon and kbd hint.
- **Default:** Pane White with Strong Hairline border; hover Hover Grey, active Press Grey; disabled at 45% opacity.
- **Primary:** Analyzer Selection Blue fill and border, white 600 label; hover Pressed Selection Blue. One per pane header.
- **Danger:** default button with Critical ink text.
- **Toolbar tools:** borderless 28px, transparent until hover (Hover Grey plus hairline); icon-only variant is 28px square.

### Chips
- **Filter presets:** 24px, 4px, hairline border on Pane White in Secondary Ink; pressed state is Selection Wash with accent border.
- **Tree action chips:** 18px, 3px, appear on row hover, selection, or focus.

### Inputs / Fields
- **Display filter:** 28px, 4px, Strong Hairline border, monospace 12.5px input with UI-face placeholder. Background turns Filter Valid Green or Filter Invalid Rose as it parses. Focus shifts the border to accent with a 2px 22% accent halo. Autocomplete list floats below with the menu shadow; the active suggestion is solid accent.
- **Switch:** 30 by 17px track, accent when on.

### Navigation
- **View tabs:** 31px, Secondary Ink, hover Hover Grey; the selected tab is Ink at 600 with a 2px accent underline inset 8px. Counts sit beside labels in Tertiary Ink; a count needing attention becomes a solid accent badge (3px).
- **Segmented control:** 24px buttons sharing a 4px frame; checked option is solid accent.

### Packet list grid
Sticky Toolbar Grey header with sortable column buttons and triangle sort indicators; 22px rows, hairline row rules at 45%, tabular numerals, right-aligned numeric columns. Rows take coloring-rule tints (severity for alerts, protocol for packets). Untriaged rows are 600 weight. Selection is solid accent with white text and white marks (82% accent when the grid loses focus). Related alerts carry a small leading dot. New rows flash their tint once (1.6s).

### Dissection tree
21px disclosure rows indented 18px per level with a rotating 13px chevron; header rows 600. Hover Row Hover Blue, selection solid accent, linked-to-hex rows Hex Hover blue.

### Hex pane
Offset | 16 bytes in two groups of 8 | ASCII, monospace 12px on 20px lines. Matched bytes are solid accent with white ink; hovered bytes Hex Hover blue; non-printables in Tertiary Ink.

### Status bar
25px Toolbar Grey strip: the expert-info button (flat 10px severity dot plus untriaged summary), a status message, and hairline-separated count cells.

### Toasts and dialogs
Toasts stack bottom-right (360px), 5px, menu shadow, severity mark plus title and monospace body; critical toasts take the critical tint. Dialogs are native `dialog` elements, 560px, 6px, 38% dark backdrop.

## Do's and Don'ts

### Do:
- **Do** use the accent (#2a62b8 light) only for selection, focus rings, and primary actions.
- **Do** tint only untriaged alert rows; drop acknowledged, false-positive, and muted rows to Pane White with Secondary Ink.
- **Do** pair every severity colour with its mark: hollow circle low, dot medium, triangle high, diamond critical.
- **Do** keep monospace to addresses, ports, bytes, timestamps, and byte or pattern fields.
- **Do** build controls from the 4px rectangle (3px for inset badges and keys).
- **Do** draw icons as 16px stroked SVG (1.7 stroke, round caps) from the inline sprite.
- **Do** keep motion state-only at 150 to 200ms ease-out, and honour reduced motion.
- **Do** use only RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) for external hosts in demo data and examples; internal demo hosts stay on a private LAN range.

### Don't:
- **Don't** build a KPI tile grid; the overview is one summary line over the I/O strip.
- **Don't** give status dots glow halos or pulsing animation.
- **Don't** signal severity by colour alone or introduce a second accent colour.
- **Don't** set signature names, counts, or prose in monospace.
- **Don't** use pill-shaped buttons or large-radius cards.
- **Don't** add shadows to panes, rows, or controls; shadows belong to floating layers only.
- **Don't** load web fonts or icon fonts from a CDN.
