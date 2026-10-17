# Changelog

All notable changes to Signature NIDS are recorded here. Versions follow
[semantic versioning](https://semver.org/): while pre-1.0, minor versions may
add features and fixes.

## [0.4.0] — 2026-10-17

### Changed
- **New dashboard.** It's rebuilt as a packet-analyzer workbench: toolbar,
  display filter, seven views (Alerts, Packets, Endpoints, Conversations,
  Signatures, I/O Graph, Reports), stacked list / dissection / hex panes with
  draggable splitters, and a status bar. Light and dark themes follow the system
  or can be set by hand. It's still build-free, with no external scripts or fonts.
- Static assets are served with `Cache-Control: no-cache` (revalidated by ETag),
  so browsers pick up a new dashboard right after `update.sh`.
- Alert CSV export appends `id` and `status` columns at the end.

### Added
- **Alert evidence.** Each alert keeps up to 512 bytes of the triggering
  payload and the exact byte span the rule matched. The dashboard highlights
  those bytes in a hex view linked to the dissection tree.
- **Triage.** Alerts are *new*, *acknowledged*, *false positive*, or *muted*.
  `POST /api/alerts/status` handles single or bulk triage. The untriaged count
  shows in the tab title, favicon, and status bar.
- **Display filter language** (`sev >= high && ip.src == …`, `contains`,
  `matches`, `!`, `||`, free text) with validation, autocomplete, saved
  filters, and right-click *Apply as filter*.
- **Host intelligence.** Per-host sent/received counters, peers, and ports
  contacted, plus a drill-down with alerts by signature (`GET /api/hosts`,
  `GET /api/hosts/{ip}`). Also a conversations view (`GET /api/flows`).
- **Rule control.** Enable/disable or mute any signature from the dashboard
  (`POST /api/rules/{id}/state`). State is persisted in the alert database
  and survives reloads and restarts. `/api/rules` now includes 24 h and
  all-time hit counts.
- **Timeline & analytics.** Alert counts over 1 h – 7 d by severity
  (`GET /api/alerts/timeline`), plus top signatures, sources, targets, and
  categories (`GET /api/analytics`).
- Alert detail (`GET /api/alerts/{id}`) with related-alert counts, and new
  `/api/alerts` filters: `status`, `host`, `rule_id`, `since`, `before_id`.
- Keyboard-driven triage: `j`/`k`, `a`, `f`, `u`, `m`, `h`, `/`, `1`–`7`, `?`.

### Fixed
- Hosts in the documentation ranges (192.0.2.0/24, 198.51.100.0/24,
  203.0.113.0/24) are no longer classified as internal.

### Upgrade notes
- The alert database is migrated in place. Alerts from before 0.4.0 are
  marked *acknowledged*, so the triage queue starts empty.
- The alert database now holds payload bytes. Treat it as sensitive.

## [0.3.0] — 2026-07-05

### Security
- Escape every dynamic value rendered into the dashboard (talker hosts, packet
  and alert src/dst/proto/detail) — previously unescaped, an XSS risk on a live
  network.
- Reject cross-origin WebSocket connections so other web pages can't silently
  read your live traffic/alert feed.
- Same-origin (CSRF) guard on `POST /api/rollover` and `POST /api/rules/reload`.
- Strict allow-list for archived report names served by `/api/logs/{name}`
  (blocks path-traversal variants and `Content-Disposition` header injection).
- Validate and bound `/api/alerts` query params (`limit`, `severity`).

### Added
- **Stateful port-scan detector** — alerts when one source probes many distinct
  ports in a short window. Tunable via `IDS_PORTSCAN_THRESHOLD` / `IDS_PORTSCAN_WINDOW`.
- **18 new signatures** (12 → 30): Log4Shell, Shellshock, Heartbleed, XSS,
  boolean/time-based SQLi, command injection, obfuscated PHP eval, reverse
  shells, Gh0st RAT, Mirai telnet creds, Stratum mining, ICMP tunneling, and
  sqlmap/Nikto/dirbuster scanner fingerprints.
- **Hot rule reload** — `POST /api/rules/reload` (and a button in the signature
  browser) re-reads the rules file without a restart; invalid files are rejected
  with an error naming the offending rule, leaving the old ruleset active.
- **Signature browser** modal in the dashboard (click the rules pill).
- **Alert search box**, **CSV export** (`GET /api/alerts.csv`), a **pause
  button** for the live traffic table, and **toast notifications** for
  critical/high alerts.
- **Version** is now exposed at `GET /api/status` and shown in the header.
- **`deploy/update.sh`** — one-command in-place updater that preserves data and
  config.
- Test suite (43 tests) covering rules, engine, detector, memory bounds, and the
  API security guards.

### Fixed
- Bound the top-talkers table so per-source counters can't grow without limit.
- Survive a broken native scapy dependency (a pyo3 panic is a `BaseException`,
  not an `Exception`) and fall back to demo mode as intended.
- Include the UTC offset in `next_rollover` so browsers parse it correctly.
- Migrate deprecated FastAPI `on_event` handlers to the `lifespan` API.
- Scale canvases by device pixel ratio so charts are crisp on hi-DPI displays.
- Rule loader now rejects duplicate ids, unknown protocols, and invalid
  regex/hex up front instead of failing later with an opaque traceback.

## [0.1.0]
- Initial signature NIDS with live dashboard, SQLite alert log, daily rollover,
  and archived report viewer.
