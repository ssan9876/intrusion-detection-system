# Changelog

All notable changes to Signature NIDS are recorded here. Versions follow
[semantic versioning](https://semver.org/): while pre-1.0, minor versions may
add features and fixes.

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
