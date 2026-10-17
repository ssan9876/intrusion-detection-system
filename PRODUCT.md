# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Delegated: the user allowed a framework, but the dashboard stays build-free
(vanilla HTML/CSS/ES modules served from `web/` by FastAPI). `deploy/install.sh`
copies `web/` verbatim into a Debian LXC with no Node toolchain, and a security
tool should not load third-party scripts or fonts from a CDN.

## Users

One owner monitoring their own homelab network (Proxmox LXC sensor, reports on
TrueNAS). They glance at the dashboard to confirm things are quiet, and dig in
when something fires: which host, which signature, what the payload said, is it
new or recurring.

## Product Purpose

Signature NIDS sniffs traffic, matches packets against JSON signatures plus
stateful detectors (port scan), and shows live throughput, flows, talkers,
protocols and security alerts. Success: the owner can tell in one glance whether
the network is calm, and can investigate any alert to a conclusion without
leaving the dashboard or reading raw logs.

## Positioning

A self-hosted, single-binary-simple NIDS whose signatures are readable JSON the
owner edits and hot-reloads, with a dashboard that explains every alert in terms
of the exact rule and bytes that triggered it. No cloud, no agent, no SIEM.

## Operating Context

- Runs as a systemd service in a Proxmox LXC; dashboard on port 8080 on a
  management network, no authentication.
- Live capture via scapy, or demo mode with synthetic traffic and attacks.
- Daily rollover archives a .txt/.json report and resets live stats.
- Alerts persist in SQLite; rules hot-reload from `rules/default.rules.json`.

## Capabilities and Constraints

- Requested for this revamp: alert investigation (full detail, matched rule,
  references, related alerts, acknowledge/triage), host intelligence (per-host
  drill-down), timeline and analytics, rule control in the UI (enable/disable,
  mute, per-rule hit counts).
- Every dynamic value rendered must be escaped; state-changing endpoints keep
  the same-origin guard; the WebSocket rejects cross-origin connections.
- Demo mode data is synthetic and must stay labeled as such.

## Evidence on Hand

- 30 signatures in `rules/default.rules.json` with MITRE / CVE references.
- No screenshots in repo (README references a missing `docs/dashboard.png`).

## Product Principles

1. Calm is a state worth showing: quiet networks should look quiet, and an alert
   should be impossible to miss.
2. Every alert is explainable down to the rule and the bytes.
3. Investigate in place: drill from alert to host to rule without losing context.
4. Self-contained and safe by default: no external calls, nothing unescaped.
