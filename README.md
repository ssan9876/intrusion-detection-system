# Signature NIDS

A lightweight **signature-based network intrusion detection system** with a
live web dashboard. It sniffs traffic, matches each packet against a set of
malware/attack signatures, and shows throughput, flows, top talkers, protocol
mix, and security alerts in real time.

![dashboard](docs/dashboard.png)

## How it works

```
                ┌──────────────┐   matches    ┌──────────────┐
  packets ─────▶│   Sensor     │─────────────▶│   Engine     │
 (scapy /       │ capture+decode│  rules.json  │ signature DB │
  demo mode)    └──────┬───────┘              └──────┬───────┘
                       │ packet records              │ alerts
                       ▼                             ▼
                ┌─────────────────────────────────────────┐
                │   Store  (ring buffers + SQLite alerts)  │
                └───────────────────┬─────────────────────┘
                                    │ 1 Hz snapshots + alert push
                                    ▼
                       ┌────────────────────────┐
                       │ FastAPI + WebSocket /ws │──▶ browser dashboard
                       └────────────────────────┘
```

- **Sensor** (`ids/capture.py`) — scapy `AsyncSniffer`. If real capture isn't
  possible (no privileges / no libpcap), it auto-falls back to **demo mode**,
  which generates realistic traffic plus periodic attacks so you can see the
  whole system work.
- **Engine** (`ids/engine.py`, `ids/rules.py`) — matches packets against a JSON
  signature set by protocol, ports, and payload (ASCII / hex / regex).
- **Detectors** (`ids/detectors.py`) — stateful heuristics that no single
  packet can trigger. Currently: a **port-scan detector** that alerts when one
  source probes ≥ `IDS_PORTSCAN_THRESHOLD` distinct ports (default 15) within
  `IDS_PORTSCAN_WINDOW` seconds (default 10).
- **Store** (`ids/store.py`) — in-memory live stats; alerts persisted to SQLite.
- **Server** (`ids/server.py`) — dashboard, REST API, and a WebSocket live feed.

## Quick start (any machine with Python 3.10+)

```bash
pip install -r requirements.txt

# Demo mode — no admin rights needed, synthetic traffic + attacks:
python -m ids --demo

# Real capture (needs root/admin + libpcap/Npcap):
sudo python -m ids --iface eth0
```

Open <http://localhost:8080>. To prove detection works, the EICAR test string
and several attack patterns fire automatically in demo mode.

### Useful flags / env vars

| Flag | Env | Purpose |
|------|-----|---------|
| `--iface eth0` | `IDS_INTERFACE` | capture interface |
| `--filter '...'` | `IDS_BPF_FILTER` | BPF capture filter |
| `--port 8080` | `IDS_PORT` | dashboard port |
| `--demo` | `IDS_DEMO=true` | synthetic traffic |
| `--rules path` | `IDS_RULES_PATH` | signature file |

## Writing signatures

Rules live in `rules/default.rules.json`. Each rule:

```json
{
  "id": "WEB-SQLI-UNION",
  "name": "SQL injection attempt (UNION SELECT)",
  "severity": "high",          // low | medium | high | critical
  "category": "web-attack",
  "protocol": "tcp",           // tcp | udp | icmp | ip | any
  "dst_port": 80,              // int or omit for any
  "regex": "union\\s+select",  // OR "content" (ascii) OR "content_hex"
  "nocase": true,
  "references": ["https://owasp.org/..."]
}
```

Match priority: `content` / `content_hex` / `regex` are all checked against the
payload; `src_port`/`dst_port`/`protocol` filter first.

Reload without restarting: click the **rules pill** in the dashboard header and
hit **Reload from disk**, or `POST /api/rules/reload`. If the edited file is
invalid (bad regex, duplicate id, unknown protocol…) the reload is rejected
with a message naming the offending rule and the old ruleset stays active.
The same pill opens a browser for every loaded signature.

## ⚠️ Seeing the whole network, not just this host

A NIDS only inspects packets it actually receives. On a switched network a host
(or LXC) sees **only its own traffic + broadcasts**. To monitor *all* traffic
you need one of:

1. **Switch port mirror / SPAN** → feed the mirrored port to the NIDS NIC. Best
   for managed switches.
2. **Run on the gateway/router** so all WAN-bound traffic passes through.
3. **Mirror at the hypervisor** — on Proxmox, mirror a bridge's traffic to the
   NIDS container's veth (see `deploy/README-proxmox.md`).

Without one of these you'll still detect attacks against/from the NIDS host and
anything broadcast, which is fine for testing.

## Daily logs & rollover

Each day at `IDS_ROLLOVER_HOUR` (local time, default **23:00**) the system writes
the day's activity to `IDS_LOG_DIR` and resets the live stats so the dashboard
starts fresh:

- `nids-YYYY-MM-DD.txt` — human-readable summary (totals, protocols, severity
  breakdown, top talkers, and every alert of the day)
- `nids-YYYY-MM-DD.json` — the same data as structured JSON

The dashboard's **Daily Reports** card lists archives newest-first. Click a name
(or **View**) to read the report in an in-page viewer, **Download** to save the
`.txt`, or **.json** for the structured file. Endpoints: `GET /api/logs`,
`GET /api/logs/{name}` (add `?download=1` to force a download), and
`POST /api/rollover` (trigger immediately). In the recommended deployment
`IDS_LOG_DIR` lives on TrueNAS, so reports are retained on the NAS.

Reports older than `IDS_LOG_RETENTION_DAYS` (default **90**) are pruned
automatically at each rollover and on startup; set it to `0` to keep forever.

## Alert export & API security

- **CSV export** — the ⬇ CSV button on the Security Alerts card (or
  `GET /api/alerts.csv?limit=…&severity=…`) downloads the alert history for
  spreadsheets / SIEM import.
- The WebSocket feed and the state-changing endpoints (`POST /api/rollover`,
  `POST /api/rules/reload`) reject cross-origin browser requests, so a web page
  you happen to visit can't read your traffic feed or reset your stats.
- The dashboard itself has **no authentication** — anyone who can reach the
  port sees your network activity. Bind it to a management network
  (`IDS_HOST`), or put it behind a reverse proxy with auth if it must be
  reachable more widely.

## Tests

```bash
pip install pytest httpx
python -m pytest tests/
```

## Deployment

See [`deploy/README-proxmox.md`](deploy/README-proxmox.md) for running this as a
Proxmox LXC with storage backed by TrueNAS.
