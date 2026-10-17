"""In-memory live state + persistent alert log.

The dashboard reads from the in-memory state (fast, volatile): recent packets,
active flows, rolling counters, per-host stats. Alerts are *also* written to
SQLite so they survive restarts, carry their triage status, and can be reviewed
historically (timeline, analytics, per-host and per-rule history).
"""
from __future__ import annotations

import ipaddress
import json
import sqlite3
import threading
import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

# Triage states an alert can be in. "new" is the only one that needs the
# owner's attention; "muted" is assigned automatically while a rule is muted.
ALERT_STATUSES = ("new", "ack", "fp", "muted")
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# Columns returned for alert lists. payload_hex is left out on purpose: it is up
# to 1 KB per alert and only the detail view needs it.
_LIST_COLUMNS = ("id, ts, rule_id, rule_name, severity, category, src, dst, proto, "
                 "sport, dport, detail, match_start, match_end, status, status_ts")

# Ports remembered per host (as a source) and peers remembered per host; caps
# keep a single noisy scanner from growing the host table without bound.
_MAX_HOST_PORTS = 256
_MAX_HOST_PEERS = 256


_INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10",
)]


def is_internal(host: str) -> bool:
    """True for RFC 1918 / CGNAT / loopback / link-local / ULA addresses.

    Deliberately not ipaddress.is_private: that also counts the documentation
    ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) as private, which
    would label attackers in those ranges as internal hosts.
    """
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(ip in n for n in _INTERNAL_NETS if n.version == ip.version)


@dataclass
class PacketRecord:
    ts: float
    src: str
    dst: str
    proto: str
    sport: int | None
    dport: int | None
    length: int
    summary: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Alert:
    ts: float
    rule_id: str
    rule_name: str
    severity: str
    category: str
    src: str
    dst: str
    proto: str
    sport: int | None
    dport: int | None
    detail: str = ""
    # evidence: the first bytes of the payload and the span the rule matched
    payload_hex: str = ""
    payload_offset: int = 0          # where the stored window starts in the payload
    match_start: int | None = None
    match_end: int | None = None
    status: str = "new"
    status_ts: float | None = None
    id: int | None = None

    def as_dict(self, payload: bool = False) -> dict[str, Any]:
        d = asdict(self)
        if not payload:
            d.pop("payload_hex", None)
        return d


@dataclass
class FlowStat:
    src: str
    dst: str
    proto: str
    packets: int = 0
    bytes: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0


@dataclass
class HostStat:
    host: str
    packets_tx: int = 0
    bytes_tx: int = 0
    packets_rx: int = 0
    bytes_rx: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    ports: set[int] = field(default_factory=set)   # dst ports this host contacted
    peers: set[str] = field(default_factory=set)

    def as_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "internal": is_internal(self.host),
            "packets": self.packets_tx + self.packets_rx,
            "bytes": self.bytes_tx + self.bytes_rx,
            "packets_tx": self.packets_tx, "bytes_tx": self.bytes_tx,
            "packets_rx": self.packets_rx, "bytes_rx": self.bytes_rx,
            "first_seen": self.first_seen, "last_seen": self.last_seen,
            "ports": len(self.ports), "peers": len(self.peers),
        }


class Store:
    def __init__(self, db_path: Path, max_recent: int, max_flows: int, alert_history: int,
                 max_talkers: int = 2000):
        self.db_path = db_path
        self.max_recent = max_recent
        self.max_flows = max_flows
        self.alert_history = alert_history
        self.max_talkers = max_talkers

        self._lock = threading.Lock()
        self._db_lock = threading.Lock()
        self.recent_packets: deque[PacketRecord] = deque(maxlen=max_recent)
        self.recent_alerts: deque[Alert] = deque(maxlen=alert_history)
        self.flows: dict[tuple, FlowStat] = {}
        self.hosts: dict[str, HostStat] = {}

        # rolling counters
        self.total_packets = 0
        self.total_bytes = 0
        self.proto_counts: dict[str, int] = defaultdict(int)
        self.severity_counts: dict[str, int] = defaultdict(int)
        self.talker_bytes: dict[str, int] = defaultdict(int)
        # alerts still waiting for triage (persisted, so it survives rollover)
        self.untriaged = 0

        # per-rule switches set from the dashboard: {rule_id: {"enabled", "muted_until"}}
        self.rule_state: dict[str, dict[str, Any]] = {}

        # per-second bandwidth ring (last 60s)
        self._bw_window: deque[tuple[int, int, int]] = deque(maxlen=60)  # (sec, packets, bytes)
        self.started_at = time.time()

        self._init_db()

    # ----- database ------------------------------------------------------
    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.db_path, timeout=10)
        con.row_factory = sqlite3.Row
        return con

    def _init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as con:
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    rule_id TEXT, rule_name TEXT, severity TEXT, category TEXT,
                    src TEXT, dst TEXT, proto TEXT, sport INTEGER, dport INTEGER,
                    detail TEXT
                )
                """
            )
            # columns added in 0.4.0; ALTER only what an older database lacks
            have = {r["name"] for r in con.execute("PRAGMA table_info(alerts)")}
            for col, decl in (("payload_hex", "TEXT DEFAULT ''"),
                              ("payload_offset", "INTEGER DEFAULT 0"),
                              ("match_start", "INTEGER"),
                              ("match_end", "INTEGER"),
                              ("status", "TEXT DEFAULT 'new'"),
                              ("status_ts", "REAL")):
                if col not in have:
                    con.execute(f"ALTER TABLE alerts ADD COLUMN {col} {decl}")
                    if col == "status":
                        # alerts from before triage existed would otherwise all
                        # land in the untriaged queue at once on upgrade
                        con.execute("UPDATE alerts SET status = 'ack'")
            con.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts)")
            con.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")
            con.execute("CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_id)")
            con.execute("CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts(src)")
            con.execute("CREATE INDEX IF NOT EXISTS idx_alerts_dst ON alerts(dst)")
            con.execute(
                """CREATE TABLE IF NOT EXISTS rule_state (
                       rule_id TEXT PRIMARY KEY,
                       enabled INTEGER NOT NULL DEFAULT 1,
                       muted_until REAL
                   )"""
            )
            for r in con.execute("SELECT * FROM rule_state"):
                self.rule_state[r["rule_id"]] = {
                    "enabled": bool(r["enabled"]), "muted_until": r["muted_until"],
                }
            self.untriaged = con.execute(
                "SELECT COUNT(*) FROM alerts WHERE status = 'new'").fetchone()[0]
            # warm the in-memory alert deque from the most recent persisted alerts
            rows = con.execute(
                f"SELECT {_LIST_COLUMNS} FROM alerts ORDER BY ts DESC LIMIT ?", (self.alert_history,)
            ).fetchall()
        for r in reversed(rows):
            self.recent_alerts.append(Alert(**{k: r[k] for k in r.keys()}))
            self.severity_counts[r["severity"]] += 1

    # ----- ingest -------------------------------------------------------
    def _host(self, host: str, ts: float) -> HostStat:
        h = self.hosts.get(host)
        if h is None:
            h = self.hosts[host] = HostStat(host=host, first_seen=ts)
        h.last_seen = ts
        return h

    def record_packet(self, pkt: PacketRecord) -> None:
        with self._lock:
            self.recent_packets.append(pkt)
            self.total_packets += 1
            self.total_bytes += pkt.length
            self.proto_counts[pkt.proto] += 1
            self.talker_bytes[pkt.src] += pkt.length
            # keep the talker table bounded: on overflow keep the biggest senders
            if len(self.talker_bytes) > self.max_talkers * 2:
                top = sorted(self.talker_bytes.items(), key=lambda kv: kv[1], reverse=True)
                self.talker_bytes = defaultdict(int, top[: self.max_talkers])

            src, dst = self._host(pkt.src, pkt.ts), self._host(pkt.dst, pkt.ts)
            src.packets_tx += 1
            src.bytes_tx += pkt.length
            dst.packets_rx += 1
            dst.bytes_rx += pkt.length
            if pkt.dport is not None and len(src.ports) < _MAX_HOST_PORTS:
                src.ports.add(pkt.dport)
            if len(src.peers) < _MAX_HOST_PEERS:
                src.peers.add(pkt.dst)
            if len(dst.peers) < _MAX_HOST_PEERS:
                dst.peers.add(pkt.src)
            # same bound as talkers: on overflow keep the busiest hosts
            if len(self.hosts) > self.max_talkers * 2:
                top = sorted(self.hosts.values(), key=lambda h: h.bytes_tx + h.bytes_rx, reverse=True)
                self.hosts = {h.host: h for h in top[: self.max_talkers]}

            key = (pkt.src, pkt.dst, pkt.proto)
            flow = self.flows.get(key)
            if flow is None:
                flow = FlowStat(src=pkt.src, dst=pkt.dst, proto=pkt.proto, first_seen=pkt.ts)
                self.flows[key] = flow
            flow.packets += 1
            flow.bytes += pkt.length
            flow.last_seen = pkt.ts

            # evict oldest flows if over budget
            if len(self.flows) > self.max_flows:
                oldest = sorted(self.flows.items(), key=lambda kv: kv[1].last_seen)
                for k, _ in oldest[: len(self.flows) - self.max_flows]:
                    self.flows.pop(k, None)

            sec = int(pkt.ts)
            if self._bw_window and self._bw_window[-1][0] == sec:
                s, p, b = self._bw_window[-1]
                self._bw_window[-1] = (s, p + 1, b + pkt.length)
            else:
                self._bw_window.append((sec, 1, pkt.length))

    def record_alert(self, alert: Alert) -> None:
        with self._db_lock, self._connect() as con:
            cur = con.execute(
                """INSERT INTO alerts
                   (ts, rule_id, rule_name, severity, category, src, dst, proto, sport, dport,
                    detail, payload_hex, payload_offset, match_start, match_end, status, status_ts)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (alert.ts, alert.rule_id, alert.rule_name, alert.severity, alert.category,
                 alert.src, alert.dst, alert.proto, alert.sport, alert.dport, alert.detail,
                 alert.payload_hex, alert.payload_offset, alert.match_start, alert.match_end, alert.status,
                 alert.status_ts),
            )
            alert.id = cur.lastrowid
        with self._lock:
            self.recent_alerts.append(alert)
            self.severity_counts[alert.severity] += 1
            if alert.status == "new":
                self.untriaged += 1

    # ----- triage --------------------------------------------------------
    def set_alert_status(self, ids: list[int], status: str) -> list[int]:
        """Set the triage status of the given alerts. Returns the ids changed."""
        if status not in ALERT_STATUSES:
            raise ValueError(f"unknown status {status!r}")
        ids = [int(i) for i in ids][:5000]
        if not ids:
            return []
        now = time.time()
        marks = ",".join("?" * len(ids))
        with self._db_lock, self._connect() as con:
            rows = con.execute(
                f"SELECT id, status FROM alerts WHERE id IN ({marks})", ids).fetchall()
            changed = [r["id"] for r in rows if r["status"] != status]
            was_new = sum(1 for r in rows if r["status"] == "new" and status != "new")
            became_new = sum(1 for r in rows if r["status"] != "new" and status == "new")
            if changed:
                cm = ",".join("?" * len(changed))
                con.execute(f"UPDATE alerts SET status = ?, status_ts = ? WHERE id IN ({cm})",
                            [status, now, *changed])
        with self._lock:
            self.untriaged = max(0, self.untriaged - was_new + became_new)
            changed_set = set(changed)
            for a in self.recent_alerts:
                if a.id in changed_set:
                    a.status, a.status_ts = status, now
        return changed

    # ----- rule switches -------------------------------------------------
    def set_rule_state(self, rule_id: str, enabled: bool | None = None,
                       muted_until: float | None | bool = False) -> dict[str, Any]:
        """Update a rule's switches. muted_until=False leaves the mute untouched,
        None clears it, a timestamp mutes until then."""
        with self._lock:
            st = dict(self.rule_state.get(rule_id, {"enabled": True, "muted_until": None}))
            if enabled is not None:
                st["enabled"] = bool(enabled)
            if muted_until is not False:
                st["muted_until"] = muted_until
            self.rule_state[rule_id] = st
        with self._db_lock, self._connect() as con:
            con.execute(
                """INSERT INTO rule_state (rule_id, enabled, muted_until) VALUES (?,?,?)
                   ON CONFLICT(rule_id) DO UPDATE SET enabled = excluded.enabled,
                                                      muted_until = excluded.muted_until""",
                (rule_id, int(st["enabled"]), st["muted_until"]),
            )
        return st

    def disabled_rules(self) -> set[str]:
        return {rid for rid, st in self.rule_state.items() if not st.get("enabled", True)}

    def is_muted(self, rule_id: str, ts: float | None = None) -> bool:
        until = self.rule_state.get(rule_id, {}).get("muted_until")
        return bool(until) and (ts or time.time()) < until

    def rule_hits(self, since: float) -> dict[str, dict[str, Any]]:
        """Per-rule hit counts: all time, since `since`, and the last hit time."""
        with self._connect() as con:
            rows = con.execute(
                """SELECT rule_id, COUNT(*) AS hits, MAX(ts) AS last_hit,
                          SUM(CASE WHEN ts >= ? THEN 1 ELSE 0 END) AS recent
                   FROM alerts GROUP BY rule_id""", (since,)).fetchall()
        return {r["rule_id"]: {"hits": r["hits"], "recent": r["recent"] or 0,
                               "last_hit": r["last_hit"]} for r in rows}

    # ----- views ---------------------------------------------------------
    def snapshot(self) -> dict[str, Any]:
        """A JSON-serializable view of current state for the dashboard."""
        with self._lock:
            now = int(time.time())
            # bandwidth series, zero-filled for the last 60 seconds
            bw_map = {s: (p, b) for s, p, b in self._bw_window}
            series = []
            for s in range(now - 59, now + 1):
                p, b = bw_map.get(s, (0, 0))
                series.append({"t": s, "pps": p, "bps": b})

            top_talkers = sorted(self.talker_bytes.items(), key=lambda kv: kv[1], reverse=True)[:10]
            top_flows = sorted(self.flows.values(), key=lambda f: f.bytes, reverse=True)[:15]

            return {
                "uptime": now - int(self.started_at),
                "started_at": self.started_at,
                "totals": {
                    "packets": self.total_packets,
                    "bytes": self.total_bytes,
                    "flows": len(self.flows),
                    "hosts": len(self.hosts),
                    "alerts": len(self.recent_alerts),
                    "untriaged": self.untriaged,
                },
                "proto_counts": dict(self.proto_counts),
                "severity_counts": dict(self.severity_counts),
                "bandwidth": series,
                "top_talkers": [{"host": h, "bytes": b} for h, b in top_talkers],
                "top_flows": [asdict(f) for f in top_flows],
                "recent_packets": [p.as_dict() for p in list(self.recent_packets)[-200:]],
                "recent_alerts": [a.as_dict() for a in list(self.recent_alerts)[-60:]],
            }

    def flows_list(self) -> list[dict[str, Any]]:
        with self._lock:
            return [asdict(f) for f in sorted(self.flows.values(), key=lambda f: f.bytes, reverse=True)]

    def hosts_list(self) -> list[dict[str, Any]]:
        with self._lock:
            hosts = [h.as_dict() for h in self.hosts.values()]
        counts: dict[str, dict[str, int]] = defaultdict(lambda: {"as_src": 0, "as_dst": 0, "untriaged": 0})
        with self._connect() as con:
            for r in con.execute("SELECT src, COUNT(*) n, SUM(status='new') u FROM alerts "
                                 "WHERE ts >= ? GROUP BY src", (self.started_at,)):
                counts[r["src"]]["as_src"] = r["n"]
                counts[r["src"]]["untriaged"] += r["u"] or 0
            for r in con.execute("SELECT dst, COUNT(*) n FROM alerts WHERE ts >= ? GROUP BY dst",
                                 (self.started_at,)):
                counts[r["dst"]]["as_dst"] = r["n"]
        for h in hosts:
            h.update(counts.get(h["host"], {"as_src": 0, "as_dst": 0, "untriaged": 0}))
        hosts.sort(key=lambda h: h["bytes"], reverse=True)
        return hosts

    def host_detail(self, host: str) -> dict[str, Any] | None:
        with self._lock:
            h = self.hosts.get(host)
            stat = h.as_dict() if h else None
            ports = sorted(h.ports) if h else []
            peers: dict[str, dict[str, int]] = defaultdict(lambda: {"packets": 0, "bytes": 0})
            for f in self.flows.values():
                if f.src == host or f.dst == host:
                    other = f.dst if f.src == host else f.src
                    peers[other]["packets"] += f.packets
                    peers[other]["bytes"] += f.bytes
        with self._connect() as con:
            n = con.execute("SELECT COUNT(*) FROM alerts WHERE src = ? OR dst = ?",
                            (host, host)).fetchone()[0]
            by_rule = [dict(r) for r in con.execute(
                """SELECT rule_id, rule_name, severity, COUNT(*) AS hits, MAX(ts) AS last_hit
                   FROM alerts WHERE src = ? OR dst = ? GROUP BY rule_id
                   ORDER BY hits DESC LIMIT 20""", (host, host))]
            first_alert = con.execute("SELECT MIN(ts) FROM alerts WHERE src = ? OR dst = ?",
                                      (host, host)).fetchone()[0]
        if stat is None and not n:
            return None
        return {
            "host": host,
            "internal": is_internal(host),
            "stats": stat,
            "ports": ports,
            "peers": sorted(({"host": k, **v} for k, v in peers.items()),
                            key=lambda p: p["bytes"], reverse=True)[:25],
            "alert_count": n,
            "first_alert": first_alert,
            "alerts_by_rule": by_rule,
            "alerts": self.query_alerts(limit=50, host=host),
        }

    # ----- history -------------------------------------------------------
    def query_alerts(self, limit: int = 200, severity: str | None = None, since: float | None = None,
                     status: str | None = None, host: str | None = None,
                     rule_id: str | None = None, before_id: int | None = None) -> list[dict]:
        sql = f"SELECT {_LIST_COLUMNS} FROM alerts"
        clauses: list[str] = []
        params: list[Any] = []
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if since is not None:
            clauses.append("ts >= ?")
            params.append(since)
        if status:
            clauses.append("status = ?")
            params.append(status)
        if host:
            clauses.append("(src = ? OR dst = ?)")
            params += [host, host]
        if rule_id:
            clauses.append("rule_id = ?")
            params.append(rule_id)
        if before_id is not None:
            clauses.append("id < ?")
            params.append(before_id)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY ts DESC, id DESC LIMIT ?"
        params.append(limit)
        with self._connect() as con:
            return [dict(r) for r in con.execute(sql, params).fetchall()]

    def get_alert(self, alert_id: int) -> dict | None:
        with self._connect() as con:
            r = con.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
            if r is None:
                return None
            a = dict(r)
            a["related"] = {
                "same_src": con.execute("SELECT COUNT(*) FROM alerts WHERE src = ?",
                                        (a["src"],)).fetchone()[0],
                "same_rule": con.execute("SELECT COUNT(*) FROM alerts WHERE rule_id = ?",
                                         (a["rule_id"],)).fetchone()[0],
                "same_pair": con.execute("SELECT COUNT(*) FROM alerts WHERE src = ? AND dst = ?",
                                         (a["src"], a["dst"])).fetchone()[0],
                "first_from_src": con.execute("SELECT MIN(ts) FROM alerts WHERE src = ?",
                                              (a["src"],)).fetchone()[0],
                "recent_from_src": [dict(x) for x in con.execute(
                    f"SELECT {_LIST_COLUMNS} FROM alerts WHERE src = ? AND id != ? "
                    "ORDER BY ts DESC LIMIT 8", (a["src"], alert_id))],
            }
        return a

    def alert_timeline(self, since: float, bucket: int) -> list[dict[str, Any]]:
        """Alert counts per time bucket and severity, zero-filled from `since` to now."""
        bucket = max(1, int(bucket))
        start = int(since // bucket * bucket)
        now = time.time()
        with self._connect() as con:
            rows = con.execute(
                """SELECT CAST(ts / ? AS INTEGER) * ? AS b, severity, COUNT(*) AS n
                   FROM alerts WHERE ts >= ? GROUP BY b, severity""",
                (bucket, bucket, start)).fetchall()
        grid: dict[int, dict[str, int]] = {}
        for t in range(start, int(now) + 1, bucket):
            grid[t] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for r in rows:
            cell = grid.setdefault(int(r["b"]), {"critical": 0, "high": 0, "medium": 0, "low": 0})
            if r["severity"] in cell:
                cell[r["severity"]] += r["n"]
        return [{"t": t, **grid[t]} for t in sorted(grid)]

    def alert_analytics(self, since: float) -> dict[str, Any]:
        with self._connect() as con:
            def q(sql: str, *args: Any) -> list[dict]:
                return [dict(r) for r in con.execute(sql, (since, *args))]
            return {
                "total": con.execute("SELECT COUNT(*) FROM alerts WHERE ts >= ?",
                                     (since,)).fetchone()[0],
                "by_status": {r["status"]: r["n"] for r in q(
                    "SELECT status, COUNT(*) n FROM alerts WHERE ts >= ? GROUP BY status")},
                "top_rules": q("""SELECT rule_id, rule_name, severity, category, COUNT(*) AS n
                                  FROM alerts WHERE ts >= ? GROUP BY rule_id
                                  ORDER BY n DESC LIMIT 10"""),
                "top_sources": q("""SELECT src AS host, COUNT(*) AS n, MAX(severity = 'critical') AS crit
                                    FROM alerts WHERE ts >= ? GROUP BY src ORDER BY n DESC LIMIT 10"""),
                "top_targets": q("""SELECT dst AS host, COUNT(*) AS n
                                    FROM alerts WHERE ts >= ? GROUP BY dst ORDER BY n DESC LIMIT 10"""),
                "categories": q("""SELECT category, COUNT(*) AS n FROM alerts WHERE ts >= ?
                                   GROUP BY category ORDER BY n DESC"""),
            }

    # ----- daily rollover ------------------------------------------------
    def build_daily_report(self) -> dict[str, Any]:
        """Summarize activity since the last reset (the current 'day')."""
        with self._lock:
            now = time.time()
            started_at = self.started_at
            top_talkers = sorted(self.talker_bytes.items(), key=lambda kv: kv[1], reverse=True)[:20]
            top_flows = sorted(self.flows.values(), key=lambda f: f.bytes, reverse=True)[:25]
            report = {
                "generated_at": datetime.fromtimestamp(now).isoformat(timespec="seconds"),
                "period_start": datetime.fromtimestamp(started_at).isoformat(timespec="seconds"),
                "period_end": datetime.fromtimestamp(now).isoformat(timespec="seconds"),
                "duration_seconds": int(now - started_at),
                "totals": {
                    "packets": self.total_packets,
                    "bytes": self.total_bytes,
                    "flows": len(self.flows),
                },
                "proto_counts": dict(self.proto_counts),
                "top_talkers": [{"host": h, "bytes": b} for h, b in top_talkers],
                "top_flows": [asdict(f) for f in top_flows],
            }
        # Alerts (and their severity breakdown) come from SQLite scoped to the
        # period, so counts stay consistent even if the service restarted mid-day
        # and warmed older alerts into the in-memory display buffer.
        alerts = self.query_alerts(limit=100000, since=started_at)
        sev: dict[str, int] = defaultdict(int)
        for a in alerts:
            sev[a["severity"]] += 1
        report["totals"]["alerts"] = len(alerts)
        report["severity_counts"] = dict(sev)
        report["alerts"] = alerts
        return report

    def reset(self) -> None:
        """Zero the live stats so a new day starts fresh.

        Triage state lives in SQLite and is deliberately kept: an alert nobody
        looked at yesterday still needs looking at today.
        """
        with self._lock:
            self.recent_packets.clear()
            self.recent_alerts.clear()
            self.flows.clear()
            self.hosts.clear()
            self.total_packets = 0
            self.total_bytes = 0
            self.proto_counts.clear()
            self.severity_counts.clear()
            self.talker_bytes.clear()
            self._bw_window.clear()
            self.started_at = time.time()

    def export_and_reset(self, log_dir: Path) -> Path:
        """Write the day's report (readable .txt + structured .json), then reset.

        Returns the path of the human-readable .txt report.
        """
        log_dir.mkdir(parents=True, exist_ok=True)
        report = self.build_daily_report()
        day = datetime.fromtimestamp(self.started_at).strftime("%Y-%m-%d")
        base = log_dir / f"nids-{day}"
        # avoid clobbering if a report for this date already exists (manual runs)
        if base.with_suffix(".txt").exists():
            base = log_dir / f"nids-{day}_{datetime.now().strftime('%H%M%S')}"

        base.with_suffix(".json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        txt_path = base.with_suffix(".txt")
        txt_path.write_text(_format_report(report), encoding="utf-8")
        self.reset()
        return txt_path

    @staticmethod
    def prune_logs(log_dir: Path, retention_days: int) -> list[str]:
        """Delete archived reports older than retention_days. Returns names removed.

        retention_days <= 0 disables pruning. Files are matched by modification
        time so both the .txt and .json (and any legacy .log) are covered.
        """
        if retention_days <= 0 or not log_dir.is_dir():
            return []
        cutoff = time.time() - retention_days * 86400
        removed: list[str] = []
        for p in log_dir.glob("nids-*"):
            try:
                if p.is_file() and p.stat().st_mtime < cutoff:
                    p.unlink()
                    removed.append(p.name)
            except OSError:
                continue
        return removed


def _format_report(r: dict) -> str:
    """Render a daily report dict as a readable plain-text log."""
    L = []
    L.append("=" * 64)
    L.append(f" Signature NIDS — Daily Activity Report")
    L.append(f" Period : {r['period_start']}  ->  {r['period_end']}")
    L.append(f" Window : {r['duration_seconds'] // 3600}h {(r['duration_seconds'] % 3600) // 60}m")
    L.append("=" * 64)
    t = r["totals"]
    L.append(f"\nTotals: {t['packets']:,} packets / {t['bytes']:,} bytes / "
             f"{t['flows']:,} flows / {t['alerts']:,} alerts")

    L.append("\nProtocols:")
    for proto, n in sorted(r["proto_counts"].items(), key=lambda kv: kv[1], reverse=True):
        L.append(f"  {proto.upper():<6} {n:,}")

    L.append("\nAlerts by severity:")
    for sev in ("critical", "high", "medium", "low"):
        if r["severity_counts"].get(sev):
            L.append(f"  {sev:<9} {r['severity_counts'][sev]:,}")

    L.append("\nTop talkers (by bytes):")
    for tk in r["top_talkers"][:10]:
        L.append(f"  {tk['host']:<18} {tk['bytes']:,} B")

    L.append(f"\nSecurity alerts ({len(r['alerts'])}):")
    if not r["alerts"]:
        L.append("  (none)")
    for a in r["alerts"]:
        ts = datetime.fromtimestamp(a["ts"]).strftime("%H:%M:%S")
        sp = f":{a['sport']}" if a.get("sport") else ""
        dp = f":{a['dport']}" if a.get("dport") else ""
        L.append(f"  [{ts}] {a['severity'].upper():<8} {a['rule_id']:<22} "
                 f"{a['src']}{sp} -> {a['dst']}{dp}  {a['rule_name']}")
    L.append("")
    return "\n".join(L)
