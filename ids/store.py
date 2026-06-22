"""In-memory live state + persistent alert log.

The dashboard reads from the in-memory state (fast, volatile): recent packets,
active flows, rolling counters. Alerts are *also* written to SQLite so they
survive restarts and can be reviewed historically.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


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

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FlowStat:
    src: str
    dst: str
    proto: str
    packets: int = 0
    bytes: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0


class Store:
    def __init__(self, db_path: Path, max_recent: int, max_flows: int, alert_history: int):
        self.db_path = db_path
        self.max_recent = max_recent
        self.max_flows = max_flows
        self.alert_history = alert_history

        self._lock = threading.Lock()
        self.recent_packets: deque[PacketRecord] = deque(maxlen=max_recent)
        self.recent_alerts: deque[Alert] = deque(maxlen=alert_history)
        self.flows: dict[tuple, FlowStat] = {}

        # rolling counters
        self.total_packets = 0
        self.total_bytes = 0
        self.proto_counts: dict[str, int] = defaultdict(int)
        self.severity_counts: dict[str, int] = defaultdict(int)
        self.talker_bytes: dict[str, int] = defaultdict(int)

        # per-second bandwidth ring (last 60s)
        self._bw_window: deque[tuple[int, int, int]] = deque(maxlen=60)  # (sec, packets, bytes)
        self.started_at = time.time()

        self._init_db()

    def _init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as con:
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
            con.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts)")
        # warm the in-memory alert deque from the most recent persisted alerts
        with sqlite3.connect(self.db_path) as con:
            con.row_factory = sqlite3.Row
            rows = con.execute(
                "SELECT * FROM alerts ORDER BY ts DESC LIMIT ?", (self.alert_history,)
            ).fetchall()
        for r in reversed(rows):
            self.recent_alerts.append(
                Alert(
                    ts=r["ts"], rule_id=r["rule_id"], rule_name=r["rule_name"],
                    severity=r["severity"], category=r["category"], src=r["src"],
                    dst=r["dst"], proto=r["proto"], sport=r["sport"], dport=r["dport"],
                    detail=r["detail"],
                )
            )
            self.severity_counts[r["severity"]] += 1

    def record_packet(self, pkt: PacketRecord) -> None:
        with self._lock:
            self.recent_packets.append(pkt)
            self.total_packets += 1
            self.total_bytes += pkt.length
            self.proto_counts[pkt.proto] += 1
            self.talker_bytes[pkt.src] += pkt.length

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
        with self._lock:
            self.recent_alerts.append(alert)
            self.severity_counts[alert.severity] += 1
        with sqlite3.connect(self.db_path) as con:
            con.execute(
                """INSERT INTO alerts
                   (ts, rule_id, rule_name, severity, category, src, dst, proto, sport, dport, detail)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (alert.ts, alert.rule_id, alert.rule_name, alert.severity, alert.category,
                 alert.src, alert.dst, alert.proto, alert.sport, alert.dport, alert.detail),
            )

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
                "totals": {
                    "packets": self.total_packets,
                    "bytes": self.total_bytes,
                    "flows": len(self.flows),
                    "alerts": len(self.recent_alerts),
                },
                "proto_counts": dict(self.proto_counts),
                "severity_counts": dict(self.severity_counts),
                "bandwidth": series,
                "top_talkers": [{"host": h, "bytes": b} for h, b in top_talkers],
                "top_flows": [asdict(f) for f in top_flows],
                "recent_packets": [p.as_dict() for p in list(self.recent_packets)[-60:]],
                "recent_alerts": [a.as_dict() for a in list(self.recent_alerts)[-60:]],
            }

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
        """Zero the live stats so a new day starts fresh."""
        with self._lock:
            self.recent_packets.clear()
            self.recent_alerts.clear()
            self.flows.clear()
            self.total_packets = 0
            self.total_bytes = 0
            self.proto_counts.clear()
            self.severity_counts.clear()
            self.talker_bytes.clear()
            self._bw_window.clear()
            self.started_at = time.time()

    def export_and_reset(self, log_dir: Path) -> Path:
        """Write the day's report (JSON + readable .log) to log_dir, then reset.

        Returns the path of the human-readable log file.
        """
        log_dir.mkdir(parents=True, exist_ok=True)
        report = self.build_daily_report()
        day = datetime.fromtimestamp(self.started_at).strftime("%Y-%m-%d")
        base = log_dir / f"nids-{day}"
        # avoid clobbering if a report for this date already exists (manual runs)
        if base.with_suffix(".log").exists():
            base = log_dir / f"nids-{day}_{datetime.now().strftime('%H%M%S')}"

        base.with_suffix(".json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        log_path = base.with_suffix(".log")
        log_path.write_text(_format_report(report), encoding="utf-8")
        self.reset()
        return log_path

    def query_alerts(self, limit: int = 200, severity: str | None = None, since: float | None = None) -> list[dict]:
        sql = "SELECT * FROM alerts"
        clauses: list[str] = []
        params: list[Any] = []
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if since is not None:
            clauses.append("ts >= ?")
            params.append(since)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)
        with sqlite3.connect(self.db_path) as con:
            con.row_factory = sqlite3.Row
            return [dict(r) for r in con.execute(sql, params).fetchall()]


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
