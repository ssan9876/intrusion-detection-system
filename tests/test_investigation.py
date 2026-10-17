"""Tests for 0.4.0: evidence capture, triage, rule control, hosts, analytics."""
import json
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from ids.capture import Sensor
from ids.config import Config
from ids.engine import Engine
from ids.rules import RuleSet
from ids.server import create_app
from ids.store import Alert, PacketRecord, Store, is_internal


def load_rules(tmp_path, rules):
    p = tmp_path / "rules.json"
    p.write_text(json.dumps({"rules": rules}), encoding="utf-8")
    return RuleSet.load(p)


# ---------- evidence: match spans ----------

def test_find_match_spans(tmp_path):
    rs = load_rules(tmp_path, [
        {"id": "C", "name": "c", "content": "EVIL", "nocase": True},
        {"id": "H", "name": "h", "content_hex": "dead beef"},
        {"id": "R", "name": "r", "regex": "union\\s+select", "nocase": True},
    ])
    c, h, r = rs.rules
    assert c.find_match(b"xx evil xx") == (3, 7)
    assert h.find_match(b"\x00\x01\xde\xad\xbe\xef") == (2, 6)
    assert r.find_match(b"id=1 UNION  SELECT x") == (5, 18)
    assert c.find_match(b"benign") is None
    assert c.find_match(b"") is None


def test_sensor_stores_payload_window_and_span(tmp_path):
    cfg = Config()
    cfg.db_path = tmp_path / "ids.db"
    rs = load_rules(tmp_path, [{"id": "C", "name": "c", "protocol": "tcp", "content": "needle"}])
    store = Store(db_path=cfg.db_path, max_recent=10, max_flows=10, alert_history=10)
    sensor = Sensor(cfg, Engine(rs), store)
    payload = b"A" * 2000 + b"needle" + b"B" * 10
    sensor._ingest(ts=time.time(), src="203.0.113.5", dst="192.168.1.2", proto="tcp",
                   sport=1234, dport=80, length=len(payload), payload=payload)
    a = store.get_alert(store.recent_alerts[-1].id)
    window = bytes.fromhex(a["payload_hex"])
    assert len(window) <= 512
    # the stored window must contain the matched bytes at the recorded offsets
    assert window[a["match_start"]:a["match_end"]] == b"needle"
    assert a["payload_offset"] + a["match_start"] == 2000
    assert a["status"] == "new"


# ---------- engine: disabled rules ----------

def test_engine_skips_disabled_rules(tmp_path):
    rs = load_rules(tmp_path, [{"id": "C", "name": "c", "content": "x"}])
    eng = Engine(rs, disabled={"C"})
    assert eng.evaluate("tcp", 1, 2, b"x") == []
    eng.disabled = set()
    assert [r.id for r in eng.evaluate("tcp", 1, 2, b"x")] == ["C"]


# ---------- store: triage, migration, hosts ----------

def _alert(**kw):
    base = dict(ts=time.time(), rule_id="R1", rule_name="rule", severity="high", category="test",
                src="203.0.113.9", dst="192.168.1.5", proto="tcp", sport=1, dport=80)
    base.update(kw)
    return Alert(**base)


def test_triage_updates_untriaged_count(tmp_path):
    s = Store(db_path=tmp_path / "t.db", max_recent=10, max_flows=10, alert_history=10)
    for _ in range(3):
        s.record_alert(_alert())
    assert s.untriaged == 3
    ids = [a.id for a in s.recent_alerts]
    assert s.set_alert_status(ids[:2], "ack") == ids[:2]
    assert s.untriaged == 1
    assert s.set_alert_status(ids[:2], "ack") == []  # no-op is not a change
    s.set_alert_status([ids[0]], "new")
    assert s.untriaged == 2
    # survives a restart (persisted), and survives a rollover reset
    s.reset()
    assert Store(db_path=tmp_path / "t.db", max_recent=10, max_flows=10, alert_history=10).untriaged == 2
    with pytest.raises(ValueError):
        s.set_alert_status(ids, "bogus")


def test_muted_alerts_do_not_need_triage(tmp_path):
    s = Store(db_path=tmp_path / "t.db", max_recent=10, max_flows=10, alert_history=10)
    s.set_rule_state("R1", muted_until=time.time() + 60)
    assert s.is_muted("R1")
    s.set_rule_state("R1", muted_until=None)
    assert not s.is_muted("R1")
    s.record_alert(_alert(status="muted"))
    assert s.untriaged == 0


def test_migration_marks_old_alerts_acknowledged(tmp_path):
    db = tmp_path / "old.db"
    with sqlite3.connect(db) as con:  # a 0.3.x database
        con.execute("""CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,
            rule_id TEXT, rule_name TEXT, severity TEXT, category TEXT, src TEXT, dst TEXT,
            proto TEXT, sport INTEGER, dport INTEGER, detail TEXT)""")
        con.execute("INSERT INTO alerts (ts, rule_id, rule_name, severity, category, src, dst, proto)"
                    " VALUES (?, 'R', 'r', 'high', 'c', '1.2.3.4', '10.0.0.1', 'tcp')", (time.time(),))
    s = Store(db_path=db, max_recent=10, max_flows=10, alert_history=10)
    assert s.untriaged == 0
    assert s.query_alerts()[0]["status"] == "ack"


def test_is_internal_excludes_documentation_ranges():
    assert is_internal("192.168.1.1") and is_internal("10.2.3.4") and is_internal("172.20.0.1")
    assert is_internal("fd00::1") and is_internal("127.0.0.1")
    for ext in ("203.0.113.66", "198.51.100.23", "8.8.8.8", "172.32.0.1", "not-an-ip"):
        assert not is_internal(ext)


def test_host_stats_and_bounds(tmp_path):
    s = Store(db_path=tmp_path / "t.db", max_recent=10, max_flows=50, alert_history=10, max_talkers=20)
    now = time.time()
    for port in range(1000, 1400):
        s.record_packet(PacketRecord(ts=now, src="203.0.113.9", dst="192.168.1.5",
                                     proto="tcp", sport=5555, dport=port, length=60))
    d = s.host_detail("203.0.113.9")
    assert d["stats"]["packets_tx"] == 400
    assert len(d["ports"]) <= 256  # per-host port memory is capped
    assert s.host_detail("192.168.1.5")["stats"]["packets_rx"] == 400
    for i in range(200):
        s.record_packet(PacketRecord(ts=now, src=f"10.1.{i // 250}.{i % 250}", dst="10.0.0.1",
                                     proto="udp", sport=1, dport=2, length=10))
    assert len(s.hosts) <= 41


# ---------- API ----------

@pytest.fixture()
def client(tmp_path):
    cfg = Config()
    cfg.demo = True
    cfg.db_path = tmp_path / "ids.db"
    cfg.log_dir = tmp_path / "logs"
    app = create_app(cfg)
    with TestClient(app) as c:
        c.store = app.state.store
        c.engine = app.state.engine
        yield c


def test_alert_detail_and_triage_endpoint(client):
    client.store.record_alert(_alert(rule_id="WEB-SQLI-UNION", payload_hex=b"x union select".hex(),
                                     match_start=2, match_end=14))
    aid = client.store.recent_alerts[-1].id
    d = client.get(f"/api/alerts/{aid}").json()
    assert d["payload_hex"] and d["match_start"] == 2
    assert d["rule"]["id"] == "WEB-SQLI-UNION"
    assert "same_src" in d["related"]
    assert client.get("/api/alerts/999999").status_code == 404
    # list endpoints leave the payload out
    assert "payload_hex" not in client.get("/api/alerts?limit=5").json()[0]

    r = client.post("/api/alerts/status", json={"ids": [aid], "status": "ack"})
    assert r.status_code == 200 and r.json()["changed"] == 1
    assert client.get(f"/api/alerts/{aid}").json()["status"] == "ack"
    assert client.post("/api/alerts/status", json={"ids": [aid], "status": "nope"}).status_code == 400
    assert client.post("/api/alerts/status", json={"ids": [aid], "status": "ack"},
                       headers={"origin": "http://evil.example"}).status_code == 403
    assert client.get("/api/alerts?status=bogus").status_code == 400


def test_alert_query_filters(client):
    client.store.record_alert(_alert(src="203.0.113.77", rule_id="ONE"))
    client.store.record_alert(_alert(src="198.51.100.1", rule_id="TWO"))
    rows = client.get("/api/alerts?host=203.0.113.77").json()
    assert rows and all("203.0.113.77" in (a["src"], a["dst"]) for a in rows)
    assert all(a["rule_id"] == "TWO" for a in client.get("/api/alerts?rule_id=TWO").json())
    assert client.get("/api/alerts?host=evil;drop").status_code == 400


def test_rule_state_endpoint(client):
    r = client.post("/api/rules/WEB-SQLI-UNION/state", json={"enabled": False})
    assert r.status_code == 200
    assert "WEB-SQLI-UNION" in client.engine.disabled
    rules = {x["id"]: x for x in client.get("/api/rules").json()}
    assert rules["WEB-SQLI-UNION"]["enabled"] is False
    assert client.get("/api/status").json()["rules_disabled"] == 1
    # disabled state survives a rules reload from disk
    client.post("/api/rules/reload")
    assert "WEB-SQLI-UNION" in client.engine.disabled

    client.post("/api/rules/WEB-SQLI-UNION/state", json={"enabled": True, "mute_minutes": 60})
    rules = {x["id"]: x for x in client.get("/api/rules").json()}
    assert rules["WEB-SQLI-UNION"]["enabled"] is True and rules["WEB-SQLI-UNION"]["muted_until"]

    assert client.post("/api/rules/NOPE/state", json={"enabled": False}).status_code == 404
    assert client.post("/api/rules/RECON-PORTSCAN/state", json={"enabled": False}).status_code == 400
    assert client.post("/api/rules/RECON-PORTSCAN/state", json={"mute_minutes": 30}).status_code == 200
    assert client.post("/api/rules/WEB-SQLI-UNION/state", json={"enabled": False},
                       headers={"origin": "http://evil.example"}).status_code == 403


def test_hosts_flows_timeline_analytics(client):
    client.store.record_packet(PacketRecord(ts=time.time(), src="192.168.1.9", dst="8.8.8.8",
                                            proto="udp", sport=5353, dport=53, length=80))
    client.store.record_alert(_alert(src="192.168.1.9"))
    hosts = {h["host"]: h for h in client.get("/api/hosts").json()}
    assert hosts["192.168.1.9"]["internal"] is True and hosts["192.168.1.9"]["as_src"] >= 1
    d = client.get("/api/hosts/192.168.1.9").json()
    assert d["alert_count"] >= 1 and d["peers"]
    assert client.get("/api/hosts/10.250.250.250").status_code == 404
    assert client.get("/api/hosts/<script>").status_code in (400, 404)
    assert isinstance(client.get("/api/flows").json(), list)

    t = client.get("/api/alerts/timeline?hours=1&buckets=12").json()
    assert t["bucket"] == 300 and sum(b["high"] for b in t["series"]) >= 1
    a = client.get("/api/analytics?hours=24").json()
    assert a["total"] >= 1 and a["top_rules"] and "by_status" in a
    assert client.get("/api/alerts/timeline?hours=0").status_code == 422


def test_static_assets_revalidate(client):
    assert client.get("/static/app.js").headers["cache-control"] == "no-cache"
    assert client.get("/").headers["cache-control"] == "no-cache"
