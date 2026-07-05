"""API tests: security guards and the new endpoints."""
import time

import pytest
from fastapi.testclient import TestClient

from ids.config import Config
from ids.server import create_app
from ids.store import Alert


@pytest.fixture()
def client(tmp_path, monkeypatch):
    cfg = Config()
    cfg.demo = True
    cfg.db_path = tmp_path / "ids.db"
    cfg.log_dir = tmp_path / "logs"
    app = create_app(cfg)
    with TestClient(app) as c:
        yield c


def test_status_and_snapshot(client):
    s = client.get("/api/status").json()
    assert s["rules_loaded"] > 0
    snap = client.get("/api/snapshot").json()
    assert "totals" in snap and "bandwidth" in snap


def test_alerts_limit_bounded(client):
    assert client.get("/api/alerts?limit=999999").status_code == 422
    assert client.get("/api/alerts?limit=0").status_code == 422
    assert client.get("/api/alerts?limit=10").status_code == 200


def test_alerts_severity_validated(client):
    assert client.get("/api/alerts?severity=bogus").status_code == 400
    assert client.get("/api/alerts?severity=high").status_code == 200


def test_alerts_csv(client):
    r = client.get("/api/alerts.csv")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert r.text.splitlines()[0].startswith("ts,time,severity")


def test_log_name_traversal_blocked(client):
    for bad in ("..%2F..%2Fetc%2Fpasswd", "nids-..txt", "nids-2024-01-01.txt.bak",
                "passwd", "nids-2024-01-01.exe"):
        assert client.get(f"/api/logs/{bad}").status_code in (400, 404)
    # regression: URL-encoded traversal must never escape the log dir
    assert client.get("/api/logs/%2e%2e%2fsecret.txt").status_code in (400, 404)


def test_log_valid_name_shape_allowed(client):
    # valid-shape name that doesn't exist -> 404, not 400
    assert client.get("/api/logs/nids-2024-01-01.txt").status_code == 404
    assert client.get("/api/logs/nids-2024-01-01_123456.json").status_code == 404


def test_rollover_csrf_guard(client):
    # cross-origin browser POST is rejected
    r = client.post("/api/rollover", headers={"origin": "http://evil.example"})
    assert r.status_code == 403
    # same-origin and non-browser (no Origin) requests pass
    host = "testserver"
    r = client.post("/api/rollover", headers={"origin": f"http://{host}", "host": host})
    assert r.status_code == 200
    r = client.post("/api/rollover")
    assert r.status_code == 200


def test_rules_reload(client):
    r = client.post("/api/rules/reload")
    assert r.status_code == 200
    assert r.json()["rules_loaded"] > 0
    r = client.post("/api/rules/reload", headers={"origin": "http://evil.example"})
    assert r.status_code == 403


def test_rollover_writes_report(client, tmp_path):
    r = client.post("/api/rollover").json()
    assert r["ok"]
    name = r["log"]
    got = client.get(f"/api/logs/{name}")
    assert got.status_code == 200
    assert "Daily Activity Report" in got.text


def test_websocket_cross_origin_rejected(client):
    with pytest.raises(Exception):
        with client.websocket_connect("/ws", headers={"origin": "http://evil.example"}):
            pass


def test_websocket_same_origin_gets_snapshot(client):
    with client.websocket_connect("/ws") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "snapshot"


def test_store_talkers_bounded(tmp_path):
    from ids.store import PacketRecord, Store
    store = Store(db_path=tmp_path / "t.db", max_recent=10, max_flows=10,
                  alert_history=10, max_talkers=50)
    now = time.time()
    for i in range(500):
        store.record_packet(PacketRecord(
            ts=now, src=f"10.9.{i // 250}.{i % 250}", dst="10.0.0.1",
            proto="tcp", sport=1, dport=2, length=100,
        ))
    assert len(store.talker_bytes) <= 101
