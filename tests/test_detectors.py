"""Unit tests for the stateful port-scan detector."""
from ids.detectors import PortScanDetector


def test_scan_fires_at_threshold():
    det = PortScanDetector(threshold=5, window=10.0, cooldown=60.0)
    hit = None
    for i, port in enumerate(range(100, 110)):
        hit = det.observe(1000.0 + i * 0.1, "10.0.0.9", "10.0.0.1", "tcp", port)
        if hit:
            break
    assert hit is not None
    assert hit.id == "RECON-PORTSCAN"
    assert "10.0.0.9" in hit.detail


def test_repeat_probes_on_same_port_do_not_fire():
    det = PortScanDetector(threshold=5, window=10.0)
    for i in range(50):
        assert det.observe(1000.0 + i * 0.1, "10.0.0.9", "10.0.0.1", "tcp", 80) is None


def test_slow_scan_outside_window_does_not_fire():
    det = PortScanDetector(threshold=5, window=10.0)
    for i, port in enumerate(range(100, 120)):
        # one port every 11s: window only ever holds one entry
        assert det.observe(1000.0 + i * 11.0, "10.0.0.9", "10.0.0.1", "tcp", port) is None


def test_cooldown_suppresses_duplicate_alerts():
    det = PortScanDetector(threshold=3, window=10.0, cooldown=60.0)
    hits = 0
    for i, port in enumerate(range(100, 130)):
        if det.observe(1000.0 + i * 0.1, "10.0.0.9", "10.0.0.1", "tcp", port):
            hits += 1
    assert hits == 1  # 30 ports in ~3s but only one alert inside the cooldown


def test_non_port_traffic_ignored():
    det = PortScanDetector(threshold=1, window=10.0)
    assert det.observe(1000.0, "a", "b", "icmp", None) is None
    assert det.observe(1000.0, "a", "b", "tcp", None) is None


def test_source_table_is_bounded():
    det = PortScanDetector(threshold=100, window=10.0, max_tracked_sources=50)
    for i in range(500):
        det.observe(1000.0 + i, f"10.1.{i // 250}.{i % 250}", "b", "tcp", 80)
    assert len(det._seen) <= 51
