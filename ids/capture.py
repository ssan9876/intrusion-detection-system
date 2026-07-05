"""Packet capture + decode layer.

Real capture uses scapy's AsyncSniffer. Each captured packet is decoded into a
small flat record, fed to the detection engine, and pushed to the store. When
real capture is unavailable (no privileges / no Npcap / no interface) the
sensor transparently falls back to demo mode, which synthesizes realistic
traffic and periodically replays attack payloads so the dashboard is alive.
"""
from __future__ import annotations

import random
import threading
import time
from typing import Callable

from .config import Config
from .detectors import PortScanDetector
from .engine import Engine
from .store import Alert, PacketRecord, Store

# scapy is imported lazily so the web app can start (in demo mode) on machines
# where scapy / Npcap isn't installed.
try:  # pragma: no cover - environment dependent
    from scapy.all import IP, TCP, UDP, ICMP, Raw, AsyncSniffer  # type: ignore

    SCAPY_AVAILABLE = True
except BaseException:  # pragma: no cover
    # BaseException, not Exception: a broken native dependency (e.g. a pyo3
    # panic inside cryptography) raises a BaseException subclass, and the
    # demo-mode fallback must survive that too.
    SCAPY_AVAILABLE = False


class Sensor:
    """Owns capture + detection, writing results into the Store."""

    def __init__(
        self,
        config: Config,
        engine: Engine,
        store: Store,
        on_alert: Callable[[Alert], None] | None = None,
    ):
        self.config = config
        self.engine = engine
        self.store = store
        self.on_alert = on_alert
        self._sniffer = None
        self._demo_thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.mode = "stopped"
        self._portscan = PortScanDetector(
            threshold=config.portscan_threshold, window=config.portscan_window
        )

    # ----- lifecycle -------------------------------------------------------
    def start(self) -> None:
        want_demo = self.config.demo or not SCAPY_AVAILABLE
        if not want_demo:
            try:
                self._start_real()
                self.mode = "live"
                return
            except Exception as exc:  # fall back rather than crash the dashboard
                print(f"[sensor] live capture failed ({exc!r}); falling back to demo mode")
        self._start_demo()
        self.mode = "demo"

    def stop(self) -> None:
        self._stop.set()
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
        if self._demo_thread is not None:
            self._demo_thread.join(timeout=2)

    # ----- real capture ----------------------------------------------------
    def _start_real(self) -> None:
        kwargs = {"prn": self._handle_scapy, "store": False}
        if self.config.interface:
            kwargs["iface"] = self.config.interface
        if self.config.bpf_filter:
            kwargs["filter"] = self.config.bpf_filter
        self._sniffer = AsyncSniffer(**kwargs)
        self._sniffer.start()

    def _handle_scapy(self, pkt) -> None:  # pragma: no cover - needs live traffic
        if IP not in pkt:
            return
        ip = pkt[IP]
        proto = "ip"
        sport = dport = None
        # Use the transport-layer payload bytes directly. Relying on Raw misses
        # data when scapy dissects the app layer into a higher protocol (e.g. it
        # parses UDP/53 into a DNS layer), so content signatures wouldn't see it.
        if TCP in pkt:
            proto, sport, dport = "tcp", int(pkt[TCP].sport), int(pkt[TCP].dport)
            payload = bytes(pkt[TCP].payload)
        elif UDP in pkt:
            proto, sport, dport = "udp", int(pkt[UDP].sport), int(pkt[UDP].dport)
            payload = bytes(pkt[UDP].payload)
        elif ICMP in pkt:
            proto = "icmp"
            payload = bytes(pkt[ICMP].payload)
        else:
            payload = bytes(ip.payload)
        self._ingest(
            ts=time.time(), src=ip.src, dst=ip.dst, proto=proto,
            sport=sport, dport=dport, length=len(pkt), payload=payload,
            summary=pkt.summary(),
        )

    # ----- shared ingest path ---------------------------------------------
    def _ingest(self, ts, src, dst, proto, sport, dport, length, payload, summary="") -> None:
        rec = PacketRecord(ts=ts, src=src, dst=dst, proto=proto, sport=sport,
                           dport=dport, length=length, summary=summary)
        self.store.record_packet(rec)

        hits = list(self.engine.evaluate(proto, sport, dport, payload))
        scan_hit = self._portscan.observe(ts, src, dst, proto, dport)
        if scan_hit is not None:
            hits.append(scan_hit)
        for rule in hits:
            detail = getattr(rule, "detail", "") or (
                payload[:120].decode("latin-1", "ignore") if payload else summary
            )
            alert = Alert(
                ts=ts, rule_id=rule.id, rule_name=rule.name, severity=rule.severity,
                category=rule.category, src=src, dst=dst, proto=proto, sport=sport,
                dport=dport, detail=detail.strip(),
            )
            self.store.record_alert(alert)
            if self.on_alert:
                self.on_alert(alert)

    # ----- demo mode -------------------------------------------------------
    def _start_demo(self) -> None:
        self._demo_thread = threading.Thread(target=self._demo_loop, daemon=True)
        self._demo_thread.start()

    def _demo_loop(self) -> None:
        hosts = [f"192.168.88.{i}" for i in (10, 12, 20, 25, 42, 100, 150, 166)]
        externals = ["8.8.8.8", "1.1.1.1", "140.82.112.3", "13.107.42.14",
                     "151.101.1.69", "203.0.113.66", "198.51.100.23"]
        benign_payloads = [
            b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
            b"GET /api/v1/status HTTP/1.1\r\nHost: dashboard.local\r\n\r\n",
            b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03",  # TLS client hello-ish
            b"",
        ]
        # (proto, dport, payload) attack samples that trip the default ruleset
        attacks = [
            ("tcp", 80, b"GET /x HTTP/1.1\r\nUser-Agent: WindowsPowerShell/5.1\r\n\r\n"),
            ("tcp", 80, b"GET /page.php?id=1 union select user,pass from admins HTTP/1.1\r\n"),
            ("tcp", 80, b"GET /../../../../etc/passwd HTTP/1.1\r\n"),
            ("tcp", 445, b"X" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"),
            ("tcp", 4444, b"this is a metasploit meterpreter session"),
            ("udp", 53, b"\x00\x01" + b"averylongsubdomainusedfordnstunnelingexfiltration0123456789" + b"\x00"),
            ("tcp", 80, b"GET /shell/cmd.php?c=whoami HTTP/1.1\r\n"),
            ("tcp", 1337, b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xeb\x1f"),
        ]
        while not self._stop.is_set():
            # burst of benign traffic
            for _ in range(random.randint(3, 9)):
                internal = random.choice(hosts)
                ext = random.choice(externals + hosts)
                if random.random() < 0.5:
                    src, dst = internal, ext
                    sport, dport = random.randint(1024, 65535), random.choice([80, 443, 53, 22])
                else:
                    src, dst = ext, internal
                    sport, dport = random.choice([80, 443, 53]), random.randint(1024, 65535)
                proto = "udp" if dport == 53 else "tcp"
                payload = random.choice(benign_payloads)
                self._ingest(
                    ts=time.time(), src=src, dst=dst, proto=proto, sport=sport,
                    dport=dport, length=len(payload) + random.randint(40, 600),
                    payload=payload, summary=f"{proto.upper()} {src}:{sport} -> {dst}:{dport}",
                )
            # rare port scan (trips the stateful PortScanDetector)
            if random.random() < 0.02:
                scanner = random.choice(externals)
                target = random.choice(hosts)
                now = time.time()
                for port in random.sample(range(20, 1100), 20):
                    self._ingest(
                        ts=now, src=scanner, dst=target, proto="tcp",
                        sport=random.randint(40000, 65535), dport=port,
                        length=60, payload=b"",
                        summary=f"TCP {scanner} -> {target}:{port} [SYN]",
                    )
            # occasional attack
            if random.random() < 0.35:
                proto, dport, payload = random.choice(attacks)
                src = random.choice(externals)
                dst = random.choice(hosts)
                self._ingest(
                    ts=time.time(), src=src, dst=dst, proto=proto,
                    sport=random.randint(1024, 65535), dport=dport,
                    length=len(payload) + 40, payload=payload,
                    summary=f"{proto.upper()} {src} -> {dst}:{dport}",
                )
            time.sleep(0.8)
