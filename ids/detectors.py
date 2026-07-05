"""Stateful (threshold-based) detectors that complement the signature engine.

Signatures match single packets; these detectors keep a little state across
packets to catch behaviours no single packet reveals — e.g. one host probing
many ports. Detectors return pseudo-rule hits shaped like `rules.Rule` so the
alert pipeline treats them uniformly.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass


@dataclass(frozen=True)
class DetectorHit:
    """Duck-types the subset of `rules.Rule` the alert pipeline needs."""

    id: str
    name: str
    severity: str
    category: str
    detail: str = ""


class PortScanDetector:
    """Flags a source that touches many distinct destination ports in a short window.

    Classic TCP/UDP port-scan heuristic: per source IP, keep the (port, time)
    pairs seen in the last `window` seconds; alert once the distinct-port count
    reaches `threshold`, then hold off for `cooldown` seconds per source so a
    long scan doesn't emit hundreds of duplicate alerts.
    """

    def __init__(self, threshold: int = 15, window: float = 10.0, cooldown: float = 60.0,
                 max_tracked_sources: int = 4096):
        self.threshold = threshold
        self.window = window
        self.cooldown = cooldown
        self.max_tracked_sources = max_tracked_sources
        self._lock = threading.Lock()
        self._seen: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        self._last_alert: dict[str, float] = {}

    def observe(self, ts: float, src: str, dst: str, proto: str, dport: int | None) -> DetectorHit | None:
        if dport is None or proto not in ("tcp", "udp"):
            return None
        with self._lock:
            q = self._seen[src]
            q.append((ts, dport))
            horizon = ts - self.window
            while q and q[0][0] < horizon:
                q.popleft()

            # bound memory: drop the stalest sources if too many are tracked
            if len(self._seen) > self.max_tracked_sources:
                stale = sorted(self._seen, key=lambda s: self._seen[s][-1][0] if self._seen[s] else 0)
                for s in stale[: len(self._seen) - self.max_tracked_sources]:
                    self._seen.pop(s, None)
                    self._last_alert.pop(s, None)

            distinct = {p for _, p in q}
            if len(distinct) < self.threshold:
                return None
            if ts - self._last_alert.get(src, 0.0) < self.cooldown:
                return None
            self._last_alert[src] = ts
            ports = sorted(distinct)
            shown = ", ".join(map(str, ports[:12])) + ("…" if len(ports) > 12 else "")
            return DetectorHit(
                id="RECON-PORTSCAN",
                name="Port scan detected (many ports probed by one host)",
                severity="high",
                category="recon",
                detail=f"{src} probed {len(distinct)} ports in {self.window:.0f}s: {shown}",
            )
