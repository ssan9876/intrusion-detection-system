"""Runtime configuration loaded from environment variables / CLI.

Everything has a sensible default so the system can run with zero config in
demo mode, and be tuned for a real deployment via environment variables
(which is how the systemd unit / LXC passes settings).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _env_bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


@dataclass
class Config:
    # Capture
    interface: str | None = field(default_factory=lambda: os.environ.get("IDS_INTERFACE") or None)
    bpf_filter: str = field(default_factory=lambda: os.environ.get("IDS_BPF_FILTER", ""))
    # When True, no real capture happens; synthetic traffic + alerts are generated.
    # Auto-enabled when scapy can't capture (e.g. dev box with no privileges).
    demo: bool = field(default_factory=lambda: _env_bool("IDS_DEMO", False))

    # Web server
    host: str = field(default_factory=lambda: os.environ.get("IDS_HOST", "0.0.0.0"))
    port: int = field(default_factory=lambda: _env_int("IDS_PORT", 8080))

    # Storage
    db_path: Path = field(
        default_factory=lambda: Path(os.environ.get("IDS_DB_PATH", str(BASE_DIR / "data" / "ids.db")))
    )
    rules_path: Path = field(
        default_factory=lambda: Path(os.environ.get("IDS_RULES_PATH", str(BASE_DIR / "rules" / "default.rules.json")))
    )
    log_dir: Path = field(
        default_factory=lambda: Path(os.environ.get("IDS_LOG_DIR", str(BASE_DIR / "data" / "logs")))
    )
    # Hour (0-23, local time) at which the day's activity is written to a log
    # file and the live stats are reset for a fresh day.
    rollover_hour: int = field(default_factory=lambda: _env_int("IDS_ROLLOVER_HOUR", 23))

    # Retention / limits
    max_recent_packets: int = field(default_factory=lambda: _env_int("IDS_MAX_RECENT_PACKETS", 500))
    max_flows: int = field(default_factory=lambda: _env_int("IDS_MAX_FLOWS", 200))
    alert_history: int = field(default_factory=lambda: _env_int("IDS_ALERT_HISTORY", 1000))

    def ensure_dirs(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)


config = Config()
