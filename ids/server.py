"""FastAPI app: serves the dashboard, a live WebSocket feed, and a small REST API."""
from __future__ import annotations

import asyncio
import contextlib
import json
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from .capture import SCAPY_AVAILABLE, Sensor
from .config import Config
from .engine import Engine
from .rules import RuleSet
from .store import Alert, Store

WEB_DIR = Path(__file__).resolve().parent.parent / "web"


def _seconds_until_hour(hour: int) -> float:
    """Seconds from now until the next occurrence of HH:00 local time."""
    now = datetime.now()
    target = now.replace(hour=hour % 24, minute=0, second=0, microsecond=0)
    if target <= now:
        target += timedelta(days=1)
    return (target - now).total_seconds()


class Hub:
    """Tracks connected websocket clients and broadcasts to them."""

    def __init__(self) -> None:
        self.clients: set[WebSocket] = set()
        self.loop: asyncio.AbstractEventLoop | None = None

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.clients.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self.clients.discard(ws)

    async def broadcast(self, message: dict) -> None:
        if not self.clients:
            return
        data = json.dumps(message, default=str)
        dead = []
        for ws in list(self.clients):
            try:
                await ws.send_text(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    def broadcast_threadsafe(self, message: dict) -> None:
        """Callable from the capture thread."""
        if self.loop is None:
            return
        asyncio.run_coroutine_threadsafe(self.broadcast(message), self.loop)


def create_app(config: Config) -> FastAPI:
    config.ensure_dirs()
    ruleset = RuleSet.load(config.rules_path)
    engine = Engine(ruleset)
    store = Store(
        db_path=config.db_path,
        max_recent=config.max_recent_packets,
        max_flows=config.max_flows,
        alert_history=config.alert_history,
    )
    hub = Hub()
    sensor = Sensor(
        config, engine, store,
        on_alert=lambda a: hub.broadcast_threadsafe({"type": "alert", "alert": a.as_dict()}),
    )

    app = FastAPI(title="Signature NIDS", version="0.1.0")

    @app.on_event("startup")
    async def _startup() -> None:
        hub.loop = asyncio.get_running_loop()
        sensor.start()
        # prune stale reports once at startup
        pruned = store.prune_logs(config.log_dir, config.log_retention_days)
        if pruned:
            print(f"[prune] removed {len(pruned)} report file(s) older than {config.log_retention_days}d")
        app.state.pusher = asyncio.create_task(_push_snapshots())
        app.state.roller = asyncio.create_task(_daily_rollover())

    @app.on_event("shutdown")
    async def _shutdown() -> None:
        for task in (app.state.pusher, app.state.roller):
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        sensor.stop()

    async def _push_snapshots() -> None:
        while True:
            await asyncio.sleep(1.0)
            await hub.broadcast({"type": "snapshot", "data": store.snapshot()})

    async def _daily_rollover() -> None:
        """At config.rollover_hour each day, archive the day and reset stats."""
        while True:
            await asyncio.sleep(_seconds_until_hour(config.rollover_hour))
            try:
                path = store.export_and_reset(config.log_dir)
                print(f"[rollover] wrote daily log {path}; stats reset")
                pruned = store.prune_logs(config.log_dir, config.log_retention_days)
                if pruned:
                    print(f"[prune] removed {len(pruned)} report file(s) older than {config.log_retention_days}d")
                await hub.broadcast({"type": "rollover", "file": path.name})
            except Exception as exc:  # never let the loop die
                print(f"[rollover] failed: {exc!r}")
            await asyncio.sleep(60)  # ensure we move past the trigger minute

    @app.get("/api/status")
    async def status() -> dict:
        return {
            "mode": sensor.mode,
            "scapy_available": SCAPY_AVAILABLE,
            "interface": config.interface or "default",
            "rules_loaded": engine.rule_count,
            "rules_source": str(config.rules_path),
        }

    @app.get("/api/snapshot")
    async def snapshot() -> dict:
        return store.snapshot()

    @app.get("/api/alerts")
    async def alerts(limit: int = 200, severity: str | None = None) -> list[dict]:
        return store.query_alerts(limit=limit, severity=severity)

    @app.get("/api/logs")
    async def list_logs() -> dict:
        """List archived daily logs (newest first) and the next rollover time."""
        logs = []
        for p in sorted(config.log_dir.glob("nids-*.txt"), reverse=True):
            st = p.stat()
            logs.append({
                "name": p.name,
                "size": st.st_size,
                "modified": datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
                # the matching structured report, if present
                "json": p.with_suffix(".json").name if p.with_suffix(".json").is_file() else None,
            })
        nxt = datetime.now() + timedelta(seconds=_seconds_until_hour(config.rollover_hour))
        return {
            "rollover_hour": config.rollover_hour,
            "next_rollover": nxt.isoformat(timespec="seconds"),
            "retention_days": config.log_retention_days,
            "log_dir": str(config.log_dir),
            "logs": logs,
        }

    @app.get("/api/logs/{name}")
    async def get_log(name: str, download: bool = False):
        """Return an archived report. ?download=1 forces a file download."""
        # prevent path traversal; only serve report files from the log dir
        if "/" in name or "\\" in name or ".." in name or not name.startswith("nids-"):
            raise HTTPException(status_code=400, detail="invalid name")
        path = config.log_dir / name
        if not path.is_file():
            raise HTTPException(status_code=404, detail="not found")
        media = "application/json" if path.suffix == ".json" else "text/plain"
        headers = {"Content-Disposition": f'attachment; filename="{name}"'} if download else {}
        return PlainTextResponse(path.read_text(encoding="utf-8"), media_type=media, headers=headers)

    @app.post("/api/rollover")
    async def rollover() -> dict:
        """Manually trigger the daily archive + stats reset (used for testing)."""
        path = store.export_and_reset(config.log_dir)
        await hub.broadcast({"type": "rollover", "file": path.name})
        return {"ok": True, "log": path.name}

    @app.get("/api/rules")
    async def rules() -> list[dict]:
        return [
            {
                "id": r.id, "name": r.name, "severity": r.severity,
                "category": r.category, "protocol": r.protocol,
                "src_port": r.src_port, "dst_port": r.dst_port,
                "references": r.references,
            }
            for r in ruleset.rules
        ]

    @app.websocket("/ws")
    async def ws_endpoint(ws: WebSocket) -> None:
        await hub.connect(ws)
        try:
            # send an immediate snapshot so the page isn't blank for up to 1s
            await ws.send_text(json.dumps({"type": "snapshot", "data": store.snapshot()}, default=str))
            while True:
                await ws.receive_text()  # keepalive / ignore client messages
        except WebSocketDisconnect:
            hub.disconnect(ws)
        except Exception:
            hub.disconnect(ws)

    @app.get("/", response_class=HTMLResponse)
    async def index() -> str:
        return (WEB_DIR / "index.html").read_text(encoding="utf-8")

    app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")
    return app
