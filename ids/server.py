"""FastAPI app: serves the dashboard, a live WebSocket feed, and a small REST API."""
from __future__ import annotations

import asyncio
import contextlib
import csv
import io
import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles

from .capture import SCAPY_AVAILABLE, Sensor
from .config import Config
from .engine import Engine
from .rules import RuleError, RuleSet
from .store import Alert, Store

WEB_DIR = Path(__file__).resolve().parent.parent / "web"

# Archived reports are only ever named nids-YYYY-MM-DD[.HHMMSS suffix].txt/.json;
# anything else is rejected before touching the filesystem.
LOG_NAME_RE = re.compile(r"^nids-\d{4}-\d{2}-\d{2}(_\d{6})?\.(txt|json)$")

SEVERITY_VALUES = {"low", "medium", "high", "critical"}


def _seconds_until_hour(hour: int) -> float:
    """Seconds from now until the next occurrence of HH:00 local time."""
    now = datetime.now()
    target = now.replace(hour=hour % 24, minute=0, second=0, microsecond=0)
    if target <= now:
        target += timedelta(days=1)
    return (target - now).total_seconds()


def _require_same_origin(request: Request) -> None:
    """CSRF guard for state-changing endpoints.

    Browsers attach Origin to cross-site POSTs; if one is present it must match
    the host we're being addressed as. Non-browser clients (curl, scripts) send
    no Origin and pass through.
    """
    origin = request.headers.get("origin")
    if not origin:
        return
    origin_host = urlsplit(origin).netloc
    if origin_host != request.headers.get("host", ""):
        raise HTTPException(status_code=403, detail="cross-origin request rejected")


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
        max_talkers=config.max_talkers,
    )
    hub = Hub()
    sensor = Sensor(
        config, engine, store,
        on_alert=lambda a: hub.broadcast_threadsafe({"type": "alert", "alert": a.as_dict()}),
    )

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

    @contextlib.asynccontextmanager
    async def _lifespan(app: FastAPI):
        hub.loop = asyncio.get_running_loop()
        sensor.start()
        # prune stale reports once at startup
        pruned = store.prune_logs(config.log_dir, config.log_retention_days)
        if pruned:
            print(f"[prune] removed {len(pruned)} report file(s) older than {config.log_retention_days}d")
        pusher = asyncio.create_task(_push_snapshots())
        roller = asyncio.create_task(_daily_rollover())
        try:
            yield
        finally:
            for task in (pusher, roller):
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            sensor.stop()

    app = FastAPI(title="Signature NIDS", version="0.2.0", lifespan=_lifespan)

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
    async def alerts(
        limit: int = Query(200, ge=1, le=5000),
        severity: str | None = Query(None),
    ) -> list[dict]:
        if severity is not None and severity not in SEVERITY_VALUES:
            raise HTTPException(status_code=400, detail="invalid severity")
        return store.query_alerts(limit=limit, severity=severity)

    @app.get("/api/alerts.csv")
    async def alerts_csv(
        limit: int = Query(1000, ge=1, le=100000),
        severity: str | None = Query(None),
    ) -> Response:
        """Alert history as CSV, for spreadsheets / SIEM import."""
        if severity is not None and severity not in SEVERITY_VALUES:
            raise HTTPException(status_code=400, detail="invalid severity")
        rows = store.query_alerts(limit=limit, severity=severity)
        buf = io.StringIO()
        fields = ["ts", "time", "severity", "rule_id", "rule_name", "category",
                  "src", "sport", "dst", "dport", "proto", "detail"]
        w = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            r["time"] = datetime.fromtimestamp(r["ts"]).isoformat(timespec="seconds")
            w.writerow(r)
        filename = f"nids-alerts-{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"
        return Response(
            buf.getvalue(), media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

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
        nxt = datetime.now().astimezone() + timedelta(seconds=_seconds_until_hour(config.rollover_hour))
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
        # strict allow-list of report names; blocks traversal and header injection
        if not LOG_NAME_RE.match(name):
            raise HTTPException(status_code=400, detail="invalid name")
        path = config.log_dir / name
        if not path.is_file():
            raise HTTPException(status_code=404, detail="not found")
        media = "application/json" if path.suffix == ".json" else "text/plain"
        headers = {"Content-Disposition": f'attachment; filename="{name}"'} if download else {}
        return FileResponse(path, media_type=media, headers=headers)

    @app.post("/api/rollover")
    async def rollover(request: Request) -> dict:
        """Manually trigger the daily archive + stats reset (used for testing)."""
        _require_same_origin(request)
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
                "content": r.content, "content_hex": r.content_hex,
                "regex": r.regex, "references": r.references,
            }
            for r in engine.ruleset.rules
        ]

    @app.post("/api/rules/reload")
    async def reload_rules(request: Request) -> dict:
        """Re-read the signature file and hot-swap it into the engine."""
        _require_same_origin(request)
        try:
            new_set = RuleSet.load(config.rules_path)
        except (RuleError, OSError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=400, detail=f"rules not reloaded: {exc}")
        engine.reload(new_set)
        await hub.broadcast({"type": "rules", "count": engine.rule_count})
        return {"ok": True, "rules_loaded": engine.rule_count}

    @app.websocket("/ws")
    async def ws_endpoint(ws: WebSocket) -> None:
        # Reject cross-site WebSocket connections: browsers always send Origin,
        # and without this check any web page could read the live traffic feed.
        origin = ws.headers.get("origin")
        if origin and urlsplit(origin).netloc != ws.headers.get("host", ""):
            await ws.close(code=4403)
            return
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
