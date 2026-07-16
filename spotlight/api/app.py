"""FastAPI backend — Phase 1 slice.

REST + WebSocket. In-memory sweep registry for Phase 1; Phase 3 migrates to
Postgres. The WS hub streams the orchestrator's EventBus to connected
clients (Live Sweep view).
"""
from __future__ import annotations

import asyncio
import json
import threading
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from spotlight.orchestrator import EventBus, Orchestrator, SweepResult

app = FastAPI(title="Spotlight API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory registries — Phase 1 only.
SWEEPS: dict[str, SweepResult] = {}
BUSES: dict[str, EventBus] = {}


class SweepRequest(BaseModel):
    repo: str
    surfaces: list[str] = ["code"]
    deployment_tier: str = "t0-mock"


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True, "service": "spotlight-api"}


@app.get("/targets")
def list_targets() -> list[dict]:
    """List the bundled fixture targets so the UI has something to pick from."""
    root = Path(__file__).resolve().parents[2] / "targets"
    if not root.exists():
        return []
    out = []
    for p in sorted(root.iterdir()):
        if not p.is_dir() or p.name.startswith(".") or p.name == "sweep-run":
            continue
        gt = p / "ground_truth.json"
        out.append({"name": p.name, "path": str(p), "has_ground_truth": gt.exists()})
    return out


@app.post("/sweeps")
def start_sweep(req: SweepRequest) -> dict:
    repo_path = Path(req.repo)
    if not repo_path.exists():
        alt = Path(__file__).resolve().parents[2] / "targets" / req.repo
        if alt.exists():
            repo_path = alt
        else:
            raise HTTPException(404, f"repo not found: {req.repo}")
    bus = EventBus()
    orch = Orchestrator(bus=bus)
    ready = threading.Event()

    def _worker():
        # Pre-emit sweep.started so the caller can grab sweep_id before the
        # heavy work begins.
        result = orch.run(repo_path)
        SWEEPS[result.sweep_id] = result

    # Register the bus BEFORE starting so the sweep_id can be captured.
    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()
    # Wait synchronously for the first event so we can return sweep_id.
    import time as _t
    for _ in range(200):
        if bus.all():
            break
        _t.sleep(0.005)
    if not bus.all():
        raise HTTPException(500, "sweep failed to start")
    sweep_id = bus.all()[0].sweep_id
    BUSES[sweep_id] = bus
    _running_threads[sweep_id] = thread
    return {"sweep_id": sweep_id, "status": "running"}


_running_threads: dict[str, threading.Thread] = {}


@app.get("/sweeps/{sweep_id}")
def get_sweep(sweep_id: str) -> dict:
    if sweep_id not in SWEEPS and sweep_id not in BUSES:
        raise HTTPException(404, "sweep not found")
    if sweep_id in SWEEPS:
        s = SWEEPS[sweep_id]
        return {
            "sweep_id": s.sweep_id,
            "repo": s.repo_path,
            "status": "finished",
            "findings_count": len(s.findings),
        }
    return {"sweep_id": sweep_id, "status": "running"}


@app.get("/sweeps/{sweep_id}/events")
def sweep_events(sweep_id: str, after: int = -1) -> list[dict]:
    if sweep_id not in BUSES:
        raise HTTPException(404, "sweep not found")
    return [e.to_dict() for e in BUSES[sweep_id].replay(sweep_id, after_seq=after)]


@app.get("/sweeps/{sweep_id}/findings")
def sweep_findings(sweep_id: str) -> list[dict]:
    if sweep_id not in SWEEPS:
        raise HTTPException(404, "sweep not finished yet or not found")
    return SWEEPS[sweep_id].findings


@app.get("/findings/{finding_id}")
def get_finding(finding_id: str) -> dict:
    for s in SWEEPS.values():
        for f in s.findings:
            if f["id"] == finding_id:
                return f
    raise HTTPException(404, "finding not found")


@app.get("/attestations/{sweep_id}")
def get_attestation(sweep_id: str) -> dict:
    if sweep_id not in SWEEPS:
        raise HTTPException(404, "sweep not found")
    return SWEEPS[sweep_id].attestations[0]


@app.websocket("/ws/sweeps/{sweep_id}")
async def ws_sweep(ws: WebSocket, sweep_id: str) -> None:
    await ws.accept()
    # Wait briefly for the sweep to register.
    for _ in range(100):
        if sweep_id in BUSES:
            break
        await asyncio.sleep(0.05)
    if sweep_id not in BUSES:
        await ws.send_json({"error": "sweep_not_found"})
        await ws.close()
        return
    bus = BUSES[sweep_id]
    q = bus.subscribe_async()
    # Replay any events already in the log so late-joining clients see the start.
    for e in bus.replay(sweep_id):
        await ws.send_json(e.to_dict())
    thread = _running_threads.get(sweep_id)
    try:
        while True:
            try:
                evt = await asyncio.wait_for(q.get(), timeout=0.5)
                await ws.send_json(evt.to_dict())
                if evt.type == "sweep.finished":
                    await asyncio.sleep(0.1)
                    break
            except asyncio.TimeoutError:
                if thread and not thread.is_alive() and q.empty():
                    break
    except WebSocketDisconnect:
        return
    await ws.close()
