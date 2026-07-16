"""FastAPI backend — Phase 1.5.

REST + WebSocket. Persistent Postgres store when DATABASE_URL is set; falls
back to in-memory otherwise (tests). Supports fixture targets *and* arbitrary
git URLs (cloned into an ephemeral workdir).
"""
from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import desc

from spotlight.orchestrator import EventBus, Orchestrator, SweepResult
from spotlight.store import (
    EventRow,
    FindingRow,
    SweepRow,
    get_session,
    init_schema,
    is_enabled as store_enabled,
)

app = FastAPI(title="Spotlight API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _startup() -> None:
    init_schema()
    _mark_orphaned_running_as_failed()


def _mark_orphaned_running_as_failed() -> None:
    """Any sweep still marked 'running' from a previous container instance is
    an orphan — the process that owned it is dead. Mark them 'failed' on
    startup so they don't pollute the history."""
    if not store_enabled():
        return
    try:
        with get_session() as sess:
            rows = sess.query(SweepRow).filter(SweepRow.status == "running").all()
            for r in rows:
                r.status = "failed"
                if r.finished_at is None:
                    r.finished_at = datetime.now(timezone.utc)
    except Exception as exc:
        print(f"[startup] orphan cleanup failed: {exc!r}")


# In-memory registries — used when DATABASE_URL isn't set (tests), *and* as a
# hot cache of in-flight sweeps so the WS hub can subscribe live.
SWEEPS: dict[str, SweepResult] = {}
BUSES: dict[str, EventBus] = {}
_running_threads: dict[str, threading.Thread] = {}
_git_workdirs: dict[str, Path] = {}


class SweepRequest(BaseModel):
    repo: str
    surfaces: list[str] = ["code"]
    deployment_tier: str = "t0-mock"


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True, "service": "spotlight-api", "storage": "postgres" if store_enabled() else "memory"}


@app.get("/targets")
def list_targets() -> list[dict]:
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
    repo_path, source = _resolve_repo(req.repo)
    bus = EventBus()
    orch = Orchestrator(bus=bus)

    def _worker():
        result = None
        try:
            result = orch.run(repo_path)
            SWEEPS[result.sweep_id] = result
            _persist_sweep(result, source=source, repo_name=repo_path.name)
        except Exception as exc:
            # Mark the row as failed so it doesn't pollute history.
            try:
                if bus.all():
                    fid = bus.all()[0].sweep_id
                    _mark_sweep_failed(fid, repr(exc)[:200])
            except Exception:
                pass
        finally:
            wd = _git_workdirs.pop(result.sweep_id if result else "", None)
            if wd and wd.exists():
                shutil.rmtree(wd, ignore_errors=True)

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()
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
    if source == "git-url":
        _git_workdirs[sweep_id] = repo_path
    # Persist the sweep header immediately so it's visible in history.
    _persist_sweep_header(sweep_id, repo_path, source)
    return {"sweep_id": sweep_id, "status": "running", "repo_name": repo_path.name, "source": source}


def _resolve_repo(repo: str) -> tuple[Path, str]:
    """Resolve a repo argument to a filesystem path, cloning if it's a git URL.

    Returns (path, source_kind).
    """
    if repo.startswith(("http://", "https://", "git@")) and repo.endswith(".git"):
        workdir = Path(tempfile.mkdtemp(prefix="spotlight-clone-"))
        # Shallow clone at HEAD — Phase 2 will accept a --pin-sha.
        proc = subprocess.run(
            ["git", "clone", "--depth", "1", repo, str(workdir / "src")],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if proc.returncode != 0:
            shutil.rmtree(workdir, ignore_errors=True)
            raise HTTPException(400, f"git clone failed: {proc.stderr.strip()[:400]}")
        return workdir / "src", "git-url"
    # Bundled fixture — look up in targets/
    p = Path(repo)
    if not p.exists():
        alt = Path(__file__).resolve().parents[2] / "targets" / repo
        if alt.exists():
            return alt, "fixture"
        raise HTTPException(404, f"repo not found: {repo}")
    return p, "fixture"


def _mark_sweep_failed(sweep_id: str, reason: str) -> None:
    if not store_enabled():
        return
    try:
        with get_session() as sess:
            row = sess.get(SweepRow, sweep_id)
            if row:
                row.status = "failed"
                row.finished_at = datetime.now(timezone.utc)
    except Exception:
        pass


def _persist_sweep_header(sweep_id: str, repo_path: Path, source: str) -> None:
    if not store_enabled():
        return
    try:
        with get_session() as sess:
            existing = sess.get(SweepRow, sweep_id)
            if existing:
                return
            sess.add(
                SweepRow(
                    id=sweep_id,
                    repo_path=str(repo_path),
                    repo_name=repo_path.name,
                    source=source,
                    status="running",
                )
            )
    except Exception:
        pass


def _persist_sweep(result: SweepResult, source: str, repo_name: str) -> None:
    if not store_enabled():
        return
    try:
        with get_session() as sess:
            row = sess.get(SweepRow, result.sweep_id) or SweepRow(id=result.sweep_id)
            row.repo_path = result.repo_path
            row.repo_name = repo_name
            row.source = source
            row.status = "finished"
            row.threat_model = result.threat_model
            row.signals = result.signals
            row.finished_at = datetime.now(timezone.utc)
            row.findings_count = len(result.findings)
            sess.merge(row)
            # Clear + rewrite findings and events for idempotency.
            sess.query(FindingRow).filter(FindingRow.sweep_id == result.sweep_id).delete()
            sess.query(EventRow).filter(EventRow.sweep_id == result.sweep_id).delete()
            for f in result.findings:
                sess.add(
                    FindingRow(
                        id=f["id"],
                        sweep_id=result.sweep_id,
                        surface=f["surface"],
                        title=f["title"],
                        severity=f["severity"],
                        class_=f["class"],
                        cwe=f["cwe"],
                        file=f["location"]["file"],
                        line=f["location"]["line"],
                        function=f["location"]["function"],
                        state=f["state"],
                        tier=f["tier"],
                        confidence=f["confidence"],
                        payload=f,
                    )
                )
            for e in result.events_log:
                sess.add(
                    EventRow(
                        sweep_id=result.sweep_id,
                        seq=e["seq"],
                        ts=e["ts"],
                        type=e["type"],
                        actor=e["actor"],
                        payload=e.get("payload", {}),
                    )
                )
    except Exception as exc:
        print(f"[persist_sweep] failed: {exc!r}")


@app.get("/sweeps")
def list_sweeps() -> list[dict]:
    if store_enabled():
        try:
            with get_session() as sess:
                rows = sess.query(SweepRow).order_by(desc(SweepRow.started_at)).limit(100).all()
                return [
                    {
                        "sweep_id": r.id,
                        "repo_name": r.repo_name,
                        "source": r.source,
                        "status": r.status,
                        "findings_count": r.findings_count,
                        "started_at": r.started_at.isoformat() if r.started_at else None,
                        "finished_at": r.finished_at.isoformat() if r.finished_at else None,
                    }
                    for r in rows
                ]
        except Exception:
            pass
    # Fallback: in-memory only.
    return [
        {
            "sweep_id": s.sweep_id,
            "repo_name": Path(s.repo_path).name,
            "source": "fixture",
            "status": "finished",
            "findings_count": len(s.findings),
            "started_at": None,
            "finished_at": None,
        }
        for s in SWEEPS.values()
    ]


@app.get("/sweeps/{sweep_id}")
def get_sweep(sweep_id: str) -> dict:
    if sweep_id in SWEEPS:
        s = SWEEPS[sweep_id]
        return {"sweep_id": s.sweep_id, "repo": s.repo_path, "status": "finished", "findings_count": len(s.findings)}
    if sweep_id in BUSES:
        return {"sweep_id": sweep_id, "status": "running"}
    if store_enabled():
        with get_session() as sess:
            row = sess.get(SweepRow, sweep_id)
            if row:
                return {
                    "sweep_id": row.id,
                    "repo": row.repo_path,
                    "status": row.status,
                    "findings_count": row.findings_count,
                }
    raise HTTPException(404, "sweep not found")


@app.delete("/sweeps/{sweep_id}")
def delete_sweep(sweep_id: str) -> dict:
    SWEEPS.pop(sweep_id, None)
    BUSES.pop(sweep_id, None)
    _running_threads.pop(sweep_id, None)
    if store_enabled():
        with get_session() as sess:
            row = sess.get(SweepRow, sweep_id)
            if row:
                sess.delete(row)  # cascade deletes findings + events
    return {"deleted": sweep_id}


@app.post("/sweeps/cleanup")
def cleanup_sweeps(status: str = "failed") -> dict:
    """Bulk-delete sweeps with the given status. Handy for clearing orphans
    from prior container restarts."""
    if not store_enabled():
        return {"deleted": 0}
    with get_session() as sess:
        rows = sess.query(SweepRow).filter(SweepRow.status == status).all()
        n = len(rows)
        for r in rows:
            sess.delete(r)
    return {"deleted": n, "status": status}


@app.get("/sweeps/{sweep_id}/events")
def sweep_events(sweep_id: str, after: int = -1) -> list[dict]:
    if sweep_id in BUSES:
        return [e.to_dict() for e in BUSES[sweep_id].replay(sweep_id, after_seq=after)]
    if store_enabled():
        with get_session() as sess:
            rows = (
                sess.query(EventRow)
                .filter(EventRow.sweep_id == sweep_id, EventRow.seq > after)
                .order_by(EventRow.seq)
                .all()
            )
            return [
                {"sweep_id": sweep_id, "seq": r.seq, "ts": r.ts, "type": r.type, "actor": r.actor, "payload": r.payload}
                for r in rows
            ]
    raise HTTPException(404, "sweep not found")


@app.get("/sweeps/{sweep_id}/findings")
def sweep_findings(sweep_id: str) -> list[dict]:
    if sweep_id in SWEEPS:
        return SWEEPS[sweep_id].findings
    if store_enabled():
        with get_session() as sess:
            rows = (
                sess.query(FindingRow)
                .filter(FindingRow.sweep_id == sweep_id)
                .order_by(FindingRow.id)
                .all()
            )
            return [r.payload for r in rows]
    raise HTTPException(404, "sweep not found")


@app.get("/findings/{finding_id}")
def get_finding(finding_id: str) -> dict:
    for s in SWEEPS.values():
        for f in s.findings:
            if f["id"] == finding_id:
                return f
    if store_enabled():
        with get_session() as sess:
            row = sess.get(FindingRow, finding_id)
            if row:
                return row.payload
    raise HTTPException(404, "finding not found")


@app.get("/attestations/{sweep_id}")
def get_attestation(sweep_id: str) -> dict:
    if sweep_id in SWEEPS:
        return SWEEPS[sweep_id].attestations[0]
    if store_enabled():
        with get_session() as sess:
            row = sess.get(SweepRow, sweep_id)
            if row:
                findings = [f.payload for f in row.findings]
                return {
                    "sweep_id": row.id,
                    "repo": row.repo_path,
                    "findings": findings,
                    "threat_model": row.threat_model,
                }
    raise HTTPException(404, "sweep not found")


@app.websocket("/ws/sweeps/{sweep_id}")
async def ws_sweep(ws: WebSocket, sweep_id: str) -> None:
    await ws.accept()
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


# --- Serve the built React SPA -------------------------------------------------

_CONSOLE_DIST = Path(__file__).resolve().parents[2] / "console" / "dist"

if _CONSOLE_DIST.exists():
    app.mount("/assets", StaticFiles(directory=_CONSOLE_DIST / "assets"), name="assets")

    @app.get("/")
    def _serve_index() -> FileResponse:
        return FileResponse(_CONSOLE_DIST / "index.html")

    @app.get("/cmul8.svg")
    def _serve_logo() -> FileResponse:
        return FileResponse(_CONSOLE_DIST / "cmul8.svg")

    @app.get("/{path:path}")
    def _spa_fallback(path: str) -> FileResponse:
        return FileResponse(_CONSOLE_DIST / "index.html")
