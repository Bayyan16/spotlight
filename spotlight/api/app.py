"""FastAPI backend — Phase 1.5.

REST + WebSocket. Persistent Postgres store when DATABASE_URL is set; falls
back to in-memory otherwise (tests). Supports fixture targets *and* arbitrary
git URLs (cloned into an ephemeral workdir).
"""
from __future__ import annotations

import asyncio
import json
import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import desc

from spotlight.orchestrator import EventBus, Orchestrator, SweepResult
from spotlight.profiles import get_profile, list_profiles
from spotlight.redaction import Redactor
from spotlight.taxonomy import ALL_CLASSES, counts_by_surface
from spotlight.store import (
    EventRow,
    FindingRow,
    SweepRow,
    get_session,
    init_schema,
    is_enabled as store_enabled,
)

# Chokepoint (c): scrub any string in an outbound JSON response body.
# Used on endpoints that return Finding / Attestation / event payloads.
# Do NOT apply to metadata endpoints like /targets or /profiles — those
# ship no target-derived strings, and the noise of scrubbing them is
# not worth the CPU. Idempotent w.r.t. events (already redacted at bus).
_RESPONSE_REDACTOR = Redactor()


def _redact_response(data: Any) -> Any:
    """Apply redactor to a dict/list about to leave the process."""
    return _RESPONSE_REDACTOR.redact_dict(data)

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
    profile_id: str | None = None
    surfaces: list[str] = ["code"]
    deployment_tier: str = "t0-mock"


@app.get("/profiles")
def get_profiles() -> list[dict]:
    return [p.to_dict() for p in list_profiles()]


@app.get("/profiles/{profile_id}")
def get_profile_by_id(profile_id: str) -> dict:
    p = get_profile(profile_id)
    return p.to_dict()


@app.get("/taxonomy")
def get_taxonomy() -> dict:
    """Full vulnerability-class catalog (CWE + OWASP + OWASP-LLM mappings).
    Used by the Console class-coverage picker and the '# of CWEs I look for'
    stat on the dashboard."""
    return {
        "counts_by_surface": counts_by_surface(),
        "total": len(ALL_CLASSES),
        "classes": [c.to_dict() for c in ALL_CLASSES],
    }


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
    profile = get_profile(req.profile_id)
    bus = EventBus()
    orch = Orchestrator(bus=bus, profile=profile)

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
        from spotlight.git_ops import GitOps
        try:
            target = GitOps().clone_at(repo)
        except RuntimeError as exc:
            raise HTTPException(400, f"git clone failed: {str(exc)[:400]}")
        return target, "git-url"
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
        return _redact_response(
            [e.to_dict() for e in BUSES[sweep_id].replay(sweep_id, after_seq=after)]
        )
    if store_enabled():
        with get_session() as sess:
            rows = (
                sess.query(EventRow)
                .filter(EventRow.sweep_id == sweep_id, EventRow.seq > after)
                .order_by(EventRow.seq)
                .all()
            )
            return _redact_response(
                [
                    {"sweep_id": sweep_id, "seq": r.seq, "ts": r.ts, "type": r.type, "actor": r.actor, "payload": r.payload}
                    for r in rows
                ]
            )
    raise HTTPException(404, "sweep not found")


@app.get("/sweeps/{sweep_id}/findings")
def sweep_findings(sweep_id: str) -> list[dict]:
    if sweep_id in SWEEPS:
        return _redact_response(SWEEPS[sweep_id].findings)
    if store_enabled():
        with get_session() as sess:
            rows = (
                sess.query(FindingRow)
                .filter(FindingRow.sweep_id == sweep_id)
                .order_by(FindingRow.id)
                .all()
            )
            return _redact_response([r.payload for r in rows])
    raise HTTPException(404, "sweep not found")


@app.get("/findings/{finding_id}")
def get_finding(finding_id: str) -> dict:
    for s in SWEEPS.values():
        for f in s.findings:
            if f["id"] == finding_id:
                return _redact_response(f)
    if store_enabled():
        with get_session() as sess:
            row = sess.get(FindingRow, finding_id)
            if row:
                return _redact_response(row.payload)
    raise HTTPException(404, "finding not found")


@app.get("/findings/{finding_id}/presence")
def get_finding_presence(finding_id: str) -> dict:
    """Cross-surface presence — is this same vulnerability *class* reachable
    in other repos in the workspace?

    Bank feedback wedge (docs/BANK_FEEDBACK_2026-07-16.md): scanners answer
    the per-repo question ("what did you find here?") but nobody answers
    the fleet question ("is this same class reachable in my other repos?").
    This endpoint groups findings by class across sweeps and returns every
    match outside the finding's own sweep.
    """
    # Locate the source finding. Check in-memory first (hot cache /
    # store-disabled tests), then fall through to Postgres if enabled.
    self_row: dict | None = None
    self_sweep_id: str | None = None
    self_repo_name: str | None = None

    for s in SWEEPS.values():
        for f in s.findings:
            if f["id"] == finding_id:
                self_row = f
                self_sweep_id = s.sweep_id
                self_repo_name = Path(s.repo_path).name
                break
        if self_row is not None:
            break

    if self_row is None and store_enabled():
        with get_session() as sess:
            row = sess.get(FindingRow, finding_id)
            if row:
                self_row = row.payload
                self_sweep_id = row.sweep_id
                sweep_row = sess.get(SweepRow, row.sweep_id)
                self_repo_name = sweep_row.repo_name if sweep_row else ""

    if self_row is None:
        raise HTTPException(404, "finding not found")

    finding_class = self_row.get("class", "")
    finding_cwe = self_row.get("cwe", "")

    matches: list[dict] = []

    if store_enabled():
        with get_session() as sess:
            rows = (
                sess.query(FindingRow)
                .filter(FindingRow.class_ == finding_class)
                .filter(FindingRow.sweep_id != self_sweep_id)
                .all()
            )
            # Group by sweep_id — take the first (lowest id) finding per sweep
            # so the panel doesn't show 5 rows for the same repo.
            by_sweep: dict[str, FindingRow] = {}
            for r in rows:
                if r.sweep_id not in by_sweep or r.id < by_sweep[r.sweep_id].id:
                    by_sweep[r.sweep_id] = r
            for sweep_id, r in by_sweep.items():
                sweep_row = sess.get(SweepRow, sweep_id)
                matches.append(
                    {
                        "sweep_id": sweep_id,
                        "repo_name": sweep_row.repo_name if sweep_row else "",
                        "finding_id": r.id,
                        "file": r.file,
                        "line": r.line,
                        "tier": r.tier,
                        "state": r.state,
                        "sweep_started_at": sweep_row.started_at.isoformat()
                        if sweep_row and sweep_row.started_at
                        else None,
                    }
                )
    else:
        # In-memory fallback (tests, or store-disabled dev).
        by_sweep_mem: dict[str, dict] = {}
        for s in SWEEPS.values():
            if s.sweep_id == self_sweep_id:
                continue
            for f in s.findings:
                if f.get("class") != finding_class:
                    continue
                cur = by_sweep_mem.get(s.sweep_id)
                if cur is None or f["id"] < cur["_finding"]["id"]:
                    by_sweep_mem[s.sweep_id] = {
                        "_sweep": s,
                        "_finding": f,
                    }
        for sweep_id, packed in by_sweep_mem.items():
            s = packed["_sweep"]
            f = packed["_finding"]
            matches.append(
                {
                    "sweep_id": sweep_id,
                    "repo_name": Path(s.repo_path).name,
                    "finding_id": f["id"],
                    "file": f["location"]["file"],
                    "line": f["location"]["line"],
                    "tier": f["tier"],
                    "state": f["state"],
                    "sweep_started_at": None,
                }
            )

    # Stable order: most recent first when we have a timestamp, else by sweep_id.
    matches.sort(
        key=lambda m: (m["sweep_started_at"] or "", m["sweep_id"]),
        reverse=True,
    )

    return _redact_response(
        {
            "class": finding_class,
            "cwe": finding_cwe,
            "self": {
                "sweep_id": self_sweep_id,
                "repo_name": self_repo_name,
                "finding_id": finding_id,
            },
            "matches": matches,
            "presence_count": len(matches),
        }
    )


@app.get("/prs/{finding_id}")
def get_pr_for_finding(finding_id: str) -> dict:
    """Return whatever PR info is stored on this finding.

    Response shape: {pr_url, branch, commit_sha}. Any field may be null if
    the sweep ran without `open_prs` enabled or `gh` failed.
    """
    payload: dict | None = None
    for s in SWEEPS.values():
        for f in s.findings:
            if f["id"] == finding_id:
                payload = f
                break
        if payload is not None:
            break
    if payload is None and store_enabled():
        with get_session() as sess:
            row = sess.get(FindingRow, finding_id)
            if row:
                payload = row.payload
    if payload is None:
        raise HTTPException(404, "finding not found")
    fix = (payload.get("evidence") or {}).get("fix") or {}
    return {
        "finding_id": finding_id,
        "pr_url": fix.get("pr_url"),
        "branch": fix.get("branch"),
        "commit_sha": fix.get("commit_sha"),
    }


@app.get("/attestations/{sweep_id}")
def get_attestation(sweep_id: str) -> dict:
    if sweep_id in SWEEPS:
        return _redact_response(SWEEPS[sweep_id].attestations[0])
    if store_enabled():
        with get_session() as sess:
            row = sess.get(SweepRow, sweep_id)
            if row:
                findings = [f.payload for f in row.findings]
                return _redact_response({
                    "sweep_id": row.id,
                    "repo": row.repo_path,
                    "findings": findings,
                    "threat_model": row.threat_model,
                })
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
