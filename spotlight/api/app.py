"""FastAPI backend — Phase 1.5.

REST + WebSocket. Persistent Postgres store when DATABASE_URL is set; falls
back to in-memory otherwise (tests). Supports fixture targets *and* arbitrary
git URLs (cloned into an ephemeral workdir).
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import shutil
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi import (
    FastAPI, Header, HTTPException, Query, Request, Response,
    WebSocket, WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import desc

from spotlight.orchestrator import EventBus, Orchestrator, SweepResult
from spotlight.api.admission import SWEEP_ADMISSION
from spotlight.api.intake import resolve_repo_input, validate_commit_sha
from spotlight.api.security import (
    AUTH_COOKIE,
    SECURITY_HEADERS,
    auth_required,
    authenticate_request,
    authenticate_websocket,
    cors_origins,
    create_session_token,
    clear_login_failures,
    is_production,
    is_public_path,
    request_origin_is_allowed,
    record_failed_login,
    validate_security_configuration,
    workspace_api_key,
)
from spotlight.finding_identity import comparison_key
from spotlight.intel.kev import enrich_finding, get_kev_entry, kev_status
from spotlight.profiles import get_profile, list_profiles
from spotlight.redaction import Redactor
from spotlight.taxonomy import ALL_CLASSES, counts_by_surface
from spotlight.store import (
    EventRow,
    FindingRow,
    SweepJobRow,
    SweepRow,
    get_session,
    init_schema,
    is_enabled as store_enabled,
)
from spotlight.store import leasing as job_leasing

# Chokepoint (c): scrub any string in an outbound JSON response body.
# Used on endpoints that return Finding / Attestation / event payloads.
# Do NOT apply to metadata endpoints like /targets or /profiles — those
# ship no target-derived strings, and the noise of scrubbing them is
# not worth the CPU. Idempotent w.r.t. events (already redacted at bus).
_RESPONSE_REDACTOR = Redactor()


def _redact_response(data: Any) -> Any:
    """Apply redactor to a dict/list about to leave the process."""
    return _RESPONSE_REDACTOR.redact_dict(data)


def _find_finding_anywhere(finding_id: str) -> tuple[dict | None, str | None]:
    """Locate a finding by id — hot cache first, then persistent store.

    Returns (finding_dict, sweep_id). Callers who mutate the returned dict
    must call `_persist_finding_update` to persist to Postgres if the store
    is enabled.
    """
    # Stable IDs intentionally recur across sweeps. Bare finding-id routes
    # resolve to the newest hot-cache occurrence; sweep-scoped routes remain
    # available when a caller needs historical precision.
    for s in reversed(list(SWEEPS.values())):
        for f in s.findings:
            if f["id"] == finding_id:
                return f, s.sweep_id
    if store_enabled():
        with get_session() as sess:
            row = _find_finding_row(sess, finding_id)
            if row is not None:
                return dict(row.payload or {}), row.sweep_id
    return None, None


def _persist_finding_update(finding_id: str, sweep_id: str | None, updated: dict) -> None:
    """Write a mutated finding back to Postgres AND update the in-memory
    hot cache. Silent no-op if the store is disabled — the hot-cache is
    then authoritative for the process lifetime."""
    # Hot cache — locate the finding and overwrite in place.
    if sweep_id and sweep_id in SWEEPS:
        for i, f in enumerate(SWEEPS[sweep_id].findings):
            if f["id"] == finding_id:
                SWEEPS[sweep_id].findings[i] = updated
                break

    if not store_enabled():
        return
    with get_session() as sess:
        row = _find_finding_row(sess, finding_id)
        if row is not None:
            row.payload = updated
            sess.commit()


def _find_finding_row(sess, finding_id: str):
    """Look up a FindingRow by either the workspace-scoped key
    (e.g. `SPOT-0001`) OR the sweep-scoped key (`sw_abc:SPOT-0001`).

    Post-fix rows use the sweep-scoped composite key; a URL like
    `/findings/SPOT-0001` still resolves via the endswith fallback so the
    Console + curl demos keep working without change. When multiple sweeps
    each produced `SPOT-0001`, we return the most recent one (max row id).
    """
    row = sess.get(FindingRow, finding_id)
    if row is not None:
        return row
    return (
        sess.query(FindingRow)
        .filter(FindingRow.id.endswith(f":{finding_id}"))
        .order_by(FindingRow.id.desc())
        .first()
    )


app = FastAPI(title="Spotlight API", version="0.1.0")

from spotlight.api.docs_router import router as _docs_router
app.include_router(_docs_router)

_CORS_ORIGINS = cors_origins()
app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_credentials=bool(_CORS_ORIGINS),
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Spotlight-API-Key"],
)


def _apply_security_headers(response: Response) -> Response:
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    if is_production():
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
    return response


@app.middleware("http")
async def _security_boundary(request: Request, call_next):
    path = request.url.path
    is_spa_navigation = (
        request.method == "GET"
        and "text/html" in request.headers.get("accept", "")
        and not path.startswith(
            (
                "/api/",
                "/sweeps",
                "/findings",
                "/prefs",
                "/paths",
                "/attestations",
                "/profiles",
                "/taxonomy",
                "/targets",
                "/prs",
                "/verify-key",
                "/intel",
                "/openapi.json",
                "/docs",
                "/redoc",
            )
        )
    )
    if request.method != "OPTIONS" and not is_public_path(path) and not is_spa_navigation:
        auth = authenticate_request(request)
        if auth is None:
            return _apply_security_headers(
                JSONResponse(
                    {"detail": "authentication required"},
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer"},
                )
            )
        if auth.mechanism == "cookie" and not request_origin_is_allowed(request):
            return _apply_security_headers(
                JSONResponse({"detail": "cross-origin mutation denied"}, status_code=403)
            )
        request.state.auth_subject = auth.subject
        request.state.auth_mechanism = auth.mechanism
    response = await call_next(request)
    return _apply_security_headers(response)


@app.on_event("startup")
def _startup() -> None:
    validate_security_configuration()
    from spotlight.sandbox import validate_sandbox_configuration
    from spotlight.non_repudiation import validate_signing_configuration

    validate_sandbox_configuration()
    validate_signing_configuration(require_persistent=is_production())
    init_schema()
    _recover_durable_jobs()


# In-memory registries — used when DATABASE_URL isn't set (tests), *and* as a
# hot cache of in-flight sweeps so the WS hub can subscribe live.
SWEEPS: dict[str, SweepResult] = {}
BUSES: dict[str, EventBus] = {}
_running_threads: dict[str, threading.Thread] = {}


class SweepRequest(BaseModel):
    repo: str
    profile_id: str | None = None
    surfaces: list[str] = ["code"]
    deployment_tier: str = "t0-mock"
    # C2 · Interactive mode — when True the orchestrator pauses after Recon
    # emits `sweep.paused_for_review`, and waits for POST /sweeps/{id}/resume
    # before continuing to Investigate. Default False to preserve legacy
    # non-interactive behavior for all existing clients.
    interactive: bool = False
    # Pin a specific commit SHA (or ref) to sweep. Only meaningful when
    # `repo` is a git URL; ignored for bundled fixture targets. Enables
    # per-commit CVE reproduction — sweep the vulnerable pre-patch commit
    # and verify Spotlight catches the same finding a published advisory
    # describes.
    commit_sha: str | None = None


class ResumeRequest(BaseModel):
    """C2 · resume payload for an interactive sweep.

    ``threat_model_edits`` merges into the orchestrator's recon_out.threat_model
    at resume time — a shallow merge keyed at the top level. The merge is
    signed into the chain of custody as ``review.threat-model-edit`` so the
    edited version is auditable against the auto-generated one.
    """

    threat_model_edits: dict | None = None
    reviewer: str = "analyst"


class SessionRequest(BaseModel):
    api_key: str


def _recover_durable_jobs() -> None:
    """Requeue unfinished jobs, sweep expired leases, and fail legacy rows.

    Called on API startup and safe to call while other workers are running:
    `spotlight.store.leasing.sweep_expired_leases` only affects rows whose
    lease has already expired, so it never steals work from a live worker.

    Ownership-transfer for jobs that this replica should re-launch (queued
    or previously owned by this process) still happens inline for the
    single-worker Railway deployment; a future multi-worker deployment
    will call sweep_expired_leases on a schedule and rely on the leasing
    module's atomic claim rather than blindly requeuing everything.
    """
    if not store_enabled():
        return
    recover: list[tuple[str, dict]] = []
    try:
        with get_session() as sess:
            # First, atomically return any expired leases to the queued pool.
            reclaimed = job_leasing.sweep_expired_leases(sess)
            if reclaimed:
                print(f"[startup] reclaimed {reclaimed} expired-lease sweep jobs")

            jobs = (
                sess.query(SweepJobRow)
                .filter(SweepJobRow.status.in_(("queued", "running")))
                .all()
            )
            for job in jobs:
                # Return every unfinished job to the queued pool so this
                # process can re-launch it. On a true multi-worker deploy,
                # this blanket requeue is replaced by "sweep expired leases
                # and leave live ones alone" — see P1.2 worker split.
                job.status = "queued"
                job.lease_owner = None
                job.lease_until = None
                recover.append((job.sweep_id, dict(job.request or {})))
            job_ids = {sweep_id for sweep_id, _ in recover}
            legacy = sess.query(SweepRow).filter(SweepRow.status == "running").all()
            for row in legacy:
                if row.id not in job_ids:
                    row.status = "failed"
                    row.finished_at = row.finished_at or datetime.now(timezone.utc)
    except Exception as exc:
        print(f"[startup] durable job recovery failed: {exc!r}")
        return
    for sweep_id, payload in recover:
        try:
            _launch_sweep_job(sweep_id, SweepRequest(**payload))
        except Exception as exc:
            _mark_sweep_failed(sweep_id, repr(exc))
            _finish_job(sweep_id, error=repr(exc))


@app.get("/auth/session")
def auth_session_status(request: Request) -> dict:
    auth = authenticate_request(request)
    return {
        "required": auth_required(),
        "authenticated": auth is not None,
        "subject": auth.subject if auth else None,
    }


@app.post("/auth/session")
def create_auth_session(body: SessionRequest, response: Response, request: Request) -> dict:
    expected = workspace_api_key()
    principal = request.client.host if request.client else "unknown-client"
    if auth_required():
        if not expected or not hmac.compare_digest(body.api_key, expected):
            record_failed_login(principal)
            raise HTTPException(401, "invalid workspace API key")
        clear_login_failures(principal)
        ttl = int(os.environ.get("SPOTLIGHT_SESSION_TTL_SECONDS", str(8 * 60 * 60)))
        response.set_cookie(
            AUTH_COOKIE,
            create_session_token(expected, ttl_seconds=ttl),
            max_age=ttl,
            httponly=True,
            secure=is_production(),
            samesite="strict",
            path="/",
        )
    return {"authenticated": True, "required": auth_required()}


@app.delete("/auth/session")
def delete_auth_session(response: Response) -> dict:
    response.delete_cookie(AUTH_COOKIE, path="/", samesite="strict")
    return {"authenticated": False}


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
    return {
        "ok": True,
        "service": "spotlight-api",
        "storage": "postgres" if store_enabled() else "memory",
        "active_sweeps": SWEEP_ADMISSION.active_count(),
    }


@app.get("/intel/kev/status")
def cisa_kev_status() -> dict:
    return kev_status()


@app.get("/intel/kev/{cve_id}")
def cisa_kev_lookup(cve_id: str) -> dict:
    entry = get_kev_entry(cve_id)
    if entry is None:
        raise HTTPException(404, "CVE is not present in the cached CISA KEV catalog")
    return entry


@app.get("/verify-key")
def workspace_verify_key() -> dict:
    """Publish the workspace Ed25519 public key + fingerprint.

    Anyone with this key can offline-verify every chain-of-custody entry
    Spotlight has ever signed under the current workspace key — no
    Spotlight infrastructure required. Load the raw 32-byte key from
    base64 into any Ed25519 library and call `verify(signature,
    f"{ts}|{actor_kind}|{actor_id}|{action}|{payload_hash}".encode())`.

    Documented under the "Non-repudiation ledger" section of the arch
    doc; this route closes the gap between that promise and reality.
    """
    try:
        from spotlight.non_repudiation import Signer

        signer = Signer()
        return {
            "algorithm": "ed25519",
            "format": "raw",
            "public_key_b64": signer.public_key_b64(),
            "fingerprint": signer.fingerprint,
            "signing_input_template": "{ts}|{actor_kind}|{actor_id}|{action}|{payload_hash}",
        }
    except Exception as exc:
        raise HTTPException(500, f"signer unavailable: {exc!r}")


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
        # Never expose server-local filesystem paths to the Console.
        out.append({"name": p.name, "path": p.name, "has_ground_truth": gt.exists()})
    return out


def _validate_sweep_request(req: SweepRequest) -> tuple[str, str]:
    targets_root = Path(__file__).resolve().parents[2] / "targets"
    resolved, source = resolve_repo_input(req.repo, targets_root=targets_root)
    validate_commit_sha(req.commit_sha)
    if source == "git-url":
        repo_name = Path(urlsplit(str(resolved)).path).stem
    else:
        repo_name = Path(resolved).name
    get_profile(req.profile_id)
    return source, repo_name


def _persist_queued_job(sweep_id: str, req: SweepRequest, source: str, repo_name: str) -> None:
    if not store_enabled():
        return
    payload = req.model_dump() if hasattr(req, "model_dump") else req.dict()
    with get_session() as sess:
        sess.add(
            SweepRow(
                id=sweep_id,
                repo_path=req.repo,
                repo_name=repo_name,
                source=source,
                status="queued",
                interactive=req.interactive,
            )
        )
        sess.add(SweepJobRow(sweep_id=sweep_id, request=payload, status="queued"))


def _claim_job(sweep_id: str) -> bool:
    """Claim the job for this process. Multi-worker safe via
    spotlight.store.leasing (FOR UPDATE SKIP LOCKED under Postgres).

    Store-disabled shortcut returns True so unit tests and CLI runners
    that do not persist can still execute the sweep inline.
    """
    if not store_enabled():
        return True
    with get_session() as sess:
        return job_leasing.claim_specific(sess, sweep_id)


def _finish_job(sweep_id: str, *, error: str | None = None) -> None:
    """Release the job's lease. Guarded by owner so a late reclaim by
    a different worker doesn't get overwritten."""
    if not store_enabled():
        return
    with get_session() as sess:
        job_leasing.release(sess, sweep_id, error=error)


def _persist_live_event(event) -> None:
    """Persist one event row idempotently.

    P1.3 — the events table has a `UNIQUE(sweep_id, seq)` constraint, so
    inserting the same (sweep_id, seq) twice is a no-op instead of a
    duplicate row. This handles crash-retry within one worker attempt
    without a TOCTOU race between SELECT and INSERT.

    Under a reclaim by a different worker, the reclaiming worker seeds its
    EventBus from `max(seq)` on the sweep so its own emissions skip the
    already-committed prefix — the constraint is a safety net, not the
    primary de-dup mechanism.
    """
    if not store_enabled():
        return
    try:
        with get_session() as sess:
            _upsert_event(sess, event)
    except Exception as exc:
        print(f"[persist_event] failed: {exc!r}")


def _upsert_event(sess, event) -> None:
    """Dialect-aware INSERT ... ON CONFLICT DO UPDATE against events."""
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    from sqlalchemy.dialects.sqlite import insert as sqlite_insert

    values = {
        "sweep_id": event.sweep_id,
        "seq": event.seq,
        "ts": event.ts,
        "type": event.type,
        "actor": event.actor,
        "payload": event.payload,
    }
    dialect = sess.bind.dialect.name if sess.bind is not None else "sqlite"
    if dialect == "postgresql":
        stmt = pg_insert(EventRow).values(**values)
        stmt = stmt.on_conflict_do_update(
            constraint="uq_events_sweep_seq",
            set_={
                "ts": stmt.excluded.ts,
                "type": stmt.excluded.type,
                "actor": stmt.excluded.actor,
                "payload": stmt.excluded.payload,
            },
        )
        sess.execute(stmt)
    elif dialect == "sqlite":
        stmt = sqlite_insert(EventRow).values(**values)
        stmt = stmt.on_conflict_do_update(
            index_elements=["sweep_id", "seq"],
            set_={
                "ts": stmt.excluded.ts,
                "type": stmt.excluded.type,
                "actor": stmt.excluded.actor,
                "payload": stmt.excluded.payload,
            },
        )
        sess.execute(stmt)
    else:
        # Fallback for unusual dialects — SELECT-then-UPDATE-or-INSERT.
        # Not atomic under concurrency, but the UNIQUE constraint will
        # still catch a duplicate INSERT.
        existing = (
            sess.query(EventRow)
            .filter(EventRow.sweep_id == event.sweep_id, EventRow.seq == event.seq)
            .first()
        )
        if existing is not None:
            existing.ts = event.ts
            existing.type = event.type
            existing.actor = event.actor
            existing.payload = event.payload
        else:
            sess.add(EventRow(**values))


def _launch_sweep_job(
    sweep_id: str,
    req: SweepRequest,
    *,
    admission_token: str | None = None,
) -> bool:
    if not _claim_job(sweep_id):
        if admission_token:
            SWEEP_ADMISSION.release(admission_token)
        return False
    bus = BUSES.get(sweep_id) or EventBus()
    BUSES[sweep_id] = bus
    bus.subscribe(_persist_live_event)

    def _worker() -> None:
        repo_path: Path | None = None
        source = "unknown"
        try:
            repo_path, source = _resolve_repo(req.repo, commit_sha=req.commit_sha)
            _persist_sweep_header(
                sweep_id, repo_path, source, interactive=req.interactive
            )
            profile = get_profile(req.profile_id)
            result = Orchestrator(bus=bus, profile=profile).run(
                repo_path,
                interactive=req.interactive,
                sweep_id=sweep_id,
            )
            SWEEPS[sweep_id] = result
            _persist_sweep(result, source=source, repo_name=repo_path.name)
            _finish_job(sweep_id)
        except Exception as exc:
            reason = repr(exc)[:1000]
            try:
                from spotlight.orchestrator.events import EventType

                bus.emit(sweep_id, EventType.SWEEP_FAILED, "orchestrator", error=reason)
            except Exception:
                pass
            _mark_sweep_failed(sweep_id, reason)
            _finish_job(sweep_id, error=reason)
        finally:
            _running_threads.pop(sweep_id, None)
            if repo_path is not None and source == "git-url":
                _remove_ephemeral_checkout(repo_path)
            if admission_token:
                SWEEP_ADMISSION.release(admission_token)

    thread = threading.Thread(target=_worker, daemon=True, name=f"sweep-{sweep_id}")
    _running_threads[sweep_id] = thread
    thread.start()
    return True


def _inline_execution_enabled() -> bool:
    """Whether the web process should also run sweeps inline.

    Default: true (dev / tests / single-container Railway deploys).
    Set SPOTLIGHT_INLINE_EXECUTION=false when the web process is paired
    with a dedicated `spotlight.worker` service — the web then only
    enqueues, and the worker(s) claim + execute.
    """
    return os.environ.get("SPOTLIGHT_INLINE_EXECUTION", "true").lower() in {
        "1", "true", "yes", "on"
    }


def _launch_sweep_job_inline(sweep_id: str, req: SweepRequest) -> None:
    """Run a sweep synchronously in the current thread. Assumes the
    caller already holds the lease (worker process path).

    Distinct from `_launch_sweep_job` in that it does NOT claim the job
    (the worker's `leasing.claim_next` already did) and does NOT spawn
    a background thread (the worker's main loop is the thread).
    """
    bus = BUSES.get(sweep_id) or EventBus()
    BUSES[sweep_id] = bus
    bus.subscribe(_persist_live_event)

    repo_path: Path | None = None
    source = "unknown"
    try:
        repo_path, source = _resolve_repo(req.repo, commit_sha=req.commit_sha)
        _persist_sweep_header(sweep_id, repo_path, source, interactive=req.interactive)
        profile = get_profile(req.profile_id)
        result = Orchestrator(bus=bus, profile=profile).run(
            repo_path, interactive=req.interactive, sweep_id=sweep_id,
        )
        SWEEPS[sweep_id] = result
        _persist_sweep(result, source=source, repo_name=repo_path.name)
        _finish_job(sweep_id)
    except Exception as exc:
        reason = repr(exc)[:1000]
        try:
            from spotlight.orchestrator.events import EventType
            bus.emit(sweep_id, EventType.SWEEP_FAILED, "orchestrator", error=reason)
        except Exception:
            pass
        _mark_sweep_failed(sweep_id, reason)
        _finish_job(sweep_id, error=reason)
    finally:
        if repo_path is not None and source == "git-url":
            _remove_ephemeral_checkout(repo_path)


@app.post("/sweeps")
def start_sweep(req: SweepRequest, request: Request) -> dict:
    principal = getattr(request.state, "auth_subject", None) or (
        request.client.host if request.client else "unknown-client"
    )
    admission_token = SWEEP_ADMISSION.admit(principal)
    try:
        source, repo_name = _validate_sweep_request(req)
        sweep_id = f"sw_{uuid4().hex[:12]}"
        _persist_queued_job(sweep_id, req, source, repo_name)
    except Exception:
        SWEEP_ADMISSION.release(admission_token)
        raise
    if not _inline_execution_enabled():
        # Enqueue-only mode: worker service picks up via leasing.claim_next.
        # Release the admission token immediately — no in-process resource
        # is being held.
        SWEEP_ADMISSION.release(admission_token)
        return {"sweep_id": sweep_id, "status": "queued", "repo_name": repo_name, "source": source}
    if not _launch_sweep_job(sweep_id, req, admission_token=admission_token):
        raise HTTPException(409, "sweep job was already claimed")
    return {"sweep_id": sweep_id, "status": "queued", "repo_name": repo_name, "source": source}


def _remove_ephemeral_checkout(repo_path: Path) -> None:
    """Remove only a GitOps-created spotlight-clone-* directory."""
    resolved = repo_path.resolve()
    workdir = resolved.parent
    if workdir.name.startswith("spotlight-clone-") and workdir.parent == Path(tempfile.gettempdir()).resolve():
        shutil.rmtree(workdir, ignore_errors=True)


def _resolve_repo(repo: str, commit_sha: str | None = None) -> tuple[Path, str]:
    """Resolve a repo argument to a filesystem path, cloning if it's a git URL.

    If ``commit_sha`` is provided AND the repo is a git URL, checkout that
    exact ref instead of HEAD. Enables per-commit CVE reproduction.

    Returns (path, source_kind).
    """
    targets_root = Path(__file__).resolve().parents[2] / "targets"
    resolved, source = resolve_repo_input(repo, targets_root=targets_root)
    pinned_sha = validate_commit_sha(commit_sha)
    if source == "git-url":
        from spotlight.git_ops import GitOps
        try:
            target = GitOps().clone_at(str(resolved), sha=pinned_sha)
        except RuntimeError as exc:
            raise HTTPException(400, f"git clone failed: {str(exc)[:400]}")
        return target, "git-url"
    return Path(resolved), source


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


def _persist_sweep_header(
    sweep_id: str,
    repo_path: Path,
    source: str,
    *,
    interactive: bool = False,
) -> None:
    if not store_enabled():
        return
    # Best-effort git introspection — captures org/commit_sha/branch so two
    # sweeps of "acme-bank" months apart are distinguishable by commit.
    ident: dict = {}
    try:
        from spotlight.git_ops import GitOps

        ident = GitOps().head_info(repo_path)
    except Exception:
        pass
    try:
        with get_session() as sess:
            existing = sess.get(SweepRow, sweep_id)
            if existing:
                existing.repo_path = str(repo_path)
                existing.repo_name = repo_path.name
                existing.source = source
                existing.status = "running"
                existing.interactive = interactive
                existing.org = ident.get("org") or None
                existing.commit_sha = ident.get("commit_sha") or None
                existing.commit_branch = ident.get("commit_branch") or None
                existing.clone_url = ident.get("clone_url") or None
                return
            sess.add(
                SweepRow(
                    id=sweep_id,
                    repo_path=str(repo_path),
                    repo_name=repo_path.name,
                    source=source,
                    status="running",
                    interactive=interactive,
                    org=ident.get("org") or None,
                    commit_sha=ident.get("commit_sha") or None,
                    commit_branch=ident.get("commit_branch") or None,
                    clone_url=ident.get("clone_url") or None,
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
            row.exploit_paths = result.exploit_paths
            row.finished_at = datetime.now(timezone.utc)
            row.findings_count = len(result.findings)
            sess.merge(row)
            # Clear + rewrite findings and events for idempotency.
            sess.query(FindingRow).filter(FindingRow.sweep_id == result.sweep_id).delete()
            sess.query(EventRow).filter(EventRow.sweep_id == result.sweep_id).delete()
            for f in result.findings:
                # FindingRow.id is workspace-global. Every sweep produces
                # 'SPOT-0001'; without namespacing the second sweep would
                # collide on the primary key and _persist_sweep would fail
                # silently (bug lived from Phase 1.5 to now). The Attestation
                # still shows f["id"] as the human label via the JSONB
                # payload; only the row key gets the sweep_id prefix.
                sess.add(
                    FindingRow(
                        id=f"{result.sweep_id}:{f['id']}",
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
                        # Sweep identity — what code did this sweep see?
                        "org": r.org,
                        "commit_sha": r.commit_sha,
                        "commit_branch": r.commit_branch,
                        "clone_url": r.clone_url,
                        "interactive": r.interactive,
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
        if store_enabled():
            with get_session() as sess:
                row = sess.get(SweepRow, sweep_id)
                if row:
                    return {
                        "sweep_id": sweep_id,
                        "repo": row.repo_path,
                        "status": row.status,
                        "findings_count": row.findings_count,
                    }
        failed = any(e.type == "sweep.failed" for e in BUSES[sweep_id].all())
        return {"sweep_id": sweep_id, "status": "failed" if failed else "running"}
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
    thread = _running_threads.get(sweep_id)
    if thread is not None and thread.is_alive():
        raise HTTPException(409, "cannot delete an active sweep")
    SWEEPS.pop(sweep_id, None)
    BUSES.pop(sweep_id, None)
    _running_threads.pop(sweep_id, None)
    if store_enabled():
        with get_session() as sess:
            row = sess.get(SweepRow, sweep_id)
            if row:
                sess.delete(row)  # cascade deletes findings + events
    return {"deleted": sweep_id}


@app.post("/sweeps/{sweep_id}/resume")
def resume_sweep(sweep_id: str, req: ResumeRequest) -> dict:
    """C2 · Resume an interactive-mode sweep paused after Recon.

    Applies `threat_model_edits` as a shallow merge over the auto-generated
    recon threat model, signs the edit into the chain of custody, then
    unblocks the orchestrator thread.

    Returns 404 if no sweep is currently paused with this id (either the
    sweep never entered interactive mode, or it already resumed).
    """
    from spotlight.orchestrator.orchestrator import resume_paused_sweep

    edits = req.threat_model_edits or None
    resumed = resume_paused_sweep(sweep_id, edits)
    if not resumed:
        raise HTTPException(404, "sweep not paused (or already resumed)")

    # Signed audit entry — attach to the bus's event log so downstream
    # consumers see the edit provenance in the same stream as other events.
    try:
        from spotlight.non_repudiation import Signer
        from spotlight.orchestrator.events import EventType

        signer = Signer()
        entry = signer.sign(
            actor_kind="human",
            actor_id=req.reviewer or "analyst",
            action="review.threat-model-edit",
            payload={
                "sweep_id": sweep_id,
                "edits": edits or {},
            },
        )
        if sweep_id in BUSES:
            BUSES[sweep_id].emit(
                sweep_id,
                EventType.SWEEP_RESUMED,
                "orchestrator",
                reviewer=req.reviewer or "analyst",
                edits=edits or {},
                signature_fingerprint=entry.get("key_fingerprint"),
            )
    except Exception as exc:
        print(f"[resume] signing failed: {exc!r}")

    return {"sweep_id": sweep_id, "resumed": True}


_GITHUB_WEBHOOK_SECRET_ENV = "GITHUB_WEBHOOK_SECRET"


def _verify_github_signature(payload: bytes, signature_header: str | None) -> bool:
    """Verify GitHub's ``X-Hub-Signature-256`` header via HMAC-SHA256.

    Returns True when the signature matches the workspace secret. If the
    secret env var isn't set we REJECT all webhook calls — leaving the
    endpoint open would let anyone kick off sweeps against arbitrary repos.
    Explicit opt-in via env var is the safer default.
    """
    secret = os.environ.get(_GITHUB_WEBHOOK_SECRET_ENV)
    if not secret:
        return False
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(
        secret.encode("utf-8"), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature_header)


@app.post("/webhooks/github")
async def github_webhook(
    request: Request,
    x_hub_signature_256: str | None = Header(None, alias="X-Hub-Signature-256"),
    x_github_event: str | None = Header(None, alias="X-GitHub-Event"),
) -> dict:
    """C7 · Watch-mode entry point.

    Kicks off a Spotlight sweep in response to a GitHub push or
    pull_request event. Reads the target repo's clone URL from the
    payload, verifies the workspace HMAC, and fires the same
    orchestrator path as an interactive /sweeps POST.

    Returns 401 if the signature doesn't match. 202 with sweep_id on
    successful trigger. Non-code-affecting events (ping, watch, etc.)
    return 204 with no sweep started.
    """
    body = await request.body()
    if not _verify_github_signature(body, x_hub_signature_256):
        raise HTTPException(401, "invalid signature")

    if x_github_event == "ping":
        return {"pong": True, "spotlight": "hello, github"}
    if x_github_event not in ("push", "pull_request"):
        # Legitimate event type we don't act on — 200 with a no-op.
        return {"skipped": True, "event": x_github_event}

    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception as exc:
        raise HTTPException(400, f"invalid json body: {exc!r}") from exc

    repo_block = payload.get("repository") or {}
    clone_url = repo_block.get("clone_url") or repo_block.get("ssh_url")
    if not clone_url:
        raise HTTPException(400, "payload missing repository.clone_url")

    # Only accept .git URLs — matches the existing /sweeps repo-resolver's
    # contract. GitHub push events carry https clone URLs by default.
    if not clone_url.endswith(".git"):
        clone_url = clone_url + ".git"

    pr_number = None
    if x_github_event == "pull_request":
        pr = payload.get("pull_request") or {}
        pr_number = pr.get("number")

    # Fire the sweep via the same POST /sweeps codepath. We construct the
    # SweepRequest in-process to reuse validation + the persistence flow.
    req = SweepRequest(repo=clone_url, profile_id=None, interactive=False)
    started = start_sweep(req, request)

    # Record the PR association BOTH in-memory (fast path for the current
    # process) AND in Postgres (survives API restarts, which is the whole
    # point of the persistence follow-up). The write-through pattern keeps
    # the in-memory read fast while the DB row is durable.
    if pr_number is not None:
        watch = {
            "repo_full_name": repo_block.get("full_name") or "",
            "pr_number": int(pr_number),
            "clone_url": clone_url,
        }
        _pr_watch_by_sweep[started["sweep_id"]] = watch
        _persist_pr_watch(started["sweep_id"], watch)

    return {
        "started": True,
        "sweep_id": started["sweep_id"],
        "event": x_github_event,
        "pr_number": pr_number,
        "clone_url": clone_url,
    }


# In-memory hot cache — mirrors the pr_watches Postgres table for fast
# lookup within the current process. The persistence layer is authoritative;
# this dict is a cache. Populated by webhook writes AND by hydration on
# first read (see get_pr_watch below).
_pr_watch_by_sweep: dict[str, dict[str, Any]] = {}


def _persist_pr_watch(sweep_id: str, watch: dict[str, Any]) -> None:
    """Write-through for the pr_watches table. Silent no-op when the store
    isn't configured (dev / tests without DATABASE_URL). Any DB failure is
    logged and swallowed — the in-memory dict is still populated so the
    current process retains the association."""
    if not store_enabled():
        return
    try:
        from spotlight.store import PrWatchRow

        with get_session() as sess:
            existing = sess.get(PrWatchRow, sweep_id)
            if existing is not None:
                existing.repo_full_name = watch["repo_full_name"]
                existing.pr_number = watch["pr_number"]
                existing.clone_url = watch["clone_url"]
            else:
                sess.add(
                    PrWatchRow(
                        sweep_id=sweep_id,
                        repo_full_name=watch["repo_full_name"],
                        pr_number=watch["pr_number"],
                        clone_url=watch["clone_url"],
                    )
                )
    except Exception as exc:
        print(f"[pr_watch] persist failed for {sweep_id}: {exc!r}")


def get_pr_watch(sweep_id: str) -> dict[str, Any] | None:
    """Fetch a PR association. Prefers the in-memory cache; falls back to
    Postgres and warms the cache on hit. Returns None if no association
    exists (webhook was for a push, not a PR)."""
    hot = _pr_watch_by_sweep.get(sweep_id)
    if hot is not None:
        return hot
    if not store_enabled():
        return None
    try:
        from spotlight.store import PrWatchRow

        with get_session() as sess:
            row = sess.get(PrWatchRow, sweep_id)
            if row is None:
                return None
            hydrated = {
                "repo_full_name": row.repo_full_name,
                "pr_number": row.pr_number,
                "clone_url": row.clone_url,
            }
            _pr_watch_by_sweep[sweep_id] = hydrated
            return hydrated
    except Exception as exc:
        print(f"[pr_watch] hydrate failed for {sweep_id}: {exc!r}")
        return None


class PrefValue(BaseModel):
    """Generic workspace preference payload. `value` is any JSON."""

    value: Any = None


_PREF_CACHE: dict[str, Any] = {}


def _prefs_read(key: str, default: Any = None) -> Any:
    """Read a workspace pref. Cache-first, DB fallback. Cached values
    survive per-process; the DB row survives redeploy."""
    if key in _PREF_CACHE:
        return _PREF_CACHE[key]
    if not store_enabled():
        return default
    try:
        from spotlight.store import WorkspacePrefRow

        with get_session() as sess:
            row = sess.get(WorkspacePrefRow, key)
            if row is None:
                return default
            _PREF_CACHE[key] = row.value
            return row.value
    except Exception as exc:
        print(f"[prefs] read {key} failed: {exc!r}")
        return default


def _prefs_write(key: str, value: Any) -> None:
    """Upsert a workspace pref. Writes to Postgres AND the hot cache so a
    subsequent read in the same process is stale-proof."""
    _PREF_CACHE[key] = value
    if not store_enabled():
        return
    try:
        from spotlight.store import WorkspacePrefRow

        with get_session() as sess:
            row = sess.get(WorkspacePrefRow, key)
            if row is None:
                sess.add(WorkspacePrefRow(key=key, value=value))
            else:
                row.value = value
    except Exception as exc:
        print(f"[prefs] write {key} failed: {exc!r}")


@app.get("/prefs/workspace/{key}")
def get_workspace_pref(key: str) -> dict:
    """Read a single workspace preference. Returns {"key", "value"};
    "value" is null if the key has never been written."""
    return {"key": key, "value": _prefs_read(key, default=None)}


@app.put("/prefs/workspace/{key}")
def put_workspace_pref(key: str, body: PrefValue) -> dict:
    """Upsert a workspace preference."""
    _prefs_write(key, body.value)
    return {"key": key, "value": body.value}


@app.get("/prefs/findings-filter/{profile_id}")
def get_findings_filter(profile_id: str, name: str = "current") -> dict:
    """Fetch a C8 findings-filter preset for the given profile.

    `name` defaults to "current" which is what the console reads/writes on
    every filter change. Named presets (future) will use different values.
    """
    if not store_enabled():
        return {"profile_id": profile_id, "name": name, "value": None}
    try:
        from spotlight.store import FindingsFilterPrefRow

        with get_session() as sess:
            row = sess.get(FindingsFilterPrefRow, (profile_id, name))
            return {
                "profile_id": profile_id,
                "name": name,
                "value": row.value if row else None,
            }
    except Exception as exc:
        print(f"[findings-filter] read failed: {exc!r}")
        return {"profile_id": profile_id, "name": name, "value": None}


@app.put("/prefs/findings-filter/{profile_id}")
def put_findings_filter(profile_id: str, body: PrefValue, name: str = "current") -> dict:
    """Upsert a C8 findings-filter preset for a profile."""
    if not store_enabled():
        return {"profile_id": profile_id, "name": name, "value": body.value}
    try:
        from spotlight.store import FindingsFilterPrefRow

        with get_session() as sess:
            row = sess.get(FindingsFilterPrefRow, (profile_id, name))
            if row is None:
                sess.add(
                    FindingsFilterPrefRow(profile_id=profile_id, key=name, value=body.value)
                )
            else:
                row.value = body.value
    except Exception as exc:
        print(f"[findings-filter] write failed: {exc!r}")
    return {"profile_id": profile_id, "name": name, "value": body.value}


@app.get("/sweeps/{sweep_id}/token-usage")
def sweep_token_usage(sweep_id: str) -> dict:
    """Return per-agent + per-sub-agent token accounting for a sweep.

    Shape:
        {
          "by_role": [ { role, model, calls, prompt_tokens,
                         completion_tokens, total_tokens } ],
          "totals":  { calls, prompt_tokens, completion_tokens,
                       total_tokens },
          "events":  [ { role, subagent, model, prompt_tokens,
                         completion_tokens, total_tokens, ts,
                         elapsed_s, fallback } ]  # per-call event log,
          "wall_seconds": float,
        }

    The tracking proxy in the Orchestrator records this transparently for
    every ``model.complete()`` call — no touches at call sites required.
    """
    def _empty() -> dict:
        return {
            "sweep_id": sweep_id,
            "by_role": [],
            "totals": {
                "calls": 0,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
            },
            "events": [],
            "wall_seconds": 0.0,
        }

    findings: list[dict] = []
    wall_seconds = 0.0
    if sweep_id in SWEEPS:
        findings = list(SWEEPS[sweep_id].findings)
        for f in findings:
            audit = f.get("audit") or {}
            wall_seconds = max(wall_seconds, float(audit.get("wall_seconds") or 0))
    elif store_enabled():
        with get_session() as sess:
            row = sess.get(SweepRow, sweep_id)
            if row is None:
                raise HTTPException(404, "sweep not found")
            frows = (
                sess.query(FindingRow)
                .filter(FindingRow.sweep_id == sweep_id)
                .order_by(FindingRow.id)
                .all()
            )
            findings = [dict(fr.payload) for fr in frows]
            for f in findings:
                audit = f.get("audit") or {}
                wall_seconds = max(wall_seconds, float(audit.get("wall_seconds") or 0))
    else:
        raise HTTPException(404, "sweep not found")

    # The tracking proxy accumulates monotonically across the sweep, so
    # the LAST finding's snapshot has the sweep totals. Falls back to
    # empty on pre-migration finding payloads that lack `token_usage`.
    latest: dict | None = None
    for f in findings:
        tu = ((f.get("audit") or {}).get("token_usage")) or None
        if tu:
            latest = tu
    if latest is None:
        empty = _empty()
        empty["wall_seconds"] = round(wall_seconds, 6)
        return empty

    # The per-call event log lives on the orchestrator's in-memory state.
    # For live sweeps it's on SWEEPS[sweep_id]; for persisted sweeps we
    # don't currently mirror it to Postgres — that's an accepted follow-
    # up (would need a new event-log table). Return empty when absent.
    events: list[dict] = []
    result = SWEEPS.get(sweep_id)
    if result is not None:
        events = list(getattr(result, "usage_events", []) or [])

    return _redact_response({
        "sweep_id": sweep_id,
        "by_role": latest.get("by_role", []),
        "totals": latest.get("totals", {}),
        "events": events,
        "wall_seconds": round(wall_seconds, 6),
    })


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
        return _redact_response([enrich_finding(f) for f in SWEEPS[sweep_id].findings])
    if store_enabled():
        with get_session() as sess:
            rows = (
                sess.query(FindingRow)
                .filter(FindingRow.sweep_id == sweep_id)
                .order_by(FindingRow.id)
                .all()
            )
            return _redact_response([enrich_finding(r.payload) for r in rows])
    raise HTTPException(404, "sweep not found")


@app.get("/sweeps/{sweep_id}/delta")
def sweep_delta(sweep_id: str, since: str) -> dict:
    """C6 · Delta between two sweeps.

    Returns three arrays keyed on Spotlight's versioned stable identity:

      * ``new``         — appears in `sweep_id` but not in `since`
      * ``resolved``    — appeared in `since` but not in `sweep_id`
      * ``still_open``  — appears in both and is not analyst-reviewed
                          away (accepted / false-positive / risk-accepted)

    Sweep freshness is not asserted here — callers pick which two sweeps
    to compare. Same-repo comparison is the intended use, but this
    endpoint is repo-agnostic so cross-target diffs also work.
    """
    curr = _load_findings_for_sweep(sweep_id)
    prev = _load_findings_for_sweep(since)
    if curr is None:
        raise HTTPException(404, f"sweep not found: {sweep_id}")
    if prev is None:
        raise HTTPException(404, f"sweep not found: {since}")

    prev_index = {comparison_key(f): f for f in prev}
    curr_index = {comparison_key(f): f for f in curr}

    def _summarize(f: dict) -> dict:
        loc = f.get("location") or {}
        return {
            "id": f.get("id"),
            "class": f.get("class"),
            "severity": f.get("severity"),
            "tier": f.get("tier"),
            "title": f.get("title"),
            "file": loc.get("file"),
            "line": loc.get("line"),
            "function": loc.get("function"),
            "review_state": (f.get("review") or {}).get("state"),
        }

    new: list[dict] = []
    still_open: list[dict] = []
    for key, f in curr_index.items():
        summary = _summarize(f)
        if key not in prev_index:
            new.append(summary)
        else:
            # Still in both sweeps — filter analyst-suppressed ones from
            # "still_open" so the count matches "what actually needs work".
            if summary["review_state"] not in ("false-positive", "accepted", "risk-accepted"):
                still_open.append(summary)

    resolved = [
        _summarize(f) for key, f in prev_index.items() if key not in curr_index
    ]

    return _redact_response({
        "sweep_id": sweep_id,
        "since": since,
        "new": new,
        "resolved": resolved,
        "still_open": still_open,
        "counts": {
            "new": len(new),
            "resolved": len(resolved),
            "still_open": len(still_open),
        },
    })


def _load_findings_for_sweep(sweep_id: str) -> list[dict] | None:
    """In-memory-first + Postgres fallback, mirroring the pattern the other
    sweep endpoints use. Returns None if the sweep isn't found in either
    surface (so the caller can 404 with a specific id)."""
    if sweep_id in SWEEPS:
        return list(SWEEPS[sweep_id].findings or [])
    if store_enabled():
        with get_session() as sess:
            rows = (
                sess.query(FindingRow)
                .filter(FindingRow.sweep_id == sweep_id)
                .order_by(FindingRow.id)
                .all()
            )
            if not rows:
                # Sweep row exists but has no findings — distinguish from
                # "no sweep" by checking the SweepRow.
                sweep_row = sess.get(SweepRow, sweep_id)
                return [] if sweep_row is not None else None
            return [dict(r.payload) for r in rows]
    return None


@app.get("/findings/{finding_id}")
def get_finding(finding_id: str) -> dict:
    for s in reversed(list(SWEEPS.values())):
        for f in s.findings:
            if f["id"] == finding_id:
                return _redact_response(enrich_finding(f))
    if store_enabled():
        with get_session() as sess:
            row = _find_finding_row(sess, finding_id)
            if row:
                return _redact_response(enrich_finding(row.payload))
    raise HTTPException(404, "finding not found")


class ReviewRequest(BaseModel):
    """C4 — analyst review verdict on a finding.

    action:
      * ``accept``            — finding is real; ship the fix.
      * ``false-positive``    — Spotlight's judgment was wrong; skip.
      * ``risk-accept-until`` — real, but risk-accepted until an ISO date.

    ``reason`` is required (analyst rationale, ~1–2 sentences). ``until``
    is required iff ``action == "risk-accept-until"``.

    ``reviewer`` is a display name — real auth lands with multi-tenant (see
    §12 · Deliberately deferred). The signed chain-of-custody entry uses
    ``actor_kind="human"`` so downstream verifiers can filter analyst
    reviews from agent actions.
    """

    action: str  # "accept" | "false-positive" | "risk-accept-until"
    reason: str
    until: str | None = None
    reviewer: str = "analyst"


_REVIEW_ACTIONS = {"accept", "false-positive", "risk-accept-until"}
_REVIEW_STATE_BY_ACTION = {
    "accept": "accepted",
    "false-positive": "false-positive",
    "risk-accept-until": "risk-accepted",
}


@app.post("/findings/{finding_id}/review")
def post_finding_review(finding_id: str, req: ReviewRequest) -> dict:
    """Analyst review — append a signed entry, update finding.review_state.

    Every review is a first-class signed action on the chain of custody, so
    a bank auditor can prove *who* accepted / rejected / risk-accepted this
    finding, when, and why. State changes are terminal (no un-accept) —
    to reverse, submit a new review with a fresh signed entry.
    """
    action = (req.action or "").strip().lower()
    if action not in _REVIEW_ACTIONS:
        raise HTTPException(
            400, f"action must be one of {sorted(_REVIEW_ACTIONS)}"
        )
    reason = (req.reason or "").strip()
    if not reason:
        raise HTTPException(400, "reason is required")
    if action == "risk-accept-until" and not req.until:
        raise HTTPException(400, "until (ISO date) is required for risk-accept-until")

    finding, sweep_id = _find_finding_anywhere(finding_id)
    if finding is None:
        raise HTTPException(404, "finding not found")

    # Sign the review entry against the workspace key. Reuse the same signer
    # the orchestrator uses so the key_fingerprint matches previous entries
    # on this finding — external verifiers pull one public key and check
    # the whole chain in one pass.
    try:
        from spotlight.non_repudiation import Signer

        signer = Signer()
        payload = {
            "finding_id": finding_id,
            "action": action,
            "reason": reason,
            "reviewer": req.reviewer or "analyst",
        }
        if req.until:
            payload["until"] = req.until
        entry = signer.sign(
            actor_kind="human",
            actor_id=req.reviewer or "analyst",
            action=f"review.{action}",
            payload=payload,
        )
    except Exception as exc:
        raise HTTPException(500, f"signing failed: {exc!r}") from exc

    # Mutate the finding — append the entry to the audit chain and stamp
    # the review_state. Update the in-memory copy AND the persisted row so
    # subsequent GETs from either surface see the same value.
    audit = finding.setdefault("audit", {})
    coc = audit.setdefault("chain_of_custody", [])
    coc.append(entry)
    review = finding.setdefault("review", {})
    review["state"] = _REVIEW_STATE_BY_ACTION[action]
    review["reason"] = reason
    review["reviewer"] = req.reviewer or "analyst"
    review["ts"] = entry["ts"]
    if req.until:
        review["until"] = req.until

    _persist_finding_update(finding_id, sweep_id, finding)

    return _redact_response(finding)


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

    for s in reversed(list(SWEEPS.values())):
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
            row = _find_finding_row(sess, finding_id)
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
                        # Identity — a match at a DIFFERENT commit on the
                        # same repo is a different match; the Console needs
                        # commit_sha to bucket correctly. `org` disambiguates
                        # two repos that share a short name across GitHub
                        # organisations.
                        "org": sweep_row.org if sweep_row else None,
                        "commit_sha": sweep_row.commit_sha if sweep_row else None,
                        "commit_branch": sweep_row.commit_branch if sweep_row else None,
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
            row = _find_finding_row(sess, finding_id)
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


@app.get("/paths/{sweep_id}")
def get_paths(sweep_id: str) -> list[dict]:
    """Tranche B4 — return the ExploitPath list for a sweep.

    Cross-surface chains like `LLM01 → LLM06 → SSRF` composed by the
    Chainer after Reduce. Empty list when the Chainer found no matching
    pair. Same in-memory-first fallback as `/sweeps/{sweep_id}/findings`.
    """
    if sweep_id in SWEEPS:
        return _redact_response(SWEEPS[sweep_id].exploit_paths)
    if store_enabled():
        with get_session() as sess:
            row = sess.get(SweepRow, sweep_id)
            if row is not None:
                return _redact_response(row.exploit_paths or [])
    raise HTTPException(404, "sweep not found")


def _load_attestation_dict(sweep_id: str) -> dict | None:
    """Fetch the assembled attestation dict for a sweep, or None if missing.

    Prefers the in-memory hot cache (which the orchestrator wrote as the
    rich v2 attestation) and falls back to the persistent store for older
    sweeps that predate B6. In the fallback we reassemble via the Reporter
    so the same shape ships regardless of storage tier.
    """
    if sweep_id in SWEEPS:
        return SWEEPS[sweep_id].attestations[0]
    if store_enabled():
        with get_session() as sess:
            row = sess.get(SweepRow, sweep_id)
            if row is not None:
                findings = [f.payload for f in row.findings]
                # Best-effort re-assembly for legacy rows. Missing events
                # log = warden block will show zero counts, which is the
                # correct answer for a sweep that never had those signals.
                from spotlight.orchestrator import SweepResult
                from spotlight.reporter import Reporter

                stub = SweepResult(
                    sweep_id=row.id,
                    repo_path=row.repo_path,
                    threat_model=row.threat_model or {},
                    signals=row.signals or [],
                    findings=findings,
                    attestations=[],
                    events_log=[],
                )
                return Reporter().assemble(stub)
    return None


@app.get("/attestations/{sweep_id}")
def get_attestation(
    sweep_id: str,
    format: str = Query(default="json", pattern="^(json|markdown|pdf)$"),
):
    """Return the attestation for a sweep in the requested format.

    - ``json`` (default) — application/json, rich structured attestation.
    - ``markdown`` — text/markdown; charset=utf-8, human-readable report.
    - ``pdf`` — application/pdf, printable report. 503 if reportlab is not
      installed in this deployment (lean image without the PDF dep).
    """
    attestation = _load_attestation_dict(sweep_id)
    if attestation is None:
        raise HTTPException(404, "sweep not found")
    attestation = _redact_response(attestation)

    if format == "json":
        return attestation

    from spotlight.reporter import PdfRenderError, render_markdown, render_pdf

    markdown = render_markdown(attestation)
    if format == "markdown":
        return PlainTextResponse(
            content=markdown, media_type="text/markdown; charset=utf-8"
        )
    # pdf
    try:
        pdf_bytes = render_pdf(markdown)
    except PdfRenderError as exc:
        raise HTTPException(503, f"pdf renderer unavailable: {exc}")
    return Response(content=pdf_bytes, media_type="application/pdf")


@app.websocket("/ws/sweeps/{sweep_id}")
async def ws_sweep(ws: WebSocket, sweep_id: str) -> None:
    if authenticate_websocket(ws) is None:
        await ws.close(code=1008, reason="authentication required")
        return
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
