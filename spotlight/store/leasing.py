"""Multi-worker safe claim, renew, release, and expiry recovery for
sweep jobs.

The `sweep_jobs` table carries an explicit lease with:
  - lease_owner     : worker id holding the job
  - lease_until     : wall-clock when the lease expires if not renewed
  - heartbeat_at    : last time the owner said "I'm alive"
  - attempts        : incremented every claim (audit + backoff)

Workers claim a job by atomically flipping status queued → running under
Postgres `SELECT ... FOR UPDATE SKIP LOCKED`. They must renew the lease
before `lease_until`, or the periodic expiry sweep returns the job to the
queued pool and any worker (including a different replica) may reclaim it.

Everything here is safe on SQLite too — SQLite serialises writers, so the
skip-locked clause is effectively a no-op but semantics still hold.
"""
from __future__ import annotations

import os
import socket
import uuid
from datetime import datetime, timedelta, timezone
from typing import Iterable

from sqlalchemy import and_, or_
from sqlalchemy.orm import Session

from spotlight.store.models import SweepJobRow, SweepRow


# ── defaults ────────────────────────────────────────────────────────────

def _env_seconds(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default


def lease_ttl() -> timedelta:
    """How long a claim survives without renewal. Default 60s."""
    return timedelta(seconds=_env_seconds("SPOTLIGHT_LEASE_TTL_SECONDS", 60))


def heartbeat_interval() -> timedelta:
    """How often a worker should call `renew` while working. Default 10s."""
    return timedelta(seconds=_env_seconds("SPOTLIGHT_HEARTBEAT_INTERVAL_SECONDS", 10))


def worker_id() -> str:
    """Stable-per-process worker identifier. Combines hostname + pid + a
    per-process uuid4 so two replicas on the same host never collide even
    if pids happen to match after a container restart."""
    hostname = socket.gethostname()
    pid = os.getpid()
    # Cache the uuid on the module so a single process always presents the
    # same id across calls.
    global _CACHED_WORKER_ID
    try:
        return _CACHED_WORKER_ID  # type: ignore[name-defined]
    except NameError:
        _CACHED_WORKER_ID = f"{hostname}:{pid}:{uuid.uuid4().hex[:8]}"
        return _CACHED_WORKER_ID


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ── claim ───────────────────────────────────────────────────────────────

def claim_specific(
    session: Session,
    sweep_id: str,
    *,
    owner: str | None = None,
    ttl: timedelta | None = None,
) -> bool:
    """Try to claim one specific sweep job. Returns True if this call now
    owns the lease.

    Claimable states:
      * status = "queued"
      * status = "running" AND lease has expired (or was never set)

    Uses `SELECT ... FOR UPDATE SKIP LOCKED` on Postgres so concurrent
    workers don't fight for the row. Any worker that would deadlock
    simply gets `None` and moves on.
    """
    owner = owner or worker_id()
    ttl = ttl or lease_ttl()
    now = _now()

    row = (
        session.query(SweepJobRow)
        .filter(SweepJobRow.sweep_id == sweep_id)
        .filter(
            or_(
                SweepJobRow.status == "queued",
                and_(
                    SweepJobRow.status == "running",
                    or_(
                        SweepJobRow.lease_until.is_(None),
                        SweepJobRow.lease_until < now,
                    ),
                ),
            )
        )
        .with_for_update(skip_locked=True)
        .first()
    )
    if row is None:
        return False

    row.status = "running"
    row.lease_owner = owner
    row.lease_until = now + ttl
    row.heartbeat_at = now
    row.attempts = (row.attempts or 0) + 1
    row.last_error = None

    # Keep the sweep row's high-level status in sync so the API surface
    # reflects the actual state without a separate write path.
    sweep_row = session.get(SweepRow, sweep_id)
    if sweep_row is not None:
        sweep_row.status = "running"
    return True


def claim_next(
    session: Session,
    *,
    owner: str | None = None,
    ttl: timedelta | None = None,
) -> str | None:
    """Try to claim the oldest available job. Returns the sweep_id if we
    claimed one, else None. Same locking semantics as `claim_specific`.

    Ordering is FIFO on `created_at`. Combined with SKIP LOCKED this gives
    starvation-free work distribution across worker replicas.
    """
    owner = owner or worker_id()
    ttl = ttl or lease_ttl()
    now = _now()

    row = (
        session.query(SweepJobRow)
        .filter(
            or_(
                SweepJobRow.status == "queued",
                and_(
                    SweepJobRow.status == "running",
                    or_(
                        SweepJobRow.lease_until.is_(None),
                        SweepJobRow.lease_until < now,
                    ),
                ),
            )
        )
        .order_by(SweepJobRow.created_at.asc())
        .with_for_update(skip_locked=True)
        .first()
    )
    if row is None:
        return None

    row.status = "running"
    row.lease_owner = owner
    row.lease_until = now + ttl
    row.heartbeat_at = now
    row.attempts = (row.attempts or 0) + 1
    row.last_error = None

    sweep_row = session.get(SweepRow, row.sweep_id)
    if sweep_row is not None:
        sweep_row.status = "running"
    return row.sweep_id


# ── renew / release ─────────────────────────────────────────────────────

def renew(
    session: Session,
    sweep_id: str,
    *,
    owner: str | None = None,
    ttl: timedelta | None = None,
) -> bool:
    """Extend lease + refresh heartbeat_at. Returns True if we still own
    the job. If another worker reclaimed after our lease expired, this
    returns False and the caller should abort its work — the reclaiming
    worker is now authoritative."""
    owner = owner or worker_id()
    ttl = ttl or lease_ttl()
    now = _now()

    updated = (
        session.query(SweepJobRow)
        .filter(
            SweepJobRow.sweep_id == sweep_id,
            SweepJobRow.lease_owner == owner,
        )
        .update(
            {
                SweepJobRow.lease_until: now + ttl,
                SweepJobRow.heartbeat_at: now,
            },
            synchronize_session=False,
        )
    )
    return bool(updated)


def release(
    session: Session,
    sweep_id: str,
    *,
    owner: str | None = None,
    error: str | None = None,
) -> bool:
    """Release lease on completion or failure. Guarded by owner so a
    late-reclaim by another worker doesn't get overwritten. Returns True
    if the release took effect."""
    owner = owner or worker_id()

    updated = (
        session.query(SweepJobRow)
        .filter(
            SweepJobRow.sweep_id == sweep_id,
            SweepJobRow.lease_owner == owner,
        )
        .update(
            {
                SweepJobRow.status: "failed" if error else "finished",
                SweepJobRow.last_error: (error[:1000] if error else None),
                SweepJobRow.lease_owner: None,
                SweepJobRow.lease_until: None,
                # heartbeat_at is deliberately left untouched — it's the
                # last-known-alive marker for diagnostics.
            },
            synchronize_session=False,
        )
    )
    return bool(updated)


# ── expiry recovery ─────────────────────────────────────────────────────

def sweep_expired_leases(session: Session) -> int:
    """Return `running` jobs whose lease expired to `queued` state. Any
    worker can call this periodically; the reclaimed jobs are then
    available to any worker via `claim_next`.

    Returns the number of jobs reclaimed.

    Race-safe: the update predicate re-checks `lease_until < now` inside
    the transaction, so two workers running the sweep simultaneously
    reclaim the same set exactly once (Postgres row-level locks handle
    the tie).
    """
    now = _now()
    updated = (
        session.query(SweepJobRow)
        .filter(
            SweepJobRow.status == "running",
            SweepJobRow.lease_until.isnot(None),
            SweepJobRow.lease_until < now,
        )
        .update(
            {
                SweepJobRow.status: "queued",
                SweepJobRow.lease_owner: None,
                SweepJobRow.lease_until: None,
            },
            synchronize_session=False,
        )
    )
    return int(updated or 0)


# ── observability ───────────────────────────────────────────────────────

def snapshot(session: Session, sweep_ids: Iterable[str] | None = None) -> list[dict]:
    """Debug helper: return lease state for the requested sweeps (or all
    active jobs). Not on the request path — for the /health/leases
    endpoint and for tests."""
    q = session.query(SweepJobRow)
    if sweep_ids is not None:
        q = q.filter(SweepJobRow.sweep_id.in_(list(sweep_ids)))
    rows = q.all()
    return [
        {
            "sweep_id": r.sweep_id,
            "status": r.status,
            "attempts": r.attempts,
            "lease_owner": r.lease_owner,
            "lease_until": r.lease_until.isoformat() if r.lease_until else None,
            "heartbeat_at": r.heartbeat_at.isoformat() if r.heartbeat_at else None,
            "last_error": r.last_error,
        }
        for r in rows
    ]
