"""Test the multi-worker safe leasing primitives in spotlight.store.leasing.

These tests exercise the core invariants:
  1. Two workers can't hold the same job at the same time (mutual exclusion).
  2. A crashed worker's job is reclaimable after lease_until passes.
  3. A worker whose lease expired mid-work has its renew() rejected.
  4. Release only affects the row if we still own the lease.
  5. Expired-lease sweep re-queues stale rows without touching healthy ones.

Uses an in-memory SQLite database so the tests are deterministic and don't
require Postgres. `FOR UPDATE SKIP LOCKED` is a no-op under SQLite but the
transactional semantics still hold — the same code paths run in production
against Postgres with the added row-level locking.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from spotlight.store import leasing
from spotlight.store.models import Base, SweepJobRow, SweepRow


@pytest.fixture
def session_factory():
    """Fresh in-memory SQLite per test — no cross-test bleed."""
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


@pytest.fixture
def sweep_job(session_factory):
    """Seed one queued sweep + sweep_job row and return its sweep_id."""
    Session = session_factory
    sweep_id = "sw_test_abc"
    with Session() as s:
        s.add(SweepRow(id=sweep_id, repo_path="fixture:demo", repo_name="demo",
                       source="fixture", status="queued"))
        s.add(SweepJobRow(sweep_id=sweep_id, request={"repo": "demo"}, status="queued"))
        s.commit()
    return sweep_id, Session


# ── mutual exclusion ────────────────────────────────────────────────────

def test_two_workers_cannot_hold_the_same_job(sweep_job):
    """Concurrent claim_specific by two workers: only one succeeds."""
    sweep_id, Session = sweep_job
    with Session() as s1:
        claimed1 = leasing.claim_specific(s1, sweep_id, owner="worker-A")
        s1.commit()
    assert claimed1 is True

    with Session() as s2:
        claimed2 = leasing.claim_specific(s2, sweep_id, owner="worker-B")
        s2.commit()
    assert claimed2 is False, "second worker must not steal an active lease"

    with Session() as s:
        job = s.get(SweepJobRow, sweep_id)
        assert job.status == "running"
        assert job.lease_owner == "worker-A"
        assert job.attempts == 1


# ── claim_next FIFO ─────────────────────────────────────────────────────

def test_claim_next_returns_oldest_queued_job(session_factory):
    Session = session_factory
    with Session() as s:
        for i, sid in enumerate(["sw_1", "sw_2", "sw_3"]):
            s.add(SweepRow(id=sid, repo_path="fixture:d", repo_name="d",
                          source="fixture", status="queued"))
            s.add(SweepJobRow(sweep_id=sid, request={}, status="queued"))
        s.commit()
    with Session() as s:
        got = leasing.claim_next(s, owner="worker-1")
        s.commit()
    assert got == "sw_1"


def test_claim_next_returns_none_when_nothing_queued(session_factory):
    Session = session_factory
    with Session() as s:
        assert leasing.claim_next(s, owner="worker-1") is None


# ── expiry recovery ────────────────────────────────────────────────────

def test_expired_lease_is_reclaimable(sweep_job):
    sweep_id, Session = sweep_job
    # Worker A claims with a 1ms TTL so it's already expired by the time we
    # try to reclaim.
    with Session() as s:
        leasing.claim_specific(s, sweep_id, owner="worker-A",
                              ttl=timedelta(milliseconds=1))
        s.commit()
    # Wait past TTL.
    import time
    time.sleep(0.05)

    with Session() as s:
        reclaimed = leasing.sweep_expired_leases(s)
        s.commit()
    assert reclaimed == 1

    with Session() as s:
        claimed_b = leasing.claim_specific(s, sweep_id, owner="worker-B")
        s.commit()
    assert claimed_b is True

    with Session() as s:
        job = s.get(SweepJobRow, sweep_id)
        assert job.lease_owner == "worker-B"
        assert job.attempts == 2, "each claim increments attempts"


def test_expired_lease_swept_returns_to_queued(sweep_job):
    sweep_id, Session = sweep_job
    with Session() as s:
        leasing.claim_specific(s, sweep_id, owner="worker-A",
                              ttl=timedelta(milliseconds=1))
        s.commit()
    import time
    time.sleep(0.05)

    with Session() as s:
        leasing.sweep_expired_leases(s)
        s.commit()

    with Session() as s:
        job = s.get(SweepJobRow, sweep_id)
        assert job.status == "queued"
        assert job.lease_owner is None
        assert job.lease_until is None


def test_healthy_lease_not_touched_by_sweep(sweep_job):
    """A running job with a live lease survives the expiry sweep."""
    sweep_id, Session = sweep_job
    with Session() as s:
        leasing.claim_specific(s, sweep_id, owner="worker-A",
                              ttl=timedelta(hours=1))
        s.commit()

    with Session() as s:
        reclaimed = leasing.sweep_expired_leases(s)
        s.commit()
    assert reclaimed == 0

    with Session() as s:
        job = s.get(SweepJobRow, sweep_id)
        assert job.status == "running"
        assert job.lease_owner == "worker-A"


# ── renew ──────────────────────────────────────────────────────────────

def test_renew_extends_lease_and_updates_heartbeat(sweep_job):
    sweep_id, Session = sweep_job
    with Session() as s:
        leasing.claim_specific(s, sweep_id, owner="worker-A",
                              ttl=timedelta(seconds=5))
        s.commit()

    with Session() as s:
        job = s.get(SweepJobRow, sweep_id)
        first_lease = job.lease_until
        first_heartbeat = job.heartbeat_at

    import time
    time.sleep(0.05)

    with Session() as s:
        renewed = leasing.renew(s, sweep_id, owner="worker-A",
                                ttl=timedelta(seconds=10))
        s.commit()
    assert renewed is True

    with Session() as s:
        job = s.get(SweepJobRow, sweep_id)
        assert job.lease_until > first_lease
        assert job.heartbeat_at > first_heartbeat


def test_renew_rejects_a_different_worker(sweep_job):
    """A worker whose lease was reclaimed cannot renew — the reclaiming
    worker is authoritative."""
    sweep_id, Session = sweep_job
    with Session() as s:
        leasing.claim_specific(s, sweep_id, owner="worker-A",
                              ttl=timedelta(milliseconds=1))
        s.commit()

    import time
    time.sleep(0.05)

    # Sweep + reclaim by worker-B
    with Session() as s:
        leasing.sweep_expired_leases(s)
        s.commit()
    with Session() as s:
        leasing.claim_specific(s, sweep_id, owner="worker-B")
        s.commit()

    # Now worker-A tries to renew — must fail
    with Session() as s:
        renewed = leasing.renew(s, sweep_id, owner="worker-A")
        s.commit()
    assert renewed is False, "worker-A must not renew a lease it no longer owns"


# ── release ────────────────────────────────────────────────────────────

def test_release_completes_the_job(sweep_job):
    sweep_id, Session = sweep_job
    with Session() as s:
        leasing.claim_specific(s, sweep_id, owner="worker-A")
        s.commit()

    with Session() as s:
        released = leasing.release(s, sweep_id, owner="worker-A")
        s.commit()
    assert released is True

    with Session() as s:
        job = s.get(SweepJobRow, sweep_id)
        assert job.status == "finished"
        assert job.lease_owner is None
        assert job.last_error is None


def test_release_with_error_marks_failed(sweep_job):
    sweep_id, Session = sweep_job
    with Session() as s:
        leasing.claim_specific(s, sweep_id, owner="worker-A")
        s.commit()
    with Session() as s:
        leasing.release(s, sweep_id, owner="worker-A", error="boom in reproducer")
        s.commit()
    with Session() as s:
        job = s.get(SweepJobRow, sweep_id)
        assert job.status == "failed"
        assert job.last_error == "boom in reproducer"


def test_release_from_wrong_owner_is_a_noop(sweep_job):
    """Worker B cannot release worker A's active lease. Protects against
    a message-ordering race after a reclaim."""
    sweep_id, Session = sweep_job
    with Session() as s:
        leasing.claim_specific(s, sweep_id, owner="worker-A")
        s.commit()

    with Session() as s:
        released = leasing.release(s, sweep_id, owner="worker-B")
        s.commit()
    assert released is False

    with Session() as s:
        job = s.get(SweepJobRow, sweep_id)
        assert job.status == "running", "wrong-owner release must not flip state"
        assert job.lease_owner == "worker-A"


# ── observability ──────────────────────────────────────────────────────

def test_snapshot_returns_lease_state(sweep_job):
    sweep_id, Session = sweep_job
    with Session() as s:
        leasing.claim_specific(s, sweep_id, owner="worker-A")
        s.commit()
    with Session() as s:
        snap = leasing.snapshot(s, sweep_ids=[sweep_id])
    assert len(snap) == 1
    entry = snap[0]
    assert entry["sweep_id"] == sweep_id
    assert entry["status"] == "running"
    assert entry["lease_owner"] == "worker-A"
    assert entry["lease_until"] is not None
    assert entry["heartbeat_at"] is not None


# ── worker id ──────────────────────────────────────────────────────────

def test_worker_id_stable_across_calls():
    """Same process, same worker_id."""
    a = leasing.worker_id()
    b = leasing.worker_id()
    assert a == b


def test_worker_id_contains_pid_and_hostname():
    import os, socket
    wid = leasing.worker_id()
    assert socket.gethostname() in wid
    assert str(os.getpid()) in wid
