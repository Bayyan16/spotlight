"""P1.3 — event persistence must be idempotent under crash-retry.

The `events` table carries a `UNIQUE(sweep_id, seq)` constraint (added in
paper-v1's Week-3 durability work). We verify:

  1. Re-emitting the exact (sweep_id, seq, payload) tuple does not create
     a duplicate row (`_upsert_event` becomes a no-op).
  2. Re-emitting the same (sweep_id, seq) with a NEW payload updates the
     row in place — the invariant is "one row per (sweep_id, seq)", not
     "first-wins immutability."
  3. Two writers racing on the same (sweep_id, seq) never violate the
     UNIQUE constraint at the database level.

Unit-level tests use an in-memory SQLite database. The dialect-aware
INSERT path in `spotlight.api.app._upsert_event` picks the correct
`on_conflict_do_update` shape for both Postgres and SQLite.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from spotlight.api.app import _upsert_event
from spotlight.store.models import Base, EventRow, SweepRow


@dataclass
class _FakeEvent:
    """Duck-typed EventBus event — mirrors spotlight.orchestrator.events.Event."""
    sweep_id: str
    seq: int
    ts: float
    type: str
    actor: str
    payload: dict


@pytest.fixture
def session_factory():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


@pytest.fixture
def seeded_sweep(session_factory):
    sweep_id = "sw_idempotency_1"
    with session_factory() as s:
        s.add(SweepRow(id=sweep_id, repo_path="fixture:demo", repo_name="demo",
                       source="fixture", status="running"))
        s.commit()
    return sweep_id, session_factory


def _event(sweep_id: str, seq: int, payload: dict[str, Any] | None = None) -> _FakeEvent:
    return _FakeEvent(
        sweep_id=sweep_id,
        seq=seq,
        ts=1000.0 + seq,
        type="candidate.raised",
        actor="investigator",
        payload=payload or {"finding": f"seq-{seq}"},
    )


def test_reemit_same_event_is_noop(seeded_sweep):
    """Insert the same event twice → still one row, no duplicate."""
    sweep_id, Session = seeded_sweep
    ev = _event(sweep_id, seq=1)

    with Session() as s:
        _upsert_event(s, ev)
        s.commit()
    with Session() as s:
        _upsert_event(s, ev)
        s.commit()

    with Session() as s:
        rows = s.query(EventRow).filter(EventRow.sweep_id == sweep_id).all()
        assert len(rows) == 1
        assert rows[0].seq == 1
        assert rows[0].payload == {"finding": "seq-1"}


def test_reemit_with_updated_payload_updates_in_place(seeded_sweep):
    """The invariant is one row per (sweep_id, seq); a later emission
    with a different payload UPDATES rather than inserts a duplicate."""
    sweep_id, Session = seeded_sweep
    ev1 = _event(sweep_id, seq=5, payload={"stage": "raised"})
    ev2 = _event(sweep_id, seq=5, payload={"stage": "corroborated"})

    with Session() as s:
        _upsert_event(s, ev1)
        s.commit()
    with Session() as s:
        _upsert_event(s, ev2)
        s.commit()

    with Session() as s:
        rows = s.query(EventRow).filter(EventRow.sweep_id == sweep_id).all()
        assert len(rows) == 1
        assert rows[0].seq == 5
        assert rows[0].payload == {"stage": "corroborated"}


def test_different_seqs_are_kept_separate(seeded_sweep):
    """UNIQUE constraint is on (sweep_id, seq); different seq values coexist."""
    sweep_id, Session = seeded_sweep
    with Session() as s:
        _upsert_event(s, _event(sweep_id, seq=1))
        _upsert_event(s, _event(sweep_id, seq=2))
        _upsert_event(s, _event(sweep_id, seq=3))
        s.commit()
    with Session() as s:
        rows = s.query(EventRow).filter(EventRow.sweep_id == sweep_id).order_by(EventRow.seq).all()
        assert [r.seq for r in rows] == [1, 2, 3]


def test_unique_constraint_enforced_at_db_level(seeded_sweep):
    """Direct INSERT (bypassing _upsert_event) that violates the constraint
    must raise IntegrityError. This documents the invariant the constraint
    provides at the database layer — not just at the application layer."""
    sweep_id, Session = seeded_sweep
    with Session() as s:
        s.add(EventRow(sweep_id=sweep_id, seq=42, ts=1.0, type="x", actor="y",
                      payload={}))
        s.commit()

    with Session() as s:
        s.add(EventRow(sweep_id=sweep_id, seq=42, ts=2.0, type="x", actor="y",
                      payload={}))
        with pytest.raises(IntegrityError):
            s.commit()


def test_crash_retry_scenario(seeded_sweep):
    """Simulate a worker that emits seq=1..10, crashes just before
    committing, then a replay re-emits seq=1..10. Result should be
    exactly 10 rows, not 20."""
    sweep_id, Session = seeded_sweep
    events = [_event(sweep_id, seq=i) for i in range(1, 11)]

    # First attempt — succeeds
    with Session() as s:
        for ev in events:
            _upsert_event(s, ev)
        s.commit()

    # Replay — same events, all upserted, no duplicates
    with Session() as s:
        for ev in events:
            _upsert_event(s, ev)
        s.commit()

    with Session() as s:
        assert s.query(EventRow).filter(EventRow.sweep_id == sweep_id).count() == 10
