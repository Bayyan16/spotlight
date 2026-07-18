"""SQLAlchemy models — Phase 1.5 persistence.

Sweeps, findings, and events survive container restarts. Everything else
(threat model, signals, artifacts) is denormalized into JSONB blobs on the
sweep row for now; Phase 2 splits them out when we need to query across them.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import JSON


class Base(DeclarativeBase):
    pass


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# Postgres gets JSONB (indexable, faster); SQLite gets plain JSON as fallback.
JsonType = JSONB().with_variant(JSON(), "sqlite")


class SweepRow(Base):
    __tablename__ = "sweeps"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    repo_path: Mapped[str] = mapped_column(String(512))
    repo_name: Mapped[str] = mapped_column(String(256))
    source: Mapped[str] = mapped_column(String(32), default="fixture")  # fixture | git-url | upload
    status: Mapped[str] = mapped_column(String(32), default="running")
    surfaces: Mapped[Any] = mapped_column(JsonType, default=list)
    model: Mapped[str] = mapped_column(String(64), default="mock")
    threat_model: Mapped[Any] = mapped_column(JsonType, nullable=True)
    signals: Mapped[Any] = mapped_column(JsonType, nullable=True)
    # Tranche B4 — cross-surface exploit paths composed from candidates.
    # JSONB list of ExploitPath dicts; empty list when the Chainer finds no
    # matching pair. Nullable=True so old rows (pre-B4) load cleanly.
    exploit_paths: Mapped[Any] = mapped_column(JsonType, nullable=True, default=list)
    # C2 · Whether this sweep was started in interactive mode. Persisted so
    # the audit trail can distinguish auto-run sweeps from human-in-the-loop
    # ones months later. Nullable=True for pre-C2 rows.
    interactive: Mapped[bool | None] = mapped_column(nullable=True, default=False)
    # Sweep identity — what code did this sweep actually see? Two sweeps of
    # "acme-bank" months apart are only meaningfully "the same" if the
    # commit_sha matches. Populated from `git rev-parse` at sweep-start
    # when the target is a git checkout; empty for pure fixture targets.
    org: Mapped[str | None] = mapped_column(String(128), nullable=True)
    commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    commit_branch: Mapped[str | None] = mapped_column(String(128), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)

    findings = relationship("FindingRow", back_populates="sweep", cascade="all, delete-orphan")
    events = relationship("EventRow", back_populates="sweep", cascade="all, delete-orphan")


class PrWatchRow(Base):
    """C7 · GitHub PR association per sweep.

    Persists the link between a sweep (fired by /webhooks/github) and the
    GitHub PR that triggered it. Without this row, an API restart between
    webhook and sweep-finished loses the PR number — no comment can be
    posted back. sweep_id is the primary key so the write is idempotent per
    sweep. Cascade-deletes when the sweep row goes away.
    """

    __tablename__ = "pr_watches"

    sweep_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("sweeps.id", ondelete="CASCADE"),
        primary_key=True,
    )
    repo_full_name: Mapped[str] = mapped_column(String(256))
    pr_number: Mapped[int] = mapped_column(Integer)
    clone_url: Mapped[str] = mapped_column(String(512))
    installation_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    # Result of the delta-comment post — populated by a follow-up job.
    # None: not yet attempted. "posted": succeeded. "failed": last-attempt
    # error captured in `comment_error`.
    comment_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    comment_error: Mapped[str | None] = mapped_column(Text, nullable=True)


class WorkspacePrefRow(Base):
    """Server-persisted workspace preferences.

    Single-workspace demo — no `user_id` yet. Keys are stable strings the
    console reads on load; the value is a JSONB blob so we can evolve
    schema without a migration per shape change. Replaces the localStorage
    reads that we moved off the browser in the persistence follow-up.
    """

    __tablename__ = "workspace_prefs"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[Any] = mapped_column(JsonType, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )


class FindingsFilterPrefRow(Base):
    """C8 · Sortable-inbox filter presets, per Profile.

    (profile_id, key) is the composite primary key so each Profile can hold
    multiple named presets — today the console writes one "current" preset
    per profile; the shape is future-proof for named ones.
    """

    __tablename__ = "findings_filter_prefs"

    profile_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[Any] = mapped_column(JsonType, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )


class FindingRow(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    sweep_id: Mapped[str] = mapped_column(String(64), ForeignKey("sweeps.id", ondelete="CASCADE"))
    surface: Mapped[str] = mapped_column(String(32))
    title: Mapped[str] = mapped_column(String(512))
    severity: Mapped[str] = mapped_column(String(16))
    class_: Mapped[str] = mapped_column("class", String(64))
    cwe: Mapped[str] = mapped_column(String(32))
    file: Mapped[str] = mapped_column(String(512))
    line: Mapped[int] = mapped_column(Integer)
    function: Mapped[str] = mapped_column(String(256))
    state: Mapped[str] = mapped_column(String(32))
    tier: Mapped[str] = mapped_column(String(32))
    confidence: Mapped[float] = mapped_column(Float)
    payload: Mapped[Any] = mapped_column(JsonType)  # the full finding dict

    sweep = relationship("SweepRow", back_populates="findings")


class EventRow(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sweep_id: Mapped[str] = mapped_column(String(64), ForeignKey("sweeps.id", ondelete="CASCADE"))
    seq: Mapped[int] = mapped_column(Integer)
    ts: Mapped[float] = mapped_column(Float)
    type: Mapped[str] = mapped_column(String(64))
    actor: Mapped[str] = mapped_column(String(64))
    payload: Mapped[Any] = mapped_column(JsonType, default=dict)

    sweep = relationship("SweepRow", back_populates="events")
