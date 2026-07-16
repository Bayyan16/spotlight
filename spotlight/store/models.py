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
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)

    findings = relationship("FindingRow", back_populates="sweep", cascade="all, delete-orphan")
    events = relationship("EventRow", back_populates="sweep", cascade="all, delete-orphan")


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
