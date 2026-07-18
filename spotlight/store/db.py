"""DB engine + session lifecycle.

Behavior:
- If `DATABASE_URL` is set → use it (Postgres in prod, SQLite for local).
- Otherwise → persistence is DISABLED. API falls back to in-memory. This lets
  the vertical-slice tests keep running without a DB.
"""
from __future__ import annotations

import os
from contextlib import contextmanager

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .models import Base

_engine: Engine | None = None
_SessionLocal: sessionmaker | None = None


def _database_url() -> str | None:
    url = os.environ.get("DATABASE_URL")
    if not url:
        return None
    # Railway hands out `postgres://...`; SQLAlchemy 2.x wants `postgresql+psycopg://...`.
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+psycopg://", 1)
    elif url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+psycopg://", 1)
    return url


def is_enabled() -> bool:
    return _database_url() is not None


def get_engine() -> Engine | None:
    global _engine, _SessionLocal
    if _engine is not None:
        return _engine
    url = _database_url()
    if not url:
        return None
    _engine = create_engine(url, pool_pre_ping=True, pool_size=5, max_overflow=5)
    _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False)
    return _engine


def init_schema() -> None:
    eng = get_engine()
    if eng is None:
        return
    Base.metadata.create_all(eng)
    _migrate_schema(eng)


# Tiny built-in migration runner. We do NOT ship Alembic; every schema
# addition is a one-line ALTER guarded by an EXISTS check so it's idempotent
# and safe to run on every startup. When Alembic lands later, this is the
# obvious first thing to retire.
#
# Each entry: (table, column, ADD COLUMN SQL fragment).
_ADDITIVE_MIGRATIONS: list[tuple[str, str, str]] = [
    # Tranche B4 — Chainer output persisted per sweep.
    ("sweeps", "exploit_paths", "ALTER TABLE sweeps ADD COLUMN IF NOT EXISTS exploit_paths JSONB"),
    # Persistence follow-up — sweep-level interactive-mode flag so the
    # audit trail can distinguish auto-run from human-in-the-loop sweeps.
    ("sweeps", "interactive", "ALTER TABLE sweeps ADD COLUMN IF NOT EXISTS interactive BOOLEAN"),
]


def _migrate_schema(eng: Engine) -> None:
    """Add columns that the ORM model declares but the live table is missing.

    `Base.metadata.create_all` only creates NEW tables — it never modifies
    existing ones. So when we add a column to an existing model (like
    `SweepRow.exploit_paths` in Tranche B4), the live Postgres table stays
    on the pre-B4 schema and every SELECT * fails with `UndefinedColumn`.
    This runs the additive migrations once per startup, in order, idempotent.
    """
    try:
        insp = inspect(eng)
        for table, column, sql in _ADDITIVE_MIGRATIONS:
            if not insp.has_table(table):
                continue
            existing_cols = {c["name"] for c in insp.get_columns(table)}
            if column in existing_cols:
                continue
            with eng.begin() as conn:
                conn.execute(text(sql))
                print(f"[db] migration applied: {sql}")
    except Exception as exc:  # never break startup over a migration
        print(f"[db] migration failed: {exc!r}")


@contextmanager
def get_session():
    if _SessionLocal is None:
        get_engine()
    if _SessionLocal is None:
        raise RuntimeError("DB not configured — call is_enabled() first")
    sess: Session = _SessionLocal()
    try:
        yield sess
        sess.commit()
    except Exception:
        sess.rollback()
        raise
    finally:
        sess.close()
