"""DB engine + session lifecycle.

Behavior:
- If `DATABASE_URL` is set → use it (Postgres in prod, SQLite for local).
- Otherwise → persistence is DISABLED. API falls back to in-memory. This lets
  the vertical-slice tests keep running without a DB.
"""
from __future__ import annotations

import os
from contextlib import contextmanager

from sqlalchemy import create_engine
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
