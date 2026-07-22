"""P1.4 — Alembic migrations must apply cleanly against a fresh database.

This test locks down the workflow that production deploys rely on:

  1. `alembic upgrade head` against a fresh SQLite DB completes without
     errors.
  2. The resulting schema matches `spotlight.store.models.Base.metadata`
     (autogenerate detects nothing missing) — the migration is exhaustive.
  3. All P1.1/P1.3 additions land: sweep_jobs.heartbeat_at column and
     events.uq_events_sweep_seq unique constraint.

If a future model change is not accompanied by a migration, test (2)
fails immediately with a helpful diff.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]


def _run(cmd: list[str], env: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=REPO,
        env={**os.environ, **env},
        timeout=60,
    )


@pytest.fixture
def fresh_sqlite_url(tmp_path: Path) -> tuple[str, Path]:
    db_path = tmp_path / "migrate.db"
    return f"sqlite:///{db_path}", db_path


def test_alembic_upgrade_head_succeeds(fresh_sqlite_url):
    url, _ = fresh_sqlite_url
    result = _run(
        [".venv/bin/alembic", "upgrade", "head"],
        env={"DATABASE_URL": url},
    )
    assert result.returncode == 0, (
        f"alembic upgrade failed:\n"
        f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}"
    )


def test_migrated_schema_matches_models(fresh_sqlite_url):
    """Autogenerate against the migrated database should report nothing
    missing. If any table / column / constraint in Base.metadata isn't
    covered by an existing migration, autogenerate detects it — and this
    test fails with a diff of what's out of sync."""
    url, _ = fresh_sqlite_url

    up = _run(
        [".venv/bin/alembic", "upgrade", "head"],
        env={"DATABASE_URL": url},
    )
    assert up.returncode == 0, up.stderr

    check = _run(
        [".venv/bin/alembic", "check"],
        env={"DATABASE_URL": url},
    )
    # `alembic check` exits 0 when no changes are detected, non-zero
    # when there is a drift. It writes the drift summary to stderr.
    assert check.returncode == 0, (
        f"models are ahead of migrations — new migration needed:\n"
        f"{check.stdout}\n{check.stderr}"
    )


def test_heartbeat_column_and_events_unique_constraint_present(fresh_sqlite_url):
    """Verify the P1.1 and P1.3 additions were captured by the baseline."""
    url, db_path = fresh_sqlite_url
    up = _run(
        [".venv/bin/alembic", "upgrade", "head"],
        env={"DATABASE_URL": url},
    )
    assert up.returncode == 0, up.stderr

    import sqlite3

    conn = sqlite3.connect(db_path)
    try:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(sweep_jobs)").fetchall()}
        assert "heartbeat_at" in cols, (
            "P1.1 regression: sweep_jobs.heartbeat_at column missing"
        )

        # Verify the events uniqueness constraint by attempting a duplicate insert.
        conn.execute(
            "INSERT INTO sweeps (id, repo_path, repo_name, source, status, "
            "surfaces, model, started_at, findings_count) "
            "VALUES ('sw_1', '/x', 'x', 'fixture', 'running', '[]', 'mock', "
            "datetime('now'), 0)"
        )
        conn.execute(
            "INSERT INTO events (sweep_id, seq, ts, type, actor, payload) "
            "VALUES ('sw_1', 1, 1.0, 't', 'a', '{}')"
        )
        conn.commit()

        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO events (sweep_id, seq, ts, type, actor, payload) "
                "VALUES ('sw_1', 1, 2.0, 't', 'a', '{}')"
            )
            conn.commit()
    finally:
        conn.close()
