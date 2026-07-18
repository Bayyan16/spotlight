"""Persistence follow-up — pr_watches, workspace_prefs, findings_filter_prefs.

Everything the console previously kept in localStorage now lives server-
side. Same for the PR-webhook association. These tests use SQLite via
DATABASE_URL to exercise the real persistence path (Postgres syntax is
guarded by JSON-vs-JSONB variant on the model).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


_HMAC_SECRET = "test-secret-please-rotate"


def _sig(body: bytes, secret: str = _HMAC_SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


@pytest.fixture
def sqlite_db(tmp_path, monkeypatch):
    """Point DATABASE_URL at a fresh SQLite file for the test's lifetime."""
    db_path = tmp_path / "spotlight.sqlite"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    # Force a re-init because module-level `_engine` might be cached from a
    # previous test that didn't set DATABASE_URL.
    from spotlight.store import db as db_mod

    db_mod._engine = None
    db_mod._SessionLocal = None
    return db_path


@pytest.fixture
def client(sqlite_db):
    from spotlight.api.app import app
    from spotlight.store import init_schema

    init_schema()
    return TestClient(app)


# ── workspace_prefs ────────────────────────────────────────────────────────

def test_workspace_pref_upsert_and_read(client):
    r = client.get("/prefs/workspace/wizard-dismissed")
    assert r.status_code == 200
    assert r.json()["value"] is None

    r = client.put(
        "/prefs/workspace/wizard-dismissed",
        json={"value": True},
    )
    assert r.status_code == 200
    assert r.json()["value"] is True

    r = client.get("/prefs/workspace/wizard-dismissed")
    assert r.json()["value"] is True


def test_workspace_pref_survives_client_restart(client, sqlite_db, monkeypatch):
    """Simulate a redeploy: write, spin up a fresh TestClient, read."""
    client.put("/prefs/workspace/auto-scan", json={"value": True})
    from spotlight.api.app import app
    from spotlight.store import db as db_mod

    db_mod._engine = None
    db_mod._SessionLocal = None
    # Clear the in-process cache so we're forced to read from disk.
    from spotlight.api import app as app_mod

    app_mod._PREF_CACHE.clear()

    fresh = TestClient(app)
    r = fresh.get("/prefs/workspace/auto-scan")
    assert r.json()["value"] is True


def test_workspace_pref_supports_nested_json(client):
    payload = {"tab": "single", "profile_id": "balanced", "meta": {"seen_at": "2026-07-17"}}
    r = client.put("/prefs/workspace/wizard-last-choice", json={"value": payload})
    assert r.status_code == 200
    r = client.get("/prefs/workspace/wizard-last-choice")
    assert r.json()["value"] == payload


# ── findings-filter presets (C8) ───────────────────────────────────────────

def test_findings_filter_pref_per_profile(client):
    # Writing preset for one profile does not clobber another.
    client.put(
        "/prefs/findings-filter/balanced",
        json={"value": {"sort": "severity", "tier": "verified", "review": "all"}},
    )
    client.put(
        "/prefs/findings-filter/deep",
        json={"value": {"sort": "class", "tier": "all", "review": "unreviewed"}},
    )

    r = client.get("/prefs/findings-filter/balanced")
    assert r.json()["value"]["sort"] == "severity"
    r = client.get("/prefs/findings-filter/deep")
    assert r.json()["value"]["sort"] == "class"


def test_findings_filter_pref_missing_profile_returns_null(client):
    r = client.get("/prefs/findings-filter/never-written")
    assert r.status_code == 200
    assert r.json()["value"] is None


# ── pr_watches (C7 persistence) ────────────────────────────────────────────

def test_pr_watch_persists_across_process(client, sqlite_db, monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", _HMAC_SECRET)
    body = json.dumps(
        {
            "action": "opened",
            "pull_request": {"number": 314},
            "repository": {
                "clone_url": "https://github.com/acme/api.git",
                "full_name": "acme/api",
            },
        }
    ).encode("utf-8")
    # Patch start_sweep so we don't clone a real repo.
    from spotlight.api import app as app_mod

    monkeypatch.setattr(app_mod, "start_sweep", lambda req: {"sweep_id": "sw_persist"})
    # Insert a matching sweep row so the FK on pr_watches doesn't reject the write.
    from spotlight.store import SweepRow, get_session, init_schema

    init_schema()
    with get_session() as sess:
        sess.add(
            SweepRow(
                id="sw_persist",
                repo_path="/tmp/dummy",
                repo_name="dummy",
                source="git-url",
                status="running",
            )
        )
    r = client.post(
        "/webhooks/github",
        content=body,
        headers={
            "X-Hub-Signature-256": _sig(body),
            "X-GitHub-Event": "pull_request",
        },
    )
    assert r.status_code == 200

    # Simulate a process restart: clear the in-memory dict and re-read.
    app_mod._pr_watch_by_sweep.clear()

    fetched = app_mod.get_pr_watch("sw_persist")
    assert fetched is not None
    assert fetched["pr_number"] == 314
    assert fetched["repo_full_name"] == "acme/api"


def test_pr_watch_unknown_sweep_returns_none(client):
    from spotlight.api.app import get_pr_watch

    assert get_pr_watch("sw_never") is None


# ── sweeps.interactive column (C2 persistence) ─────────────────────────────

def test_sweeps_interactive_column_persists(client, sqlite_db):
    from spotlight.store import SweepRow, get_session

    with get_session() as sess:
        sess.add(
            SweepRow(
                id="sw_i",
                repo_path="/tmp/x",
                repo_name="x",
                source="fixture",
                status="running",
                interactive=True,
            )
        )
    with get_session() as sess:
        row = sess.get(SweepRow, "sw_i")
        assert row is not None
        assert row.interactive is True
