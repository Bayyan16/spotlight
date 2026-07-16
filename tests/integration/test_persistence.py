"""Persistence integration test using SQLite (survives the Postgres path
because SQLAlchemy is the boundary). Proves that a sweep survives a
'restart' — clearing the in-memory dicts but keeping the DB — and that
DELETE actually removes it."""
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def api_client(tmp_path, monkeypatch):
    db = tmp_path / "spotlight.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db}")

    # Force fresh import so DATABASE_URL is seen when engine is first built.
    import importlib
    import spotlight.store.db as db_mod
    import spotlight.api.app as app_mod
    importlib.reload(db_mod)
    importlib.reload(app_mod)
    app_mod.init_schema()

    client = TestClient(app_mod.app)
    yield client, app_mod


def test_sweep_persists_across_memory_clear(api_client):
    client, app_mod = api_client
    r = client.post("/sweeps", json={"repo": "vuln-bank-api"})
    sweep_id = r.json()["sweep_id"]
    # Poll for completion.
    import time
    for _ in range(50):
        s = client.get(f"/sweeps/{sweep_id}").json()
        if s["status"] == "finished":
            break
        time.sleep(0.1)
    assert s["status"] == "finished"

    # Simulate a restart: clear the in-memory dicts.
    app_mod.SWEEPS.clear()
    app_mod.BUSES.clear()
    app_mod._running_threads.clear()

    # Sweep is still visible via /sweeps list from DB.
    sweeps = client.get("/sweeps").json()
    assert any(s["sweep_id"] == sweep_id for s in sweeps)
    # Findings still queryable.
    findings = client.get(f"/sweeps/{sweep_id}/findings").json()
    assert len(findings) == 1
    assert findings[0]["tier"] == "verified"
    # Attestation still assembled.
    att = client.get(f"/attestations/{sweep_id}").json()
    assert att["sweep_id"] == sweep_id


def test_delete_removes_sweep(api_client):
    client, _ = api_client
    r = client.post("/sweeps", json={"repo": "vuln-bank-api"})
    sweep_id = r.json()["sweep_id"]
    import time
    for _ in range(50):
        s = client.get(f"/sweeps/{sweep_id}").json()
        if s["status"] == "finished":
            break
        time.sleep(0.1)

    d = client.delete(f"/sweeps/{sweep_id}").json()
    assert d == {"deleted": sweep_id}

    # Gone from list, 404 on lookup.
    sweeps = client.get("/sweeps").json()
    assert not any(s["sweep_id"] == sweep_id for s in sweeps)
    assert client.get(f"/sweeps/{sweep_id}").status_code == 404


def test_git_url_rejected_when_not_git(api_client):
    client, _ = api_client
    # Non-git URL falls through to fixture lookup and 404s.
    r = client.post("/sweeps", json={"repo": "https://example.com/not-a-repo"})
    # Currently we require .git suffix to trigger the git path — plain
    # HTTPS URLs go through the fixture lookup and fail.
    assert r.status_code == 404
