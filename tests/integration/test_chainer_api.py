"""Tranche B4 — API contract for the Chainer endpoint.

Two things need to hold at the HTTP boundary:

  * `GET /paths/{sweep_id}` returns whatever the Chainer composed for
    that sweep (empty list if nothing chained). 404 for unknown ids.
  * `GET /sweeps/{sweep_id}/findings` returns findings with the
    `exploit_path` field present (nullable) — the Console keys off it
    to render the chain badge.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from spotlight.api.app import BUSES, SWEEPS, _running_threads, app

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _clear_registries():
    BUSES.clear()
    SWEEPS.clear()
    _running_threads.clear()
    yield


def _run_sweep(client: TestClient, repo: str) -> str:
    r = client.post("/sweeps", json={"repo": repo})
    assert r.status_code == 200
    sweep_id = r.json()["sweep_id"]
    import time
    for _ in range(50):
        s = client.get(f"/sweeps/{sweep_id}").json()
        if s["status"] == "finished":
            break
        time.sleep(0.1)
    return sweep_id


def test_paths_endpoint_returns_empty_list_when_no_chains():
    """vuln-bank-api produces exactly one SQLi finding — no agentic,
    no secrets → no chains. Endpoint must return `[]`, not 404."""
    client = TestClient(app)
    sweep_id = _run_sweep(client, "vuln-bank-api")
    r = client.get(f"/paths/{sweep_id}")
    assert r.status_code == 200
    assert r.json() == []


def test_paths_endpoint_404_for_unknown_sweep():
    client = TestClient(app)
    r = client.get("/paths/sw_doesnotexist")
    assert r.status_code == 404


def test_findings_endpoint_includes_exploit_path_field():
    """Every finding row must serialize `exploit_path` — the Console
    depends on the field's presence to decide whether to render the
    chain link. `None` is the correct null value; missing is a bug."""
    client = TestClient(app)
    sweep_id = _run_sweep(client, "vuln-bank-api")
    findings = client.get(f"/sweeps/{sweep_id}/findings").json()
    assert len(findings) >= 1
    for f in findings:
        assert "exploit_path" in f
        # No chain composed in this fixture — must be None.
        assert f["exploit_path"] is None
