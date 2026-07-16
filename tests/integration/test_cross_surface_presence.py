"""Cross-surface presence — Tranche B7.

The bank-security wedge (docs/BANK_FEEDBACK_2026-07-16.md): every scanner
answers "what did you find in *this* repo?", but nobody answers "is this
same vulnerability class also reachable in my OTHER repos?" The
`GET /findings/{id}/presence` endpoint is Spotlight's answer.

These tests run *two* sweeps — one on `vuln-bank-api` (Python SQLi) and one
on `vuln-node-api` (JavaScript SQLi) — and verify that the presence lookup
correctly correlates the same *class* (`sqli`) across sweep boundaries.
They exercise the actual endpoint via TestClient rather than the DB query
directly, so a regression in grouping, filtering, or response shape gets
caught end-to-end.

Uses `SPOTLIGHT_SANDBOX=subprocess` so no Modal/container spin-up.
"""
from __future__ import annotations

import os
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("SPOTLIGHT_SANDBOX", "subprocess")

from spotlight.api.app import BUSES, SWEEPS, _running_threads, app  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _clear_registries():
    BUSES.clear()
    SWEEPS.clear()
    _running_threads.clear()
    yield


def _run_sweep_to_completion(client: TestClient, repo: str) -> str:
    r = client.post("/sweeps", json={"repo": repo})
    assert r.status_code == 200, r.text
    sweep_id = r.json()["sweep_id"]
    # Poll for the sweep worker thread to finish.
    for _ in range(200):
        s = client.get(f"/sweeps/{sweep_id}").json()
        if s.get("status") == "finished":
            return sweep_id
        time.sleep(0.05)
    pytest.fail(f"sweep {sweep_id} on {repo} never finished")


def _first_finding(client: TestClient, sweep_id: str) -> dict:
    findings = client.get(f"/sweeps/{sweep_id}/findings").json()
    assert findings, f"sweep {sweep_id} produced zero findings"
    return findings[0]


def test_presence_matches_same_class_across_sweeps():
    """SQLi in vuln-bank-api should be discoverable in vuln-node-api via
    the presence endpoint. Both fixtures ship a single SQLi finding."""
    client = TestClient(app)

    bank_sweep = _run_sweep_to_completion(client, "vuln-bank-api")
    node_sweep = _run_sweep_to_completion(client, "vuln-node-api")

    bank_finding = _first_finding(client, bank_sweep)
    assert bank_finding["class"] == "sqli"

    r = client.get(f"/findings/{bank_finding['id']}/presence")
    assert r.status_code == 200, r.text
    body = r.json()

    # Response contract.
    assert body["class"] == "sqli"
    assert body["cwe"] == "CWE-89"
    assert body["self"]["sweep_id"] == bank_sweep
    assert body["self"]["repo_name"] == "vuln-bank-api"
    assert body["self"]["finding_id"] == bank_finding["id"]

    # Should find the SQLi in vuln-node-api and *not* count itself.
    assert body["presence_count"] == 1
    assert len(body["matches"]) == 1
    match = body["matches"][0]
    assert match["repo_name"] == "vuln-node-api"
    assert match["sweep_id"] == node_sweep
    assert match["sweep_id"] != bank_sweep
    # Match carries file/line so the panel can render the "where" cell.
    assert isinstance(match["file"], str) and match["file"]
    assert isinstance(match["line"], int)
    assert match["tier"] in {"verified", "high-confidence", "needs-review", "held"}
    assert match["state"]


def test_presence_zero_when_class_has_no_cross_surface_matches():
    """If only one sweep in the workspace has a SQLi finding, the presence
    lookup for that finding must return presence_count == 0 (no matches
    outside its own sweep)."""
    client = TestClient(app)

    bank_sweep = _run_sweep_to_completion(client, "vuln-bank-api")
    bank_finding = _first_finding(client, bank_sweep)

    r = client.get(f"/findings/{bank_finding['id']}/presence")
    assert r.status_code == 200, r.text
    body = r.json()

    assert body["class"] == "sqli"
    assert body["self"]["sweep_id"] == bank_sweep
    assert body["presence_count"] == 0
    assert body["matches"] == []


def test_presence_404_for_unknown_finding():
    client = TestClient(app)
    r = client.get("/findings/SPOT-DOES-NOT-EXIST/presence")
    assert r.status_code == 404
