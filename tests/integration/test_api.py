"""FastAPI contract tests."""
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from spotlight.api.app import app, BUSES, SWEEPS, _running_threads

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _clear_registries():
    BUSES.clear()
    SWEEPS.clear()
    _running_threads.clear()
    yield


def test_healthz():
    client = TestClient(app)
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"ok": True, "service": "spotlight-api"}


def test_list_targets_includes_fixtures():
    client = TestClient(app)
    r = client.get("/targets")
    assert r.status_code == 200
    names = {t["name"] for t in r.json()}
    assert "vuln-bank-api" in names
    assert "clean-bank-api" in names


def test_full_sweep_via_api():
    client = TestClient(app)
    r = client.post("/sweeps", json={"repo": "vuln-bank-api"})
    assert r.status_code == 200
    sweep_id = r.json()["sweep_id"]
    # Poll for completion.
    import time
    for _ in range(50):
        s = client.get(f"/sweeps/{sweep_id}").json()
        if s["status"] == "finished":
            break
        time.sleep(0.1)
    assert s["status"] == "finished"
    assert s["findings_count"] == 1

    findings = client.get(f"/sweeps/{sweep_id}/findings").json()
    assert findings[0]["tier"] == "verified"
    assert findings[0]["state"] == "confirmed-fixed"

    att = client.get(f"/attestations/{sweep_id}").json()
    assert att["sweep_id"] == sweep_id
    assert len(att["findings"]) == 1

    events = client.get(f"/sweeps/{sweep_id}/events").json()
    types = {e["type"] for e in events}
    assert "sweep.started" in types
    assert "attestation.written" in types


def test_clean_sweep_via_api_produces_zero_findings():
    client = TestClient(app)
    r = client.post("/sweeps", json={"repo": "clean-bank-api"})
    sweep_id = r.json()["sweep_id"]
    import time
    for _ in range(50):
        s = client.get(f"/sweeps/{sweep_id}").json()
        if s["status"] == "finished":
            break
        time.sleep(0.1)
    findings = client.get(f"/sweeps/{sweep_id}/findings").json()
    assert findings == []


def test_websocket_streams_events():
    client = TestClient(app)
    r = client.post("/sweeps", json={"repo": "vuln-bank-api"})
    sweep_id = r.json()["sweep_id"]
    received: list[dict] = []
    with client.websocket_connect(f"/ws/sweeps/{sweep_id}") as ws:
        try:
            while True:
                msg = ws.receive_json()
                received.append(msg)
                if msg.get("type") == "sweep.finished":
                    break
        except Exception:
            pass
    types = {e.get("type") for e in received}
    assert "sweep.started" in types
    assert "attestation.written" in types
    assert "sweep.finished" in types


def test_finding_lookup_by_id():
    client = TestClient(app)
    r = client.post("/sweeps", json={"repo": "vuln-bank-api"})
    sweep_id = r.json()["sweep_id"]
    import time
    for _ in range(50):
        s = client.get(f"/sweeps/{sweep_id}").json()
        if s["status"] == "finished":
            break
        time.sleep(0.1)
    findings = client.get(f"/sweeps/{sweep_id}/findings").json()
    fid = findings[0]["id"]
    f = client.get(f"/findings/{fid}").json()
    assert f["id"] == fid
    assert f["cwe"] == "CWE-89"
