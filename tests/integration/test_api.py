"""FastAPI contract tests."""
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from spotlight.api.app import app, BUSES, SWEEPS, _running_threads

ROOT = Path(__file__).resolve().parents[2]

# A sweep runs the full pipeline on a worker thread. The old 5-second poll
# budget was only ever enough because the machine was fast; on a loaded CI
# runner it turned "the sweep is slow" into "the API is broken". Wait long
# enough for the answer to mean something, and fail with the last status we
# saw rather than a bare KeyError on the next line.
SWEEP_TIMEOUT_S = 120.0


def _wait_for_sweep(client: TestClient, sweep_id: str, timeout_s: float = SWEEP_TIMEOUT_S) -> dict:
    """Poll until the sweep finishes, or fail with what it was doing."""
    deadline = time.monotonic() + timeout_s
    status: dict = {}
    while time.monotonic() < deadline:
        status = client.get(f"/sweeps/{sweep_id}").json()
        if status.get("status") in {"finished", "failed", "error"}:
            return status
        time.sleep(0.1)
    raise AssertionError(
        f"sweep {sweep_id} did not finish within {timeout_s}s; last status: {status}"
    )


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
    body = r.json()
    assert body["ok"] is True
    assert body["service"] == "spotlight-api"
    assert body["storage"] in {"memory", "postgres"}


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
    s = _wait_for_sweep(client, sweep_id)
    assert s["status"] == "finished"
    # The sqli in this fixture is the finding under test. Pick it out by
    # CWE rather than by index: with Semgrep switched on (see the
    # _no_semgrep_registry fixture) the external signals add findings of
    # their own, and which one lands at index 0 depends on the rulepack.
    assert s["findings_count"] >= 1
    findings = client.get(f"/sweeps/{sweep_id}/findings").json()
    sqli = [f for f in findings if f["cwe"] == "CWE-89"]
    assert sqli, f"no CWE-89 finding in {[f['cwe'] for f in findings]}"
    assert sqli[0]["tier"] == "verified"
    assert sqli[0]["state"] == "confirmed-fixed"

    att = client.get(f"/attestations/{sweep_id}").json()
    assert att["sweep_id"] == sweep_id
    assert len(att["findings"]) == len(findings)

    events = client.get(f"/sweeps/{sweep_id}/events").json()
    types = {e["type"] for e in events}
    assert "sweep.started" in types
    assert "attestation.written" in types


def test_clean_sweep_via_api_produces_zero_findings():
    client = TestClient(app)
    r = client.post("/sweeps", json={"repo": "clean-bank-api"})
    sweep_id = r.json()["sweep_id"]
    assert _wait_for_sweep(client, sweep_id)["status"] == "finished"
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
    assert _wait_for_sweep(client, sweep_id)["status"] == "finished"
    findings = client.get(f"/sweeps/{sweep_id}/findings").json()
    sqli = [f for f in findings if f["cwe"] == "CWE-89"]
    assert sqli, f"no CWE-89 finding in {[f['cwe'] for f in findings]}"
    fid = sqli[0]["id"]
    f = client.get(f"/findings/{fid}").json()
    assert f["id"] == fid
    assert f["cwe"] == "CWE-89"
