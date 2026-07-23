"""C6 · Delta view between two sweeps.

Fingerprint = (class, file, function). Two sweeps produce three arrays:
    new         — in current, not in previous
    resolved    — in previous, not in current
    still_open  — in both, and not analyst-suppressed

These tests build synthetic SweepResults directly in the API's in-memory
cache so we don't have to run two full sweeps.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest
from fastapi.testclient import TestClient


@dataclass
class _StubSweep:
    sweep_id: str
    findings: list[dict[str, Any]] = field(default_factory=list)


@pytest.fixture
def client():
    from spotlight.api.app import app

    return TestClient(app)


def _f(id_: str, cls: str, file: str, fn: str, *, review_state: str | None = None) -> dict:
    payload = {
        "id": id_,
        "class": cls,
        "severity": "high",
        "tier": "verified",
        "title": f"{cls} in {fn}",
        "location": {"file": file, "line": 42, "function": fn},
    }
    if review_state:
        payload["review"] = {"state": review_state, "reason": "n/a", "reviewer": "analyst", "ts": ""}
    return payload


@pytest.fixture
def two_sweeps():
    """Seed two synthetic sweeps into the in-memory cache with overlapping,
    new, and resolved findings — plus one review-suppressed still-open."""
    from spotlight.api.app import SWEEPS

    prev = _StubSweep(
        sweep_id="sw_prev",
        findings=[
            _f("SPOT-A", "sqli", "app.py", "get_account"),
            _f("SPOT-B", "cmdi", "app.py", "handle"),
            _f("SPOT-C", "ssrf", "app.py", "fetch"),  # will be resolved
        ],
    )
    curr = _StubSweep(
        sweep_id="sw_curr",
        findings=[
            _f("SPOT-A", "sqli", "app.py", "get_account"),  # still open
            _f("SPOT-B", "cmdi", "app.py", "handle", review_state="false-positive"),
            _f("SPOT-D", "prompt-injection", "app.py", "chat"),  # new
        ],
    )
    SWEEPS["sw_prev"] = prev
    SWEEPS["sw_curr"] = curr
    yield "sw_curr", "sw_prev"
    del SWEEPS["sw_prev"]
    del SWEEPS["sw_curr"]


def test_delta_new_resolved_still_open(client, two_sweeps):
    curr_id, prev_id = two_sweeps
    r = client.get(f"/sweeps/{curr_id}/delta?since={prev_id}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["counts"]["new"] == 1
    assert body["counts"]["resolved"] == 1
    # SPOT-B is still in curr but marked false-positive → excluded from still_open.
    assert body["counts"]["still_open"] == 1
    new_classes = {x["class"] for x in body["new"]}
    resolved_classes = {x["class"] for x in body["resolved"]}
    still_classes = {x["class"] for x in body["still_open"]}
    assert new_classes == {"prompt-injection"}
    assert resolved_classes == {"ssrf"}
    assert still_classes == {"sqli"}


def test_delta_missing_curr_returns_404(client, two_sweeps):
    _, prev_id = two_sweeps
    r = client.get(f"/sweeps/unknown/delta?since={prev_id}")
    assert r.status_code == 404
    assert "unknown" in r.text


def test_delta_missing_prev_returns_404(client, two_sweeps):
    curr_id, _ = two_sweeps
    r = client.get(f"/sweeps/{curr_id}/delta?since=nope")
    assert r.status_code == 404
    assert "nope" in r.text


def test_delta_identical_sweeps(client):
    """Same sweep on both sides → new = resolved = 0, still_open matches
    non-suppressed count."""
    from spotlight.api.app import SWEEPS

    stub = _StubSweep(
        sweep_id="sw_same",
        findings=[
            _f("SPOT-A", "sqli", "app.py", "f1"),
            _f("SPOT-B", "cmdi", "app.py", "f2"),
        ],
    )
    SWEEPS["sw_same"] = stub
    try:
        r = client.get("/sweeps/sw_same/delta?since=sw_same")
        assert r.status_code == 200
        body = r.json()
        assert body["counts"] == {"new": 0, "resolved": 0, "still_open": 2}
    finally:
        del SWEEPS["sw_same"]


def test_delta_ignores_ephemeral_checkout_prefix(client):
    from spotlight.api.app import SWEEPS

    previous = _StubSweep(
        sweep_id="sw_old_checkout",
        findings=[_f("SPOT-OLD", "eval", "/tmp/spotlight-clone-one/src/pkg/run.py", "run")],
    )
    current = _StubSweep(
        sweep_id="sw_new_checkout",
        findings=[_f("SPOT-NEW", "eval", "/private/tmp/spotlight-clone-two/src/pkg/run.py", "run")],
    )
    SWEEPS[previous.sweep_id] = previous
    SWEEPS[current.sweep_id] = current
    try:
        response = client.get(
            f"/sweeps/{current.sweep_id}/delta?since={previous.sweep_id}"
        )
        assert response.status_code == 200
        assert response.json()["counts"] == {
            "new": 0,
            "resolved": 0,
            "still_open": 1,
        }
    finally:
        del SWEEPS[previous.sweep_id]
        del SWEEPS[current.sweep_id]
