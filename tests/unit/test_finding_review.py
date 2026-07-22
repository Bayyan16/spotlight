"""C4 — Per-finding analyst review endpoint.

A review is a first-class signed action on the finding's chain of custody.
State changes are terminal (no un-accept); to reverse, submit a new review.

These tests pin the endpoint contract + invariants:
  * three canonical actions accepted; anything else 400
  * reason required
  * `risk-accept-until` requires an ISO `until` date
  * successful review appends a signed entry (actor_kind="human")
  * signature verifies against the workspace public key
  * finding.review.state updates to the matching label
  * chain-of-custody grows by exactly one entry per review
  * missing finding → 404
"""
from __future__ import annotations

import base64
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def deterministic_workspace_key(monkeypatch):
    priv = Ed25519PrivateKey.generate()
    raw = priv.private_bytes_raw()
    monkeypatch.setenv("SPOTLIGHT_SIGNING_KEY", base64.b64encode(raw).decode("ascii"))


@pytest.fixture
def client():
    # Import inside fixture so monkeypatch of the env var is applied before
    # the module-level Signer initializes.
    from spotlight.api.app import app

    return TestClient(app)


@pytest.fixture
def sweep_with_findings(client):
    """Seed a real sweep against the acme-bank fixture so the endpoint has
    something to review. Uses the app's own POST /sweeps to stay close to
    production behavior."""
    # Intake accepts fixture *names* (validated by _FIXTURE_NAME), not paths.
    # The API resolves the name against `targets_root`; sending a slash-bearing
    # value hits the hardened rejection path in spotlight.api.intake.
    resp = client.post("/sweeps", json={"repo": "acme-bank"})
    assert resp.status_code == 200, resp.text
    sweep_id = resp.json()["sweep_id"]
    import time

    # Sweep runs in a background thread — poll findings until at least one
    # lands. The acme-bank sweep produces ~9 findings in <10s.
    for _ in range(60):
        r = client.get(f"/sweeps/{sweep_id}/findings")
        if r.status_code == 200 and len(r.json()) > 0:
            return sweep_id, r.json()
        time.sleep(0.5)
    raise RuntimeError("sweep produced no findings after polling")


def test_accept_review_appends_signed_entry(client, sweep_with_findings):
    _, findings = sweep_with_findings
    fid = findings[0]["id"]

    r = client.get(f"/findings/{fid}")
    assert r.status_code == 200
    coc_before = len((r.json().get("audit") or {}).get("chain_of_custody") or [])

    r = client.post(
        f"/findings/{fid}/review",
        json={"action": "accept", "reason": "Verified with product manager"},
    )
    assert r.status_code == 200, r.text
    finding = r.json()
    assert finding["review"]["state"] == "accepted"
    coc_after = len((finding.get("audit") or {}).get("chain_of_custody") or [])
    assert coc_after == coc_before + 1
    last_entry = finding["audit"]["chain_of_custody"][-1]
    assert last_entry["actor_kind"] == "human"
    assert last_entry["action"] == "review.accept"
    assert last_entry["signature"]
    assert last_entry["key_fingerprint"]


def test_false_positive_updates_state(client, sweep_with_findings):
    _, findings = sweep_with_findings
    fid = findings[1]["id"] if len(findings) > 1 else findings[0]["id"]
    r = client.post(
        f"/findings/{fid}/review",
        json={"action": "false-positive", "reason": "guarded by upstream WAF rule"},
    )
    assert r.status_code == 200
    assert r.json()["review"]["state"] == "false-positive"


def test_risk_accept_requires_until(client, sweep_with_findings):
    _, findings = sweep_with_findings
    fid = findings[0]["id"]
    r = client.post(
        f"/findings/{fid}/review",
        json={"action": "risk-accept-until", "reason": "planned Q3 fix"},
    )
    assert r.status_code == 400
    r = client.post(
        f"/findings/{fid}/review",
        json={
            "action": "risk-accept-until",
            "reason": "planned Q3 fix",
            "until": "2026-09-30",
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["review"]["state"] == "risk-accepted"
    assert body["review"]["until"] == "2026-09-30"


def test_unknown_action_rejected(client, sweep_with_findings):
    _, findings = sweep_with_findings
    fid = findings[0]["id"]
    r = client.post(
        f"/findings/{fid}/review",
        json={"action": "vibe-check", "reason": "eh"},
    )
    assert r.status_code == 400


def test_missing_reason_rejected(client, sweep_with_findings):
    _, findings = sweep_with_findings
    fid = findings[0]["id"]
    r = client.post(f"/findings/{fid}/review", json={"action": "accept", "reason": "  "})
    assert r.status_code == 400


def test_review_signature_verifies_against_workspace_key(client, sweep_with_findings):
    from spotlight.non_repudiation import Signer, verify_action

    _, findings = sweep_with_findings
    fid = findings[0]["id"]
    r = client.post(
        f"/findings/{fid}/review",
        json={"action": "accept", "reason": "verified"},
    )
    entry = r.json()["audit"]["chain_of_custody"][-1]
    assert verify_action(entry, Signer().public_key)


def test_missing_finding_returns_404(client):
    r = client.post(
        "/findings/DOES-NOT-EXIST/review",
        json={"action": "accept", "reason": "n/a"},
    )
    assert r.status_code == 404


def test_multiple_reviews_are_terminal(client, sweep_with_findings):
    """State changes are additive — every review appends a new entry, but
    the visible review.state reflects the latest."""
    _, findings = sweep_with_findings
    fid = findings[0]["id"]

    r1 = client.post(
        f"/findings/{fid}/review",
        json={"action": "accept", "reason": "first pass"},
    )
    coc1 = len(r1.json()["audit"]["chain_of_custody"])

    r2 = client.post(
        f"/findings/{fid}/review",
        json={"action": "false-positive", "reason": "reconsidered"},
    )
    assert r2.json()["review"]["state"] == "false-positive"
    coc2 = len(r2.json()["audit"]["chain_of_custody"])
    assert coc2 == coc1 + 1
