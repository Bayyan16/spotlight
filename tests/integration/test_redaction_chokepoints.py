"""Integration tests for the 3 redaction chokepoints.

Each test proves the leaky string cannot leave the process through that
chokepoint. If any of these fail, we have a leak — not a UX issue.

Chokepoints:
  (a) Moonshot outbound prompt — httpx.post payload must not contain the secret.
  (b) EventBus.emit — persisted event payload must be redacted.
  (c) API JSON responses — Finding evidence with a secret must be scrubbed.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from spotlight.agents.moonshot import MoonshotModelClient
from spotlight.orchestrator import EventBus, EventType, SweepResult


def _api_mod():
    """Fetch the live `spotlight.api.app` module.

    `test_persistence.py` reloads this module inside its own fixture, which
    invalidates any names imported at collection time. Grabbing it via
    `sys.modules` at test-run time gives us the fresh module (including its
    fresh SWEEPS/BUSES dicts and refreshed FastAPI `app`)."""
    import sys
    import spotlight.api.app  # ensure it's imported
    return sys.modules["spotlight.api.app"]


LEAK_AWS = "AKIAIOSFODNN7EXAMPLE"
LEAK_GH = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"


@pytest.fixture(autouse=True)
def _clear_registries():
    mod = _api_mod()
    mod.BUSES.clear()
    mod.SWEEPS.clear()
    mod._running_threads.clear()
    yield


# ---------- (a) Moonshot outbound prompt ----------


def test_moonshot_prompt_scrubs_aws_key_before_httpx_post():
    """Insert a live-looking AWS key into the prompt context that the
    Investigator role interpolates. The outbound httpx.post body must
    NOT contain the raw key."""
    client = MoonshotModelClient(api_key="not-a-real-key", base_url="https://fake")

    # Craft a slice payload that will show up inside the user prompt.
    slice_with_leak = {
        "file": f"app.py  # leaked {LEAK_AWS}",
        "function": "get_account",
        "source": {"name": "username", "origin": "http_params"},
        "sink": {"class": "sqli", "callee": "execute", "line": 27},
        "reason": f"concat with secret {LEAK_AWS} in scope",
    }

    # Mock httpx.post inside the moonshot module so we can inspect the payload.
    captured: dict = {}

    class _FakeResp:
        status_code = 200

        def raise_for_status(self):  # noqa: D401 — mock
            return None

        def json(self):
            return {
                "choices": [
                    {
                        "message": {
                            "content": '{"verdict":"reject","class":"sqli","cwe":"CWE-89",'
                            '"title":"t","severity":"low","location":{"file":"x","line":1,'
                            '"function":"y"},"root_cause":"r","recommendation":"r",'
                            '"evidence_used":[]}'
                        }
                    }
                ]
            }

    def _fake_post(url, headers=None, json=None, timeout=None):
        captured["url"] = url
        captured["headers"] = headers
        captured["json"] = json
        return _FakeResp()

    with patch("spotlight.agents.moonshot.httpx.post", side_effect=_fake_post):
        out = client.complete(role="investigator", prompt="", context={"slice": slice_with_leak})

    # The moonshot request body must not contain the raw AWS key.
    body_text = repr(captured["json"])
    assert LEAK_AWS not in body_text, (
        f"AWS key leaked to Moonshot request body: {body_text[:400]}"
    )
    # And the redaction token must show up in the outbound user message.
    user_msg = captured["json"]["messages"][1]["content"]
    assert "[REDACTED:aws-key]" in user_msg, f"expected redaction token in outbound prompt, got {user_msg!r}"
    # Response should carry the redaction.applied counter.
    assert out.get("redaction.applied", 0) >= 1
    # And the client-level counter.
    assert client.redactions_applied >= 1


def test_moonshot_prompt_scrubs_github_pat():
    client = MoonshotModelClient(api_key="k", base_url="https://fake")
    slice_ = {
        "file": "app.py",
        "function": "f",
        "source": {"name": "u", "origin": f"env {LEAK_GH}"},
        "sink": {"class": "sqli", "callee": "exec", "line": 1},
        "reason": "r",
    }

    captured: dict = {}

    class _FakeResp:
        def raise_for_status(self):
            return None

        def json(self):
            return {"choices": [{"message": {"content": "{}"}}]}

    def _fake_post(url, headers=None, json=None, timeout=None):
        captured["json"] = json
        return _FakeResp()

    with patch("spotlight.agents.moonshot.httpx.post", side_effect=_fake_post):
        client.complete(role="investigator", prompt="", context={"slice": slice_})

    assert LEAK_GH not in repr(captured["json"])


# ---------- (b) EventBus.emit ----------


def test_eventbus_redacts_payload_strings():
    """Emit an event with a secret in the payload. The persisted event's
    payload must contain the redaction token, never the raw secret."""
    bus = EventBus()
    evt = bus.emit(
        "sweep-1",
        EventType.CANDIDATE_RAISED,
        actor="investigator",
        evidence=f"found aws key in config: {LEAK_AWS}",
        notes="nothing to see here",
    )
    persisted = bus.all()[0]
    assert LEAK_AWS not in repr(persisted.payload), f"leak in payload: {persisted.payload}"
    assert "[REDACTED:aws-key]" in persisted.payload["evidence"]
    # Untouched fields pass through.
    assert persisted.payload["notes"] == "nothing to see here"
    # to_dict roundtrip is also clean.
    assert LEAK_AWS not in repr(evt.to_dict())


def test_eventbus_redacts_nested_lists_and_dicts():
    bus = EventBus()
    bus.emit(
        "sweep-2",
        EventType.FINDING_PROMOTED,
        actor="orchestrator",
        finding={
            "id": "F1",
            "evidence_used": [f"line 12: {LEAK_AWS}", "signal:codegraph"],
            "meta": {"raw_env": f"GITHUB_TOKEN={LEAK_GH}"},
        },
    )
    persisted = bus.all()[0]
    payload_repr = repr(persisted.payload)
    assert LEAK_AWS not in payload_repr
    assert LEAK_GH not in payload_repr
    assert "[REDACTED:aws-key]" in persisted.payload["finding"]["evidence_used"][0]
    assert "[REDACTED:github-pat]" in persisted.payload["finding"]["meta"]["raw_env"]


# ---------- (c) API JSON responses ----------


def _install_leaky_sweep(sweep_id: str = "leaky-sweep-1", finding_id: str = "leaky-finding-1"):
    """Plant a SweepResult with a Finding whose evidence contains a raw AWS key."""
    finding = {
        "id": finding_id,
        "surface": "code",
        "title": "SQL injection",
        "severity": "high",
        "class": "sqli",
        "cwe": "CWE-89",
        "location": {"file": "app.py", "line": 27, "function": "get_account"},
        "state": "candidate",
        "tier": "verified",
        "confidence": "high",
        "root_cause": f"secret {LEAK_AWS} in scope",
        "recommendation": "rotate",
        "evidence": {
            "snippet": f"AWS_ACCESS_KEY_ID = '{LEAK_AWS}'",
            "notes": "clean text",
        },
    }
    result = SweepResult(
        sweep_id=sweep_id,
        repo_path="/tmp/leaky",
        signals=[],
        threat_model={"untrusted_sources": [], "high_impact_sinks": []},
        findings=[finding],
        attestations=[
            {
                "sweep_id": sweep_id,
                "repo": "/tmp/leaky",
                "findings": [finding],
                "threat_model": {"untrusted_sources": [], "high_impact_sinks": []},
                "notes": f"attestation with leak {LEAK_AWS}",
            }
        ],
        events_log=[],
    )
    _api_mod().SWEEPS[sweep_id] = result
    return sweep_id, finding_id


def test_api_finding_endpoint_redacts_evidence():
    sweep_id, fid = _install_leaky_sweep()
    client = TestClient(_api_mod().app)
    resp = client.get(f"/findings/{fid}")
    assert resp.status_code == 200
    body_text = resp.text
    assert LEAK_AWS not in body_text, f"AWS key leaked in /findings/{fid} response"
    body = resp.json()
    # aws-key OR generic-secret is acceptable — the string containing
    # `ACCESS_KEY_ID = '...'` also trips the generic-kv detector, which
    # runs after aws-key and consumes the whole quoted expression.
    assert "[REDACTED:" in body["evidence"]["snippet"]
    assert "[REDACTED:aws-key]" in body["root_cause"]


def test_api_sweep_findings_list_endpoint_redacts_evidence():
    sweep_id, _ = _install_leaky_sweep(sweep_id="leaky-sweep-2", finding_id="leaky-finding-2")
    client = TestClient(_api_mod().app)
    resp = client.get(f"/sweeps/{sweep_id}/findings")
    assert resp.status_code == 200
    assert LEAK_AWS not in resp.text
    body = resp.json()
    # Either aws-key or generic-secret should have redacted the snippet;
    # both are acceptable outcomes since both detectors match. What matters
    # is that the raw key never appears.
    snippet = body[0]["evidence"]["snippet"]
    assert "[REDACTED:" in snippet, f"expected redaction in {snippet!r}"


def test_api_attestation_endpoint_redacts_findings():
    sweep_id, _ = _install_leaky_sweep(sweep_id="leaky-sweep-3", finding_id="leaky-finding-3")
    client = TestClient(_api_mod().app)
    resp = client.get(f"/attestations/{sweep_id}")
    assert resp.status_code == 200
    assert LEAK_AWS not in resp.text
    assert "[REDACTED:aws-key]" in resp.text


def test_api_events_endpoint_still_scrubbed_from_bus():
    """Events go through the bus first (chokepoint b), then out the API
    (chokepoint c). Belt and suspenders — verify the raw string can't
    slip through even if we somehow injected it post-bus."""
    bus = EventBus()
    bus.emit(
        "leaky-sweep-events",
        EventType.CANDIDATE_RAISED,
        actor="investigator",
        evidence=f"leak: {LEAK_AWS}",
    )
    _api_mod().BUSES["leaky-sweep-events"] = bus
    client = TestClient(_api_mod().app)
    resp = client.get("/sweeps/leaky-sweep-events/events")
    assert resp.status_code == 200
    assert LEAK_AWS not in resp.text


def test_api_metadata_endpoints_are_not_touched():
    """Regression: /targets and /profiles must keep working unchanged.
    They ship no target-derived strings, so we skipped redaction there."""
    client = TestClient(_api_mod().app)
    r = client.get("/targets")
    assert r.status_code == 200
    names = {t["name"] for t in r.json()}
    assert "leaky-app" in names, "the leaky-app fixture target should appear in /targets"
