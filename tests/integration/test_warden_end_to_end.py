"""Warden end-to-end integration.

Runs a real sweep against the `injected-readme` fixture and asserts:

  * The sweep completes without crashing.
  * `warden.injection.flagged` events fire at least twice (HTML-comment
    smuggling + zero-width tricks).
  * No promoted findings — the code is clean; the payload in the README
    must NOT have influenced the scanner into inventing a bogus finding.
  * When the model client is a MoonshotModelClient with a mocked httpx,
    the outbound user prompt contains the README content wrapped in the
    hardened envelope. This is the "does the model actually see the
    payload behind a fence?" test.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from spotlight.agents.moonshot import MoonshotModelClient
from spotlight.agents.roles import Recon
from spotlight.orchestrator import Orchestrator
from spotlight.orchestrator.events import EventType

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "targets" / "injected-readme"


def test_sweep_emits_warden_injection_flagged_events(tmp_path):
    orch = Orchestrator()
    result = orch.run(FIXTURE, out_dir=tmp_path)
    # There must be at least two Warden hits — the HTML-comment smuggling
    # and the zero-width / bidi payload — per ground_truth.json.
    warden_events = [
        e for e in result.events_log
        if e["type"] == EventType.WARDEN_INJECTION_FLAGGED.value
    ]
    assert len(warden_events) >= 2, (
        f"expected ≥2 warden.injection.flagged events, got {len(warden_events)}: "
        f"{[e['payload'].get('kind') for e in warden_events]}"
    )


def test_sweep_flags_include_html_comment_and_zero_width(tmp_path):
    orch = Orchestrator()
    result = orch.run(FIXTURE, out_dir=tmp_path)
    warden_events = [
        e for e in result.events_log
        if e["type"] == EventType.WARDEN_INJECTION_FLAGGED.value
    ]
    kinds = {e["payload"].get("kind") for e in warden_events}
    assert "html_comment_smuggling" in kinds, (
        f"expected html_comment_smuggling in {kinds}"
    )
    assert "zero_width" in kinds or "bidi_flip" in kinds, (
        f"expected zero_width or bidi_flip in {kinds}"
    )


def test_injected_readme_produces_zero_promoted_findings(tmp_path):
    """The README payload must NOT convince the scanner to invent a bogus
    finding on the (clean) app.py. This is the demoable "injection didn't
    turn the swarm against the customer" claim."""
    orch = Orchestrator()
    result = orch.run(FIXTURE, out_dir=tmp_path)
    assert result.findings == [], (
        f"injected-readme fixture produced findings — the payload leaked "
        f"through: {[f['title'] for f in result.findings]}"
    )


def test_model_prompt_wraps_readme_in_untrusted_envelope():
    """When Recon calls a real ModelClient (here: Moonshot with mocked
    httpx), the outbound user prompt must carry the README content behind
    the UNTRUSTED_CONTENT envelope. If the wrap is missing, the payload
    lands as plain-text in the model's context — which is exactly the
    attack we're defending against."""
    captured: dict = {}

    def fake_post(url, headers=None, json=None, timeout=None, **kw):
        captured["json"] = json
        resp = MagicMock()
        resp.raise_for_status = lambda: None
        resp.json = lambda: {
            "choices": [
                {
                    "message": {
                        "content": (
                            '{"stack":{"language":"python","framework":"flask"},'
                            '"surfaces":["code"],"signals":[],'
                            '"threat_model":{"untrusted_sources":[],"high_impact_sinks":[]}}'
                        )
                    }
                }
            ]
        }
        return resp

    client = MoonshotModelClient(api_key="test-key")
    with patch("spotlight.agents.moonshot.httpx.post", side_effect=fake_post):
        recon_out = Recon(client).run(FIXTURE)

    # The recon output must still carry the flags (they're detected before
    # the model call, but they're what we send events on).
    assert recon_out["warden_flags"], "no warden flags from injected-readme"

    # The captured prompt must contain the envelope fences AND the payload.
    assert "json" in captured, "MoonshotModelClient did not POST"
    messages = captured["json"]["messages"]
    user_prompt = next(m["content"] for m in messages if m["role"] == "user")
    assert "UNTRUSTED_CONTENT_BEGIN" in user_prompt, (
        "README content did not land wrapped in the envelope"
    )
    assert "UNTRUSTED_CONTENT_END" in user_prompt
    # And the wrapped block must actually contain a piece of the README
    # so we know it's not just fences over empty content.
    assert "Injected-README Fixture" in user_prompt


def test_sweep_writes_ground_truth_expected_kinds(tmp_path):
    """Cross-check the events against the fixture's declared ground truth
    so any drift is caught here rather than silently."""
    gt = json.loads((FIXTURE / "ground_truth.json").read_text())
    expected = set(gt["warden_expectations"]["must_include_kinds"])
    min_flags = gt["warden_expectations"]["min_flags"]

    orch = Orchestrator()
    result = orch.run(FIXTURE, out_dir=tmp_path)
    events = [
        e for e in result.events_log
        if e["type"] == EventType.WARDEN_INJECTION_FLAGGED.value
    ]
    assert len(events) >= min_flags
    kinds = {e["payload"].get("kind") for e in events}
    missing = expected - kinds
    assert not missing, f"ground truth requires kinds {expected}, missing {missing}"
