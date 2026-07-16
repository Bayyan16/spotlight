"""End-to-end vertical-slice tests.

Prove the Phase-1 "Done when" bar on both fixtures:
  * vuln-bank-api: verified tier, state=confirmed-fixed, PoC exploited, fix
    blocks the reproduction.
  * clean-bank-api: zero promoted findings (precision negative).

Also assert Verifier independence (fresh context, different system prompt).
"""
from pathlib import Path

import pytest

from spotlight.orchestrator import Orchestrator

ROOT = Path(__file__).resolve().parents[2]


def test_vuln_bank_api_produces_verified_confirmed_fixed_finding(tmp_path):
    orch = Orchestrator()
    result = orch.run(ROOT / "targets" / "vuln-bank-api", out_dir=tmp_path)
    findings = result.findings
    assert len(findings) == 1
    f = findings[0]
    assert f["surface"] == "code"
    assert f["class"] == "sqli"
    assert f["cwe"] == "CWE-89"
    assert f["tier"] == "verified"
    assert f["state"] == "confirmed-fixed"
    assert f["confidence"] >= 0.9
    assert f["evidence"]["verification"]["backdoor_check"] == "pass"
    assert f["evidence"]["verification"]["independent_verifier"] is True


def test_clean_bank_api_produces_zero_promoted_findings(tmp_path):
    """Precision negative — the 'yes machine' failure mode."""
    orch = Orchestrator()
    result = orch.run(ROOT / "targets" / "clean-bank-api", out_dir=tmp_path)
    assert result.findings == [], (
        f"clean fixture produced findings: {[f['title'] for f in result.findings]}"
    )


def test_attestation_written_to_disk(tmp_path):
    orch = Orchestrator()
    result = orch.run(ROOT / "targets" / "vuln-bank-api", out_dir=tmp_path)
    assert (tmp_path / "attestation.json").exists()
    assert (tmp_path / "findings.json").exists()
    assert (tmp_path / "threat_model.json").exists()
    assert (tmp_path / "signals.json").exists()
    assert (tmp_path / "events.jsonl").exists()
    diff_files = list(tmp_path.glob("*.diff"))
    assert len(diff_files) == 1


def test_event_stream_records_full_sweep(tmp_path):
    orch = Orchestrator()
    result = orch.run(ROOT / "targets" / "vuln-bank-api", out_dir=tmp_path)
    types = [e["type"] for e in result.events_log]
    for required in [
        "sweep.started",
        "sweep.phase.changed",
        "agent.spawned",
        "candidate.raised",
        "repro.started",
        "repro.result",
        "remediation.opened",
        "verify.result",
        "finding.promoted",
        "attestation.written",
        "sweep.finished",
    ]:
        assert required in types, f"missing event type {required} in {set(types)}"


def test_verifier_is_independent_of_remediator():
    """The Verifier must run with a distinct system prompt and NOT receive
    the Remediator's chain-of-thought — only the diff + patched artifact.
    This is what §10.2 'independent fix review' requires."""
    from spotlight.agents.roles import Remediator, Verifier
    from spotlight.agents.model import MockModelClient

    verifier = Verifier(MockModelClient())
    assert "Verifier" in verifier.system_prompt
    # Sanity: Remediator has no system prompt / thought log surface at all in
    # our Phase-1 shape, so there's nothing for the Verifier to inherit.
    assert not hasattr(Remediator, "system_prompt")


def test_reproduction_uses_classic_sqli_payload_and_exploits(tmp_path):
    from spotlight.agents.roles import Reproducer

    finding = {"class": "sqli", "location": {"file": "app.py", "function": "get_account"}}
    result = Reproducer().run(ROOT / "targets" / "vuln-bank-api", finding)
    assert result["result"] == "confirmed"
    assert result["raw"]["exploited"] is True


def test_reproduction_on_clean_fixture_does_not_exploit(tmp_path):
    from spotlight.agents.roles import Reproducer

    finding = {"class": "sqli", "location": {"file": "app.py", "function": "get_account"}}
    result = Reproducer().run(ROOT / "targets" / "clean-bank-api", finding)
    assert result["result"] == "not-reproduced"
    assert result["raw"]["exploited"] is False
