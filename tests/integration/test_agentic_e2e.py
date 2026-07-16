"""End-to-end Agentic Sweep integration tests.

Runs a full Orchestrator sweep over the vuln-langchain-agent fixture and
asserts:

  * At least one promoted finding carries `surface="agentic"`.
  * Its `owasp_llm` is one of LLM01/LLM05/LLM06 — the three classes the
    seeded fixture plants.
  * The `cog-*` worker events show the agentic fan-out ran, distinct from
    `inv-*` classic-Investigator workers.
  * The clean-langchain-agent fixture produces zero agentic findings.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from spotlight.orchestrator import Orchestrator

ROOT = Path(__file__).resolve().parents[2]
VULN = ROOT / "targets" / "vuln-langchain-agent"
CLEAN = ROOT / "targets" / "clean-langchain-agent"


def test_vuln_langchain_agent_produces_agentic_finding(tmp_path):
    orch = Orchestrator()
    result = orch.run(VULN, out_dir=tmp_path)
    agentic = [f for f in result.findings if f.get("surface") == "agentic"]
    assert agentic, (
        "expected at least one promoted agentic finding — got: "
        + str([{"surface": f.get("surface"), "class": f.get("class")}
               for f in result.findings])
    )
    codes = {f.get("owasp_llm") for f in agentic}
    assert codes & {"LLM01", "LLM05", "LLM06"}, (
        f"expected LLM01/05/06 in {codes}"
    )


def test_vuln_langchain_agent_spawns_cog_workers(tmp_path):
    orch = Orchestrator()
    result = orch.run(VULN, out_dir=tmp_path)
    workers = {
        e["payload"].get("worker") for e in result.events_log
        if e["type"] in ("agent.spawned", "agent.finished")
        and e["payload"].get("worker")
    }
    cog_workers = {w for w in workers if isinstance(w, str) and w.startswith("cog-")}
    assert cog_workers, (
        f"expected at least one cog-* worker in {sorted(w for w in workers if w)}"
    )


def test_clean_langchain_agent_produces_zero_agentic_findings(tmp_path):
    orch = Orchestrator()
    result = orch.run(CLEAN, out_dir=tmp_path)
    agentic = [f for f in result.findings if f.get("surface") == "agentic"]
    assert agentic == [], f"clean fixture leaked agentic findings: {agentic}"


def test_recon_output_carries_agentic_signals(tmp_path):
    """The Agentic Sweep runs inside Recon; its output must land on
    `agentic_signals` so the orchestrator's fan-out can consume it."""
    from spotlight.agents import Recon
    from spotlight.agents.model import MockModelClient

    recon_out = Recon(MockModelClient()).run(VULN)
    assert "agentic_signals" in recon_out
    assert isinstance(recon_out["agentic_signals"], list)
    assert recon_out["agentic_signals"], (
        "expected non-empty agentic_signals on the vuln fixture"
    )
    for sig in recon_out["agentic_signals"]:
        assert sig.get("surface") == "agentic"
        assert sig.get("class_")
        assert sig.get("owasp_llm")


def test_agentic_analyst_role_returns_findings():
    """AgenticAnalyst is no longer a placeholder — it wraps the scanner
    and returns real dict findings the orchestrator can consume."""
    from spotlight.agents import AgenticAnalyst

    findings = AgenticAnalyst().run(VULN)
    assert findings, "AgenticAnalyst should return non-empty findings for the vuln fixture"
    classes = {f["class_"] for f in findings}
    assert "prompt-injection" in classes
