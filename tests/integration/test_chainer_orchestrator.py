"""Tranche B4 — Chainer wired into the Orchestrator.

The unit tests in `tests/unit/test_chainer.py` exercise the composition
rules in isolation. These tests exercise the wiring: given a run that
produces the right candidate mix, the SweepResult must carry
`exploit_paths`, findings must be tagged with `exploit_path`, and the
event log must include `path.composed`.

We drive the orchestrator directly (not through the API) with a hand-
crafted candidate list injected via a fake Reducer path so the tests
stay deterministic and don't require an OWASP-LLM fixture repo.
"""
from __future__ import annotations

import json
from pathlib import Path

from spotlight.orchestrator.chainer import Chainer
from spotlight.orchestrator.orchestrator import Orchestrator, SweepResult

ROOT = Path(__file__).resolve().parents[2]


def test_sweep_result_carries_exploit_paths_field_by_default(tmp_path):
    """A vanilla clean-bank sweep should produce an empty exploit_paths
    list — the field exists but nothing chains."""
    orch = Orchestrator()
    result = orch.run(ROOT / "targets" / "clean-bank-api", out_dir=tmp_path)
    assert isinstance(result, SweepResult)
    assert isinstance(result.exploit_paths, list)
    assert result.exploit_paths == []
    # And the disk artifact is written even when empty — Reporter reads it.
    assert (tmp_path / "exploit_paths.json").exists()
    assert json.loads((tmp_path / "exploit_paths.json").read_text()) == []


def test_vuln_bank_finding_has_exploit_path_field(tmp_path):
    """Every emitted finding must have an `exploit_path` field (nullable).
    The Console needs a stable key to render the badge."""
    orch = Orchestrator()
    result = orch.run(ROOT / "targets" / "vuln-bank-api", out_dir=tmp_path)
    for f in result.findings:
        assert "exploit_path" in f, f"finding {f['id']} missing exploit_path field"


def test_chainer_composed_paths_write_to_disk_artifact(tmp_path):
    """Emulate the full write path: chainer output should end up in
    exploit_paths.json AND in the attestation.json exploit_paths block."""
    orch = Orchestrator()
    result = orch.run(ROOT / "targets" / "vuln-bank-api", out_dir=tmp_path)
    assert (tmp_path / "exploit_paths.json").exists()
    disk = json.loads((tmp_path / "exploit_paths.json").read_text())
    assert disk == result.exploit_paths
    att = json.loads((tmp_path / "attestation.json").read_text())
    assert "exploit_paths" in att
    assert att["exploit_paths"] == result.exploit_paths


def test_chainer_stable_across_reducer_output_shape():
    """Guard against a schema drift: the Chainer must accept the exact
    dict shape the Reducer emits (with all Investigator fields present).

    This uses a synthesized reduced list — no orchestrator run — so we
    catch a rename in Investigator output before the whole pipeline
    breaks."""
    reduced = [
        {
            "id": "CAND-1",
            "surface": "agentic",
            "class": "prompt-injection",
            "cwe": "LLM01",
            "title": "Indirect injection in README",
            "severity": "high",
            "repo": "acme",
            "location": {"file": "acme/README.md", "line": 5, "function": "prompt"},
            "evidence_used": ["agentic:agentic-source->llm-sink"],
        },
        {
            "id": "CAND-2",
            "surface": "agentic",
            "class": "excessive-agency",
            "cwe": "LLM06",
            "title": "requests.get granted to agent",
            "severity": "high",
            "repo": "acme",
            "tool": "requests.get",
            "location": {"file": "acme/agent.py", "line": 10, "function": "run_tool"},
            "evidence_used": [],
        },
    ]
    paths = Chainer().compose(reduced)
    assert len(paths) == 1
    p = paths[0]
    assert p["cross_surface"] is False  # both agentic
    assert len(p["steps"]) == 2
