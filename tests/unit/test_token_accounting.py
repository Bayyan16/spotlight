"""Per-agent + per-sub-agent token accounting.

Every call through `self.model.complete()` in the Orchestrator now lands
in two accumulators (see `_TrackingModel` in orchestrator.py):

  * `_usage_by_role`  — per-role rollup: {role: {model, calls,
                         prompt_tokens, completion_tokens, total_tokens}}
  * `_usage_events`   — per-call event log with subagent id + elapsed_s
                         + model + fallback flag

The proxy is transparent — call sites don't change. These tests pin the
proxy's contract with mock model clients (no real LLM calls).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from spotlight.orchestrator import Orchestrator


class _TrackedMock:
    """Mock model client that reports realistic `usage` blocks so the
    proxy has something to extract. Emits different usage per role so we
    can assert the accumulator differentiates them."""

    family = "mock-tracked"

    _PER_ROLE = {
        "investigator": (400, 120),
        "verifier": (900, 80),
        "plain-language": (300, 60),
        "hypothesis-proposer": (1500, 220),
        "recon": (500, 90),
    }

    def complete(self, *, role, prompt, context):
        pt, ct = self._PER_ROLE.get(role, (100, 30))
        base: dict = {
            "verdict": "candidate",
            "result": "repro-now-blocked",
            "one_liner": "sample",
            "usage": {
                "prompt_tokens": pt,
                "completion_tokens": ct,
                "total_tokens": pt + ct,
            },
            "model": "mock-tracked-v1",
        }
        if role == "investigator":
            slice_ = context.get("slice", {})
            base["class"] = slice_.get("sink", {}).get("class", "sqli")
            base["cwe"] = "CWE-89"
            base["title"] = "T"
            base["severity"] = "high"
            base["location"] = {
                "file": slice_.get("file", "x.py"),
                "line": slice_.get("sink", {}).get("line", 1),
                "function": slice_.get("function", "f"),
            }
            base["root_cause"] = "rc"
            base["recommendation"] = "fix it"
            base["evidence_used"] = []
        if role == "verifier":
            base["result"] = "repro-now-blocked"
            base["backdoor_check"] = "pass"
            base["security_regression"] = "pass"
            base["independent_verifier"] = True
            base["notes"] = "n"
        if role == "hypothesis-proposer":
            base["chains"] = []
        return base


def _acme() -> Path:
    root = Path(__file__).resolve().parents[2] / "targets" / "acme-bank"
    if not (root / "app.py").exists():
        pytest.skip("acme-bank fixture missing")
    return root


def test_by_role_accumulator_partitions_correctly(tmp_path):
    orch = Orchestrator(model=_TrackedMock())
    orch.run(_acme(), out_dir=tmp_path / "sweep")

    by_role = orch._usage_by_role
    # Expected roles the sweep should have hit at least once.
    for r in ("recon", "investigator", "verifier", "plain-language"):
        assert r in by_role, f"role {r} not tracked. Have: {list(by_role)}"
        b = by_role[r]
        assert b["calls"] > 0
        assert b["prompt_tokens"] > 0
        assert b["completion_tokens"] > 0
        assert b["total_tokens"] == b["prompt_tokens"] + b["completion_tokens"]
        assert b["model"] == "mock-tracked-v1"


def test_event_log_records_per_call(tmp_path):
    orch = Orchestrator(model=_TrackedMock())
    orch.run(_acme(), out_dir=tmp_path / "sweep")

    events = orch._usage_events
    assert len(events) > 0
    # Every event carries the identifying fields.
    for e in events:
        assert e["role"]
        assert e["subagent"]
        assert e["model"] == "mock-tracked-v1"
        assert e["total_tokens"] > 0
        assert e["elapsed_s"] >= 0
        assert isinstance(e["fallback"], bool)


def test_event_log_capped(tmp_path, monkeypatch):
    """Even on very large sweeps the event log must stay bounded."""
    from spotlight.orchestrator import orchestrator as orch_mod

    monkeypatch.setattr(orch_mod._TrackingModel, "_EVENT_CAP", 3)

    orch = Orchestrator(model=_TrackedMock())
    orch.run(_acme(), out_dir=tmp_path / "sweep")
    assert len(orch._usage_events) <= 3


def test_finding_carries_token_usage_snapshot(tmp_path):
    """Each finding's audit block includes a token_usage snapshot so the
    attestation is self-contained without querying the orchestrator."""
    orch = Orchestrator(model=_TrackedMock())
    result = orch.run(_acme(), out_dir=tmp_path / "sweep")
    assert result.findings
    for f in result.findings:
        tu = (f.get("audit") or {}).get("token_usage")
        assert tu is not None
        assert "by_role" in tu
        assert "totals" in tu
        assert tu["totals"]["total_tokens"] > 0


def test_sweep_result_exposes_snapshot(tmp_path):
    """SweepResult.token_usage + .usage_events are populated at finalize."""
    orch = Orchestrator(model=_TrackedMock())
    result = orch.run(_acme(), out_dir=tmp_path / "sweep")
    assert result.token_usage
    assert result.token_usage["totals"]["total_tokens"] > 0
    assert result.usage_events
    assert result.usage_events[0]["role"]
