"""Tranche B5 — Hypothesis Path Proposer.

The proposer runs ONE LLM call per sweep and lets the model propose
plausible attack chains the deterministic Chainer didn't rule-match.
Every proposal:

  * carries tier="hypothesis" (never enters the signed attestation lane)
  * carries origin="llm-proposal"
  * references only real candidate ids (invented ids are silently dropped)
  * is deduped against Chainer verified paths sharing the same finding-id set

These tests exercise the *guardrails*, not just the happy path. The
critical invariant — hypothesis paths NEVER get tier="verified" — is
what preserves the meaning of a signed attestation.
"""
from __future__ import annotations

from typing import Any

from spotlight.orchestrator.hypothesis import HypothesisProposer


# ── mock model clients ─────────────────────────────────────────────────

class _FixedChainsModel:
    """Returns a caller-supplied `chains` list from `.complete()`."""

    def __init__(self, chains: list[dict[str, Any]]):
        self.family = "mock"
        self._chains = chains
        self.calls = 0

    def complete(self, *, role, prompt, context):
        self.calls += 1
        return {"chains": list(self._chains)}


class _BoomModel:
    family = "mock"

    def complete(self, *, role, prompt, context):
        raise RuntimeError("model went down")


# ── candidate fixtures ─────────────────────────────────────────────────

def _pi() -> dict:
    return {
        "id": "PI-1", "class": "prompt-injection", "surface": "agentic",
        "severity": "high", "cwe": "LLM01",
        "location": {"file": "app/README.md", "line": 4, "function": "system_prompt"},
    }


def _ssrf() -> dict:
    return {
        "id": "SSRF-1", "class": "ssrf", "surface": "code",
        "severity": "high", "cwe": "CWE-918",
        "location": {"file": "app/server.py", "line": 42, "function": "handle_url"},
    }


def _sqli() -> dict:
    return {
        "id": "SQLI-1", "class": "sqli", "surface": "code",
        "severity": "critical", "cwe": "CWE-89",
        "location": {"file": "app/db.py", "line": 22, "function": "get_account"},
    }


# ── happy path ─────────────────────────────────────────────────────────

def test_proposes_valid_hypothesis_chain():
    model = _FixedChainsModel([
        {
            "title": "PI → SSRF exfil",
            "rationale": "model thinks this composes",
            "severity": "high",
            "step_finding_ids": ["PI-1", "SSRF-1"],
        }
    ])
    proposer = HypothesisProposer(model)
    paths = proposer.propose(candidates=[_pi(), _ssrf()])
    assert len(paths) == 1
    p = paths[0]
    assert p["tier"] == "hypothesis"
    assert p["origin"] == "llm-proposal"
    assert p["id"] == "H-EP-0001"
    assert p["cross_surface"] is True
    assert [s["finding_id"] for s in p["steps"]] == ["PI-1", "SSRF-1"]
    assert p["steps"][0]["order"] == 1
    assert p["steps"][1]["order"] == 2


def test_only_one_llm_call_per_sweep():
    """Cost gate: propose() must not fan out per candidate."""
    model = _FixedChainsModel([])
    HypothesisProposer(model).propose(candidates=[_pi(), _ssrf(), _sqli()])
    assert model.calls == 1


# ── invariants ──────────────────────────────────────────────────────────

def test_invented_step_ids_are_silently_dropped():
    """Model hallucinates a finding id → proposal must not survive."""
    model = _FixedChainsModel([
        {"step_finding_ids": ["PI-1", "GHOST-42"]},   # dropped
        {"step_finding_ids": ["PI-1", "SSRF-1"]},     # kept
    ])
    paths = HypothesisProposer(model).propose(candidates=[_pi(), _ssrf()])
    assert len(paths) == 1
    assert [s["finding_id"] for s in paths[0]["steps"]] == ["PI-1", "SSRF-1"]


def test_never_marks_tier_verified():
    """Non-negotiable — hypothesis lane must not produce signed paths."""
    model = _FixedChainsModel([
        {"step_finding_ids": ["PI-1", "SSRF-1"]},
    ])
    paths = HypothesisProposer(model).propose(candidates=[_pi(), _ssrf()])
    assert all(p["tier"] == "hypothesis" for p in paths)
    assert all(p.get("origin") == "llm-proposal" for p in paths)


def test_dedup_vs_verified_paths():
    """If Chainer already emitted the same finding-id set, drop the twin."""
    verified = [{
        "id": "EP-0001",
        "steps": [
            {"finding_id": "PI-1"}, {"finding_id": "SSRF-1"},
        ],
        "tier": "verified",
    }]
    model = _FixedChainsModel([
        {"step_finding_ids": ["PI-1", "SSRF-1"]},   # dupe → drop
        {"step_finding_ids": ["PI-1", "SQLI-1"]},   # unique → keep
    ])
    paths = HypothesisProposer(model).propose(
        candidates=[_pi(), _ssrf(), _sqli()],
        verified=verified,
    )
    assert len(paths) == 1
    assert [s["finding_id"] for s in paths[0]["steps"]] == ["PI-1", "SQLI-1"]


def test_dedup_within_batch():
    """Same chain twice in one model response → dedup."""
    model = _FixedChainsModel([
        {"step_finding_ids": ["PI-1", "SSRF-1"]},
        {"step_finding_ids": ["PI-1", "SSRF-1"]},
    ])
    paths = HypothesisProposer(model).propose(candidates=[_pi(), _ssrf()])
    assert len(paths) == 1


def test_single_step_chains_rejected():
    """A one-step 'chain' isn't a chain — reject."""
    model = _FixedChainsModel([
        {"step_finding_ids": ["PI-1"]},
    ])
    paths = HypothesisProposer(model).propose(candidates=[_pi(), _ssrf()])
    assert paths == []


def test_empty_candidates_short_circuits():
    """Never call the model when there's nothing to compose."""
    model = _FixedChainsModel([{"step_finding_ids": ["PI-1", "SSRF-1"]}])
    proposer = HypothesisProposer(model)
    assert proposer.propose(candidates=[]) == []
    assert proposer.propose(candidates=[_pi()]) == []
    assert model.calls == 0


def test_model_failure_returns_empty_not_raise():
    """Hypothesis lane must never crash a sweep."""
    paths = HypothesisProposer(_BoomModel()).propose(candidates=[_pi(), _ssrf()])
    assert paths == []


def test_cross_surface_flag_reflects_step_surfaces():
    model = _FixedChainsModel([
        {"step_finding_ids": ["PI-1", "SSRF-1"]},   # agentic + code
        {"step_finding_ids": ["SSRF-1", "SQLI-1"]}, # code + code
    ])
    paths = HypothesisProposer(model).propose(
        candidates=[_pi(), _ssrf(), _sqli()]
    )
    ids_to_cross = {p["id"]: p["cross_surface"] for p in paths}
    # First proposal spans agentic + code → cross_surface True.
    # Second spans code + code → False.
    assert True in ids_to_cross.values()
    assert False in ids_to_cross.values()


def test_step_ids_normalized_to_str():
    """Model may return numeric ids — we coerce to str for lookup."""
    cand = {**_pi(), "id": 42}
    model = _FixedChainsModel([
        {"step_finding_ids": [42, "SSRF-1"]},
    ])
    paths = HypothesisProposer(model).propose(candidates=[cand, _ssrf()])
    assert len(paths) == 1
    assert paths[0]["steps"][0]["finding_id"] in (42, "42")


def test_mock_model_hypothesis_role_produces_chain():
    """MockModelClient covers hypothesis-proposer role — used by orchestrator."""
    from spotlight.agents.model import MockModelClient
    model = MockModelClient()
    resp = model.complete(
        role="hypothesis-proposer",
        prompt="propose",
        context={"candidates": [_pi(), _ssrf()]},
    )
    assert "chains" in resp
    assert len(resp["chains"]) >= 1
    assert resp["chains"][0].get("step_finding_ids") == ["PI-1", "SSRF-1"]
