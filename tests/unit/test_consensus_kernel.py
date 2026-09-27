"""Consensus Kernel v1 — independence check + adjudicator.

These tests exercise the actual decision surface — `promote(candidate,
evidence)` — because that's the code path the orchestrator calls per
finding. Type-checking would not have caught v3's mistake of counting two
same-model votes as two votes; only running the kernel with rigged
evidence lists does.

Coverage:
  * Two independent evidence items (static_fact + reproduction) -> verified.
  * Two independent evidence items (static_fact + independent_agent, different
    model family) -> verified via the high-confidence route + reproduction.
  * Two evidence items from the SAME model + SAME context collapse to 1
    (per PRD §8.1) and do NOT reach the verified tier on their own.
  * Disagreement (static_fact "reachable" vs external_signal "sanitized")
    invokes the adjudicator; its decision is stored on the TierDecision.
  * Static-fact class `secrets` with just a static_fact -> verified at 0.95
    (legacy compat preserved).
  * No evidence at all -> held.
  * Reproduction alone -> needs-review (no independent corroborator).
"""
from __future__ import annotations

from typing import Any

import pytest

from spotlight.consensus import ConsensusKernel, EvidenceItem, TierDecision
from spotlight.consensus.adjudicator import Adjudicator


# ── helpers ────────────────────────────────────────────────────────────


class _StubAdjudicator:
    """Records what it was asked and returns a canned decision."""

    def __init__(self, decision: dict[str, Any] | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self._decision = decision or {
            "decision": "promote",
            "rationale": "stub: static fact is stronger than the signal",
            "side_taken": "static_analysis_fact",
        }

    def adjudicate(
        self, *, candidate, positions, code_graph_slice, model
    ) -> dict[str, Any]:
        self.calls.append(
            {
                "candidate": candidate,
                "positions": positions,
                "code_graph_slice": code_graph_slice,
                "model": model,
            }
        )
        return self._decision


def _sqli_candidate() -> dict[str, Any]:
    return {
        "class": "sqli",
        "cwe": "CWE-89",
        "title": "SQLi in login",
        "severity": "high",
        "location": {"file": "app.py", "line": 42, "function": "login"},
        "root_cause": "user input concatenated into SQL",
        "evidence_used": ["codegraph:source->sink reachable"],
    }


def _secrets_candidate() -> dict[str, Any]:
    return {
        "class": "secrets",
        "cwe": "CWE-798",
        "title": "hardcoded AWS key",
        "severity": "high",
        "location": {"file": "config.py", "line": 3, "function": "<module>"},
        "root_cause": "credential literal in source",
        "evidence_used": ["codegraph:source->sink reachable"],
    }


# ── tests ──────────────────────────────────────────────────────────────


def test_static_fact_plus_reproduction_is_verified():
    """PRD §8.2 Verified tier: reproduced AND ≥1 independent corroborator.

    Two DIFFERENT modalities means two independent votes, so this promotes.
    """
    kernel = ConsensusKernel()
    evidence = [
        EvidenceItem(
            modality="static_analysis_fact",
            origin={"tool": "sg-core", "context_id": "sw_test:codegraph"},
            result="confirmed",
        ),
        EvidenceItem(
            modality="dynamic_reproduction",
            origin={"tool": "reproducer", "context_id": "sw_test:repro"},
            result="confirmed",
        ),
    ]
    decision = kernel.promote(_sqli_candidate(), evidence)

    assert decision.tier == "verified"
    assert decision.independent_corroborators == 2
    assert decision.confidence >= 0.9
    assert "reproduction" in decision.rationale
    assert "static-analysis fact" in decision.rationale


def test_static_fact_plus_different_model_family_is_verified_high_conf():
    """Two independent corroborators incl. static-analysis fact, different
    modalities/origins, no reproduction -> high-confidence tier per §8.2.
    """
    kernel = ConsensusKernel()
    evidence = [
        EvidenceItem(
            modality="static_analysis_fact",
            origin={"tool": "sg-core", "context_id": "sw_test:codegraph"},
            result="confirmed",
        ),
        EvidenceItem(
            modality="independent_agent",
            origin={
                "model_family": "anthropic-claude",
                "context_id": "sw_test:second-opinion",
                "role": "investigator",
            },
            result="confirmed",
        ),
    ]
    decision = kernel.promote(_sqli_candidate(), evidence)

    # No reproduction, so we can't reach Verified; but two independent
    # corroborators including static fact must land at high-confidence.
    assert decision.tier == "high-confidence"
    assert decision.independent_corroborators == 2
    assert decision.confidence >= 0.8


def test_two_passes_same_model_same_context_count_as_one():
    """Independence rule (§8.1): two passes of the SAME model in the SAME
    context are ONE vote, not two. The kernel must not promote to verified
    from a doubled-up single opinion.
    """
    kernel = ConsensusKernel()
    same_origin = {
        "model_family": "moonshot",
        "context_id": "sw_test:investigator:SQLi in login",
        "role": "investigator",
    }
    evidence = [
        EvidenceItem(
            modality="independent_agent",
            origin=same_origin,
            result="confirmed",
        ),
        EvidenceItem(
            modality="independent_agent",
            origin=dict(same_origin),  # identical key
            result="confirmed",
        ),
    ]
    decision = kernel.promote(_sqli_candidate(), evidence)

    # Only one vote survives the independence filter.
    assert decision.independent_corroborators == 1
    # And with only one vote (no static fact, no reproduction) we do NOT
    # reach the verified or high-confidence tiers.
    assert decision.tier not in ("verified", "high-confidence")


def test_disagreement_invokes_adjudicator_and_stores_decision():
    """§8.3: when corroborators disagree (static fact says reachable, an
    external signal says sanitized), we must invoke the adjudicator and
    persist its `{decision, rationale, side_taken}` on the TierDecision.
    """
    stub = _StubAdjudicator(
        decision={
            "decision": "promote",
            "rationale": (
                "Static reachability is deterministic; the SAST signal misread "
                "the sanitizer's scope in this control flow."
            ),
            "side_taken": "static_analysis_fact",
        }
    )
    kernel = ConsensusKernel(adjudicator=stub)
    evidence = [
        EvidenceItem(
            modality="static_analysis_fact",
            origin={"tool": "sg-core", "context_id": "sw_test:codegraph"},
            result="confirmed",
        ),
        EvidenceItem(
            modality="external_signal",
            origin={"tool": "semgrep", "context_id": "sw_test:sast"},
            result="sanitized",
        ),
    ]
    decision = kernel.promote(_sqli_candidate(), evidence)

    assert len(stub.calls) == 1, "adjudicator was not invoked on disagreement"
    assert decision.adjudication is not None
    assert decision.adjudication["decision"] == "promote"
    assert decision.adjudication["side_taken"] == "static_analysis_fact"
    assert "sanitizer" in decision.adjudication["rationale"]
    assert decision.tier == "needs-review"


def test_secrets_class_with_static_fact_is_verified_at_0_95():
    """Legacy behavior preserved: `secrets` / `hardcoded-secret` with a
    static_fact goes straight to `verified` at confidence 0.95. This is the
    "no PoC needed, the credential IS the finding" short-circuit.
    """
    kernel = ConsensusKernel()
    evidence = [
        EvidenceItem(
            modality="static_analysis_fact",
            origin={"tool": "sg-core", "context_id": "sw_test:codegraph"},
            result="confirmed",
        ),
    ]
    decision = kernel.promote(_secrets_candidate(), evidence)

    assert decision.tier == "verified"
    assert decision.confidence == pytest.approx(0.95)
    assert "static-fact class" in decision.rationale


def test_no_evidence_yields_held():
    """§8.2 Held tier: no independent evidence at all."""
    kernel = ConsensusKernel()
    decision = kernel.promote(_sqli_candidate(), [])

    assert decision.tier == "held"
    assert decision.independent_corroborators == 0
    assert decision.confidence < 0.5


def test_reproduction_alone_requires_review():
    """A PoC needs an independent observation before it is Verified."""
    kernel = ConsensusKernel()
    evidence = [
        EvidenceItem(
            modality="dynamic_reproduction",
            origin={"tool": "reproducer", "context_id": "sw_test:repro"},
            result="confirmed",
        ),
    ]
    decision = kernel.promote(_sqli_candidate(), evidence)

    assert decision.tier == "needs-review"
    assert decision.confidence == pytest.approx(0.65)
    assert "corroborator missing" in decision.rationale


def test_evidence_item_independence_key_shape():
    """The (modality, model_family, context_id) key is what powers §8.1.
    Guard the shape explicitly so a future refactor can't silently change it.
    """
    item = EvidenceItem(
        modality="independent_agent",
        origin={"model_family": "moonshot", "context_id": "abc"},
    )
    assert item.independence_key() == ("independent_agent", "moonshot", "abc")


def test_tier_decision_to_dict_shape():
    """The orchestrator reads these fields into the finding's `consensus`
    block. If someone renames a field, this test fails loudly.
    """
    d = TierDecision(
        tier="verified",
        confidence=0.9,
        rationale="x",
        independent_corroborators=2,
        adjudication={"decision": "promote", "rationale": "y", "side_taken": "z"},
    )
    dumped = d.to_dict()
    assert set(dumped.keys()) == {
        "tier",
        "confidence",
        "rationale",
        "independent_corroborators",
        "adjudication",
        # Cortex block — None unless a learned policy was supplied to
        # promote(). Present in the shape so the orchestrator can persist it
        # without a key check.
        "cortex",
    }
    assert dumped["cortex"] is None


def test_adjudicator_heuristic_fallback_when_no_model():
    """Adjudicator without a model must still return a well-formed decision.

    This guards the silent-failure path: if the model client fails at run
    time, we still want the finding to carry a decision + rationale so the
    Console has something to show the analyst.
    """
    adj = Adjudicator()
    positions = [
        {"modality": "static_analysis_fact", "result": "confirmed"},
        {"modality": "external_signal", "result": "sanitized"},
    ]
    out = adj.adjudicate(
        candidate=_sqli_candidate(),
        positions=positions,
        code_graph_slice=None,
        model=None,
    )
    assert set(out.keys()) == {"decision", "rationale", "side_taken"}
    # Static fact outranks external signal in the heuristic ordering.
    assert out["side_taken"] == "static_analysis_fact"
    assert out["decision"] == "promote"
