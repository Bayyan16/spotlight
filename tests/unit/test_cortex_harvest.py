"""Harvest — the bridge from a finished finding to a ledger row.

The reconstruction of the evidence signature has to agree with the
orchestrator's `_build_evidence`, or a review filed weeks after the sweep would
land in a different cohort than the sweep did and calibration would be
measuring two different things under one name. The parity test below is the
guard: it runs both paths over the same candidate and compares.
"""
from __future__ import annotations

from spotlight.consensus.kernel import _dedupe_independent
from spotlight.cortex.experience import (
    FALSE_POSITIVE,
    SOURCE_ANALYST,
    SOURCE_REPRODUCTION,
    TRUE_POSITIVE,
    UNKNOWN,
    evidence_signature,
)
from spotlight.cortex.harvest import (
    evidence_decision,
    experience_from_finding,
    experience_from_review,
    experiences_from_sweep,
    modalities_from_finding,
)
from spotlight.orchestrator.orchestrator import _build_evidence


def _finding(
    *,
    class_="sqli",
    repro="confirmed",
    static=True,
    semgrep=False,
    tier="verified",
    confidence=0.93,
    review=None,
):
    evidence_used = []
    if static:
        evidence_used.append("codegraph:source->sink reachable")
    reason = "taint reaches cursor.execute"
    if semgrep:
        reason += " · signal:semgrep:python.flask.sqli"
    evidence_used.append(reason)
    finding = {
        "id": "SPOT-ABC",
        "class": class_,
        "cwe": "CWE-89",
        "surface": "code",
        "severity": "high",
        "tier": tier,
        "confidence": confidence,
        "identity": {"fingerprint": "fp-abc"},
        "location": {
            "repo_relative_path": "app/api/users.py",
            "file": "app/api/users.py",
            "function": "get_user",
            "line": 42,
        },
        "code_preview": {"lines": ["SECRET = 'AKIAIOSFODNN7EXAMPLE'"]},
        "evidence": {
            "corroboration": [
                {"type": "static-fact", "detail": evidence_used},
                {"type": "reproduction", "result": repro},
            ],
            "verification": {"result": "repro-now-blocked", "backdoor_check": "pass"},
            "threat_model": {
                "stack": {"language": "python", "framework": "flask"},
                "profile": "balanced",
            },
        },
    }
    if review:
        finding["review"] = review
    return finding


# ── modality reconstruction ─────────────────────────────────────────────


def test_modalities_match_the_orchestrator_evidence_builder():
    """Parity guard between the two paths into a cohort."""
    candidate = {
        "class": "sqli",
        "title": "SQLI in get_user",
        "root_cause": "concatenation",
        "evidence_used": [
            "codegraph:source->sink reachable",
            "taint reaches cursor.execute · signal:semgrep:python.flask.sqli",
        ],
    }
    repro = {"result": "confirmed", "notes": "rows returned"}
    kernel_side = evidence_signature(
        [i.modality for i in _dedupe_independent(_build_evidence(candidate, repro, "mock", "sw_1"))]
    )
    harvest_side = evidence_signature(
        modalities_from_finding(_finding(semgrep=True, repro="confirmed"))
    )
    assert kernel_side == harvest_side
    assert "dynamic_reproduction" in harvest_side
    assert "external_signal" in harvest_side
    assert "static_analysis_fact" in harvest_side
    assert "independent_agent" in harvest_side


def test_modalities_are_not_over_claimed():
    modalities = modalities_from_finding(_finding(static=False, semgrep=False, repro=""))
    assert modalities == ["independent_agent"]


def test_agentic_facts_count_as_static_analysis():
    finding = _finding(class_="prompt-injection", static=False, repro="")
    finding["evidence"]["corroboration"][0]["detail"] = ["agentic:source->llm-sink"]
    assert "static_analysis_fact" in modalities_from_finding(finding)


# ── labelling through the harvest path ──────────────────────────────────


def test_confirmed_reproduction_harvests_as_a_true_positive():
    exp = experience_from_finding(_finding(), sweep_id="sw_1")
    assert exp.label == TRUE_POSITIVE
    assert exp.label_source == SOURCE_REPRODUCTION
    assert exp.tier == "verified"


def test_unreproduced_finding_harvests_as_unknown_with_a_weak_negative():
    exp = experience_from_finding(
        _finding(repro="not-reproduced", tier="high-confidence"), sweep_id="sw_1"
    )
    assert exp.label == UNKNOWN
    assert exp.weak_negative is True


def test_review_harvest_outranks_the_reproduction():
    exp = experience_from_review(
        _finding(), review_state="false-positive", reason="fixture, not production code"
    )
    assert exp.label == FALSE_POSITIVE
    assert exp.label_source == SOURCE_ANALYST
    assert "fixture" in exp.label_reason


def test_persisted_review_block_is_honored():
    exp = experience_from_finding(
        _finding(review={"state": "accepted", "reason": "confirmed by the team"}),
        sweep_id="sw_1",
    )
    assert exp.label_source == SOURCE_ANALYST
    assert exp.label == TRUE_POSITIVE


def test_secrets_class_is_self_proving_without_a_poc():
    exp = experience_from_finding(
        _finding(class_="secrets", repro="not-applicable", tier="verified"), sweep_id="sw_1"
    )
    assert exp.label == TRUE_POSITIVE


# ── what a row is allowed to contain ────────────────────────────────────


def test_features_are_structural_and_carry_no_target_code():
    exp = experience_from_finding(_finding(), sweep_id="sw_1")
    assert exp.features["path"] == "app/api/users.py"
    assert exp.features["framework"] == "flask"
    blob = str(exp.to_dict())
    # The finding carried a code preview with a literal key in it; a ledger row
    # feeds prompts, so nothing derived from target bytes may ride along.
    assert "AKIAIOSFODNN7EXAMPLE" not in blob
    assert "code_preview" not in blob


def test_identity_is_derived_when_a_persisted_row_predates_the_field():
    finding = _finding()
    finding.pop("identity")
    exp = experience_from_finding(finding, sweep_id="sw_1")
    assert len(exp.finding_key) == 64   # sha256 hex


def test_harvesting_a_sweep_result_reads_every_finding():
    class Result:
        sweep_id = "sw_42"
        repo_path = "/tmp/target"
        findings = [_finding(), _finding(class_="ssrf", repro="not-reproduced")]

    rows = experiences_from_sweep(Result(), commit_sha="abc123")
    assert [r.sweep_id for r in rows] == ["sw_42", "sw_42"]
    assert rows[0].commit_sha == "abc123"
    assert rows[0].repo == "/tmp/target"
    assert {r.label for r in rows} == {TRUE_POSITIVE, UNKNOWN}


def test_harvest_skips_non_dict_entries():
    class Result:
        sweep_id = "sw_1"
        repo_path = ""
        findings = [_finding(), "not-a-finding", None]

    assert len(experiences_from_sweep(Result())) == 1


# ── the ledger must not learn from the policy's own output ───────────────


def test_a_nudged_finding_is_recorded_at_its_evidence_tier():
    """The subtlest failure mode in the whole subsystem.

    When a policy routes a cohort, every finding in it ships as
    ``needs-review``. If the ledger recorded *that*, the shadow replay would
    later see a row already at ``needs-review``, conclude that routing the
    cohort demotes nothing, and pass the gate — while the policy is in fact
    burying a sandbox-confirmed exploit. The policy would have erased the only
    witness to its own harm, and no check could ever notice.
    """
    finding = _finding(tier="needs-review", confidence=0.78)
    finding["consensus"] = {
        "tier": "needs-review",
        "confidence": 0.78,
        "cortex": {
            "applied": True,
            "cohort": "sqli|x",
            "policy_id": "p1",
            "tier_before": "verified",
            "confidence_before": 0.93,
            "adjustments": [{"action": "route-to-review"}],
        },
    }
    assert evidence_decision(finding) == ("verified", 0.93)

    exp = experience_from_finding(finding, sweep_id="sw_1")
    assert exp.tier == "verified"
    assert exp.confidence == 0.93
    assert exp.label == TRUE_POSITIVE   # the sandbox still confirmed it


def test_an_untouched_finding_records_its_own_tier():
    finding = _finding(tier="verified", confidence=0.93)
    finding["consensus"] = {"tier": "verified", "confidence": 0.93, "cortex": None}
    assert evidence_decision(finding) == ("verified", 0.93)


def test_a_finding_the_policy_saw_but_did_not_change_records_its_own_tier():
    finding = _finding(tier="verified", confidence=0.93)
    finding["consensus"] = {
        "tier": "verified",
        "confidence": 0.93,
        "cortex": {"applied": False, "cohort": "sqli|x", "policy_id": "p1"},
    }
    assert evidence_decision(finding) == ("verified", 0.93)
