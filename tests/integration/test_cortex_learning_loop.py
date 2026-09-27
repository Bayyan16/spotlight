"""The loop, end to end: judge → be corrected → evolve → judge better.

This is the test that says the thing actually learns. It runs real sweeps
against the bundled fixtures with the mock model (offline, deterministic),
feeds analyst verdicts back through the same path the API uses, evolves the
policy under the real governor, and then checks that the *next* sweep tiers the
corrected cohort differently — while a reproduced finding is left exactly where
the evidence put it.
"""
from __future__ import annotations

import json

import pytest

from spotlight.cortex import (
    FALSE_POSITIVE,
    SELF_APPROVER,
    TRUE_POSITIVE,
    Cortex,
    Experience,
)
from spotlight.cortex.experience import SOURCE_ANALYST, SOURCE_REPRODUCTION
from spotlight.orchestrator import Orchestrator

TARGET = "targets/vuln-bank-api"


@pytest.fixture
def cortex(tmp_path):
    from spotlight.non_repudiation import Signer

    return Cortex(root=tmp_path / "cortex", signer=Signer())


def _row(cortex, *, cohort, label, source, key, tier="high-confidence", conf=0.82, reason=""):
    return cortex.ledger.append(
        Experience(
            sweep_id="sw_seed",
            finding_key=key,
            class_=cohort.split("|", 1)[0],
            cohort=cohort,
            signature=cohort.split("|", 1)[1],
            tier=tier,
            confidence=conf,
            label=label,
            label_source=source,
            label_reason=reason,
            features={"path": "app/render.py"},
        )
    )


# ── a sweep with no memory behaves exactly as before ────────────────────


def test_sweep_without_a_cortex_is_unchanged(tmp_path):
    result = Orchestrator().run(TARGET, out_dir=tmp_path / "run")
    assert result.findings
    for finding in result.findings:
        assert (finding["consensus"] or {}).get("cortex") is None
    assert result.attestations[0].get("cortex") in ({}, None)
    assert not [e for e in result.events_log if e["type"].startswith("cortex.")]


# ── a sweep with memory records what it did ─────────────────────────────


def test_sweep_pins_a_policy_and_harvests_its_own_outcome(cortex, tmp_path):
    result = Orchestrator(cortex=cortex).run(TARGET, out_dir=tmp_path / "run")
    assert result.findings

    # The pin names both inputs to any nudge: policy id and ledger head.
    pinned = [e for e in result.events_log if e["type"] == "cortex.policy.pinned"]
    assert len(pinned) == 1
    assert pinned[0]["payload"]["policy_id"]
    assert pinned[0]["payload"]["policy_is_identity"] is True

    attestation = result.attestations[0]
    assert attestation["cortex"]["policy_id"] == pinned[0]["payload"]["policy_id"]
    assert attestation["cortex"]["harvest"]["experiences_recorded"] == len(result.findings)

    # One ledger row per finding, and the sandbox-confirmed SQLi is a label.
    rows = cortex.ledger.experiences()
    assert len(rows) == len(result.findings)
    sqli = [r for r in rows if r.class_ == "sqli"][0]
    assert sqli.label == TRUE_POSITIVE
    assert sqli.label_source == SOURCE_REPRODUCTION
    assert cortex.verify().ok is True


def test_attestation_json_on_disk_carries_the_cortex_block(cortex, tmp_path):
    out = tmp_path / "run"
    Orchestrator(cortex=cortex).run(TARGET, out_dir=out)
    written = json.loads((out / "attestation.json").read_text())
    assert written["cortex"]["ledger_head"]
    assert written["cortex"]["harvest"]["experiences_recorded"] >= 1


def test_markdown_report_documents_the_policy_in_effect(cortex, tmp_path):
    out = tmp_path / "run"
    Orchestrator(cortex=cortex).run(TARGET, out_dir=out)
    report = (out / "report.md").read_text()
    assert "## Cortex — Learned Policy in Effect" in report
    assert "Experience ledger head" in report


# ── the loop closes: corrections change the next sweep ──────────────────


def test_analyst_corrections_change_the_next_sweep_tier(cortex, tmp_path):
    """Six false-positive verdicts on one evidence shape, then the tier moves.

    The corrected cohort is the one the SQLi fixture actually produces, so the
    second sweep exercises the real path: pinned policy → kernel → finding.
    """
    first = Orchestrator(cortex=cortex).run(TARGET, out_dir=tmp_path / "run-1")
    target_finding = first.findings[0]
    cohort = target_finding["consensus"]["cortex"]["cohort"] if target_finding["consensus"].get(
        "cortex"
    ) else None
    # No policy was active on the first sweep, so derive the cohort the same way
    # the kernel does.
    from spotlight.cortex.experience import cohort_key, evidence_signature
    from spotlight.cortex.harvest import modalities_from_finding

    cohort = cohort or cohort_key(
        target_finding["class"], evidence_signature(modalities_from_finding(target_finding))
    )

    # Six analyst false-positive verdicts in that cohort, filed the way
    # POST /findings/{id}/review files them.
    for i in range(6):
        _row(
            cortex,
            cohort=cohort,
            label=FALSE_POSITIVE,
            source=SOURCE_ANALYST,
            key=f"analyst-fp-{i}",
            tier=target_finding["tier"],
            conf=target_finding["confidence"],
            reason="scanner keeps flagging our parameterized helper",
        )

    report = cortex.evolve()
    assert report.activation.activated is True
    assert report.activation.approver == SELF_APPROVER      # conservative → unattended
    assert report.proposal.shadow.tp_demoted == 0
    assert report.proposal.shadow.fp_demoted >= 6

    second = Orchestrator(cortex=cortex).run(TARGET, out_dir=tmp_path / "run-2")
    same = [f for f in second.findings if f["class"] == target_finding["class"]][0]
    block = same["consensus"]["cortex"]
    assert block["applied"] is True
    assert block["cohort"] == cohort
    assert same["tier"] == "needs-review"                   # routed, not suppressed
    assert same["confidence"] < target_finding["confidence"]
    assert block["policy_id"] == report.activation.policy_id

    # The finding is still in the report — routing is not suppression.
    assert same in second.findings
    applied = [e for e in second.events_log if e["type"] == "cortex.adjustment.applied"]
    assert applied and applied[0]["payload"]["tier_after"] == "needs-review"


def test_a_reproduced_finding_is_never_demoted_by_learning(cortex, tmp_path):
    """The hard gate, exercised through the real pipeline.

    The same cohort carries one sandbox-confirmed finding and nine analyst
    false positives. A policy that would route the cohort would bury the
    confirmed one, so the governor must refuse it outright — noise stays until
    the evidence can be separated.
    """
    first = Orchestrator(cortex=cortex).run(TARGET, out_dir=tmp_path / "run-1")
    finding = first.findings[0]
    from spotlight.cortex.experience import cohort_key, evidence_signature
    from spotlight.cortex.harvest import modalities_from_finding

    cohort = cohort_key(
        finding["class"], evidence_signature(modalities_from_finding(finding))
    )
    for i in range(9):
        _row(
            cortex, cohort=cohort, label=FALSE_POSITIVE, source=SOURCE_ANALYST,
            key=f"noise-{i}", tier="verified", conf=0.93,
        )

    report = cortex.evolve()
    assert report.proposal.shadow.tp_demoted >= 1
    assert report.activation.activated is False
    assert "true positive" in report.activation.reason

    second = Orchestrator(cortex=cortex).run(TARGET, out_dir=tmp_path / "run-2")
    same = [f for f in second.findings if f["class"] == finding["class"]][0]
    assert same["tier"] == finding["tier"]
    assert same["confidence"] == finding["confidence"]


# ── audit trail across the loop ─────────────────────────────────────────


def test_the_tier_decision_is_signed_with_the_policy_that_made_it(cortex, tmp_path):
    from spotlight.non_repudiation.signing import verify_action

    first = Orchestrator(cortex=cortex).run(TARGET, out_dir=tmp_path / "run-1")
    finding = first.findings[0]
    from spotlight.cortex.experience import cohort_key, evidence_signature
    from spotlight.cortex.harvest import modalities_from_finding

    cohort = cohort_key(
        finding["class"], evidence_signature(modalities_from_finding(finding))
    )
    for i in range(6):
        _row(
            cortex, cohort=cohort, label=FALSE_POSITIVE, source=SOURCE_ANALYST,
            key=f"fp-{i}", tier=finding["tier"], conf=finding["confidence"],
        )
    cortex.evolve()

    second = Orchestrator(cortex=cortex).run(TARGET, out_dir=tmp_path / "run-2")
    same = [f for f in second.findings if f["class"] == finding["class"]][0]
    entries = same["audit"]["chain_of_custody"]
    tier_entry = [e for e in entries if e["action"] == "tier-decided"][0]
    assert tier_entry["payload"]["cortex_applied"] is True
    assert tier_entry["payload"]["cortex_policy_id"] == cortex.active_policy().policy_id
    assert verify_action(tier_entry, cortex.signer.public_key) is True


def test_rollback_restores_the_previous_tier(cortex, tmp_path):
    first = Orchestrator(cortex=cortex).run(TARGET, out_dir=tmp_path / "run-1")
    finding = first.findings[0]
    from spotlight.cortex.experience import cohort_key, evidence_signature
    from spotlight.cortex.harvest import modalities_from_finding

    cohort = cohort_key(
        finding["class"], evidence_signature(modalities_from_finding(finding))
    )
    for i in range(6):
        _row(
            cortex, cohort=cohort, label=FALSE_POSITIVE, source=SOURCE_ANALYST,
            key=f"fp-{i}", tier=finding["tier"], conf=finding["confidence"],
        )
    cortex.evolve()
    assert cortex.active_policy().is_identity is False

    bootstrap = [p for p in cortex.policies.history() if p.is_identity]
    if not bootstrap:
        from spotlight.cortex import CortexPolicy

        cortex.policies.save(CortexPolicy.bootstrap())
        bootstrap = [p for p in cortex.policies.history() if p.is_identity]
    result = cortex.rollback(bootstrap[0].policy_id, approver="oncall@bank.example")
    assert result.activated is True

    third = Orchestrator(cortex=cortex).run(TARGET, out_dir=tmp_path / "run-3")
    same = [f for f in third.findings if f["class"] == finding["class"]][0]
    assert same["tier"] == finding["tier"]
    assert same["confidence"] == finding["confidence"]


def test_lessons_reach_the_investigator_context(cortex, tmp_path, monkeypatch):
    """A correction becomes advisory prompt context on the next sweep."""
    first = Orchestrator(cortex=cortex).run(TARGET, out_dir=tmp_path / "run-1")
    finding = first.findings[0]
    path = finding["location"]["repo_relative_path"]
    for i, key in enumerate(("lesson-a", "lesson-b")):
        cortex.ledger.append(
            Experience(
                sweep_id="sw_seed",
                finding_key=key,
                class_=finding["class"],
                cohort="x|independent_agent",
                signature="independent_agent",
                tier="needs-review",
                confidence=0.4,
                label=FALSE_POSITIVE,
                label_source=SOURCE_ANALYST,
                label_reason="our helper already parameterizes this query",
                features={"path": path},
            )
        )
    cortex.lessons.refresh(cortex.ledger.latest_by_finding().values())
    assert cortex.served_lessons()

    seen: list[dict] = []
    orch = Orchestrator(cortex=cortex)
    inner = orch.model.complete

    def _spy(*, role, prompt, context):
        if role == "investigator":
            seen.append(context)
        return inner(role=role, prompt=prompt, context=context)

    monkeypatch.setattr(orch.model, "complete", _spy)
    orch.run(TARGET, out_dir=tmp_path / "run-2")

    with_lessons = [c for c in seen if c.get("lessons")]
    assert with_lessons, "no investigator context carried a lesson"
    text = " ".join(with_lessons[0]["lessons"])
    assert "parameterizes" in text
    assert "false-positive" in text
