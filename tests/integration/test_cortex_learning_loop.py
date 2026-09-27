"""The loop, end to end: judge → be corrected → evolve → judge better.

This is the test that says the thing actually learns. It runs real sweeps
against a bundled fixture with the mock model (offline, deterministic), feeds
analyst verdicts into the ledger the way `POST /findings/{id}/review` does,
evolves the policy under the real governor, and then checks that the *next*
sweep tiers the corrected cohort differently — while a finding the sandbox
confirmed is left exactly where the evidence put it.

Two things about the setup are load-bearing:

* **The control sweep runs with no Cortex.** Attaching one would harvest that
  sweep's own sandbox-confirmed SQLi into the very cohort the test then seeds
  with false positives — and the governor would (correctly) refuse to route a
  cohort containing a confirmed true positive, so the test would be asserting
  against contamination it created itself.
* **The cohort is derived from a real sweep, never hard-coded.** The evidence
  shape depends on what is installed: a machine with a working Semgrep
  contributes an `external_signal` modality and therefore a different cohort
  name. Hard-coding it would make this suite pass or fail on the runner's
  tooling rather than on Spotlight's behaviour.

Sweeps are the expensive thing here, so the read-only assertions share two
module-scoped ones.
"""
from __future__ import annotations

import json

import pytest

from spotlight.cortex import FALSE_POSITIVE, SELF_APPROVER, TRUE_POSITIVE, Cortex, Experience
from spotlight.cortex.experience import (
    SOURCE_ANALYST,
    SOURCE_REPRODUCTION,
    cohort_key,
    evidence_signature,
)
from spotlight.cortex.harvest import modalities_from_finding
from spotlight.orchestrator import Orchestrator

TARGET = "targets/vuln-bank-api"


def _cohort_of(finding: dict) -> str:
    """The cohort the Consensus Kernel would key this finding on."""
    return cohort_key(
        finding["class"], evidence_signature(modalities_from_finding(finding))
    )


@pytest.fixture(scope="module")
def baseline(tmp_path_factory):
    """One sweep with no memory at all — the control. See module docstring."""
    out = tmp_path_factory.mktemp("baseline")
    result = Orchestrator().run(TARGET, out_dir=out)
    assert result.findings, "fixture produced no findings; the rest is meaningless"
    return {"result": result, "finding": result.findings[0], "out": out}


@pytest.fixture(scope="module")
def memory_sweep(tmp_path_factory):
    """One sweep with a fresh Cortex — reused by the read-only assertions."""
    from spotlight.non_repudiation import Signer

    root = tmp_path_factory.mktemp("cortex-first")
    out = tmp_path_factory.mktemp("cortex-first-run")
    cortex = Cortex(root=root / "cortex", signer=Signer())
    result = Orchestrator(cortex=cortex).run(TARGET, out_dir=out)
    return {"cortex": cortex, "result": result, "out": out}


@pytest.fixture
def cortex(tmp_path):
    from spotlight.non_repudiation import Signer

    return Cortex(root=tmp_path / "cortex", signer=Signer())


def _seed_false_positives(cortex, *, cohort, n, tier, confidence, reason="", path="app/x.py"):
    """n analyst false-positive verdicts in one cohort, as the API would file them."""
    for i in range(n):
        cortex.ledger.append(
            Experience(
                sweep_id="sw_seed",
                finding_key=f"seed-fp-{i}",
                class_=cohort.split("|", 1)[0],
                cohort=cohort,
                signature=cohort.split("|", 1)[1],
                tier=tier,
                confidence=confidence,
                label=FALSE_POSITIVE,
                label_source=SOURCE_ANALYST,
                label_reason=reason,
                features={"path": path},
            )
        )


# ── no memory means no change ────────────────────────────────────────────


def test_sweep_without_a_cortex_is_unchanged(baseline):
    result = baseline["result"]
    for finding in result.findings:
        assert (finding["consensus"] or {}).get("cortex") is None
    assert result.attestations[0].get("cortex") in ({}, None)
    assert not [e for e in result.events_log if e["type"].startswith("cortex.")]


# ── a sweep with memory records what it did ──────────────────────────────


def test_sweep_pins_a_policy_and_harvests_its_own_outcome(memory_sweep):
    result = memory_sweep["result"]
    cortex = memory_sweep["cortex"]

    # The pin names both inputs to any nudge: policy id and ledger head.
    pinned = [e for e in result.events_log if e["type"] == "cortex.policy.pinned"]
    assert len(pinned) == 1
    assert pinned[0]["payload"]["policy_id"]
    assert pinned[0]["payload"]["policy_is_identity"] is True

    attestation = result.attestations[0]
    assert attestation["cortex"]["policy_id"] == pinned[0]["payload"]["policy_id"]
    assert attestation["cortex"]["harvest"]["experiences_recorded"] == len(result.findings)

    # One ledger row per finding, and the sandbox-confirmed SQLi carries a label.
    rows = cortex.ledger.experiences()
    assert len(rows) == len(result.findings)
    sqli = [r for r in rows if r.class_ == "sqli"][0]
    assert sqli.label == TRUE_POSITIVE
    assert sqli.label_source == SOURCE_REPRODUCTION
    assert cortex.verify().ok is True


def test_attestation_and_report_document_the_policy_in_effect(memory_sweep):
    out = memory_sweep["out"]
    written = json.loads((out / "attestation.json").read_text())
    assert written["cortex"]["ledger_head"]
    assert written["cortex"]["harvest"]["experiences_recorded"] >= 1

    report = (out / "report.md").read_text()
    assert "## Cortex — Learned Policy in Effect" in report
    assert "Experience ledger head" in report


def test_first_sweep_derives_a_candidate_policy_but_withholds_it(memory_sweep):
    """Nothing is labelled a false positive yet, so there is nothing to learn."""
    evolution = memory_sweep["result"].attestations[0]["cortex"]["harvest"]["evolution"]
    assert evolution["activated"] is False
    assert evolution["shadow"]["tp_demoted"] == 0


# ── the loop closes: corrections change the next sweep ───────────────────


def test_analyst_corrections_change_the_next_sweep_tier(cortex, baseline, tmp_path):
    finding = baseline["finding"]
    cohort = _cohort_of(finding)
    _seed_false_positives(
        cortex, cohort=cohort, n=6, tier=finding["tier"], confidence=finding["confidence"],
        reason="scanner keeps flagging our parameterized helper",
    )

    report = cortex.evolve()
    assert report.activation.activated is True, report.activation.reason
    assert report.activation.approver == SELF_APPROVER      # conservative → unattended
    assert report.proposal.shadow.tp_demoted == 0
    assert report.proposal.shadow.fp_demoted >= 6

    second = Orchestrator(cortex=cortex).run(TARGET, out_dir=tmp_path / "run-2")
    same = [f for f in second.findings if f["class"] == finding["class"]][0]
    block = same["consensus"]["cortex"]
    assert block["applied"] is True
    assert block["cohort"] == cohort
    assert block["policy_id"] == report.activation.policy_id
    assert same["tier"] == "needs-review"                   # routed …
    assert same["confidence"] < finding["confidence"]
    assert same in second.findings                          # … not suppressed

    applied = [e for e in second.events_log if e["type"] == "cortex.adjustment.applied"]
    assert applied and applied[0]["payload"]["tier_after"] == "needs-review"

    # And the signed tier decision names the policy that made it.
    from spotlight.non_repudiation.signing import verify_action

    tier_entry = [
        e for e in same["audit"]["chain_of_custody"] if e["action"] == "tier-decided"
    ][0]
    assert tier_entry["payload"]["cortex_applied"] is True
    assert tier_entry["payload"]["cortex_policy_id"] == report.activation.policy_id
    assert verify_action(tier_entry, cortex.signer.public_key) is True


def test_a_reproduced_finding_is_never_demoted_by_learning(cortex, baseline, tmp_path):
    """The hard gate, exercised through the real pipeline.

    One sandbox-confirmed true positive sits in the same cohort as nine analyst
    false positives. Routing the cohort would bury the confirmed one, so the
    governor must refuse outright — the noise stays until the evidence can be
    separated. This is the regression that matters: a self-tuning scanner that
    trades recall for a quieter inbox is worse than no scanner, because the
    silence is indistinguishable from safety.
    """
    finding = baseline["finding"]
    cohort = _cohort_of(finding)
    cortex.ledger.append(
        Experience(
            sweep_id="sw_seed",
            finding_key="confirmed-real",
            class_=finding["class"],
            cohort=cohort,
            signature=cohort.split("|", 1)[1],
            tier=finding["tier"],
            confidence=finding["confidence"],
            label=TRUE_POSITIVE,
            label_source=SOURCE_REPRODUCTION,
        )
    )
    _seed_false_positives(
        cortex, cohort=cohort, n=9, tier=finding["tier"], confidence=finding["confidence"]
    )

    report = cortex.evolve()
    assert report.proposal.shadow.tp_demoted >= 1
    assert report.activation.activated is False
    assert "true positive" in report.activation.reason

    second = Orchestrator(cortex=cortex).run(TARGET, out_dir=tmp_path / "run-2")
    same = [f for f in second.findings if f["class"] == finding["class"]][0]
    assert same["tier"] == finding["tier"]
    assert same["confidence"] == finding["confidence"]


def test_a_policy_that_goes_stale_is_retracted_on_the_next_sweep(cortex, baseline, tmp_path):
    """The activation gate runs once; evidence keeps arriving.

    The policy ships while the cohort is all false positives. Then a sweep
    reproduces a real exploit in that same cohort — and the harvest at the end
    of that sweep triggers the retraction, unattended.
    """
    finding = baseline["finding"]
    cohort = _cohort_of(finding)
    _seed_false_positives(
        cortex, cohort=cohort, n=6, tier=finding["tier"], confidence=finding["confidence"]
    )
    assert cortex.evolve().activation.activated is True
    assert cortex.active_policy().is_identity is False

    # This sweep reproduces the SQLi, harvesting a confirmed true positive into
    # the routed cohort — which makes the active policy harmful.
    after = Orchestrator(cortex=cortex).run(TARGET, out_dir=tmp_path / "run-2")
    assert cortex.active_policy().is_identity is True
    retracted = [
        e for e in cortex.governance.entries() if e["action"] == "policy.retracted"
    ]
    assert retracted, "a policy that now demotes a confirmed finding must be dropped"
    assert retracted[0]["actor"] == SELF_APPROVER

    # The sweep that triggered it still ran under the pinned (old) policy —
    # retraction applies to the next one, never retroactively.
    assert after.attestations[0]["cortex"]["policy_is_identity"] is False

    third = Orchestrator(cortex=cortex).run(TARGET, out_dir=tmp_path / "run-3")
    same = [f for f in third.findings if f["class"] == finding["class"]][0]
    assert same["tier"] == finding["tier"]
    assert same["confidence"] == finding["confidence"]


def test_rollback_restores_the_previous_tier(cortex, baseline, tmp_path):
    from spotlight.cortex import CortexPolicy

    finding = baseline["finding"]
    cohort = _cohort_of(finding)
    _seed_false_positives(
        cortex, cohort=cohort, n=6, tier=finding["tier"], confidence=finding["confidence"]
    )
    assert cortex.evolve().activation.activated is True
    assert cortex.active_policy().is_identity is False

    boot = CortexPolicy.bootstrap()
    cortex.policies.save(boot)
    assert cortex.rollback(boot.policy_id, approver="oncall@bank.example").activated is True

    after = Orchestrator(cortex=cortex).run(TARGET, out_dir=tmp_path / "run-3")
    same = [f for f in after.findings if f["class"] == finding["class"]][0]
    assert same["tier"] == finding["tier"]
    assert same["confidence"] == finding["confidence"]
    # Both policies remain on disk — rollback is a pointer move, not a deletion.
    assert len(cortex.policies.history()) >= 2


def test_lessons_reach_the_investigator_as_advisory_context(
    cortex, baseline, tmp_path, monkeypatch
):
    finding = baseline["finding"]
    path = finding["location"]["repo_relative_path"]
    for key in ("lesson-a", "lesson-b"):
        cortex.ledger.append(
            Experience(
                sweep_id="sw_seed",
                finding_key=key,
                class_=finding["class"],
                cohort=_cohort_of(finding),
                signature=_cohort_of(finding).split("|", 1)[1],
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
