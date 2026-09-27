"""Calibration arithmetic and the six policy invariants.

The invariants are the promise that makes this system safe to run unattended,
so each one gets a test that tries to violate it — once through `validate()`
(the activation path) and, where it matters, once through `apply()` (the
runtime path, which must hold even for a policy file someone edited on disk).
"""
from __future__ import annotations

import json

from spotlight.cortex.calibrate import calibrate
from spotlight.cortex.experience import (
    FALSE_POSITIVE,
    SOURCE_ANALYST,
    SOURCE_REPRODUCTION,
    TRUE_POSITIVE,
    UNKNOWN,
    Experience,
)
from spotlight.cortex.policy import (
    ACTION_ADJUST,
    ACTION_NONE,
    ACTION_ROUTE,
    CONFIDENCE_CAP,
    MAX_CONFIDENCE_DELTA,
    CohortDirective,
    CortexPolicy,
    PolicyStore,
    derive_policy,
)

COHORT = "ssti|independent_agent+static_analysis_fact"


def _rows(n, label, source=SOURCE_ANALYST, cohort=COHORT, class_="ssti", **kw):
    return [
        Experience(
            sweep_id="sw_1",
            finding_key=f"{class_}-{label}-{i}",
            class_=class_,
            cohort=cohort,
            signature=cohort.split("|", 1)[1],
            tier="high-confidence",
            confidence=0.82,
            label=label,
            label_source=source,
            **kw,
        )
        for i in range(n)
    ]


# ── calibration ─────────────────────────────────────────────────────────


def test_unlabeled_rows_never_count_as_negatives():
    """Coverage is reported; absence of a label is not evidence of absence."""
    cal = calibrate(_rows(4, TRUE_POSITIVE) + _rows(6, UNKNOWN, source="unlabeled"))
    stats = cal.cohorts[COHORT]
    assert stats.n_labeled == 4
    assert stats.unknown == 6
    assert stats.fp == 0
    assert 0.3 < stats.label_coverage < 0.5


def test_small_cohorts_are_not_actionable():
    cal = calibrate(_rows(4, FALSE_POSITIVE))
    assert cal.cohorts[COHORT].actionable is False
    assert cal.actionable() == {}


def test_precision_lower_is_below_the_mean():
    """Down-weighting decisions use the pessimistic end of the interval."""
    cal = calibrate(_rows(5, TRUE_POSITIVE) + _rows(5, FALSE_POSITIVE))
    stats = cal.cohorts[COHORT]
    assert stats.precision_lower < stats.precision_mean


def test_weak_negatives_are_tracked_separately_from_false_positives():
    cal = calibrate(_rows(6, UNKNOWN, source="unlabeled", weak_negative=True))
    stats = cal.cohorts[COHORT]
    assert stats.weak_negatives == 6
    assert stats.fp == 0


# ── derivation ──────────────────────────────────────────────────────────


def test_a_mostly_wrong_cohort_is_routed_to_review():
    policy = derive_policy(calibrate(_rows(6, FALSE_POSITIVE), ledger_head="h"))
    assert policy.directives[COHORT].action == ACTION_ROUTE
    assert policy.validate() == []


def test_a_reliable_cohort_without_human_confirmation_is_left_alone():
    """I5 — an agent may not certify its own reliability."""
    policy = derive_policy(
        calibrate(_rows(6, TRUE_POSITIVE, source=SOURCE_REPRODUCTION), ledger_head="h")
    )
    directive = policy.directives[COHORT]
    assert directive.action == ACTION_NONE
    assert "no analyst-confirmed true positive" in directive.rationale


def test_a_human_confirmed_cohort_may_be_recalibrated_upward():
    policy = derive_policy(calibrate(_rows(6, TRUE_POSITIVE), ledger_head="h"))
    directive = policy.directives[COHORT]
    assert directive.action == ACTION_ADJUST
    assert directive.human_tp == 6
    assert policy.validate() == []


def test_derivation_is_idempotent_for_the_same_ledger():
    """Re-deriving must not mint a new id, or the history becomes unreadable."""
    cal = calibrate(_rows(6, FALSE_POSITIVE), ledger_head="h")
    assert derive_policy(cal).policy_id == derive_policy(cal).policy_id


def test_bootstrap_is_an_identity_policy():
    boot = CortexPolicy.bootstrap()
    assert boot.is_identity is True
    effect = boot.apply(tier="verified", confidence=0.93, rationale="r", cohort=COHORT)
    assert (effect.tier, effect.confidence, effect.changed) == ("verified", 0.93, False)


# ── I1 · no manufactured proof ──────────────────────────────────────────


def test_policy_can_never_raise_a_tier():
    """A hand-written directive aiming at 0.95 still cannot promote."""
    policy = CortexPolicy(
        version=1,
        directives={
            COHORT: CohortDirective(
                cohort=COHORT, action=ACTION_ADJUST, target_confidence=0.95,
                n_labeled=50, tp=50, fp=0, human_tp=50,
                precision_mean=0.99, precision_lower=0.93,
            )
        },
    )
    effect = policy.apply(
        tier="needs-review", confidence=0.5, rationale="r", cohort=COHORT
    )
    assert effect.tier == "needs-review"          # tier untouched
    assert effect.confidence == 0.65              # confidence moved by the cap only


def test_route_only_acts_on_promoted_tiers():
    policy = CortexPolicy(
        version=1,
        directives={
            COHORT: CohortDirective(
                cohort=COHORT, action=ACTION_ROUTE, n_labeled=10, tp=1, fp=9,
                precision_mean=0.13, precision_lower=0.02,
            )
        },
    )
    for tier in ("needs-review", "held"):
        effect = policy.apply(tier=tier, confidence=0.4, rationale="r", cohort=COHORT)
        assert effect.changed is False
        assert effect.tier == tier


# ── I2 · bounded movement ───────────────────────────────────────────────


def test_confidence_moves_by_at_most_the_cap():
    policy = CortexPolicy(
        version=1,
        directives={
            COHORT: CohortDirective(
                cohort=COHORT, action=ACTION_ADJUST, target_confidence=0.05,
                n_labeled=20, tp=1, fp=19, human_tp=1,
                precision_mean=0.07, precision_lower=0.01,
            )
        },
    )
    effect = policy.apply(tier="verified", confidence=0.93, rationale="r", cohort=COHORT)
    assert effect.confidence == round(0.93 - MAX_CONFIDENCE_DELTA, 6)
    assert effect.tier == "verified"


def test_out_of_band_target_is_rejected_by_validate():
    policy = CortexPolicy(
        version=1,
        directives={
            COHORT: CohortDirective(
                cohort=COHORT, action=ACTION_ADJUST, target_confidence=1.4,
                n_labeled=20, tp=20, fp=0, human_tp=20,
                precision_mean=0.99, precision_lower=0.9,
            )
        },
    )
    assert any("outside" in v for v in policy.validate())


def test_apply_clamps_even_an_out_of_band_target():
    """Runtime defense: an edited policy file still cannot exceed the band."""
    policy = CortexPolicy(
        version=1,
        directives={
            COHORT: CohortDirective(
                cohort=COHORT, action=ACTION_ADJUST, target_confidence=9.0,
                n_labeled=20, tp=20, fp=0, human_tp=20,
                precision_mean=0.99, precision_lower=0.9,
            )
        },
    )
    effect = policy.apply(tier="verified", confidence=0.93, rationale="r", cohort=COHORT)
    assert effect.confidence <= CONFIDENCE_CAP


# ── I3 · nothing disappears ─────────────────────────────────────────────


def test_no_directive_shape_can_produce_held_or_drop_a_finding():
    policy = derive_policy(calibrate(_rows(20, FALSE_POSITIVE), ledger_head="h"))
    for tier in ("verified", "high-confidence", "needs-review", "held"):
        effect = policy.apply(tier=tier, confidence=0.9, rationale="r", cohort=COHORT)
        assert effect.tier in ("verified", "high-confidence", "needs-review", "held")
        assert effect.tier != "held" or tier == "held"
        assert effect.confidence >= 0.05


# ── I4 · out of scope by construction ───────────────────────────────────


def test_unknown_action_verbs_are_rejected():
    """There is nowhere in the schema to express a Warden or sandbox change."""
    policy = CortexPolicy(
        version=1,
        directives={COHORT: CohortDirective(cohort=COHORT, action="disable-warden", n_labeled=99)},
    )
    assert any("unknown action" in v for v in policy.validate())
    effect = policy.apply(tier="verified", confidence=0.9, rationale="r", cohort=COHORT)
    assert effect.changed is False


def test_policy_body_has_no_safety_control_fields():
    body = json.dumps(CortexPolicy.bootstrap().body())
    for forbidden in ("warden", "egress", "redact", "backdoor", "capability", "sandbox"):
        assert forbidden not in body


# ── I5 · agents may not certify themselves ──────────────────────────────


def test_upward_directive_without_a_human_label_fails_validation():
    policy = CortexPolicy(
        version=1,
        directives={
            COHORT: CohortDirective(
                cohort=COHORT, action=ACTION_ADJUST, target_confidence=0.9,
                n_labeled=10, tp=10, fp=0, human_tp=0,
                precision_mean=0.95, precision_lower=0.7,
            )
        },
    )
    assert any("(I5)" in v for v in policy.validate())


# ── I6 · immutable and pinned ───────────────────────────────────────────


def test_policy_id_is_a_content_hash_of_behaviour_only():
    a = CortexPolicy(version=1, ledger_head="h", created_at="2026-01-01T00:00:00.000000Z")
    b = CortexPolicy(version=1, ledger_head="h", created_at="2026-09-09T00:00:00.000000Z")
    assert a.policy_id == b.policy_id


def test_changing_a_directive_changes_the_id():
    base = derive_policy(calibrate(_rows(6, FALSE_POSITIVE), ledger_head="h"))
    other = derive_policy(calibrate(_rows(8, FALSE_POSITIVE), ledger_head="h"))
    assert base.policy_id != other.policy_id


def test_saved_policies_are_never_rewritten(tmp_path):
    store = PolicyStore(tmp_path)
    policy = derive_policy(calibrate(_rows(6, FALSE_POSITIVE), ledger_head="h"))
    path = store.save(policy)
    original = path.read_text()
    store.save(policy)
    assert path.read_text() == original


def test_under_supported_directive_on_disk_is_ignored_at_runtime(tmp_path):
    policy = CortexPolicy(
        version=1,
        min_support=5,
        directives={
            COHORT: CohortDirective(
                cohort=COHORT, action=ACTION_ROUTE, n_labeled=1, tp=0, fp=1,
                precision_mean=0.25, precision_lower=0.0,
            )
        },
    )
    effect = policy.apply(tier="verified", confidence=0.93, rationale="r", cohort=COHORT)
    assert effect.changed is False


def test_store_activation_and_rollback_are_pointer_moves(tmp_path):
    store = PolicyStore(tmp_path)
    assert store.active().is_identity is True

    v1 = derive_policy(calibrate(_rows(6, FALSE_POSITIVE), ledger_head="h1"))
    store.activate(v1, approver="analyst-a")
    assert store.active().policy_id == v1.policy_id
    assert store.active_pointer()["approver"] == "analyst-a"

    v2 = derive_policy(calibrate(_rows(9, FALSE_POSITIVE), ledger_head="h2"), previous=v1)
    store.activate(v2, approver="analyst-b")
    assert store.active().policy_id == v2.policy_id

    store.activate(v1, approver="analyst-c")
    assert store.active().policy_id == v1.policy_id
    # Both versions remain on disk, byte-identical to when they were minted.
    assert {p.policy_id for p in store.history()} == {v1.policy_id, v2.policy_id}


def test_adjustment_record_carries_its_own_evidence():
    policy = derive_policy(calibrate(_rows(6, FALSE_POSITIVE), ledger_head="h"))
    effect = policy.apply(
        tier="high-confidence", confidence=0.82, rationale="two corroborators", cohort=COHORT
    )
    adj = effect.adjustments[0]
    assert adj.evidence["n_labeled"] == 6
    assert adj.evidence["fp"] == 6
    assert adj.evidence["policy_id"] == policy.policy_id
    assert "false positives" in adj.rationale
    assert "cortex" in effect.rationale
