"""The labelling policy is the Cortex's constitution at the data layer.

Every branch of `label_for` gets a test, because a wrong label here is not a
bug that shows up as a crash — it shows up six months later as a class of
vulnerability the tool quietly stopped reporting.
"""
from __future__ import annotations

from spotlight.cortex.experience import (
    FALSE_POSITIVE,
    SOURCE_ANALYST,
    SOURCE_REPRODUCTION,
    SOURCE_STATIC_FACT,
    SOURCE_UNLABELED,
    TRUE_POSITIVE,
    UNKNOWN,
    Experience,
    cohort_key,
    evidence_signature,
    is_weak_negative,
    label_for,
)


def _exp(**kw) -> Experience:
    base = dict(
        sweep_id="sw_1",
        finding_key="fp1",
        class_="sqli",
        cohort="sqli|independent_agent",
        signature="independent_agent",
        tier="verified",
        confidence=0.9,
    )
    base.update(kw)
    return Experience(**base)


# ── signatures and cohorts ──────────────────────────────────────────────


def test_evidence_signature_is_order_independent():
    """Agent scheduling order must not change which cohort a finding lands in."""
    a = evidence_signature(["independent_agent", "static_analysis_fact"])
    b = evidence_signature(["static_analysis_fact", "independent_agent"])
    assert a == b == "independent_agent+static_analysis_fact"


def test_evidence_signature_dedupes_and_drops_blanks():
    assert evidence_signature(["x", "x", "", "  "]) == "x"


def test_cohort_key_normalizes_class_case():
    assert cohort_key("SQLi", "a") == cohort_key("sqli", "a") == "sqli|a"


# ── labelling authority ─────────────────────────────────────────────────


def test_analyst_false_positive_is_the_only_negative_label():
    label, source, reason = label_for(
        class_="sqli", repro_result="confirmed", review_state="false-positive",
        has_static_fact=True, review_reason="test fixture, not reachable in prod",
    )
    # A human outranks a reproduction: if the analyst says the sandbox proved
    # something about a fixture rather than the product, the human wins.
    assert (label, source) == (FALSE_POSITIVE, SOURCE_ANALYST)
    assert "fixture" in reason


def test_analyst_accept_and_risk_accept_are_true_positives():
    for state in ("accepted", "risk-accepted"):
        label, source, _ = label_for(
            class_="ssrf", repro_result="", review_state=state, has_static_fact=False
        )
        assert (label, source) == (TRUE_POSITIVE, SOURCE_ANALYST)


def test_reproduction_confirms_without_a_human():
    label, source, _ = label_for(
        class_="cmdi", repro_result="confirmed", review_state=None, has_static_fact=False
    )
    assert (label, source) == (TRUE_POSITIVE, SOURCE_REPRODUCTION)


def test_not_reproduced_is_never_a_false_positive():
    """The single most important rule in the package.

    `not-reproduced` says our Reproducer has no template for this class — it
    says nothing about the code. Counting it as a false positive would teach
    the Cortex to bury exactly the classes it is weakest at (authz, IDOR,
    crypto misuse) while precision looked great.
    """
    for result in ("not-reproduced", "inconclusive", "not-applicable"):
        label, source, _ = label_for(
            class_="missing-authz", repro_result=result, review_state=None,
            has_static_fact=True,
        )
        assert label == UNKNOWN, result
        assert source == SOURCE_UNLABELED, result


def test_static_fact_classes_are_self_proving():
    label, source, _ = label_for(
        class_="secrets", repro_result="not-applicable", review_state=None,
        has_static_fact=True,
    )
    assert (label, source) == (TRUE_POSITIVE, SOURCE_STATIC_FACT)


def test_static_fact_shortcut_does_not_apply_to_other_classes():
    label, _, _ = label_for(
        class_="sqli", repro_result="not-reproduced", review_state=None,
        has_static_fact=True,
    )
    assert label == UNKNOWN


def test_weak_negative_flags_a_ran_but_silent_reproducer():
    assert is_weak_negative("not-reproduced") is True
    assert is_weak_negative("confirmed") is False
    assert is_weak_negative("") is False


# ── authority ordering ──────────────────────────────────────────────────


def test_analyst_row_supersedes_reproduction_row_for_same_finding():
    human = _exp(label=FALSE_POSITIVE, label_source=SOURCE_ANALYST)
    machine = _exp(label=TRUE_POSITIVE, label_source=SOURCE_REPRODUCTION)
    assert human.supersedes(machine) is True
    assert machine.supersedes(human) is False


def test_unlabeled_resweep_cannot_erase_a_human_verdict():
    human = _exp(label=FALSE_POSITIVE, label_source=SOURCE_ANALYST)
    resweep = _exp(label=UNKNOWN, label_source=SOURCE_UNLABELED)
    assert resweep.supersedes(human) is False


def test_supersedes_requires_the_same_finding():
    a = _exp(finding_key="a", label=FALSE_POSITIVE, label_source=SOURCE_ANALYST)
    b = _exp(finding_key="b", label=UNKNOWN, label_source=SOURCE_UNLABELED)
    assert a.supersedes(b) is False


# ── content addressing ──────────────────────────────────────────────────


def test_content_hash_ignores_timestamp_so_retries_dedupe():
    """A retried sweep must not inflate a cohort's counts."""
    a = _exp(ts="2026-01-01T00:00:00.000000Z")
    b = _exp(ts="2026-06-01T00:00:00.000000Z")
    assert a.content_hash() == b.content_hash()


def test_content_hash_changes_with_the_label():
    assert _exp(label=TRUE_POSITIVE).content_hash() != _exp(label=FALSE_POSITIVE).content_hash()


def test_round_trip_through_dict_tolerates_unknown_keys():
    raw = _exp().to_dict()
    raw["some_future_field"] = 1
    assert Experience.from_dict(raw).finding_key == "fp1"


def test_labeled_property():
    assert _exp(label=TRUE_POSITIVE).labeled is True
    assert _exp(label=UNKNOWN).labeled is False
