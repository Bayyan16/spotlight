"""The gate. These tests are the argument for letting this run unattended.

Two hard zeros are pinned here: a policy may never demote a finding a sandbox
or a human confirmed was real, and may never grow more confident about one that
was wrong. Everything else — who may approve what — follows from those.
"""
from __future__ import annotations

from spotlight.cortex.experience import (
    FALSE_POSITIVE,
    SOURCE_ANALYST,
    SOURCE_REPRODUCTION,
    TRUE_POSITIVE,
    UNKNOWN,
    Experience,
)
from spotlight.cortex.governance import (
    SELF_APPROVER,
    GovernanceGates,
    GovernanceLog,
    Governor,
    check_gates,
    shadow_replay,
)
from spotlight.cortex.policy import (
    ACTION_ADJUST,
    ACTION_ROUTE,
    CohortDirective,
    CortexPolicy,
    PolicyStore,
)

NOISY = "ssti|independent_agent+static_analysis_fact"
SOLID = "sqli|dynamic_reproduction+independent_agent+static_analysis_fact"


def _row(cohort, label, source=SOURCE_ANALYST, tier="high-confidence", conf=0.82, key=None):
    return Experience(
        sweep_id="sw_1",
        finding_key=key or f"{cohort}-{label}-{conf}",
        class_=cohort.split("|", 1)[0],
        cohort=cohort,
        signature=cohort.split("|", 1)[1],
        tier=tier,
        confidence=conf,
        label=label,
        label_source=source,
    )


def _route_policy(cohort=NOISY, **kw):
    directive = dict(
        cohort=cohort, action=ACTION_ROUTE, n_labeled=10, tp=1, fp=9,
        precision_mean=0.14, precision_lower=0.02,
        rationale="9/10 were false positives",
    )
    directive.update(kw)
    return CortexPolicy(version=1, directives={cohort: CohortDirective(**directive)})


def _governor(tmp_path, signer=None, gates=None):
    return Governor(
        PolicyStore(tmp_path), GovernanceLog(tmp_path, signer=signer), gates=gates
    )


# ── shadow replay ───────────────────────────────────────────────────────


def test_shadow_counts_false_positive_demotions_as_the_benefit():
    rows = [_row(NOISY, FALSE_POSITIVE, key=f"k{i}") for i in range(4)]
    report = shadow_replay(_route_policy(), rows)
    assert report.fp_demoted == 4
    assert report.tp_demoted == 0
    assert report.beneficial_effects >= 4


def test_shadow_catches_a_demotion_of_a_reproduced_finding():
    """The regression that matters: quieting something the sandbox proved."""
    rows = [
        _row(NOISY, TRUE_POSITIVE, source=SOURCE_REPRODUCTION, tier="verified",
             conf=0.93, key="real-1"),
        _row(NOISY, FALSE_POSITIVE, key="noise-1"),
    ]
    report = shadow_replay(_route_policy(), rows)
    assert report.tp_demoted == 1
    assert report.demoted_true_positive_keys == ["real-1"]


def test_unlabeled_rows_score_neither_credit_nor_debit():
    rows = [_row(NOISY, UNKNOWN, source="unlabeled", key=f"u{i}") for i in range(5)]
    report = shadow_replay(_route_policy(), rows)
    assert report.rows_replayed == 5
    assert report.labeled_rows == 0
    assert report.fp_demoted == report.tp_demoted == 0


def test_a_policy_that_touches_nothing_reports_unchanged():
    rows = [_row(SOLID, TRUE_POSITIVE, tier="verified", conf=0.93, key=f"s{i}") for i in range(3)]
    report = shadow_replay(_route_policy(), rows)
    assert report.unchanged == 3


# ── gates ───────────────────────────────────────────────────────────────


def test_true_positive_demotion_is_a_hard_zero(tmp_path):
    rows = [
        _row(NOISY, TRUE_POSITIVE, source=SOURCE_REPRODUCTION, tier="verified",
             conf=0.93, key="real-1"),
        *[_row(NOISY, FALSE_POSITIVE, key=f"noise-{i}") for i in range(9)],
    ]
    shadow = shadow_replay(_route_policy(), rows)
    failures = check_gates(shadow, GovernanceGates())
    assert failures
    assert "demote 1 confirmed true positive" in failures[0]


def test_false_positive_boost_is_a_hard_zero():
    policy = CortexPolicy(
        version=1,
        directives={
            NOISY: CohortDirective(
                cohort=NOISY, action=ACTION_ADJUST, target_confidence=0.9,
                n_labeled=10, tp=9, fp=1, human_tp=9,
                precision_mean=0.86, precision_lower=0.6,
            )
        },
    )
    rows = [_row(NOISY, FALSE_POSITIVE, conf=0.4, key="noise-1")]
    shadow = shadow_replay(policy, rows)
    assert shadow.fp_boosted == 1
    assert any("false" in f for f in check_gates(shadow, GovernanceGates()))


def test_death_by_a_thousand_cuts_is_capped():
    """No demotions, but 20 small shavings off confirmed findings — still refused."""
    policy = CortexPolicy(
        version=1,
        directives={
            SOLID: CohortDirective(
                cohort=SOLID, action=ACTION_ADJUST, target_confidence=0.8,
                n_labeled=30, tp=25, fp=5, human_tp=25,
                precision_mean=0.83, precision_lower=0.66,
            )
        },
    )
    rows = [
        _row(SOLID, TRUE_POSITIVE, source=SOURCE_REPRODUCTION, tier="verified",
             conf=0.93, key=f"real-{i}")
        for i in range(20)
    ]
    shadow = shadow_replay(policy, rows)
    assert shadow.tp_demoted == 0
    assert shadow.tp_confidence_loss > 0.10
    assert any("cumulative confidence loss" in f for f in check_gates(shadow, GovernanceGates()))


def test_a_policy_with_no_measurable_benefit_is_refused():
    shadow = shadow_replay(_route_policy(), [])
    assert any("no measurable benefit" in f for f in check_gates(shadow, GovernanceGates()))


# ── bounded autonomy ────────────────────────────────────────────────────


def test_conservative_proposal_activates_itself(tmp_path):
    governor = _governor(tmp_path)
    rows = [_row(NOISY, FALSE_POSITIVE, key=f"n{i}") for i in range(6)]
    proposal = governor.propose(rows, ledger_head="h1")
    assert proposal.auto_activatable is True
    result = governor.activate(proposal)
    assert result.activated is True
    assert result.approver == SELF_APPROVER
    assert governor.store.active().policy_id == proposal.policy.policy_id


def test_an_assertive_proposal_is_withheld_from_the_cortex(tmp_path):
    """Upward movement needs a person, even when every gate passes."""
    governor = _governor(tmp_path)
    rows = [
        *[_row(NOISY, FALSE_POSITIVE, key=f"n{i}") for i in range(6)],
        *[_row(SOLID, TRUE_POSITIVE, tier="verified", conf=0.70, key=f"s{i}") for i in range(6)],
    ]
    proposal = governor.propose(rows, ledger_head="h1")
    assert proposal.policy.directives[SOLID].action == ACTION_ADJUST
    assert proposal.requires_human is True
    assert proposal.auto_activatable is False

    refused = governor.activate(proposal)
    assert refused.activated is False
    assert "human approver" in refused.reason
    assert governor.store.active().is_identity is True

    approved = governor.activate(proposal, approver="ciso@bank.example")
    assert approved.activated is True
    assert approved.approver == "ciso@bank.example"


def test_the_cortex_cannot_pose_as_a_human_approver(tmp_path):
    governor = _governor(tmp_path)
    rows = [
        *[_row(NOISY, FALSE_POSITIVE, key=f"n{i}") for i in range(6)],
        *[_row(SOLID, TRUE_POSITIVE, tier="verified", conf=0.70, key=f"s{i}") for i in range(6)],
    ]
    proposal = governor.propose(rows, ledger_head="h1")
    result = governor.activate(proposal, approver=SELF_APPROVER)
    assert result.activated is False


def test_an_inadmissible_proposal_is_refused_even_with_a_human(tmp_path):
    governor = _governor(tmp_path)
    rows = [
        _row(NOISY, TRUE_POSITIVE, source=SOURCE_REPRODUCTION, tier="verified",
             conf=0.93, key="real-1"),
        *[_row(NOISY, FALSE_POSITIVE, key=f"n{i}") for i in range(9)],
    ]
    proposal = governor.propose(rows, ledger_head="h1")
    assert proposal.admissible is False
    result = governor.activate(proposal, approver="ciso@bank.example")
    assert result.activated is False
    assert "gate failures" in result.reason
    assert governor.store.active().is_identity is True


def test_identity_proposal_is_not_activated(tmp_path):
    governor = _governor(tmp_path)
    proposal = governor.propose([], ledger_head="h0")
    result = governor.activate(proposal, approver="ciso@bank.example")
    assert result.activated is False


# ── rollback ────────────────────────────────────────────────────────────


def test_rollback_is_ungated_but_named(tmp_path):
    governor = _governor(tmp_path)
    rows = [_row(NOISY, FALSE_POSITIVE, key=f"n{i}") for i in range(6)]
    proposal = governor.propose(rows, ledger_head="h1")
    governor.activate(proposal)
    boot = CortexPolicy.bootstrap()
    governor.store.save(boot)

    anonymous = governor.rollback(boot.policy_id, approver="")
    assert anonymous.activated is False

    result = governor.rollback(boot.policy_id, approver="oncall@bank.example")
    assert result.activated is True
    assert governor.store.active().is_identity is True


def test_rollback_to_an_unknown_policy_fails(tmp_path):
    assert _governor(tmp_path).rollback("deadbeef", approver="x").activated is False


# ── audit trail ─────────────────────────────────────────────────────────


def test_every_decision_lands_in_the_governance_log(tmp_path):
    governor = _governor(tmp_path)
    rows = [_row(NOISY, FALSE_POSITIVE, key=f"n{i}") for i in range(6)]
    proposal = governor.propose(rows, ledger_head="h1")
    governor.activate(proposal)
    actions = [e["action"] for e in governor.log.entries()]
    assert actions == ["policy.proposed", "policy.activated"]


def test_a_refusal_is_recorded_with_its_reason(tmp_path):
    governor = _governor(tmp_path)
    rows = [
        _row(NOISY, TRUE_POSITIVE, source=SOURCE_REPRODUCTION, tier="verified",
             conf=0.93, key="real-1"),
        *[_row(NOISY, FALSE_POSITIVE, key=f"n{i}") for i in range(9)],
    ]
    governor.activate(governor.propose(rows, ledger_head="h1"))
    rejected = [e for e in governor.log.entries() if e["action"] == "policy.rejected"]
    assert rejected and "true positive" in rejected[0]["payload"]["reason"]


def test_activation_entries_are_signed_and_attribute_the_actor(tmp_path):
    from spotlight.non_repudiation import Signer
    from spotlight.non_repudiation.signing import verify_action

    signer = Signer()
    governor = _governor(tmp_path, signer=signer)
    rows = [_row(NOISY, FALSE_POSITIVE, key=f"n{i}") for i in range(6)]
    governor.activate(governor.propose(rows, ledger_head="h1"))

    activation = [e for e in governor.log.entries() if e["action"] == "policy.activated"][0]
    entry = activation["signature"]
    assert verify_action(entry, signer.public_key) is True
    # An agent's self-approval must never be recorded as a human action.
    assert entry["actor_kind"] == "agent"
    assert entry["actor_id"] == SELF_APPROVER


def test_human_activation_is_signed_as_a_human(tmp_path):
    from spotlight.non_repudiation import Signer

    signer = Signer()
    governor = _governor(tmp_path, signer=signer)
    rows = [
        *[_row(NOISY, FALSE_POSITIVE, key=f"n{i}") for i in range(6)],
        *[_row(SOLID, TRUE_POSITIVE, tier="verified", conf=0.70, key=f"s{i}") for i in range(6)],
    ]
    governor.activate(governor.propose(rows, ledger_head="h1"), approver="ciso@bank.example")
    activation = [e for e in governor.log.entries() if e["action"] == "policy.activated"][0]
    assert activation["signature"]["actor_kind"] == "human"
    assert activation["payload"]["autonomous"] is False


# ── retraction — the gate that keeps working after activation ────────────


def test_an_active_policy_that_becomes_harmful_is_retracted_unattended(tmp_path):
    """Evidence keeps arriving after a policy ships.

    A cohort that was 6/6 false positives when the policy was activated can
    hold a sandbox-confirmed exploit later. The activation gate has already
    run and cannot help; this is the check that notices, and it needs no human
    because returning to evidence-only tiering can only reveal, never hide.
    """
    governor = _governor(tmp_path)
    noisy = [_row(NOISY, FALSE_POSITIVE, key=f"n{i}") for i in range(6)]
    assert governor.activate(governor.propose(noisy, ledger_head="h1")).activated is True
    assert governor.store.active().is_identity is False

    # June: the same cohort now contains something the sandbox confirmed.
    now = noisy + [
        _row(NOISY, TRUE_POSITIVE, source=SOURCE_REPRODUCTION, tier="verified",
             conf=0.93, key="real-1")
    ]
    assert governor.audit_active(now).tp_demoted == 1

    result, shadow = governor.retract_if_harmful(now)
    assert result is not None and result.activated is True
    assert result.approver == SELF_APPROVER
    assert shadow.tp_demoted == 1
    assert governor.store.active().is_identity is True

    entry = [e for e in governor.log.entries() if e["action"] == "policy.retracted"][0]
    assert entry["payload"]["demoted_true_positive_keys"] == ["real-1"]
    assert entry["actor"] == SELF_APPROVER


def test_a_still_healthy_policy_is_left_alone(tmp_path):
    governor = _governor(tmp_path)
    noisy = [_row(NOISY, FALSE_POSITIVE, key=f"n{i}") for i in range(6)]
    governor.activate(governor.propose(noisy, ledger_head="h1"))
    active_before = governor.store.active().policy_id

    result, shadow = governor.retract_if_harmful(noisy)
    assert result is None
    assert shadow.tp_demoted == 0
    assert governor.store.active().policy_id == active_before


def test_retraction_is_a_no_op_under_the_identity_policy(tmp_path):
    governor = _governor(tmp_path)
    result, shadow = governor.retract_if_harmful([_row(NOISY, FALSE_POSITIVE, key="n1")])
    assert result is None and shadow is None


def test_evolve_retracts_before_it_proposes(tmp_path):
    """The whole cycle, through the façade an operator actually calls."""
    from spotlight.cortex import Cortex

    cortex = Cortex(root=tmp_path / "cortex")
    for i in range(6):
        cortex.ledger.append(
            _row(NOISY, FALSE_POSITIVE, key=f"n{i}")
        )
    assert cortex.evolve().activation.activated is True
    assert cortex.active_policy().is_identity is False

    cortex.ledger.append(
        _row(NOISY, TRUE_POSITIVE, source=SOURCE_REPRODUCTION, tier="verified",
             conf=0.93, key="real-1")
    )
    assert cortex.audit_active_policy().tp_demoted == 1

    report = cortex.evolve()
    assert report.retraction is not None
    assert report.retraction.activated is True
    assert cortex.active_policy().is_identity is True
    # And the replacement proposal is refused for the same reason.
    assert report.activation.activated is False
    assert "true positive" in report.activation.reason


def test_disabling_autonomy_does_not_disable_retraction(tmp_path):
    """Turning off self-activation must not turn off self-protection.

    `SPOTLIGHT_CORTEX_AUTONOMY=off` is an operator saying "propose, don't
    ship". It is not a request to keep running a policy that has started
    demoting confirmed findings — retraction is a safety action, not an
    evolution, and it runs either way.
    """
    from spotlight.cortex import Cortex

    cortex = Cortex(root=tmp_path / "cortex", autonomy=True)
    for i in range(6):
        cortex.ledger.append(_row(NOISY, FALSE_POSITIVE, key=f"n{i}"))
    assert cortex.evolve().activation.activated is True

    cortex.autonomy = False
    cortex.ledger.append(
        _row(NOISY, TRUE_POSITIVE, source=SOURCE_REPRODUCTION, tier="verified",
             conf=0.93, key="real-1")
    )
    report = cortex.evolve()
    assert report.retraction is not None and report.retraction.activated is True
    assert cortex.active_policy().is_identity is True
