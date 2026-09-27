"""The Cortex HTTP surface.

Two things are checked here beyond the happy path: that the write surface is
narrow (there is no route that edits a policy or relaxes a gate), and that a
workspace with no Cortex configured says so cleanly instead of half-working.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from spotlight.api.app import app
from spotlight.cortex import SELF_APPROVER, Cortex, Experience
from spotlight.cortex.experience import (
    FALSE_POSITIVE,
    SOURCE_ANALYST,
    SOURCE_REPRODUCTION,
    TRUE_POSITIVE,
)

COHORT = "ssti|independent_agent+static_analysis_fact"


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def cortex_dir(tmp_path, monkeypatch):
    root = tmp_path / "cortex"
    monkeypatch.setenv("SPOTLIGHT_CORTEX_DIR", str(root))
    return root


def _seed(
    root, n=6, label=FALSE_POSITIVE, source=SOURCE_ANALYST, cohort=COHORT,
    tier="high-confidence",
):
    cortex = Cortex(root=root)
    for i in range(n):
        cortex.ledger.append(
            Experience(
                sweep_id="sw_1",
                finding_key=f"{label}-{i}",
                class_=cohort.split("|", 1)[0],
                cohort=cohort,
                signature=cohort.split("|", 1)[1],
                tier=tier,
                confidence=0.82,
                label=label,
                label_source=source,
                label_reason="our helper already escapes this",
                features={"path": "app/templates/render.py"},
            )
        )
    return cortex


# ── not configured ──────────────────────────────────────────────────────


def test_every_cortex_route_404s_when_memory_is_not_configured(client, monkeypatch):
    monkeypatch.delenv("SPOTLIGHT_CORTEX_DIR", raising=False)
    for path in (
        "/cortex/status", "/cortex/policy", "/cortex/policy/history",
        "/cortex/calibration", "/cortex/lessons", "/cortex/ledger/verify",
        "/cortex/governance",
    ):
        r = client.get(path)
        assert r.status_code == 404, path
        assert "SPOTLIGHT_CORTEX_DIR" in r.json()["detail"]


# ── reads ───────────────────────────────────────────────────────────────


def test_status_reports_an_identity_policy_on_a_fresh_workspace(client, cortex_dir):
    body = client.get("/cortex/status").json()
    assert body["policy"]["is_identity"] is True
    assert body["ledger"]["records"] == 0
    assert body["autonomy"] is True


def test_calibration_exposes_the_arithmetic_behind_a_directive(client, cortex_dir):
    _seed(cortex_dir)
    body = client.get("/cortex/calibration").json()
    stats = body["cohorts"][COHORT]
    assert stats["n_labeled"] == 6
    assert stats["fp"] == 6
    assert stats["actionable"] is True
    assert stats["precision_lower"] <= stats["precision_mean"]


def test_ledger_verify_reports_an_intact_chain(client, cortex_dir):
    _seed(cortex_dir, n=3)
    body = client.get("/cortex/ledger/verify").json()
    assert body["ok"] is True
    assert body["records"] == 3


def test_lessons_route_separates_served_from_quarantined(client, cortex_dir):
    cortex = _seed(cortex_dir, n=2)
    cortex.lessons.refresh(cortex.ledger.latest_by_finding().values())
    body = client.get("/cortex/lessons").json()
    assert body["served"]
    assert body["quarantined"] == []
    assert "escapes" in body["served"][0]["text"]


# ── evolution ───────────────────────────────────────────────────────────


def test_evolve_activates_a_conservative_proposal(client, cortex_dir):
    _seed(cortex_dir)
    body = client.post("/cortex/evolve").json()
    assert body["activation"]["activated"] is True
    assert body["activation"]["approver"] == SELF_APPROVER
    assert body["proposal"]["shadow"]["tp_demoted"] == 0

    active = client.get("/cortex/policy").json()
    assert active["policy"]["policy_id"] == body["activation"]["policy_id"]
    assert active["pointer"]["approver"] == SELF_APPROVER


def test_evolve_withholds_a_proposal_that_would_bury_a_real_finding(client, cortex_dir):
    root = cortex_dir
    _seed(root, n=9)
    _seed(root, n=1, label=TRUE_POSITIVE, source=SOURCE_REPRODUCTION, tier="verified")
    body = client.post("/cortex/evolve").json()
    assert body["activation"]["activated"] is False
    assert "true positive" in body["activation"]["reason"]
    assert client.get("/cortex/policy").json()["policy"]["is_identity"] is True


def test_activation_requires_a_named_human(client, cortex_dir):
    _seed(cortex_dir)
    # An empty or whitespace approver is a 400 from the handler (pydantic
    # accepts the string; the *meaning* of "nobody signed off" is ours to
    # reject). A missing field is a 422 from pydantic.
    assert client.post("/cortex/policy/activate", json={"approver": ""}).status_code == 400
    assert client.post("/cortex/policy/activate", json={"approver": "   "}).status_code == 400
    assert client.post("/cortex/policy/activate", json={}).status_code == 422
    r = client.post("/cortex/policy/activate", json={"approver": SELF_APPROVER})
    assert r.status_code == 400
    assert "cannot be used" in r.json()["detail"]


def test_activation_refuses_a_stale_pin(client, cortex_dir):
    _seed(cortex_dir)
    r = client.post(
        "/cortex/policy/activate",
        json={"approver": "ciso@bank.example", "policy_id": "stale-id"},
    )
    assert r.status_code == 409
    assert "ledger moved" in r.json()["detail"]


def test_history_marks_the_active_policy(client, cortex_dir):
    _seed(cortex_dir)
    client.post("/cortex/evolve")
    history = client.get("/cortex/policy/history").json()
    assert history["policies"]
    active = [p for p in history["policies"] if p["is_active"]]
    assert len(active) == 1
    assert active[0]["policy_id"] == history["active_policy_id"]


def test_rollback_needs_an_approver_and_a_known_policy(client, cortex_dir):
    _seed(cortex_dir)
    client.post("/cortex/evolve")
    assert client.post(
        "/cortex/policy/rollback", json={"policy_id": "nope", "approver": "x"}
    ).status_code == 400

    from spotlight.cortex import CortexPolicy

    boot = CortexPolicy.bootstrap()
    Cortex(root=cortex_dir).policies.save(boot)
    r = client.post(
        "/cortex/policy/rollback",
        json={"policy_id": boot.policy_id, "approver": "oncall@bank.example"},
    )
    assert r.status_code == 200
    assert client.get("/cortex/policy").json()["policy"]["is_identity"] is True


def test_governance_log_is_readable_and_capped(client, cortex_dir):
    _seed(cortex_dir)
    client.post("/cortex/evolve")
    body = client.get("/cortex/governance?limit=1").json()
    assert body["total"] >= 2
    assert len(body["entries"]) == 1


# ── write surface is narrow by construction ─────────────────────────────


def test_there_is_no_route_that_edits_a_policy_or_a_gate():
    """A learned change can only come from the ledger, through the governor."""
    cortex_routes = {
        (r.path, tuple(sorted(r.methods)))
        for r in app.routes
        if getattr(r, "path", "").startswith("/cortex")
    }
    writes = {path for path, methods in cortex_routes if "POST" in methods}
    assert writes == {
        "/cortex/evolve",
        "/cortex/policy/activate",
        "/cortex/policy/rollback",
    }
    assert not any(
        m in methods for _, methods in cortex_routes for m in ("PUT", "PATCH", "DELETE")
    )


# ── the benchmark must not grade its own homework ────────────────────────


def test_eval_harness_runs_with_memory_disabled(monkeypatch, tmp_path):
    """A paired-CVE run must never be tiered by a policy it also trains.

    The harness gates CI, so a sweep that harvests its findings into the
    ledger and is then judged under a policy derived from that ledger would be
    measuring itself. `use_cortex=False` is the opt-out, and it has to beat the
    environment variable.
    """
    from spotlight.orchestrator import Orchestrator

    monkeypatch.setenv("SPOTLIGHT_CORTEX_DIR", str(tmp_path / "cortex"))
    assert Orchestrator().cortex is not None
    assert Orchestrator(use_cortex=False).cortex is None


def test_eval_module_opts_out_explicitly():
    """Pin the call site — a future refactor must not silently re-enable it."""
    import inspect

    from spotlight.eval import paired_cve

    source = inspect.getsource(paired_cve)
    assert "Orchestrator(use_cortex=False)" in source


def test_injected_cortex_signer_is_adopted_for_the_chain_of_custody(tmp_path):
    """One workspace key must verify a whole sweep.

    The Cortex signs every ledger row; the orchestrator signs every chain-of-
    custody entry. If those are two different key instances, an auditor needs
    two public keys to check one attestation — and with no persistent
    SPOTLIGHT_SIGNING_KEY they would be two *different* ephemeral keys.
    """
    from spotlight.cortex import Cortex
    from spotlight.non_repudiation import Signer
    from spotlight.orchestrator import Orchestrator

    cortex = Cortex(root=tmp_path / "cortex", signer=Signer())
    orch = Orchestrator(cortex=cortex)
    assert orch._signer is cortex.signer
    assert orch._signer.fingerprint == cortex.signer.fingerprint


def test_a_stale_pin_is_refused_before_anything_is_activated(client, cortex_dir):
    """The refusal must come before the side effect, not after it."""
    _seed(cortex_dir)
    r = client.post(
        "/cortex/policy/activate",
        json={"approver": "ciso@bank.example", "policy_id": "stale"},
    )
    assert r.status_code == 409
    # Nothing was activated, and the look did not leave a second proposal row.
    assert client.get("/cortex/policy").json()["policy"]["is_identity"] is True
    actions = [e["action"] for e in client.get("/cortex/governance").json()["entries"]]
    assert actions == []


def test_propose_does_not_activate_or_log_when_only_looking(tmp_path):
    from spotlight.cortex import Cortex

    cortex = Cortex(root=tmp_path / "cortex")
    _seed(tmp_path / "cortex")
    proposal = cortex.propose(record=False)
    assert proposal.policy.directives
    assert cortex.active_policy().is_identity is True
    assert cortex.governance.entries() == []


def test_status_exposes_the_standing_audit_of_the_policy_in_force(client, cortex_dir):
    """An operator should not learn from a moved tier that the policy went stale."""
    from spotlight.cortex import Cortex, Experience
    from spotlight.cortex.experience import SOURCE_REPRODUCTION, TRUE_POSITIVE

    _seed(cortex_dir)
    assert client.post("/cortex/evolve").json()["activation"]["activated"] is True
    assert client.get("/cortex/status").json()["active_policy_audit"]["tp_demoted"] == 0

    # A sandbox-confirmed finding lands in the routed cohort.
    Cortex(root=cortex_dir).ledger.append(
        Experience(
            sweep_id="sw_2",
            finding_key="confirmed-real",
            class_="ssti",
            cohort=COHORT,
            signature=COHORT.split("|", 1)[1],
            tier="verified",
            confidence=0.93,
            label=TRUE_POSITIVE,
            label_source=SOURCE_REPRODUCTION,
        )
    )
    assert client.get("/cortex/status").json()["active_policy_audit"]["tp_demoted"] == 1

    # The next cycle retracts it without being asked.
    body = client.post("/cortex/evolve").json()
    assert body["retraction"]["activated"] is True
    assert client.get("/cortex/policy").json()["policy"]["is_identity"] is True
