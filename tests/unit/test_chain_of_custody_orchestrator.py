"""Orchestrator auto-populates finding.audit.chain_of_custody.

R1 refinement — the Ed25519 signer + ChainOfCustody class have shipped for
weeks, but the orchestrator's per-finding loop never called them. Findings
landed with an empty stub. This test suite pins the shape and content that
downstream verifiers rely on.

Guarantees:
  * every finding carries a non-empty chain_of_custody
  * canonical actors + actions appear in order (investigator → reproducer →
    remediator (if applied) → verifier → consensus)
  * every entry independently verifies against the workspace public key
  * signing failure never crashes the sweep — chain degrades to [] instead
"""
from __future__ import annotations

import base64
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from spotlight.non_repudiation import Signer, verify_action
from spotlight.orchestrator import Orchestrator


@pytest.fixture(autouse=True)
def deterministic_workspace_key(monkeypatch):
    """Pin SPOTLIGHT_SIGNING_KEY so the orchestrator's Signer and the test's
    verify_action() share a public key. Without this, each Signer() call
    generates an ephemeral key that no external verifier can check."""
    priv = Ed25519PrivateKey.generate()
    raw = priv.private_bytes_raw()
    monkeypatch.setenv("SPOTLIGHT_SIGNING_KEY", base64.b64encode(raw).decode("ascii"))


@pytest.fixture
def acme_repo() -> Path:
    root = Path(__file__).resolve().parents[2] / "targets" / "acme-bank"
    if not (root / "app.py").exists():
        pytest.skip("acme-bank fixture missing")
    return root


def test_finding_has_signed_chain_of_custody(acme_repo, tmp_path):
    result = Orchestrator().run(acme_repo, out_dir=tmp_path / "sweep")
    assert result.findings, "sweep produced no findings"
    for f in result.findings:
        coc = (f.get("audit") or {}).get("chain_of_custody") or []
        assert isinstance(coc, list), f"chain_of_custody not a list: {type(coc)}"
        assert len(coc) >= 2, f"finding {f['id']} has {len(coc)} entries"
        # Canonical actor order — investigator raises first, consensus decides
        # last. Between them, at least reproducer + verifier must appear.
        actor_ids = [e.get("actor_id") for e in coc]
        assert actor_ids[0] == "investigator"
        assert actor_ids[-1] == "consensus"
        assert "reproducer" in actor_ids
        assert "verifier" in actor_ids


def test_every_entry_verifies_against_workspace_key(acme_repo, tmp_path):
    result = Orchestrator().run(acme_repo, out_dir=tmp_path / "sweep")
    pub = Signer().public_key
    for f in result.findings:
        for entry in (f.get("audit") or {}).get("chain_of_custody") or []:
            assert verify_action(entry, pub), (
                f"entry did not verify: finding={f['id']} action={entry.get('action')}"
            )


def test_entries_carry_finding_id_and_action(acme_repo, tmp_path):
    """Downstream tooling groups by finding_id in the payload; enforce it."""
    result = Orchestrator().run(acme_repo, out_dir=tmp_path / "sweep")
    for f in result.findings:
        for entry in (f.get("audit") or {}).get("chain_of_custody") or []:
            assert entry.get("action"), "entry missing action"
            assert entry.get("actor_kind") == "agent"
            assert entry.get("key_fingerprint"), "entry missing key_fingerprint"
            assert entry.get("payload_hash"), "entry missing payload_hash"
            assert entry.get("signature"), "entry missing signature"
            assert entry.get("ts"), "entry missing timestamp"


def test_sweep_attestation_aggregates_all_finding_entries(acme_repo, tmp_path):
    """attestation.chain_of_custody.entries should be the union of every
    per-finding entry plus any SWEEP-LEVEL signed actions (currently:
    the Planner's `plan.rules-written` — one entry per sweep when the
    Planner ran)."""
    result = Orchestrator().run(acme_repo, out_dir=tmp_path / "sweep")
    per_finding_total = sum(
        len((f.get("audit") or {}).get("chain_of_custody") or [])
        for f in result.findings
    )
    assert result.attestations, "no attestation produced"
    coc = result.attestations[0].get("chain_of_custody") or {}
    entries = coc.get("entries", [])
    # Count sweep-level signed actions (non-finding-scoped). Today: just
    # the planner. If we add more (e.g., recon-threat-model-signed) they
    # go here too.
    sweep_level = sum(
        1
        for e in entries
        if e.get("action", "").startswith("plan.")
    )
    assert len(entries) == per_finding_total + sweep_level, (
        f"expected per-finding {per_finding_total} + sweep-level "
        f"{sweep_level} entries, got {len(entries)}"
    )


def test_signer_failure_degrades_gracefully(acme_repo, tmp_path, monkeypatch):
    """If the workspace signer can't be created, findings still ship — with
    an empty chain_of_custody, not a raised exception."""
    from spotlight.orchestrator import orchestrator as orch_mod

    monkeypatch.setattr(orch_mod, "_get_signer", lambda: None)
    result = Orchestrator().run(acme_repo, out_dir=tmp_path / "sweep")
    assert result.findings
    for f in result.findings:
        coc = (f.get("audit") or {}).get("chain_of_custody")
        assert coc == [], f"expected empty coc, got {coc}"
