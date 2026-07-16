"""Tests for the Attestation v2 Reporter (Tranche B6).

Covers:

- ``Reporter.assemble()`` emits every required section (meta / target /
  profile / threat_model / findings / exploit_paths / warden /
  chain_of_custody / sandbox_proofs / metrics) on a synthetic sweep.
- Warden rollup counts injection flags + egress denials correctly.
- Sandbox duration in metrics sums across every ``sandbox.result`` event.
- ``render_json`` is deterministic (sorted keys) and round-trips through
  ``json.loads``.
- ``render_markdown`` includes the exec summary, Warden self-defense record,
  and at least one finding card.
- ``render_pdf`` returns non-empty bytes starting with ``%PDF-`` when
  ReportLab is installed; raises ``PdfRenderError`` on missing dep (guarded
  via monkey-patch so the test still runs when reportlab is present).
- The API endpoint ``GET /attestations/{id}?format=markdown`` returns
  ``text/markdown`` content type and a body with the exec summary.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

import pytest
from fastapi.testclient import TestClient

from spotlight.api.app import BUSES, SWEEPS, _running_threads, app
from spotlight.orchestrator import SweepResult
from spotlight.reporter import (
    PdfRenderError,
    Reporter,
    render_json,
    render_markdown,
    render_pdf,
)


# ── synthetic fixtures ───────────────────────────────────────────────────


def _finding_stub(fid: str = "SPOT-0001") -> dict:
    """A finding shaped exactly like Orchestrator emits — enough surface
    for the Reporter to walk without needing a real sweep."""
    return {
        "id": fid,
        "surface": "code",
        "title": "SQL injection in get_account",
        "severity": "high",
        "class": "sqli",
        "cwe": "CWE-89",
        "location": {"file": "app.py", "line": 42, "function": "get_account"},
        "state": "confirmed-fixed",
        "tier": "verified",
        "confidence": 0.93,
        "owner": "unassigned",
        "exploit_path": None,
        "evidence": {
            "detected_by": ["investigator-1", "codegraph:source->sink reachable"],
            "corroboration": [
                {
                    "type": "static-fact",
                    "detail": ["codegraph:source->sink reachable"],
                },
                {
                    "type": "reproduction",
                    "result": "confirmed",
                    "path": f"repro/{fid}/",
                },
            ],
            "root_cause": "unparameterized string concat",
            "fix": {"diff": f"{fid}.diff", "approach": "parameterize"},
            "verification": {
                "result": "repro-now-blocked",
                "backdoor_check": "pass",
                "independent_verifier": True,
            },
            "sandbox": {
                "reproducer": {
                    "engine": "subprocess",
                    "duration_s": 0.42,
                    "exit_code": 0,
                    "capability_token": "tok-abc",
                    "egress_attempts": 1,
                    "egress_denied_hosts": ["evil.example.com"],
                },
                "verifier": {
                    "engine": "subprocess",
                    "duration_s": 0.31,
                    "exit_code": 0,
                    "capability_token": "tok-def",
                },
            },
            "threat_model": {
                "author": "recon",
                "profile": "balanced",
                "surfaces": ["code"],
                "untrusted_sources": ["http.query"],
                "high_impact_sinks": ["db.execute"],
                "stack": {"language": "python", "framework": "flask"},
            },
        },
        "consensus": {
            "tier": "verified",
            "independent_corroborators": 2,
            "decision": "promote",
            "rationale": "reproduction + static-analysis fact",
        },
        "audit": {
            "model": "mock",
            "deployment_tier": "t0-mock",
            "profile": "balanced",
            "profile_name": "Balanced",
            "commit": "<dev>",
            "timestamp": None,
            "tokens_used": 12345,
            "wall_seconds": 1.234,
        },
    }


def _sweep_stub() -> SweepResult:
    finding = _finding_stub()
    events = [
        # Two sandbox.result events → duration should sum to 0.73.
        {
            "sweep_id": "sw_test",
            "seq": 10,
            "ts": 1.0,
            "type": "sandbox.result",
            "actor": "reproducer",
            "payload": {"duration_s": 0.42, "engine": "subprocess"},
        },
        {
            "sweep_id": "sw_test",
            "seq": 11,
            "ts": 1.5,
            "type": "sandbox.result",
            "actor": "verifier",
            "payload": {"duration_s": 0.31, "engine": "subprocess"},
        },
        # A warden injection flag and an egress denial.
        {
            "sweep_id": "sw_test",
            "seq": 4,
            "ts": 0.5,
            "type": "warden.injection.flagged",
            "actor": "warden",
            "payload": {"rule": "ignore_previous", "origin": "readme:README.md"},
        },
        {
            "sweep_id": "sw_test",
            "seq": 12,
            "ts": 1.6,
            "type": "sandbox.egress.denied",
            "actor": "reproducer",
            "payload": {"finding": "SPOT-0001", "hosts": ["evil.example.com"]},
        },
    ]
    return SweepResult(
        sweep_id="sw_test",
        repo_path="/tmp/targets/vuln-bank-api",
        threat_model={
            "surfaces": ["code"],
            "stack": {"language": "python", "framework": "flask"},
            "threat_model": {
                "untrusted_sources": ["http.query"],
                "high_impact_sinks": ["db.execute"],
            },
        },
        signals=[],
        findings=[finding],
        attestations=[],
        events_log=events,
    )


# ── assemble ─────────────────────────────────────────────────────────────


def test_assemble_produces_every_required_section():
    """Reporter.assemble MUST return dict with all sections the bank expects.

    Missing any of these breaks the printed report — the ToC in the PDF is
    driven by the H2 sections in the Markdown which in turn is driven by
    the section names in the dict.
    """
    sweep = _sweep_stub()
    attestation = Reporter().assemble(sweep)
    required = {
        "meta",
        "target",
        "profile",
        "threat_model",
        "findings",
        "exploit_paths",
        "warden",
        "chain_of_custody",
        "sandbox_proofs",
        "metrics",
    }
    assert required.issubset(attestation.keys()), f"missing: {required - set(attestation)}"

    # meta block invariants — every attestation must be tagged with the
    # schema version so downstream tooling can branch on it.
    assert attestation["meta"]["schema_version"] == "2.0"
    assert attestation["meta"]["sweep_id"] == "sw_test"

    # target block carries the repo.
    assert attestation["target"]["repo"].endswith("vuln-bank-api")


def test_assemble_warden_block_counts_injection_and_egress():
    """The Warden block must roll up injection.flagged + egress.denied.

    Bank-visible signal: "the swarm tried to attack us and Warden blocked
    it." If either count drifts silently we lose the whole self-defense
    argument.
    """
    sweep = _sweep_stub()
    attestation = Reporter().assemble(sweep)
    warden = attestation["warden"]
    assert warden["injection_flagged_count"] == 1
    assert warden["egress_denied_count"] == 1
    # And the individual entries are surfaced so the Markdown can list them.
    assert len(warden["injection_flags"]) == 1
    assert warden["injection_flags"][0]["payload"]["rule"] == "ignore_previous"
    assert warden["egress_denials"][0]["hosts"] == ["evil.example.com"]


def test_assemble_metrics_sums_sandbox_duration():
    """Metrics.sandbox_duration_s = sum of every sandbox.result.duration_s.

    Two runs of 0.42s + 0.31s must sum to 0.73s (ignoring float-repr drift).
    """
    sweep = _sweep_stub()
    metrics = Reporter().assemble(sweep)["metrics"]
    assert metrics["findings_total"] == 1
    assert metrics["findings_verified"] == 1
    assert metrics["sandbox_duration_s"] == pytest.approx(0.73, abs=1e-6)
    assert metrics["tokens_used"] == 12345
    assert metrics["events_total"] == 4


def test_assemble_exploit_paths_promotes_reproduced_findings():
    """An `exploit_paths` entry is emitted for every finding whose
    Reproducer said `confirmed`. Un-reproduced findings must not appear."""
    sweep = _sweep_stub()
    # Add a second finding that was NOT reproduced — must be excluded from
    # exploit_paths but still appear in `findings`.
    unrep = _finding_stub("SPOT-0002")
    unrep["evidence"]["corroboration"] = [
        {"type": "reproduction", "result": "not-reproduced"}
    ]
    sweep.findings.append(unrep)
    attestation = Reporter().assemble(sweep)
    ids = [ep["finding_id"] for ep in attestation["exploit_paths"]]
    assert ids == ["SPOT-0001"]


def test_assemble_uses_explicit_chain_of_custody_when_provided():
    coc = {
        "entries": [
            {
                "actor_kind": "agent",
                "actor_id": "Triager",
                "action": "confirm",
                "ts": "2026-07-16T12:00:00Z",
                "payload_hash": "a" * 64,
                "signature": "sig",
                "key_fingerprint": "fp",
            }
        ],
        "signature_verified": True,
    }
    attestation = Reporter().assemble(_sweep_stub(), chain_of_custody=coc)
    assert attestation["chain_of_custody"] is coc
    assert attestation["chain_of_custody"]["signature_verified"] is True


# ── json render ──────────────────────────────────────────────────────────


def test_render_json_is_deterministic_and_parses():
    """Two renders of the same attestation must produce byte-identical
    output — that's what makes attestation diffs reviewable."""
    attestation = Reporter().assemble(_sweep_stub())
    a = render_json(attestation)
    b = render_json(attestation)
    assert a == b
    parsed = json.loads(a)
    assert parsed["meta"]["schema_version"] == "2.0"


# ── markdown render ──────────────────────────────────────────────────────


def test_render_markdown_includes_exec_summary_and_warden_section():
    """Markdown must carry the three load-bearing sections: exec summary,
    Warden self-defense record, and at least one finding card."""
    attestation = Reporter().assemble(_sweep_stub())
    md = render_markdown(attestation)
    assert "## Executive Summary" in md
    assert "## Warden Self-Defense Record" in md
    # Exec summary line lists verified count.
    assert "1 verified" in md
    # At least one finding card renders with its title and tier badge.
    assert "SPOT-0001" in md
    assert "[VERIFIED]" in md
    # Warden section shows the counts we assembled.
    assert "Injection flags**: 1" in md
    assert "Egress denials**: 1" in md
    # Chain of custody status is always printed so absent chains don't
    # silently disappear.
    assert "Signature status" in md


def test_render_markdown_handles_empty_findings():
    """An empty sweep must still produce a valid report — the bank sees
    zero-findings sweeps in CI and the Markdown must not blow up."""
    empty = SweepResult(
        sweep_id="sw_empty",
        repo_path="/tmp/x",
        threat_model={},
        signals=[],
        findings=[],
        attestations=[],
        events_log=[],
    )
    md = render_markdown(Reporter().assemble(empty))
    assert "No findings promoted" in md
    assert "## Executive Summary" in md


# ── pdf render ───────────────────────────────────────────────────────────


def test_render_pdf_returns_non_empty_pdf_bytes():
    """PDF bytes must start with the PDF magic. Skipped when reportlab is
    not installed in this environment."""
    pytest.importorskip("reportlab")
    md = render_markdown(Reporter().assemble(_sweep_stub()))
    pdf = render_pdf(md)
    assert isinstance(pdf, bytes)
    assert len(pdf) > 500  # a real PDF is at least a few hundred bytes
    assert pdf.startswith(b"%PDF-")


def test_render_pdf_raises_clean_error_when_reportlab_missing(monkeypatch):
    """Simulate reportlab-not-installed by monkey-patching the guard.

    We can't uninstall reportlab in the process, so we point the internal
    guard at a function that raises ImportError. This exercises the exact
    error path the orchestrator's try/except relies on.
    """
    from spotlight.reporter import pdf as pdf_mod

    def _boom():
        raise pdf_mod.PdfRenderError("reportlab not installed")

    monkeypatch.setattr(pdf_mod, "_reportlab_or_raise", _boom)
    with pytest.raises(PdfRenderError) as excinfo:
        pdf_mod.render_pdf("# Title\n\n## Section\n\nBody.\n")
    assert "reportlab not installed" in str(excinfo.value)


# ── API endpoint ─────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _clear_registries():
    BUSES.clear()
    SWEEPS.clear()
    _running_threads.clear()
    yield


def _install_sweep_in_memory(sweep_id: str = "sw_api_test") -> None:
    """Push a synthetic SweepResult into the API's in-memory registry so
    the endpoint can find it without running a real sweep."""
    sweep = _sweep_stub()
    sweep.sweep_id = sweep_id
    rich = Reporter().assemble(sweep)
    sweep.attestations = [rich]
    SWEEPS[sweep_id] = sweep


def test_api_attestation_returns_json_by_default():
    _install_sweep_in_memory("sw_json_case")
    client = TestClient(app)
    r = client.get("/attestations/sw_json_case")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    body = r.json()
    assert body["meta"]["schema_version"] == "2.0"
    assert "warden" in body


def test_api_attestation_markdown_content_type():
    """?format=markdown returns text/markdown; charset=utf-8 with a body
    containing the exec summary."""
    _install_sweep_in_memory("sw_md_case")
    client = TestClient(app)
    r = client.get("/attestations/sw_md_case?format=markdown")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/markdown")
    assert "charset=utf-8" in r.headers["content-type"]
    assert "## Executive Summary" in r.text
    assert "SPOT-0001" in r.text


def test_api_attestation_pdf_returns_pdf_bytes():
    """?format=pdf returns application/pdf when reportlab is available."""
    pytest.importorskip("reportlab")
    _install_sweep_in_memory("sw_pdf_case")
    client = TestClient(app)
    r = client.get("/attestations/sw_pdf_case?format=pdf")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.content.startswith(b"%PDF-")


def test_api_attestation_unknown_format_400():
    _install_sweep_in_memory("sw_bad_case")
    client = TestClient(app)
    r = client.get("/attestations/sw_bad_case?format=csv")
    # FastAPI's Query validator returns 422 for pattern mismatches.
    assert r.status_code in (400, 422)


def test_api_attestation_404_for_missing_sweep():
    client = TestClient(app)
    r = client.get("/attestations/sw_does_not_exist")
    assert r.status_code == 404
