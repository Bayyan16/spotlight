"""C3 · plain-language "why this matters" per finding.

The mock produces canned per-class prose so demos + regression tests are
deterministic. The real model produces bespoke prose but must respect the
same output shape — three short paragraphs, no jargon.

Tests here pin the mock's contract: the six most common classes get
custom copy, unknown classes fall back to a generic stub, and the shape
is stable across calls.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from spotlight.agents.model import MockModelClient
from spotlight.orchestrator import Orchestrator


def _explain(cls: str) -> dict:
    return MockModelClient().complete(
        role="plain-language",
        prompt="explain",
        context={"finding": {"class": cls, "location": {"file": "app/db.py"}}},
    )


@pytest.mark.parametrize(
    "cls",
    ["sqli", "ssrf", "cmdi", "secrets", "prompt-injection", "excessive-agency"],
)
def test_known_classes_have_bespoke_copy(cls):
    resp = _explain(cls)
    for key in ("one_liner", "blast_radius", "urgency"):
        assert resp[key], f"{cls} missing {key}"
    # Sanity: bespoke copy mentions class-specific concepts.
    joined = " ".join(resp.values()).lower()
    if cls == "sqli":
        assert "database" in joined or "sql" in joined.lower()
    if cls == "ssrf":
        assert "url" in joined
    if cls == "secrets":
        assert "credential" in joined or "key" in joined
    if cls == "prompt-injection":
        assert "model" in joined or "llm" in joined or "ai" in joined


def test_unknown_class_falls_back():
    resp = _explain("some-brand-new-class")
    assert resp["one_liner"]
    assert resp["blast_radius"]
    assert resp["urgency"]


def test_no_jargon_regression():
    """Ban a small set of obviously-jargon words the plain-language mock
    must not use — this is what makes it 'plain-language' vs. the technical
    root_cause block that already exists on the finding."""
    banned = {"cwe-", "canonicaliz", "corroborat", "adjudicat"}
    for cls in ("sqli", "ssrf", "cmdi", "secrets"):
        resp = _explain(cls)
        joined = " ".join(str(v) for v in resp.values()).lower()
        for word in banned:
            assert word not in joined, f"{cls} has banned jargon: {word}"


def test_orchestrator_populates_plain_language_on_findings(tmp_path):
    acme = Path(__file__).resolve().parents[2] / "targets" / "acme-bank"
    if not (acme / "app.py").exists():
        pytest.skip("acme-bank fixture missing")
    result = Orchestrator().run(acme, out_dir=tmp_path / "sweep")
    assert result.findings
    for f in result.findings:
        pl = f.get("plain_language") or {}
        assert isinstance(pl, dict), f"finding {f['id']} plain_language not a dict"
        assert pl.get("one_liner"), f"finding {f['id']} missing one_liner"
