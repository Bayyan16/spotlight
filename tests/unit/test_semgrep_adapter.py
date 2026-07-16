"""Semgrep Signal Adapter — tests.

These cover the local invariants without touching the real semgrep CLI:
canonical class mapping, slice-shape normalisation, missing-executable
graceful degradation. A separate live-semgrep test lives behind an env
gate so CI doesn't slow down.
"""
from __future__ import annotations

import os
import json
import shutil
from pathlib import Path

import pytest

from spotlight.signals.semgrep_adapter import (
    SemgrepAdapter,
    SemgrepMatch,
    _canonical_class,
    _extract_matches,
)


# ── canonical-class table ───────────────────────────────────────────────

def test_canonical_class_maps_sqli_variants():
    for check_id in [
        "python.flask.security.injection.tainted-sql-string",
        "python.sqlalchemy.security.sqlalchemy-execute-raw-query",
        "javascript.express.sql-injection",
    ]:
        assert _canonical_class(check_id) == "sqli"


def test_canonical_class_maps_cmdi_variants():
    for check_id in [
        "python.lang.security.dangerous-subprocess",
        "javascript.node.dangerous-system-call",
    ]:
        assert _canonical_class(check_id) == "cmdi"


def test_canonical_class_maps_secrets_variants():
    for check_id in [
        "python.lang.security.hardcoded-password",
        "generic.secrets.hardcoded-token",
    ]:
        assert _canonical_class(check_id) == "secrets"


def test_canonical_class_returns_none_for_unknown():
    assert _canonical_class("style.python.line-too-long") is None
    assert _canonical_class("") is None


# ── extract_matches shape ───────────────────────────────────────────────

def test_extract_matches_parses_typical_output():
    fake = {
        "results": [
            {
                "check_id": "python.flask.security.injection.tainted-sql-string",
                "path": "app.py",
                "start": {"line": 42},
                "end": {"line": 44},
                "extra": {
                    "severity": "ERROR",
                    "message": "Tainted string reaches SQL execute.",
                    "lines": "cursor.execute(query)",
                },
            },
            # This one has no canonical mapping — should be filtered out.
            {
                "check_id": "style.python.line-too-long",
                "path": "app.py",
                "start": {"line": 100},
                "end": {"line": 100},
                "extra": {"severity": "INFO", "message": "line too long"},
            },
        ]
    }
    matches = _extract_matches(fake)
    assert len(matches) == 1
    m = matches[0]
    assert m.class_ == "sqli"
    assert m.file == "app.py"
    assert m.line == 42
    assert m.severity == "ERROR"
    assert m.origin == "signal:semgrep"


def test_extract_matches_empty_when_no_results():
    assert _extract_matches({}) == []
    assert _extract_matches({"results": []}) == []


# ── SemgrepMatch → slice-dict ──────────────────────────────────────────

def test_match_as_slice_dict_matches_datflowslice_shape():
    m = SemgrepMatch(
        file="app.py", line=42, end_line=42,
        check_id="python.flask.security.injection.tainted-sql-string",
        class_="sqli", severity="ERROR",
        message="Tainted string reaches SQL execute.",
        snippet="cursor.execute(query)",
    )
    d = m.as_slice_dict()
    assert d["file"] == "app.py"
    assert d["sink"]["class"] == "sqli"
    assert d["sink"]["line"] == 42
    assert d["sanitized"] is False
    assert d["external_signal"] is True
    assert d["source"]["origin"].startswith("signal:semgrep")
    assert "semgrep" in d["reason"]


# ── graceful degradation ────────────────────────────────────────────────

def test_adapter_returns_empty_when_semgrep_missing(monkeypatch):
    """When the CLI is not on PATH, .scan() returns [] and never raises."""
    monkeypatch.setattr(
        "spotlight.signals.semgrep_adapter.shutil.which",
        lambda _cmd: None,
    )
    a = SemgrepAdapter()
    assert a.available() is False
    assert a.scan(Path(".")) == []


def test_adapter_returns_empty_on_subprocess_timeout(monkeypatch, tmp_path):
    """Timeout mid-scan must not crash the sweep."""
    import subprocess

    def boom(*a, **kw):
        raise subprocess.TimeoutExpired(cmd="semgrep", timeout=30)

    monkeypatch.setattr(
        "spotlight.signals.semgrep_adapter.shutil.which",
        lambda _cmd: "/usr/local/bin/semgrep",
    )
    monkeypatch.setattr(
        "spotlight.signals.semgrep_adapter.subprocess.run",
        boom,
    )
    assert SemgrepAdapter().scan(tmp_path) == []


# ── live end-to-end (env-gated) ─────────────────────────────────────────

@pytest.mark.skipif(
    not shutil.which("semgrep") or not os.environ.get("SPOTLIGHT_TEST_SEMGREP"),
    reason="requires SPOTLIGHT_TEST_SEMGREP=1 + semgrep on PATH",
)
def test_live_semgrep_scan_produces_sqli_on_vuln_bank_api():
    root = Path(__file__).resolve().parents[2] / "targets" / "vuln-bank-api"
    matches = SemgrepAdapter(timeout_s=45).scan(root)
    assert any(m.class_ == "sqli" for m in matches), (
        f"expected at least one sqli match, got {[m.check_id for m in matches]}"
    )
