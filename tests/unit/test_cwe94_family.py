"""CWE-94 family — SSTI, dynamic imports, deserialization, path traversal.

Before this suite, sg-core's sink dict had only sqli / cmdi / eval / ssrf.
That covered CWE-95 (direct eval) but missed the broader CWE-94 umbrella:
Server-Side Template Injection (CWE-1336), dynamic imports (CWE-94
proper), and adjacent classes like deserialization (CWE-502), path
traversal (CWE-22), and weak crypto (CWE-327).

Each test constructs a minimal Python source with a tainted flow into
one of the new sinks and asserts:
  * CodeGraph classifies the sink correctly
  * the produced slice's `sink.class` matches
  * the MockModel maps `class` → the right CWE, and (for CWE-94 members)
    exposes cwe_family = "CWE-94"

These are the honest recall gaps the user surfaced; landing them here
means a future regression that drops a sink can't ship silently.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from spotlight.agents.model import MockModelClient
from spotlight.sg_core.graph import CodeGraph, SINKS


# ── SINKS registry regression ─────────────────────────────────────────────

def test_sinks_covers_cwe94_family_and_neighbors():
    """Regression fence — future refactors can't quietly drop these."""
    expected = {
        "sqli",
        "cmdi",
        "eval",
        "ssrf",
        "ssti",
        "dynamic-import",
        "deserialization",
        "path-traversal",
        "weak-hash",
        "verify-disabled",
    }
    missing = expected - set(SINKS.keys())
    assert not missing, f"SINKS dropped these classes: {missing}"


# ── SSTI (CWE-1336, parent CWE-94) ────────────────────────────────────────

def _write_py(tmp: Path, name: str, body: str) -> Path:
    p = tmp / name
    p.write_text(body)
    return p


def _slice_classes(paths: list[Path]) -> list[str]:
    graph = CodeGraph.build(paths)
    return [s.sink.class_ for s in graph.reachable_slices()]


def test_ssti_jinja2_template_from_string_is_flagged(tmp_path):
    p = _write_py(
        tmp_path,
        "ssti.py",
        """
from jinja2 import Environment
env = Environment()
def render(user_input):
    tpl = env.from_string(user_input)
    return tpl.render()
""",
    )
    classes = _slice_classes([p])
    assert "ssti" in classes, f"expected ssti, got {classes}"


def test_ssti_bare_template_render_is_flagged(tmp_path):
    p = _write_py(
        tmp_path,
        "ssti2.py",
        """
from jinja2 import Template
def unsafe(user_input):
    return Template(user_input).render()
""",
    )
    classes = _slice_classes([p])
    assert "ssti" in classes


# ── Dynamic imports (CWE-94 direct) ────────────────────────────────────────

def test_dynamic_import_via_importlib_is_flagged(tmp_path):
    p = _write_py(
        tmp_path,
        "dynimp.py",
        """
import importlib
def load(user_input):
    mod = importlib.import_module(user_input)
    return mod
""",
    )
    classes = _slice_classes([p])
    assert "dynamic-import" in classes


def test_dunder_import_is_flagged(tmp_path):
    p = _write_py(
        tmp_path,
        "dunder.py",
        """
def load(user_input):
    return __import__(user_input)
""",
    )
    classes = _slice_classes([p])
    assert "dynamic-import" in classes


# ── Deserialization (CWE-502) ──────────────────────────────────────────────

def test_pickle_loads_of_untrusted_data_is_flagged(tmp_path):
    p = _write_py(
        tmp_path,
        "pkl.py",
        """
import pickle
def deser(user_input):
    return pickle.loads(user_input)
""",
    )
    classes = _slice_classes([p])
    assert "deserialization" in classes


def test_yaml_load_unsafe_is_flagged(tmp_path):
    p = _write_py(
        tmp_path,
        "yml.py",
        """
import yaml
def unsafe(user_input):
    return yaml.load(user_input)
""",
    )
    classes = _slice_classes([p])
    assert "deserialization" in classes


# ── Path traversal (CWE-22) ────────────────────────────────────────────────

def test_open_of_user_controlled_path_is_flagged(tmp_path):
    p = _write_py(
        tmp_path,
        "pt.py",
        """
def read(user_input):
    return open(user_input).read()
""",
    )
    classes = _slice_classes([p])
    assert "path-traversal" in classes


# ── Weak crypto (CWE-327) — surfaces with tainted input, no false-flag on
#    checksums where the input is a literal ────────────────────────────────

def test_md5_of_user_input_is_flagged(tmp_path):
    p = _write_py(
        tmp_path,
        "md5.py",
        """
import hashlib
def hash_pw(user_input):
    return hashlib.md5(user_input.encode()).hexdigest()
""",
    )
    classes = _slice_classes([p])
    assert "weak-hash" in classes


# ── CWE mapping — child + parent family exposed ────────────────────────────

@pytest.mark.parametrize(
    "cls,cwe,family",
    [
        ("eval", "CWE-95", "CWE-94"),
        ("ssti", "CWE-1336", "CWE-94"),
        ("dynamic-import", "CWE-94", "CWE-94"),
        ("deserialization", "CWE-502", ""),
        ("path-traversal", "CWE-22", ""),
        ("weak-hash", "CWE-327", ""),
    ],
)
def test_mock_model_maps_class_to_cwe_and_family(cls, cwe, family):
    slice_ = {
        "file": "app.py",
        "function": "handler",
        "source": {"name": "user_input", "origin": "param:user_input", "line": 1},
        "sink": {"callee": "sink", "class": cls, "line": 42, "argument": ""},
        "reason": "",
    }
    resp = MockModelClient().complete(
        role="investigator", prompt="", context={"slice": slice_}
    )
    assert resp["cwe"] == cwe, f"{cls}: expected {cwe}, got {resp['cwe']}"
    assert resp.get("cwe_family", "") == family, (
        f"{cls}: expected cwe_family={family!r}, got {resp.get('cwe_family')!r}"
    )
