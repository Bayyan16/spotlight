"""Planner — repo-native rule authoring.

Pins the three-tier fall-through, the grep validator, and the sg-core
integration where the Planner's extra sinks / sources / sanitizers land
inside the CodeGraph and drive reachability.

Zero LLM calls — the MockModelClient's `planner` role produces a
deterministic canned plan. Real Moonshot / OpenAI planner is exercised
in live sweeps.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from spotlight.agents.model import MockModelClient
from spotlight.planner import PlanRule, Planner
from spotlight.planner.planner import _resolve_class
from spotlight.planner.validator import GrepValidator
from spotlight.sg_core import CodeGraph


# ── three-tier resolution ─────────────────────────────────────────────

class TestTiering:
    def test_tier_1_existing_class_passes_through(self):
        cls, tier = _resolve_class(explicit="deserialization", cwe="", identifier="x")
        assert cls == "deserialization"
        assert tier == 1

    def test_tier_2_cwe_maps_to_known_class(self):
        cls, tier = _resolve_class(explicit="", cwe="CWE-89", identifier="db.q")
        assert cls == "sqli"
        assert tier == 2

    def test_tier_2_ldap_maps_to_class(self):
        cls, tier = _resolve_class(explicit="ldap-injection", cwe="CWE-90", identifier="ldap.search")
        assert cls == "ldap-injection"
        assert tier == 1  # explicit hit before CWE

    def test_tier_3_falls_through_to_external_planner(self):
        cls, tier = _resolve_class(explicit="", cwe="CWE-99999", identifier="acme.exotic.thing")
        assert cls.startswith("external:planner:")
        assert tier == 3


# ── grep validator drops hallucinated identifiers ────────────────────

class TestValidator:
    def test_hallucinated_identifier_not_found(self, tmp_path):
        (tmp_path / "real.py").write_text("def real_function():\n    pass\n")
        v = GrepValidator(tmp_path)
        assert v.check("real_function").found is True
        assert v.check("this_never_existed_anywhere").found is False

    def test_dotted_name_uses_last_segment(self, tmp_path):
        (tmp_path / "a.py").write_text("from acme import load_yaml\n")
        v = GrepValidator(tmp_path)
        assert v.check("acme.utils.load_yaml").found is True

    def test_scans_multiple_extensions(self, tmp_path):
        (tmp_path / "a.py").write_text("pass\n")
        (tmp_path / "b.js").write_text("function jsHelper() {}\n")
        v = GrepValidator(tmp_path)
        assert v.check("jsHelper").found is True


# ── planner drops hallucinated rules end-to-end ──────────────────────

def test_planner_drops_hallucinated_rules(tmp_path):
    (tmp_path / "app.py").write_text(
        "from acme import load_yaml\n"
        "def handler(data):\n"
        "    return load_yaml(data)\n"
    )

    class _FakeModel:
        family = "fake"

        def complete(self, *, role, prompt, context):
            return {
                "framework": "flask",
                "rules": [
                    {
                        "identifier": "load_yaml",
                        "role": "sink",
                        "target_class": "deserialization",
                        "cwe": "CWE-502",
                    },
                    {
                        "identifier": "this_never_exists",  # hallucination — must drop
                        "role": "sink",
                        "target_class": "deserialization",
                        "cwe": "CWE-502",
                    },
                ],
                "semgrep_rules_yaml": "",
            }

    plan = Planner(_FakeModel()).plan(tmp_path)
    kept_ids = {r.identifier for r in plan.rules}
    rejected_ids = {r["identifier"] for r in plan.validation.rejected}
    assert "load_yaml" in kept_ids
    assert "this_never_exists" in rejected_ids
    assert "this_never_exists" not in kept_ids


# ── sg-core integration: extras land in reachability ─────────────────

def test_sg_core_extra_sinks_produce_slice(tmp_path):
    # Synthetic file — the callable `acme_deser.load` is NOT in sg-core's
    # baseline SINKS, so without the Planner we'd miss it. With the
    # extra sink registered under the Planner's per-sweep override, the
    # slice should land as class=deserialization.
    (tmp_path / "app.py").write_text(
        "def handler(payload):\n"
        "    return acme_deser.load(payload)\n"
    )
    graph = CodeGraph.build(
        [tmp_path / "app.py"],
        extra_sinks={"deserialization": ["acme_deser.load"]},
    )
    slice_classes = [s.sink.class_ for s in graph.reachable_slices()]
    assert "deserialization" in slice_classes


def test_sg_core_extra_source_seeds_taint(tmp_path):
    # `queue_consume` isn't in sg-core's UNTRUSTED_ATTRS. Register it as
    # an extra source; then a downstream eval should be reachable.
    (tmp_path / "app.py").write_text(
        "def worker():\n"
        "    msg = queue_consume()\n"
        "    return eval(msg)\n"
    )
    graph = CodeGraph.build(
        [tmp_path / "app.py"],
        extra_sources=["queue_consume"],
    )
    slice_classes = [s.sink.class_ for s in graph.reachable_slices()]
    assert "eval" in slice_classes


def test_sg_core_extra_sanitizer_marks_flow_safe(tmp_path):
    (tmp_path / "app.py").write_text(
        "def handler(x):\n"
        "    return eval(html_escape(x))\n"
    )
    graph = CodeGraph.build(
        [tmp_path / "app.py"],
        extra_sanitizers=["html_escape"],
    )
    slices = list(graph.slices())
    # At least one slice for eval — but marked sanitized because
    # html_escape wraps the tainted value.
    eval_slices = [s for s in slices if s.sink.class_ == "eval"]
    assert eval_slices
    assert any(s.sanitized for s in eval_slices)


# ── output shape stability ───────────────────────────────────────────

def test_plan_output_dict_shape():
    class _M:
        family = "fake"

        def complete(self, *, role, prompt, context):
            return {"framework": "flask", "rules": [], "semgrep_rules_yaml": ""}

    plan = Planner(_M()).plan(Path("/tmp"))
    d = plan.to_dict()
    assert set(d.keys()) == {"framework", "rules", "semgrep_rules_yaml", "validation"}
    assert set(d["validation"].keys()) == {"kept_count", "rejected_count", "rejected"}


def test_mock_model_planner_role_produces_plan(tmp_path):
    """The MockModelClient's `planner` role is the canned deterministic
    fallback used in tests + demos. Assert its return shape."""
    resp = MockModelClient().complete(
        role="planner", prompt="", context={"index": "@app.route"}
    )
    assert resp["framework"] == "flask"
    assert isinstance(resp["rules"], list)
    assert all(
        r.get("identifier") and r.get("role") and r.get("target_class")
        for r in resp["rules"]
    )
