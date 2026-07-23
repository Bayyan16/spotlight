import json

import pytest

from spotlight.eval.paired_cve import (
    _passes_gates,
    aggregate_per_class,
    evaluate_negative_control,
    evaluate_pair,
    load_manifest,
)


CASE = {
    "id": "CVE-TEST-1",
    "expected": {
        "class": "eval",
        "cwe_family": "CWE-94",
        "path": "pkg/type_utils.py",
        "function": "vector_in",
    },
}


def _finding(**overrides) -> dict:
    base = {
        "id": "SPOT-ABC",
        "class": "eval",
        "cwe": "CWE-95",
        "cwe_family": "CWE-94",
        "location": {
            "file": "pkg/type_utils.py",
            "repo_relative_path": "pkg/type_utils.py",
            "function": "vector_in",
        },
    }
    base.update(overrides)
    return base


# ---------- evaluate_pair (v1 behavior preserved) ----------


def test_pair_passes_only_when_vulnerable_matches_and_fixed_is_clean():
    assert evaluate_pair(CASE, [_finding()], [])["passed"] is True
    assert evaluate_pair(CASE, [], [])["passed"] is False
    assert evaluate_pair(CASE, [_finding()], [_finding()])["passed"] is False


def test_pair_records_cwe_family_for_class_metrics():
    result = evaluate_pair(CASE, [_finding()], [])
    assert result["cwe_family"] == "CWE-94"


def test_pair_records_none_cwe_family_when_expected_omits_it():
    case = {"id": "X", "expected": {"class": "eval"}}
    result = evaluate_pair(case, [_finding()], [])
    assert result["cwe_family"] is None


# ---------- evaluate_negative_control ----------


def test_negative_control_passes_when_no_finding_matches_forbidden_pattern():
    control = {
        "id": "NEG-clean-abc",
        "expected_no_matches_for": [{"cwe_family": "CWE-94"}],
    }
    result = evaluate_negative_control(control, [])
    assert result["passed"] is True
    assert result["total_findings"] == 0
    assert result["false_positive_finding_ids"] == []


def test_negative_control_fails_on_advisory_family_match():
    control = {
        "id": "NEG-clean-abc",
        "expected_no_matches_for": [{"cwe_family": "CWE-94"}],
    }
    result = evaluate_negative_control(control, [_finding()])
    assert result["passed"] is False
    assert result["false_positive_finding_ids"] == ["SPOT-ABC"]


def test_negative_control_ignores_findings_outside_forbidden_families():
    control = {
        "id": "NEG-clean-abc",
        "expected_no_matches_for": [{"cwe_family": "CWE-89"}],  # SQLi only
    }
    # A CWE-94 finding on unrelated code is NOT a false positive for a
    # SQLi-only control — the control only forbids SQLi false positives.
    result = evaluate_negative_control(control, [_finding()])
    assert result["passed"] is True


def test_negative_control_counts_each_finding_at_most_once():
    control = {
        "id": "NEG-clean-abc",
        "expected_no_matches_for": [
            {"cwe_family": "CWE-94"},
            {"class": "eval"},  # would also match the same finding
        ],
    }
    result = evaluate_negative_control(control, [_finding()])
    assert len(result["false_positive_finding_ids"]) == 1


# ---------- aggregate_per_class ----------


def test_aggregate_per_class_groups_and_computes_recall():
    cases = [
        {"passed": True, "fixed_clean": True, "cwe_family": "CWE-94"},
        {"passed": False, "fixed_clean": True, "cwe_family": "CWE-94"},
        {"passed": True, "fixed_clean": False, "cwe_family": "CWE-89"},
    ]
    out = aggregate_per_class(cases)
    assert out["CWE-94"] == {
        "cases": 2, "passed": 1, "recall": 0.5, "fixed_false_positive_cases": 0,
    }
    assert out["CWE-89"] == {
        "cases": 1, "passed": 1, "recall": 1.0, "fixed_false_positive_cases": 1,
    }


def test_aggregate_per_class_buckets_missing_family_as_unclassified():
    out = aggregate_per_class([
        {"passed": True, "fixed_clean": True, "cwe_family": None},
    ])
    assert "unclassified" in out
    assert out["unclassified"]["cases"] == 1


# ---------- manifest loading & schema ----------


def test_manifest_rejects_short_refs(tmp_path):
    path = tmp_path / "manifest.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "cases": [
                    {
                        "id": "CVE-X",
                        "repo": "https://github.com/o/r.git",
                        "vulnerable_commit": "main",
                        "fixed_commit": "deadbeef",
                        "expected": {"class": "eval"},
                    }
                ],
            }
        )
    )
    with pytest.raises(ValueError, match="full commit SHA"):
        load_manifest(path)


def test_manifest_accepts_v2_with_negative_controls(tmp_path):
    path = tmp_path / "m.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "cases": [
                    {
                        "id": "CVE-Y",
                        "repo": "https://github.com/o/r.git",
                        "vulnerable_commit": "a" * 40,
                        "fixed_commit": "b" * 40,
                        "expected": {"class": "eval", "cwe_family": "CWE-94"},
                    }
                ],
                "negative_controls": [
                    {
                        "id": "NEG-1",
                        "repo": "https://github.com/o/other.git",
                        "commit": "c" * 40,
                        "expected_no_matches_for": [{"cwe_family": "CWE-94"}],
                    }
                ],
            }
        )
    )
    m = load_manifest(path)
    assert m["schema_version"] == 2
    assert len(m["negative_controls"]) == 1


def test_manifest_rejects_negative_control_with_bad_sha(tmp_path):
    path = tmp_path / "m.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "cases": [
                    {
                        "id": "CVE-Y",
                        "repo": "https://github.com/o/r.git",
                        "vulnerable_commit": "a" * 40,
                        "fixed_commit": "b" * 40,
                        "expected": {"class": "eval"},
                    }
                ],
                "negative_controls": [
                    {
                        "id": "NEG-1",
                        "repo": "https://github.com/o/other.git",
                        "commit": "deadbeef",  # too short
                        "expected_no_matches_for": [{"cwe_family": "CWE-94"}],
                    }
                ],
            }
        )
    )
    with pytest.raises(ValueError, match="full commit SHA"):
        load_manifest(path)


def test_manifest_rejects_negative_control_missing_patterns(tmp_path):
    path = tmp_path / "m.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "cases": [
                    {
                        "id": "CVE-Y",
                        "repo": "https://github.com/o/r.git",
                        "vulnerable_commit": "a" * 40,
                        "fixed_commit": "b" * 40,
                        "expected": {"class": "eval"},
                    }
                ],
                "negative_controls": [
                    {
                        "id": "NEG-1",
                        "repo": "https://github.com/o/other.git",
                        "commit": "c" * 40,
                        "expected_no_matches_for": [],  # empty
                    }
                ],
            }
        )
    )
    with pytest.raises(ValueError, match="expected_no_matches_for"):
        load_manifest(path)


def test_manifest_rejects_unknown_schema_version(tmp_path):
    path = tmp_path / "m.json"
    path.write_text(json.dumps({"schema_version": 99, "cases": [{}]}))
    with pytest.raises(ValueError, match="schema_version"):
        load_manifest(path)


def test_repository_manifest_is_pinned():
    manifest = load_manifest("Evals/paired_cves.json")
    ids = [c["id"] for c in manifest["cases"]]
    assert "CVE-2026-8838" in ids


# ---------- gate enforcement ----------


def _report(**overrides) -> dict:
    metrics = {
        "paired_cases": 1,
        "paired_passed": 1,
        "paired_recall": 1.0,
        "fixed_false_positive_cases": 0,
        "negative_controls_total": 0,
        "negative_control_false_positive_cases": 0,
        "per_class": {"CWE-94": {"cases": 1, "passed": 1, "recall": 1.0, "fixed_false_positive_cases": 0}},
    }
    metrics.update(overrides.get("metrics", {}))
    gates = {
        "min_paired_recall": 1.0,
        "max_fixed_false_positive_cases": 0,
        "max_negative_control_false_positive_cases": 0,
        "per_class_min_recall": {},
        "min_paired_cases": 0,
    }
    gates.update(overrides.get("gates", {}))
    return {"metrics": metrics, "gates": gates}


def test_gates_pass_baseline():
    assert _passes_gates(_report()) is True


def test_gates_fail_on_negative_control_false_positive():
    r = _report(metrics={"negative_control_false_positive_cases": 1})
    assert _passes_gates(r) is False


def test_gates_fail_when_per_class_recall_below_threshold():
    r = _report(
        metrics={"per_class": {"CWE-94": {"cases": 2, "passed": 1, "recall": 0.5, "fixed_false_positive_cases": 0}}},
        gates={"per_class_min_recall": {"CWE-94": 1.0}},
    )
    assert _passes_gates(r) is False


def test_gates_fail_when_per_class_gate_names_missing_class():
    r = _report(gates={"per_class_min_recall": {"CWE-89": 1.0}})
    assert _passes_gates(r) is False, "gate for missing class must fail — no silent skips"


def test_gates_fail_when_min_paired_cases_not_met():
    r = _report(gates={"min_paired_cases": 10})
    assert _passes_gates(r) is False


def test_gates_pass_with_negative_controls_all_clean():
    r = _report(metrics={"negative_controls_total": 5, "negative_control_false_positive_cases": 0})
    assert _passes_gates(r) is True
