"""Paired vulnerable/fixed commit evaluation.

The fixed commit is a mandatory negative. A detector only earns credit when
the advisory-matching finding is present before the patch and absent after it.

Schema v1 (paired cases only):
  {"schema_version": 1, "gates": {...}, "cases": [...]}

Schema v2 (adds negative controls and per-class gates, optional):
  {"schema_version": 2,
   "gates": {..., "max_negative_control_false_positive_cases": 0,
                  "per_class_min_recall": {"CWE-94": 1.0}},
   "cases": [...],
   "negative_controls": [
     {"id": "NEG-...", "repo": "https://...", "commit": "<40 hex>",
      "expected_no_matches_for": [{"cwe_family": "CWE-94"}]}
   ]}

v1 manifests continue to load unchanged. `negative_controls` and the two
new gate fields default to empty/permissive.
"""
from __future__ import annotations

import argparse
import json
import shutil
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from spotlight.git_ops import GitOps
from spotlight.orchestrator import Orchestrator


_SUPPORTED_SCHEMA_VERSIONS = {1, 2}


def load_manifest(path: str | Path) -> dict[str, Any]:
    manifest = json.loads(Path(path).read_text())
    version = manifest.get("schema_version")
    if version not in _SUPPORTED_SCHEMA_VERSIONS or not manifest.get("cases"):
        raise ValueError(
            f"paired CVE manifest must use schema_version in {_SUPPORTED_SCHEMA_VERSIONS} "
            f"and contain cases"
        )
    for case in manifest["cases"]:
        for field in ("id", "repo", "vulnerable_commit", "fixed_commit", "expected"):
            if not case.get(field):
                raise ValueError(f"case missing required field: {field}")
        for field in ("vulnerable_commit", "fixed_commit"):
            _validate_sha(case[field], case_id=case["id"], field=field)
    for control in manifest.get("negative_controls") or []:
        for field in ("id", "repo", "commit", "expected_no_matches_for"):
            if not control.get(field):
                raise ValueError(f"negative control missing required field: {field}")
        _validate_sha(control["commit"], case_id=control["id"], field="commit")
        if not isinstance(control["expected_no_matches_for"], list) or not control["expected_no_matches_for"]:
            raise ValueError(
                f"negative control {control['id']} expected_no_matches_for must be a non-empty list"
            )
    return manifest


def _validate_sha(value: Any, *, case_id: str, field: str) -> None:
    value = str(value)
    if len(value) not in (40, 64) or any(c not in "0123456789abcdefABCDEF" for c in value):
        raise ValueError(f"{case_id} {field} must be a full commit SHA")


def _matches(finding: dict[str, Any], expected: dict[str, Any]) -> bool:
    location = finding.get("location") or {}
    expected_path = str(expected.get("path") or "")
    actual_path = str(location.get("repo_relative_path") or location.get("file") or "")
    if expected.get("class") and finding.get("class") != expected["class"]:
        return False
    if expected.get("cwe") and finding.get("cwe") != expected["cwe"]:
        return False
    if expected.get("cwe_family") and finding.get("cwe_family") != expected["cwe_family"]:
        return False
    if expected_path and actual_path != expected_path:
        return False
    if expected.get("function") and location.get("function") != expected["function"]:
        return False
    return True


def evaluate_pair(
    case: dict[str, Any],
    vulnerable_findings: list[dict[str, Any]],
    fixed_findings: list[dict[str, Any]],
) -> dict[str, Any]:
    expected = case["expected"]
    vulnerable_matches = [f for f in vulnerable_findings if _matches(f, expected)]
    fixed_matches = [f for f in fixed_findings if _matches(f, expected)]
    passed = bool(vulnerable_matches) and not fixed_matches
    return {
        "id": case["id"],
        "cwe_family": expected.get("cwe_family"),
        "passed": passed,
        "vulnerable_detected": bool(vulnerable_matches),
        "fixed_clean": not fixed_matches,
        "vulnerable_total_findings": len(vulnerable_findings),
        "fixed_total_findings": len(fixed_findings),
        "vulnerable_match_ids": [f.get("id") for f in vulnerable_matches],
        "fixed_match_ids": [f.get("id") for f in fixed_matches],
    }


def evaluate_negative_control(
    control: dict[str, Any],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """A negative control passes when NO finding matches ANY of the
    control's `expected_no_matches_for` patterns. Any matching finding
    is an advisory-family false positive on unrelated code."""
    patterns = control.get("expected_no_matches_for") or []
    false_positives: list[dict[str, Any]] = []
    for finding in findings:
        for pattern in patterns:
            if _matches(finding, pattern):
                false_positives.append(finding)
                break
    return {
        "id": control["id"],
        "passed": not false_positives,
        "total_findings": len(findings),
        "false_positive_finding_ids": [f.get("id") for f in false_positives],
    }


def aggregate_per_class(case_results: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Group case results by cwe_family and emit recall + fixed-FP counts
    per class. Cases without a cwe_family go under 'unclassified'."""
    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for case in case_results:
        family = case.get("cwe_family") or "unclassified"
        buckets[family].append(case)
    out: dict[str, dict[str, Any]] = {}
    for family, cases in buckets.items():
        passed = sum(1 for c in cases if c["passed"])
        fixed_fp = sum(1 for c in cases if not c["fixed_clean"])
        out[family] = {
            "cases": len(cases),
            "passed": passed,
            "recall": passed / len(cases) if cases else 0.0,
            "fixed_false_positive_cases": fixed_fp,
        }
    return out


def _scan(repo: str, commit: str, output: Path) -> list[dict[str, Any]]:
    checkout = GitOps().clone_at(repo, sha=commit)
    try:
        result = Orchestrator().run(checkout, out_dir=output)
        return result.findings
    finally:
        workdir = checkout.resolve().parent
        if workdir.name.startswith("spotlight-clone-"):
            shutil.rmtree(workdir, ignore_errors=True)


def run_manifest(manifest: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    cases: list[dict[str, Any]] = []
    for case in manifest["cases"]:
        case_dir = output_dir / case["id"].lower()
        vulnerable = _scan(
            case["repo"], case["vulnerable_commit"], case_dir / "vulnerable"
        )
        fixed = _scan(case["repo"], case["fixed_commit"], case_dir / "fixed")
        (case_dir / "vulnerable_findings.json").write_text(json.dumps(vulnerable, indent=2))
        (case_dir / "fixed_findings.json").write_text(json.dumps(fixed, indent=2))
        cases.append(evaluate_pair(case, vulnerable, fixed))

    controls: list[dict[str, Any]] = []
    for control in manifest.get("negative_controls") or []:
        control_dir = output_dir / "negatives" / control["id"].lower()
        findings = _scan(control["repo"], control["commit"], control_dir)
        (control_dir / "findings.json").write_text(json.dumps(findings, indent=2))
        controls.append(evaluate_negative_control(control, findings))

    passed = sum(1 for case in cases if case["passed"])
    per_class = aggregate_per_class(cases)
    negative_control_fp_cases = sum(1 for c in controls if not c["passed"])
    report: dict[str, Any] = {
        "schema_version": manifest.get("schema_version", 1),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "cases": cases,
        "negative_controls": controls,
        "metrics": {
            "paired_cases": len(cases),
            "paired_passed": passed,
            "paired_recall": passed / len(cases) if cases else 0.0,
            "fixed_false_positive_cases": sum(1 for case in cases if not case["fixed_clean"]),
            "negative_controls_total": len(controls),
            "negative_control_false_positive_cases": negative_control_fp_cases,
            "per_class": per_class,
        },
    }
    gates_in = manifest.get("gates") or {}
    report["gates"] = {
        "min_paired_recall": gates_in.get("min_paired_recall", 1.0),
        "max_fixed_false_positive_cases": gates_in.get("max_fixed_false_positive_cases", 0),
        "max_negative_control_false_positive_cases": gates_in.get(
            "max_negative_control_false_positive_cases", 0
        ),
        "per_class_min_recall": gates_in.get("per_class_min_recall", {}),
        "min_paired_cases": gates_in.get("min_paired_cases", 0),
    }
    report["passed"] = _passes_gates(report)
    (output_dir / "report.json").write_text(json.dumps(report, indent=2))
    return report


def _passes_gates(report: dict[str, Any]) -> bool:
    gates = report["gates"]
    metrics = report["metrics"]
    if metrics["paired_recall"] < gates["min_paired_recall"]:
        return False
    if metrics["fixed_false_positive_cases"] > gates["max_fixed_false_positive_cases"]:
        return False
    if metrics["negative_control_false_positive_cases"] > gates["max_negative_control_false_positive_cases"]:
        return False
    if metrics["paired_cases"] < gates["min_paired_cases"]:
        return False
    for family, required_recall in (gates["per_class_min_recall"] or {}).items():
        class_metrics = metrics["per_class"].get(family)
        if class_metrics is None:
            # Gate demands a class the manifest doesn't cover — treat as failure
            # so a curator can't silently drop a class from the benchmark.
            return False
        if class_metrics["recall"] < required_recall:
            return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Run paired vulnerable/fixed CVE evals")
    parser.add_argument("--manifest", default="Evals/paired_cves.json")
    parser.add_argument("--output", default="Evals/results/latest-paired-cves")
    args = parser.parse_args()
    report = run_manifest(load_manifest(args.manifest), Path(args.output))
    print(json.dumps(report["metrics"], indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
