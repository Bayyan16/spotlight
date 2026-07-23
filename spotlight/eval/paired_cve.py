"""Paired vulnerable/fixed commit evaluation.

The fixed commit is a mandatory negative. A detector only earns credit when
the advisory-matching finding is present before the patch and absent after it.
"""
from __future__ import annotations

import argparse
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from spotlight.git_ops import GitOps
from spotlight.orchestrator import Orchestrator


def load_manifest(path: str | Path) -> dict[str, Any]:
    manifest = json.loads(Path(path).read_text())
    if manifest.get("schema_version") != 1 or not manifest.get("cases"):
        raise ValueError("paired CVE manifest must use schema_version=1 and contain cases")
    for case in manifest["cases"]:
        for field in ("id", "repo", "vulnerable_commit", "fixed_commit", "expected"):
            if not case.get(field):
                raise ValueError(f"case missing required field: {field}")
        for field in ("vulnerable_commit", "fixed_commit"):
            value = str(case[field])
            if len(value) not in (40, 64) or any(c not in "0123456789abcdefABCDEF" for c in value):
                raise ValueError(f"{case['id']} {field} must be a full commit SHA")
    return manifest


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
        "passed": passed,
        "vulnerable_detected": bool(vulnerable_matches),
        "fixed_clean": not fixed_matches,
        "vulnerable_total_findings": len(vulnerable_findings),
        "fixed_total_findings": len(fixed_findings),
        "vulnerable_match_ids": [f.get("id") for f in vulnerable_matches],
        "fixed_match_ids": [f.get("id") for f in fixed_matches],
    }


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

    passed = sum(1 for case in cases if case["passed"])
    report = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "cases": cases,
        "metrics": {
            "paired_cases": len(cases),
            "paired_passed": passed,
            "paired_recall": passed / len(cases) if cases else 0.0,
            "fixed_false_positive_cases": sum(1 for case in cases if not case["fixed_clean"]),
        },
    }
    gates = manifest.get("gates") or {}
    report["gates"] = {
        "min_paired_recall": gates.get("min_paired_recall", 1.0),
        "max_fixed_false_positive_cases": gates.get("max_fixed_false_positive_cases", 0),
    }
    report["passed"] = (
        report["metrics"]["paired_recall"] >= report["gates"]["min_paired_recall"]
        and report["metrics"]["fixed_false_positive_cases"]
        <= report["gates"]["max_fixed_false_positive_cases"]
    )
    (output_dir / "report.json").write_text(json.dumps(report, indent=2))
    return report


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
