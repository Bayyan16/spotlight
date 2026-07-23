import json

import pytest

from spotlight.eval.paired_cve import evaluate_pair, load_manifest


CASE = {
    "id": "CVE-TEST-1",
    "expected": {
        "class": "eval",
        "cwe_family": "CWE-94",
        "path": "pkg/type_utils.py",
        "function": "vector_in",
    },
}


def _finding() -> dict:
    return {
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


def test_pair_passes_only_when_vulnerable_matches_and_fixed_is_clean():
    assert evaluate_pair(CASE, [_finding()], [])["passed"] is True
    assert evaluate_pair(CASE, [], [])["passed"] is False
    assert evaluate_pair(CASE, [_finding()], [_finding()])["passed"] is False


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


def test_repository_manifest_is_pinned():
    manifest = load_manifest("Evals/paired_cves.json")
    assert manifest["cases"][0]["id"] == "CVE-2026-8838"
