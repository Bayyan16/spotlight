from pathlib import Path

from spotlight.finding_identity import (
    canonical_repo_path,
    comparison_key,
    finding_identity,
    stable_finding_id,
)


def _finding(path: str) -> dict:
    return {
        "class": "eval",
        "location": {"file": path, "function": "execute", "line": 41},
    }


def test_temp_checkout_does_not_change_identity():
    first = _finding("/tmp/spotlight-clone-abc/src/pkg/runner.py")
    second = _finding("/private/var/tmp/spotlight-clone-xyz/src/pkg/runner.py")

    assert stable_finding_id(first) == stable_finding_id(second)
    assert comparison_key(first) == comparison_key(second)


def test_line_drift_does_not_change_identity():
    first = _finding("pkg/runner.py")
    second = _finding("pkg/runner.py")
    second["location"]["line"] = 99

    assert finding_identity(first) == finding_identity(second)


def test_repo_root_normalizes_absolute_path(tmp_path: Path):
    repo = tmp_path / "repo"
    target = repo / "src" / "app.py"
    target.parent.mkdir(parents=True)
    target.write_text("pass\n")

    assert canonical_repo_path(str(target), repo) == "src/app.py"


def test_legacy_finding_prefers_repo_relative_path():
    old = _finding("/tmp/random-checkout/pkg/runner.py")
    old["location"]["repo_relative_path"] = "pkg/runner.py"

    assert comparison_key(old) == comparison_key(_finding("pkg/runner.py"))
