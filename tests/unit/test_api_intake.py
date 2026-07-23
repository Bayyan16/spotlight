from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import HTTPException

from spotlight.api.intake import (
    resolve_repo_input,
    validate_commit_sha,
    validate_git_url,
)


def test_git_url_is_canonical_and_allowlisted():
    assert (
        validate_git_url("https://github.com/aws/amazon-redshift-python-driver.git")
        == "https://github.com/aws/amazon-redshift-python-driver.git"
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/owner/repo.git",
        "git@github.com:owner/repo.git",
        "https://example.com/owner/repo.git",
        "https://user:secret@github.com/owner/repo.git",
        "https://github.com:8443/owner/repo.git",
        "https://github.com/owner/../repo.git",
        "https://github.com/owner/repo",
    ],
)
def test_git_url_rejects_unsafe_shapes(url):
    with pytest.raises(HTTPException):
        validate_git_url(url)


def test_commit_requires_full_sha():
    sha = "a" * 40
    assert validate_commit_sha(sha) == sha
    with pytest.raises(HTTPException):
        validate_commit_sha("main")
    with pytest.raises(HTTPException):
        validate_commit_sha("deadbeef")


def test_absolute_local_path_is_not_accepted_by_default(tmp_path):
    targets = tmp_path / "targets"
    targets.mkdir()
    local = tmp_path / "private-repo"
    local.mkdir()
    with pytest.raises(HTTPException) as exc:
        resolve_repo_input(str(local), targets_root=targets)
    assert exc.value.status_code == 404


def test_named_fixture_stays_within_targets(tmp_path):
    targets = tmp_path / "targets"
    fixture = targets / "safe-fixture"
    fixture.mkdir(parents=True)
    resolved, source = resolve_repo_input("safe-fixture", targets_root=targets)
    assert resolved == fixture.resolve()
    assert source == "fixture"


def test_local_repo_requires_explicit_root(tmp_path, monkeypatch):
    targets = tmp_path / "targets"
    targets.mkdir()
    allowed = tmp_path / "allowed"
    repo = allowed / "repo"
    repo.mkdir(parents=True)
    monkeypatch.setenv("SPOTLIGHT_ALLOW_LOCAL_REPOS", "true")
    monkeypatch.setenv("SPOTLIGHT_LOCAL_REPO_ROOTS", str(allowed))
    resolved, source = resolve_repo_input(str(repo), targets_root=targets)
    assert resolved == repo.resolve()
    assert source == "local"
