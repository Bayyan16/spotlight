"""Integration tests for `spotlight.git_ops.GitOps`.

Exercises the real `git` binary against a local bare repo (no network) and
mocks `subprocess.run` for the `gh pr create` path. This is the same
strategy production would take: real git, wrapped `gh`.
"""
from __future__ import annotations

import subprocess
import types
from pathlib import Path

import pytest

from spotlight.git_ops import GitOps, PROpenResult
from spotlight.git_ops.ops import _PR_URL_RE


def _git(cwd: Path, *args: str) -> str:
    """Helper: run git in `cwd`, capture stdout, raise on failure."""
    r = subprocess.run(
        ["git", *args], cwd=str(cwd), capture_output=True, text=True, check=True
    )
    return r.stdout


@pytest.fixture
def local_repo_and_bare(tmp_path):
    """Set up a source repo with one commit, then a bare mirror we can clone
    from. Returns (source_repo, bare_repo)."""
    src = tmp_path / "src-repo"
    src.mkdir()
    _git(src, "init", "-q", "-b", "main")
    _git(src, "config", "user.email", "test@spotlight.local")
    _git(src, "config", "user.name", "Spotlight Test")
    (src / "app.py").write_text("print('hello world')\n")
    _git(src, "add", "app.py")
    _git(src, "commit", "-q", "-m", "initial")
    head_sha = _git(src, "rev-parse", "HEAD").strip()

    # Second commit so we have a range for the SHA test.
    (src / "app.py").write_text("print('hello world v2')\n")
    _git(src, "commit", "-q", "-am", "v2")

    bare = tmp_path / "bare.git"
    _git(tmp_path, "clone", "--bare", "-q", str(src), str(bare))
    return src, bare, head_sha


def test_clone_at_default_head(local_repo_and_bare):
    _, bare, _ = local_repo_and_bare
    gh = GitOps()
    checkout = gh.clone_at(str(bare))
    assert checkout.exists()
    assert (checkout / ".git").exists()
    assert (checkout / "app.py").exists()
    # HEAD is the second commit ("v2") since we didn't pin.
    text = (checkout / "app.py").read_text()
    assert "v2" in text


def test_clone_at_pinned_sha(local_repo_and_bare):
    _, bare, head_sha = local_repo_and_bare
    gh = GitOps()
    checkout = gh.clone_at(str(bare), sha=head_sha)
    resolved = _git(checkout, "rev-parse", "HEAD").strip()
    assert resolved == head_sha
    # And the file content matches the first commit, not v2.
    assert "v2" not in (checkout / "app.py").read_text()


def test_is_git_repo_true_and_false(local_repo_and_bare, tmp_path):
    src, _, _ = local_repo_and_bare
    gh = GitOps()
    assert gh.is_git_repo(src) is True
    # A plain dir with a file in it is NOT a git repo.
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "x.txt").write_text("hi")
    assert gh.is_git_repo(plain) is False


def test_create_scratch_branch_is_valid_and_checked_out(local_repo_and_bare):
    src, _, _ = local_repo_and_bare
    gh = GitOps()
    branch = gh.create_scratch_branch(src, "SPOT-0001")
    assert branch.startswith("spotlight/SPOT-0001-")
    # git knows about it and it's the current branch.
    current = _git(src, "rev-parse", "--abbrev-ref", "HEAD").strip()
    assert current == branch


def test_stage_and_commit_returns_valid_sha(local_repo_and_bare):
    src, _, _ = local_repo_and_bare
    gh = GitOps()
    gh.create_scratch_branch(src, "SPOT-0002")
    (src / "app.py").write_text("print('patched')\n")
    sha = gh.stage_and_commit(src, [src / "app.py"], message="fix: patch it")
    # Valid full-length sha.
    assert len(sha) == 40
    assert all(c in "0123456789abcdef" for c in sha)
    # And the commit is HEAD.
    head = _git(src, "rev-parse", "HEAD").strip()
    assert head == sha
    # Message survived.
    msg = _git(src, "log", "-1", "--format=%s").strip()
    assert msg == "fix: patch it"


def test_open_pr_parses_url_from_gh_stdout(local_repo_and_bare, monkeypatch):
    """Mock `subprocess.run` at the module boundary; do NOT hit real GitHub."""
    src, _, _ = local_repo_and_bare
    gh = GitOps()

    canned_url = "https://github.com/AbhiK24/Spotlight/pull/42"
    fake_stdout = f"Creating pull request for scratch into main in AbhiK24/Spotlight\n\n{canned_url}\n"

    calls: list[list[str]] = []

    def fake_run(args, **kwargs):
        calls.append(args)
        assert args[0] == "gh"
        assert "shell" not in kwargs or kwargs["shell"] is False
        return subprocess.CompletedProcess(args, 0, stdout=fake_stdout, stderr="")

    monkeypatch.setattr("spotlight.git_ops.ops.subprocess.run", fake_run)

    result = gh.open_pr(
        src, base="main", head="spotlight/SPOT-0001-abcdefg",
        title="fix: sqli", body="body",
    )
    assert isinstance(result, PROpenResult)
    assert result.ok is True
    assert result.pr_url == canned_url
    assert result.branch == "spotlight/SPOT-0001-abcdefg"
    # We passed an arg list (never shell string).
    assert calls and calls[0][:3] == ["gh", "pr", "create"]


def test_open_pr_returns_ok_false_when_gh_fails(local_repo_and_bare, monkeypatch):
    src, _, _ = local_repo_and_bare
    gh = GitOps()

    def fake_run(args, **kwargs):
        return subprocess.CompletedProcess(
            args, 1, stdout="", stderr="pull request create failed: fork required"
        )

    monkeypatch.setattr("spotlight.git_ops.ops.subprocess.run", fake_run)
    result = gh.open_pr(src, base="main", head="scratch", title="t", body="b")
    assert result.ok is False
    assert result.pr_url is None
    assert "fork required" in result.stderr


def test_open_pr_handles_missing_gh_binary(local_repo_and_bare, monkeypatch):
    src, _, _ = local_repo_and_bare
    gh = GitOps()

    def fake_run(args, **kwargs):
        raise FileNotFoundError("gh not found")

    monkeypatch.setattr("spotlight.git_ops.ops.subprocess.run", fake_run)
    result = gh.open_pr(src, base="main", head="scratch", title="t", body="b")
    assert result.ok is False
    assert "gh not on PATH" in result.stderr


def test_pr_url_regex_matches_various_shapes():
    assert _PR_URL_RE.search("https://github.com/foo/bar/pull/1")
    assert _PR_URL_RE.search("noise\nhttps://github.com/foo-org/repo.name/pull/9999\nmore")
    assert not _PR_URL_RE.search("https://gitlab.com/foo/bar/-/merge_requests/1")


# --------------------------------------------------------- Remediator.open_pr
def test_remediator_open_pr_returns_none_when_toggle_off(tmp_path):
    """Guardrail: even in a git repo, `open_prs=False` short-circuits."""
    from spotlight.agents.roles import Remediator

    src = tmp_path / "repo"
    src.mkdir()
    _git(src, "init", "-q", "-b", "main")
    _git(src, "config", "user.email", "t@t.local")
    _git(src, "config", "user.name", "T")
    (src / "app.py").write_text("x=1\n")
    _git(src, "add", "app.py")
    _git(src, "commit", "-q", "-m", "seed")

    finding = {"id": "SPOT-9", "location": {"file": "app.py"}, "class": "sqli"}
    remediation = {"applied": True, "diff": "d", "patched_content": "x=2\n",
                   "target_path": str(src / "app.py")}
    r = Remediator()
    assert r.open_pr(src, finding, remediation, open_prs=False) is None


def test_remediator_open_pr_returns_none_when_not_git_repo(tmp_path):
    from spotlight.agents.roles import Remediator

    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "app.py").write_text("x=1\n")
    finding = {"id": "SPOT-9", "location": {"file": "app.py"}, "class": "sqli"}
    remediation = {"applied": True, "diff": "d", "patched_content": "x=2\n",
                   "target_path": str(plain / "app.py")}
    r = Remediator()
    assert r.open_pr(plain, finding, remediation, open_prs=True) is None


def test_remediator_open_pr_end_to_end_with_mocked_gh(tmp_path, monkeypatch):
    """End-to-end: real git repo, mocked `gh`. Assert commit+branch happen
    and pr_url/branch/commit_sha flow through."""
    from spotlight.agents.roles import Remediator

    src = tmp_path / "repo"
    src.mkdir()
    _git(src, "init", "-q", "-b", "main")
    _git(src, "config", "user.email", "t@t.local")
    _git(src, "config", "user.name", "T")
    (src / "app.py").write_text("x=1  # vulnerable\n")
    _git(src, "add", "app.py")
    _git(src, "commit", "-q", "-m", "seed")

    finding = {
        "id": "SPOT-0007",
        "class": "sqli",
        "title": "toy",
        "cwe": "CWE-89",
        "root_cause": "concatenation",
        "location": {"file": "app.py", "function": "handler"},
    }
    remediation = {
        "applied": True,
        "diff": "-x=1\n+x=2\n",
        "patched_content": "x=2  # fixed\n",
        "target_path": str(src / "app.py"),
        "patched_path": str(src / "app.patched.py"),
    }

    canned_url = "https://github.com/AbhiK24/Spotlight/pull/7"

    def fake_run(args, **kwargs):
        # Only intercept `gh`; let real git commands pass through.
        if args and args[0] == "gh":
            return subprocess.CompletedProcess(args, 0, stdout=canned_url + "\n", stderr="")
        return subprocess._original_run(args, **kwargs)  # type: ignore[attr-defined]

    subprocess._original_run = subprocess.run  # type: ignore[attr-defined]
    monkeypatch.setattr("spotlight.git_ops.ops.subprocess.run", fake_run)

    r = Remediator()
    out = r.open_pr(src, finding, remediation, open_prs=True)
    assert out is not None
    assert out["pr_url"] == canned_url
    assert out["branch"].startswith("spotlight/SPOT-0007-")
    assert len(out["commit_sha"]) == 40
    # The file on disk was overwritten with patched content on the branch.
    assert (src / "app.py").read_text() == "x=2  # fixed\n"
