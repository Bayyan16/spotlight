"""Git operations — clone, branch, commit, and PR creation via `gh`.

All shell-outs use argument lists (never shell=True). This is our
command-injection guardrail: repo URLs, branch names, and commit messages
never get interpolated into a shell string.

The `gh` binary must be on PATH and authenticated (`gh auth status`); if
either fails, `open_pr` returns a PROpenResult with `ok=False` and the stderr
tail so the caller can log-and-continue.
"""
from __future__ import annotations

import hashlib
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass
class PROpenResult:
    ok: bool
    pr_url: str | None
    branch: str
    stderr: str = ""


_PR_URL_RE = re.compile(r"https?://github\.com/[^\s]+/pull/\d+")


class GitOps:
    """Thin wrapper over `git` and `gh` shell commands.

    Stateless — all methods take an explicit repo path (or return a fresh
    workdir for `clone_at`).
    """

    def __init__(self, timeout: int = 120) -> None:
        self.timeout = timeout

    # ------------------------------------------------------------------ clone
    def clone_at(self, repo_url: str, sha: str | None = None) -> Path:
        """Shallow clone `repo_url` into a fresh temp dir. If `sha` is given,
        clone with more depth and check out the pinned SHA. Returns the
        checkout dir (i.e. the `src/` inside the workdir tempdir)."""
        workdir = Path(tempfile.mkdtemp(prefix="spotlight-clone-"))
        target = workdir / "src"
        # For a pinned SHA we don't know how far back to go, so fetch full
        # history. For plain HEAD we shallow-clone.
        if sha:
            self._run(
                ["git", "clone", repo_url, str(target)],
                cwd=None,
            )
            self._run(["git", "checkout", sha], cwd=target)
        else:
            self._run(
                ["git", "clone", "--depth", "1", repo_url, str(target)],
                cwd=None,
            )
        return target

    # ------------------------------------------------------------------ probe
    def is_git_repo(self, path: Path) -> bool:
        """True iff `path` is (or contains) a real git checkout."""
        p = Path(path)
        if not p.exists():
            return False
        # Fast path: `.git` present.
        if (p / ".git").exists():
            return True
        # Slow path: `git rev-parse` succeeds anywhere inside.
        try:
            r = subprocess.run(
                ["git", "-C", str(p), "rev-parse", "--is-inside-work-tree"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return r.returncode == 0 and r.stdout.strip() == "true"
        except Exception:
            return False

    # ------------------------------------------------------------------ branch
    def create_scratch_branch(self, repo: Path, finding_id: str) -> str:
        """Create + checkout `spotlight/<finding_id>-<short>`. Return the
        branch name.

        `<short>` is a 7-char digest derived from finding_id + current HEAD
        so re-runs don't collide.
        """
        head = self._run(
            ["git", "rev-parse", "HEAD"], cwd=repo
        ).stdout.strip() or "nohead"
        short = hashlib.sha1(f"{finding_id}:{head}".encode()).hexdigest()[:7]
        # Sanitize finding_id for git branch rules.
        safe_fid = re.sub(r"[^A-Za-z0-9_.-]", "-", finding_id)
        branch = f"spotlight/{safe_fid}-{short}"
        self._run(["git", "checkout", "-b", branch], cwd=repo)
        return branch

    # ------------------------------------------------------------------ commit
    def stage_and_commit(
        self,
        repo: Path,
        files: list[Path],
        message: str,
        author: str = "Spotlight <bot@cmul8.com>",
    ) -> str:
        """Stage `files` and create one commit. Returns the commit SHA."""
        # Stage each file explicitly — never `git add -A` (safety: don't sweep
        # up stray artifacts from the workdir).
        rel_paths = []
        for f in files:
            fp = Path(f)
            try:
                rel = fp.resolve().relative_to(Path(repo).resolve())
                rel_paths.append(str(rel))
            except ValueError:
                # Not under the repo — skip it defensively.
                continue
        if not rel_paths:
            raise RuntimeError("stage_and_commit: no files inside repo to stage")
        self._run(["git", "add", "--", *rel_paths], cwd=repo)
        # Use -c overrides so we don't touch the global git config.
        self._run(
            [
                "git",
                "-c",
                f"user.name={_author_name(author)}",
                "-c",
                f"user.email={_author_email(author)}",
                "commit",
                "-m",
                message,
                "--author",
                author,
            ],
            cwd=repo,
        )
        sha = self._run(["git", "rev-parse", "HEAD"], cwd=repo).stdout.strip()
        return sha

    # ------------------------------------------------------------------ PR
    def open_pr(
        self, repo: Path, base: str, head: str, title: str, body: str
    ) -> PROpenResult:
        """Shell out to `gh pr create` and parse the PR URL from stdout.

        Never raises: on any failure returns PROpenResult(ok=False, ...) with
        the stderr tail so the caller can log and move on.
        """
        try:
            r = subprocess.run(
                [
                    "gh",
                    "pr",
                    "create",
                    "--base",
                    base,
                    "--head",
                    head,
                    "--title",
                    title,
                    "--body",
                    body,
                ],
                cwd=str(repo),
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except FileNotFoundError:
            return PROpenResult(ok=False, pr_url=None, branch=head, stderr="gh not on PATH")
        except subprocess.TimeoutExpired:
            return PROpenResult(ok=False, pr_url=None, branch=head, stderr="gh timeout")
        if r.returncode != 0:
            return PROpenResult(
                ok=False,
                pr_url=None,
                branch=head,
                stderr=(r.stderr or "")[-400:],
            )
        # gh prints the PR URL as the last non-empty line on success. Regex
        # scan to be robust against extra chatter.
        m = _PR_URL_RE.search(r.stdout or "")
        pr_url = m.group(0) if m else (r.stdout or "").strip().splitlines()[-1].strip()
        return PROpenResult(ok=True, pr_url=pr_url, branch=head, stderr="")

    # --------------------------------------------------------------- internal
    def _run(self, args: list[str], cwd: Path | None) -> subprocess.CompletedProcess:
        """Run a subprocess with arg list; raise with clean stderr on failure."""
        assert isinstance(args, list) and all(isinstance(a, str) for a in args), (
            "GitOps._run requires an arg list (never shell=True)"
        )
        r = subprocess.run(
            args,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=self.timeout,
            check=False,
        )
        if r.returncode != 0:
            raise RuntimeError(
                f"git command failed ({args[:3]}...): {r.stderr.strip()[:400]}"
            )
        return r


def _author_name(author: str) -> str:
    # "Name <email>" -> "Name"
    if "<" in author:
        return author.split("<", 1)[0].strip()
    return author


def _author_email(author: str) -> str:
    if "<" in author and ">" in author:
        return author.split("<", 1)[1].split(">", 1)[0].strip()
    return "bot@cmul8.com"
