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
import os
import re
import shutil
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
        try:
            # Fetch only the requested commit instead of cloning full history.
            # This makes paired-CVE scans reproducible without letting a caller
            # force an unbounded history download merely by supplying a SHA.
            if sha:
                target.mkdir()
                self._run(["git", "init", "--quiet"], cwd=target)
                self._run(["git", "remote", "add", "origin", repo_url], cwd=target)
                self._run(
                    ["git", "fetch", "--depth", "1", "--no-tags", "origin", sha],
                    cwd=target,
                )
                self._run(["git", "checkout", "--quiet", "--detach", "FETCH_HEAD"], cwd=target)
            else:
                self._run(
                    [
                        "git", "clone", "--quiet", "--depth", "1", "--no-tags",
                        "--filter=blob:none", "--", repo_url, str(target),
                    ],
                    cwd=None,
                )
            self._enforce_checkout_limits(target)
            return target
        except Exception:
            shutil.rmtree(workdir, ignore_errors=True)
            raise

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

    # ------------------------------------------------------------------ head
    def head_info(self, path: Path) -> dict:
        """Best-effort identity block for a repo path.

        Returns {org, commit_sha, commit_branch, clone_url} — any field is
        empty string when we can't determine it. Never raises.

        Used at sweep-start so every SweepRow knows *what code* the sweep
        actually saw. Two sweeps of the same repo months apart are only
        "the same" if commit_sha matches.
        """
        out = {"org": "", "commit_sha": "", "commit_branch": "", "clone_url": ""}
        p = Path(path)
        if not self.is_git_repo(p):
            return out
        try:
            sha = self._capture(["git", "-C", str(p), "rev-parse", "HEAD"])
            out["commit_sha"] = sha
        except Exception:
            pass
        try:
            branch = self._capture(["git", "-C", str(p), "rev-parse", "--abbrev-ref", "HEAD"])
            out["commit_branch"] = branch if branch != "HEAD" else ""
        except Exception:
            pass
        try:
            url = self._capture(["git", "-C", str(p), "config", "--get", "remote.origin.url"])
            out["clone_url"] = url
            out["org"] = _org_from_url(url)
        except Exception:
            pass
        return out

    def _capture(self, args: list[str]) -> str:
        """Run a git command and return trimmed stdout. Raises on non-zero."""
        r = subprocess.run(args, capture_output=True, text=True, timeout=self.timeout)
        if r.returncode != 0:
            raise RuntimeError(r.stderr.strip() or f"git failed: {args}")
        return r.stdout.strip()

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
        trailers: dict[str, str] | None = None,
    ) -> str:
        """Stage `files` and create one commit. Returns the commit SHA.

        `trailers`, when provided, are appended to the commit message as
        ``Key: Value`` lines separated from the body by a blank line — this is
        the mechanism the non-repudiation layer uses to attach a
        ``Signed-off-by-agent`` trailer that points at the finding's
        Attestation.
        """
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
        final_message = _append_trailers(message, trailers)
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
                final_message,
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

    def _enforce_checkout_limits(self, target: Path) -> None:
        max_bytes = int(os.environ.get("SPOTLIGHT_MAX_REPO_BYTES", str(250 * 1024 * 1024)))
        max_files = int(os.environ.get("SPOTLIGHT_MAX_REPO_FILES", "100000"))
        total_bytes = 0
        total_files = 0
        for root, dirs, files in os.walk(target, followlinks=False):
            # Never traverse symlinked directories from an untrusted checkout.
            dirs[:] = [d for d in dirs if not (Path(root) / d).is_symlink()]
            for name in files:
                path = Path(root) / name
                try:
                    stat = path.lstat()
                except OSError:
                    continue
                total_files += 1
                total_bytes += stat.st_size
                if total_files > max_files:
                    raise RuntimeError(f"repository exceeds file limit ({max_files})")
                if total_bytes > max_bytes:
                    raise RuntimeError(f"repository exceeds size limit ({max_bytes} bytes)")


def _append_trailers(message: str, trailers: dict[str, str] | None) -> str:
    """Append ``Key: Value`` trailer lines to `message`, blank-line separated.

    Empty/None trailers are a no-op. We keep this pure so tests can pin the
    exact wire format without touching git.
    """
    if not trailers:
        return message
    lines = [f"{k}: {v}" for k, v in trailers.items()]
    return message.rstrip("\n") + "\n\n" + "\n".join(lines) + "\n"


def format_non_repudiation_footer(attestation_url: str) -> str:
    """Return the PR-body ``## Non-repudiation`` section as a Markdown block.

    Callers concatenate this onto their PR body so every Spotlight-authored
    PR carries a pointer at the finding's signed Attestation. Kept in
    ``git_ops`` (not in ``non_repudiation``) so we don't create a cycle:
    ``non_repudiation`` shouldn't need to know about PRs.
    """
    return (
        "\n\n## Non-repudiation\n\n"
        f"This PR was opened by the Spotlight agent. Full signed chain of "
        f"custody, including every Triager / Remediator / Verifier action, "
        f"is available at the finding's Attestation:\n\n"
        f"{attestation_url}\n"
    )


def _author_name(author: str) -> str:
    # "Name <email>" -> "Name"
    if "<" in author:
        return author.split("<", 1)[0].strip()
    return author


def _author_email(author: str) -> str:
    if "<" in author and ">" in author:
        return author.split("<", 1)[1].split(">", 1)[0].strip()
    return "bot@cmul8.com"


def _org_from_url(url: str) -> str:
    """Extract the org/user segment from a git remote URL.

    Handles the common shapes:
        https://github.com/acme/api.git         -> "acme"
        git@github.com:acme/api.git             -> "acme"
        https://gitlab.com/foo/bar/baz.git      -> "foo/bar"

    Returns "" if the URL doesn't look parseable.
    """
    url = (url or "").strip()
    if not url:
        return ""
    # Strip protocol.
    if "://" in url:
        _, _, rest = url.partition("://")
    elif url.startswith("git@"):
        _, _, rest = url.partition(":")
    else:
        rest = url
    # rest = host/path OR path (ssh-form).
    if "/" not in rest:
        return ""
    _, _, path = rest.partition("/")
    # Drop trailing .git and any /repo segment (the LAST segment is the repo).
    if path.endswith(".git"):
        path = path[:-4]
    parts = path.split("/")
    if len(parts) < 2:
        return ""
    return "/".join(parts[:-1])
