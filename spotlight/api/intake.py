"""Validation for repositories accepted by the public API."""
from __future__ import annotations

import os
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

from fastapi import HTTPException


_FIXTURE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_COMMIT_SHA = re.compile(r"^[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?$")
_REPO_PATH = re.compile(r"^/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+\.git$")


def allowed_git_hosts() -> set[str]:
    raw = os.environ.get("SPOTLIGHT_GIT_HOSTS", "github.com")
    return {host.strip().lower() for host in raw.split(",") if host.strip()}


def validate_commit_sha(commit_sha: str | None) -> str | None:
    if commit_sha is None:
        return None
    value = commit_sha.strip()
    if not _COMMIT_SHA.fullmatch(value):
        raise HTTPException(400, "commit_sha must be a full 40- or 64-character hex SHA")
    return value.lower()


def validate_git_url(repo_url: str) -> str:
    try:
        parsed = urlsplit(repo_url)
        port = parsed.port
    except ValueError as exc:
        raise HTTPException(400, "invalid git URL") from exc
    host = (parsed.hostname or "").lower().rstrip(".")
    if parsed.scheme != "https":
        raise HTTPException(400, "only HTTPS git URLs are accepted")
    if host not in allowed_git_hosts():
        raise HTTPException(400, f"git host is not allow-listed: {host or '<missing>'}")
    if parsed.username or parsed.password or port not in (None, 443):
        raise HTTPException(400, "git URL credentials and custom ports are not accepted")
    if parsed.query or parsed.fragment:
        raise HTTPException(400, "git URL query strings and fragments are not accepted")
    path = unquote(parsed.path)
    if ".." in Path(path).parts or not _REPO_PATH.fullmatch(path):
        raise HTTPException(400, "git URL must identify an owner/repository.git path")
    return f"https://{host}{path}"


def _allowed_local_roots() -> list[Path]:
    raw = os.environ.get("SPOTLIGHT_LOCAL_REPO_ROOTS", "")
    roots: list[Path] = []
    for item in raw.split(os.pathsep):
        if item.strip():
            roots.append(Path(item).expanduser().resolve())
    return roots


def resolve_repo_input(repo: str, *, targets_root: Path) -> tuple[Path | str, str]:
    """Return a validated fixture Path, local Path, or canonical HTTPS URL."""
    value = (repo or "").strip()
    if value.startswith(("http://", "https://", "git@")):
        return validate_git_url(value), "git-url"

    if _FIXTURE_NAME.fullmatch(value):
        fixture = (targets_root / value).resolve()
        try:
            fixture.relative_to(targets_root.resolve())
        except ValueError as exc:  # defensive; regex already rejects traversal
            raise HTTPException(400, "invalid fixture name") from exc
        if fixture.is_dir():
            return fixture, "fixture"

    if os.environ.get("SPOTLIGHT_ALLOW_LOCAL_REPOS", "").lower() in {"1", "true", "yes"}:
        candidate = Path(value).expanduser().resolve()
        for root in _allowed_local_roots():
            try:
                candidate.relative_to(root)
            except ValueError:
                continue
            if candidate.is_dir():
                return candidate, "local"
        raise HTTPException(403, "local repository is outside SPOTLIGHT_LOCAL_REPO_ROOTS")

    raise HTTPException(404, f"repository or fixture not found: {value}")
