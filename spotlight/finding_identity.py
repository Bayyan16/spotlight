"""Stable, repository-scoped identity for findings.

Sweep-local sequence numbers make the same vulnerability look new whenever
agent ordering or a temporary checkout directory changes.  Identity here is
derived only from semantic location fields that survive those changes.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any


_CLONE_SEGMENT = re.compile(r"^spotlight-clone-[A-Za-z0-9_.-]+$")


def canonical_repo_path(file_hint: str | None, repo_root: str | Path | None = None) -> str:
    """Return a portable repo-relative path without leaking host temp paths."""
    raw = str(file_hint or "").strip().replace("\\", "/")
    if not raw:
        return ""

    if repo_root is not None:
        try:
            return Path(raw).resolve().relative_to(Path(repo_root).resolve()).as_posix()
        except (OSError, ValueError):
            pass

    parts = PurePosixPath(raw).parts
    for index, part in enumerate(parts[:-1]):
        if _CLONE_SEGMENT.fullmatch(part) and index + 1 < len(parts) and parts[index + 1] == "src":
            return PurePosixPath(*parts[index + 2 :]).as_posix()

    if not PurePosixPath(raw).is_absolute():
        normalized = PurePosixPath(raw).as_posix()
        while normalized.startswith("./"):
            normalized = normalized[2:]
        return normalized

    # An absolute path outside the declared repository is not a stable
    # location and must not be exposed in an API payload.
    return PurePosixPath(raw).name


def finding_identity(
    finding: dict[str, Any], *, repo_root: str | Path | None = None
) -> dict[str, str]:
    loc = finding.get("location") or {}
    path = canonical_repo_path(
        loc.get("repo_relative_path") or loc.get("file"), repo_root
    )
    components = {
        "class": str(finding.get("class") or "").strip().lower(),
        "path": path,
        "symbol": str(loc.get("function") or "").strip(),
    }
    serialized = json.dumps(components, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    return {
        "version": "v1",
        "fingerprint": digest,
        "key": f"v1:{digest}",
        **components,
    }


def stable_finding_id(
    finding: dict[str, Any], *, repo_root: str | Path | None = None
) -> str:
    identity = finding_identity(finding, repo_root=repo_root)
    return f"SPOT-{identity['fingerprint'][:12].upper()}"


def comparison_key(finding: dict[str, Any]) -> str:
    """Identity key for deltas, compatible with findings from older sweeps."""
    existing = finding.get("identity") or {}
    if existing.get("key"):
        return str(existing["key"])
    return finding_identity(finding)["key"]
