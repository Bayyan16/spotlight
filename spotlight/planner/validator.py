"""Grep-based validator for planner-proposed rules.

The Planner's LLM step can hallucinate a plausible-sounding callable
(``acme.utils.load_yaml``) that doesn't actually exist in the target
repo. Before we feed any proposed rule into the downstream engines we
verify the identifier(s) actually appear in the source. Rules whose
identifiers can't be located are DROPPED and the reason recorded on the
signed audit trail — never silently swallowed.

Same trust discipline as the B5 Hypothesis Proposer's step-id
verification: the model gets creativity, the validator keeps it honest.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


@dataclass
class ValidationOutcome:
    identifier: str
    found: bool
    hit_files: list[str] = field(default_factory=list)


class GrepValidator:
    """Cheap, fast identifier lookup across a repo.

    Not a semantic check — we only confirm the *name* appears in the
    codebase. That's sufficient to catch outright hallucinations (a name
    the model invented that doesn't exist anywhere) without paying the
    cost of a proper import-resolution pass.
    """

    _EXTS = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".pyi")

    def __init__(self, repo_root: Path) -> None:
        self.repo_root = Path(repo_root).resolve()
        # Lazy — indexed on first lookup, then cached for the sweep.
        self._index: dict[str, list[str]] | None = None
        self._file_count: int = 0

    def _index_repo(self) -> None:
        idx: dict[str, list[str]] = {}
        for f in self.repo_root.rglob("*"):
            if not f.is_file():
                continue
            if f.suffix.lower() not in self._EXTS:
                continue
            if any(seg in f.parts for seg in ("node_modules", ".venv", "dist", ".git")):
                continue
            try:
                text = f.read_text(errors="ignore")
            except Exception:
                continue
            self._file_count += 1
            rel = str(f.relative_to(self.repo_root))
            for tok in set(_IDENT_RE.findall(text)):
                idx.setdefault(tok, []).append(rel)
        self._index = idx

    def check(self, identifier: str) -> ValidationOutcome:
        """Return whether the identifier appears anywhere in the repo.

        For dotted names (``acme.utils.load_yaml``) we require the LAST
        segment to appear — Python and JS callers frequently write
        ``from acme.utils import load_yaml; load_yaml(x)`` so the dotted
        prefix isn't visible at the call site."""
        if self._index is None:
            self._index_repo()
        assert self._index is not None
        needle = identifier.split(".")[-1]
        if not needle or not _IDENT_RE.fullmatch(needle):
            return ValidationOutcome(identifier=identifier, found=False)
        hits = self._index.get(needle, [])
        return ValidationOutcome(
            identifier=identifier, found=bool(hits), hit_files=hits[:5]
        )
