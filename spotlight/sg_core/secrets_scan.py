"""Hardcoded-secret detector for sg-core (CWE-798).

Reuses the redaction detectors to find live-looking credentials embedded in
source. Emits DataFlowSlice-shaped results so the orchestrator can treat them
like any other finding — but with a synthetic source ("hardcoded-literal")
and a synthetic sink named after the credential kind (aws-key, github-pat,
openai-key, etc.).

Reproduction is skipped for this class: there's no PoC to run — the finding
IS the fact that the credential is in the source tree. Consensus Kernel
promotes on static-fact alone (high-confidence tier).
"""
from __future__ import annotations

from pathlib import Path

from spotlight.redaction.detectors import all_detectors as _all_detectors

DETECTORS = _all_detectors()

from .graph import DataFlowSlice, Sink, Source


# File extensions we scan. Skip binaries and lockfiles.
_SCAN_EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".env", ".yaml", ".yml", ".json", ".toml", ".ini", ".conf", ".sh", ".rb", ".go", ".java", ".php"}
_SKIP_DIRS = {"node_modules", ".venv", "venv", "dist", "build", ".git", "__pycache__"}
_MAX_FILE_BYTES = 200_000  # skip huge files


def scan_secrets(root: Path) -> list[DataFlowSlice]:
    """Walk `root` and return a slice per hardcoded-secret match."""
    results: list[DataFlowSlice] = []
    if root.is_file():
        results.extend(_scan_file(root))
        return results
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in _SCAN_EXTS:
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        results.extend(_scan_file(path))
    return results


def _scan_file(path: Path) -> list[DataFlowSlice]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    slices: list[DataFlowSlice] = []
    for detector in DETECTORS:
        for match in detector.pattern.finditer(text):
            # Line the match starts on (1-based).
            line = text[: match.start()].count("\n") + 1
            # Bit of surrounding context for the argument_source field.
            snippet = match.group(0)
            # Truncate long secrets so we don't leak in memory-side channels
            # (event log redaction will re-scrub before persist regardless).
            display = snippet[:12] + "…" if len(snippet) > 24 else snippet
            slices.append(
                DataFlowSlice(
                    file=str(path),
                    function="<module>",
                    source=Source(
                        name="literal",
                        origin=f"hardcoded:{detector.kind}",
                        line=line,
                    ),
                    sink=Sink(
                        callee=detector.kind,
                        class_="secrets",
                        line=line,
                        argument_source=display,
                    ),
                    sanitized=False,
                    reason=f"hardcoded {detector.kind} in source (matches {detector.kind} pattern)",
                )
            )
    return slices
