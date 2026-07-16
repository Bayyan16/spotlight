"""Semgrep Signal Adapter.

Adds Semgrep's ~4000 community rules as an INDEPENDENT evidence stream that
the Consensus Kernel can count alongside sg-core's reachability graph. When
sg-core says "reachable from an untrusted source" AND Semgrep independently
flags the same file:line with its own taint rule, we've got two evidence
items — different tool, different rule-authoring convention, different
model family. Independence per PRD §8.1.

The adapter is best-effort:
  * If the `semgrep` CLI is not installed, `available()` returns False and
    the pipeline skips it silently.
  * If Semgrep times out on a slow repo we return an empty match list —
    the sweep continues on sg-core alone. Semgrep is a corroborator, not
    a gate.
  * The subprocess call is arg-list (no `shell=True`), so target paths
    can't shell-inject Spotlight.

Emits `SemgrepMatch` records mirroring the sg-core `DataFlowSlice` shape
so downstream Investigator + Consensus code treats them uniformly.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path


# ── canonical-class alias table ─────────────────────────────────────────
# Semgrep's `check_id` is a dotted string like
# `python.flask.security.injection.tainted-sql-string.tainted-sql-string`.
# We fold it into our own class labels so the Consensus Kernel + Chainer
# see the same class as sg-core does.
_CHECK_ID_MATCHES: list[tuple[str, str]] = [
    # SQL injection
    ("tainted-sql-string", "sqli"),
    ("sqlalchemy-execute-raw-query", "sqli"),
    ("sql-injection", "sqli"),
    ("tainted-sql", "sqli"),
    # Command injection / shell
    ("dangerous-subprocess", "cmdi"),
    ("dangerous-system-call", "cmdi"),
    ("shell-injection", "cmdi"),
    ("command-injection", "cmdi"),
    ("tainted-command", "cmdi"),
    # Code injection / eval
    ("dangerous-eval", "code-injection"),
    ("dangerous-exec", "code-injection"),
    ("code-injection", "code-injection"),
    # SSRF
    ("ssrf", "ssrf"),
    ("tainted-url", "ssrf"),
    # XSS
    ("xss", "xss"),
    ("dangerous-inner-html", "xss"),
    ("mark-safe", "xss"),
    # Path traversal
    ("path-traversal", "path-traversal"),
    ("tainted-path", "path-traversal"),
    # Deserialization
    ("dangerous-pickle", "deserialization"),
    ("dangerous-yaml-load", "deserialization"),
    ("insecure-deserialization", "deserialization"),
    # Weak crypto
    ("weak-hash", "weak-hash"),
    ("weak-ssl", "verify-disabled"),
    ("insecure-ssl", "verify-disabled"),
    # Secrets
    ("hardcoded-password", "secrets"),
    ("hardcoded-secret", "secrets"),
    ("hardcoded-token", "secrets"),
]


@dataclass
class SemgrepMatch:
    """One Semgrep finding, in a shape the orchestrator can treat like a
    sg-core DataFlowSlice."""

    file: str
    line: int
    end_line: int
    check_id: str
    class_: str  # canonicalized ('sqli', 'ssrf', ...)
    severity: str  # INFO | WARNING | ERROR
    message: str
    snippet: str = ""
    origin: str = "signal:semgrep"

    def to_dict(self) -> dict:
        d = asdict(self)
        # Rename `class_` so JSON consumers see `class` (not `class_`).
        d["class"] = d.pop("class_")
        return d

    def as_slice_dict(self) -> dict:
        """Return in the DataFlowSlice-shaped dict the orchestrator consumes.

        Recon builds signals as a list of dicts with a `sink.class` field;
        we synthesise a source (`literal`) and sink (Semgrep's check id) so
        the Investigator's LLM prompt template doesn't have to know about
        two shapes.
        """
        return {
            "file": self.file,
            "function": f"semgrep::{self.check_id.split('.')[-1]}",
            "source": {
                "name": "semgrep",
                "origin": f"signal:semgrep",
                "line": self.line,
            },
            "sink": {
                "callee": self.check_id,
                "class": self.class_,
                "line": self.line,
                "argument_source": (self.snippet or self.message)[:200],
            },
            "sanitized": False,
            "reason": f"semgrep rule {self.check_id}: {self.message[:120]}",
            "external_signal": True,
        }


def _canonical_class(check_id: str) -> str | None:
    key = check_id.lower()
    for needle, canonical in _CHECK_ID_MATCHES:
        if needle in key:
            return canonical
    return None


@dataclass
class SemgrepAdapter:
    """Wraps the semgrep CLI. Instantiate once per sweep."""

    timeout_s: int = 60
    # `p/default` is Semgrep's curated community security ruleset. Beats
    # `auto` because auto requires metrics-on (phones home per run), which
    # we don't want either in demos or in a bank's env. `p/default` is
    # local-only.
    config: str = "p/default"
    executable: str = "semgrep"

    def available(self) -> bool:
        return shutil.which(self.executable) is not None

    def scan(self, root: Path) -> list[SemgrepMatch]:
        if not self.available():
            return []
        try:
            proc = subprocess.run(
                [
                    self.executable,
                    "--config", self.config,
                    "--json",
                    "--quiet",
                    "--timeout", str(self.timeout_s),
                    "--metrics=off",
                    str(root),
                ],
                capture_output=True,
                text=True,
                timeout=self.timeout_s + 15,
                check=False,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []
        if not proc.stdout:
            return []
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return []
        return list(_extract_matches(data))


def _extract_matches(data: dict) -> list[SemgrepMatch]:
    out: list[SemgrepMatch] = []
    for r in data.get("results", []):
        check_id = str(r.get("check_id", ""))
        cls = _canonical_class(check_id)
        if not cls:
            # Skip categories we don't have a canonical class for. Semgrep
            # community rules include a lot of noise (style, best-practices,
            # framework-specific hints) that isn't relevant to Consensus.
            continue
        path = str(r.get("path", ""))
        start_line = int(r.get("start", {}).get("line") or 0)
        end_line = int(r.get("end", {}).get("line") or start_line)
        extra = r.get("extra", {}) or {}
        severity = str(extra.get("severity", "WARNING"))
        message = str(extra.get("message", "")).strip()
        snippet = str(extra.get("lines", "")).strip()
        out.append(
            SemgrepMatch(
                file=path,
                line=start_line,
                end_line=end_line,
                check_id=check_id,
                class_=cls,
                severity=severity,
                message=message,
                snippet=snippet,
            )
        )
    return out


def run_semgrep(root: Path, *, timeout_s: int = 60, config: str = "auto") -> list[SemgrepMatch]:
    """Convenience for callers that don't need to hold an adapter instance."""
    return SemgrepAdapter(timeout_s=timeout_s, config=config).scan(root)
