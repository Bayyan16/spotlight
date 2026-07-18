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
from typing import Any


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
    # Server-Side Template Injection (CWE-1336, parent CWE-94).
    ("jinja2", "ssti"),
    ("mako", "ssti"),
    ("ssti", "ssti"),
    ("template-injection", "ssti"),
    # Dynamic import (CWE-94 direct).
    ("dynamic-import", "dynamic-import"),
    ("insecure-import", "dynamic-import"),
]


@dataclass
class SemgrepMatch:
    """One Semgrep finding, in a shape the orchestrator can treat like a
    sg-core DataFlowSlice.

    Preserves Semgrep's own CWE / OWASP metadata alongside our canonical
    class label. Two-part strategy: for the ~10 classes the Chainer +
    Consensus Kernel key off explicitly (sqli, cmdi, eval, ssrf, secrets,
    ssti, dynamic-import, deserialization, path-traversal, weak-hash) we
    normalize to our canonical label; for everything else we pass through
    Semgrep's own vulnerability-class and CWE so the Console + attestation
    can render the finding accurately without our taxonomy having to grow.
    """

    file: str
    line: int
    end_line: int
    check_id: str
    class_: str  # canonicalized when in our alias table, else "external:<slug>"
    severity: str  # INFO | WARNING | ERROR
    message: str
    snippet: str = ""
    origin: str = "signal:semgrep"
    # Semgrep-provided metadata — kept verbatim so downstream consumers
    # don't have to re-parse the raw output.
    cwe: list[str] = field(default_factory=list)  # e.g. ["CWE-89: SQL Injection"]
    owasp: list[str] = field(default_factory=list)  # e.g. ["A03:2021 - Injection"]
    confidence: str = ""  # HIGH | MEDIUM | LOW when present
    category: str = ""  # security | best-practice | correctness | ...

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
                # Semgrep's own CWE / OWASP tagging is authoritative for
                # externally-classified findings (class="external:*").
                # Downstream code reads these instead of guessing from
                # class label when they're present.
                "cwe": self.cwe,
                "owasp": self.owasp,
                "confidence": self.confidence,
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

    def scan(
        self,
        root: Path,
        *,
        extra_configs: list[str] | None = None,
    ) -> list[SemgrepMatch]:
        """Run Semgrep against `root`.

        `extra_configs` — additional `--config` values appended after the
        base rulepack. Enables the Planner-authored ephemeral YAML rulepack
        to ride alongside `p/default` for a single sweep. Silently ignored
        entries that don't resolve to a file or a valid config id are
        semgrep's problem, not ours (its `--config` handling accepts
        broken values and just logs a warning).
        """
        if not self.available():
            return []
        cmd = [
            self.executable,
            "--config", self.config,
            "--json",
            "--quiet",
            "--timeout", str(self.timeout_s),
            "--metrics=off",
        ]
        for extra in extra_configs or []:
            if extra:
                cmd.extend(["--config", str(extra)])
        cmd.append(str(root))
        try:
            proc = subprocess.run(
                cmd,
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
    """Convert Semgrep's raw JSON output into SemgrepMatch records.

    Filtering policy (changed 2026-07-18 in response to the "we only fire
    for 4 classes" audit): we keep any match that either
      (a) maps to one of our canonical class labels, OR
      (b) carries security metadata — non-empty CWE list OR
          category == "security" OR OWASP mapping.

    Everything else (style / best-practice / correctness noise) is
    dropped. Previously we filtered on our own tiny alias table alone,
    which discarded ~90% of Semgrep's Top-25-covering matches. That's
    the honest recall gap being closed here.
    """
    out: list[SemgrepMatch] = []
    for r in data.get("results", []):
        check_id = str(r.get("check_id", ""))
        extra = r.get("extra", {}) or {}
        metadata = extra.get("metadata", {}) or {}
        cwe_list = _as_str_list(metadata.get("cwe"))
        owasp_list = _as_str_list(metadata.get("owasp"))
        category = str(metadata.get("category", "")).lower()
        confidence = str(metadata.get("confidence", "")).upper()

        canonical = _canonical_class(check_id)
        is_security = (
            category == "security"
            or bool(cwe_list)
            or bool(owasp_list)
        )
        if canonical is None and not is_security:
            # Noise (style / best-practice) — skip.
            continue

        # Class label: prefer our canonical when the alias table matched,
        # else use Semgrep's own vulnerability_class (or a slug derived
        # from the check_id's last segment) prefixed with "external:" so
        # downstream code can tell "we normalized this" from "we passed
        # this through untranslated".
        if canonical is not None:
            cls_label = canonical
        else:
            vc = _first(_as_str_list(metadata.get("vulnerability_class"))) or ""
            if not vc:
                vc = check_id.split(".")[-1] or "unknown"
            cls_label = f"external:{_slugify(vc)}"

        path = str(r.get("path", ""))
        start_line = int(r.get("start", {}).get("line") or 0)
        end_line = int(r.get("end", {}).get("line") or start_line)
        severity = str(extra.get("severity", "WARNING"))
        message = str(extra.get("message", "")).strip()
        snippet = str(extra.get("lines", "")).strip()
        out.append(
            SemgrepMatch(
                file=path,
                line=start_line,
                end_line=end_line,
                check_id=check_id,
                class_=cls_label,
                severity=severity,
                message=message,
                snippet=snippet,
                cwe=cwe_list,
                owasp=owasp_list,
                confidence=confidence,
                category=category or "security",
            )
        )
    return out


def _as_str_list(v: Any) -> list[str]:
    """Semgrep sometimes returns a bare string, sometimes a list. Normalize."""
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    if isinstance(v, list):
        return [str(x) for x in v if x]
    return []


def _first(xs: list[str]) -> str:
    return xs[0] if xs else ""


def _slugify(s: str) -> str:
    import re

    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-") or "unknown"


def run_semgrep(root: Path, *, timeout_s: int = 60, config: str = "auto") -> list[SemgrepMatch]:
    """Convenience for callers that don't need to hold an adapter instance."""
    return SemgrepAdapter(timeout_s=timeout_s, config=config).scan(root)
