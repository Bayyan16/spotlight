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

Operator switches (both read once per adapter instance):
  * `SPOTLIGHT_SEMGREP=off|auto|on` (default `auto`). `off` makes
    `available()` return False immediately — no subprocess, no wait. `on`
    ignores the process-wide degradation latch described below, for
    operators who would rather retry every sweep.
  * `SPOTLIGHT_SEMGREP_CONFIG=<config>` overrides the default `p/default`
    rulepack. Point it at a vendored ruleset directory (or a
    comma-separated list semgrep understands) on an air-gapped T2 install
    so no scan ever reaches semgrep.dev.

Failure is latched, not re-paid. `p/default` is a *registry* reference:
semgrep downloads it from semgrep.dev at scan time. Where that host is
unreachable — air-gapped T2, a restricted CI runner, a proxy that 403s the
registry — the subprocess blocks until `timeout_s + 15` and then yields
nothing. The first such failure prints one line and latches for the rest of
the process, so the next sweep skips straight past instead of paying the
timeout again.

Emits `SemgrepMatch` records mirroring the sg-core `DataFlowSlice` shape
so downstream Investigator + Consensus code treats them uniformly.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
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


# ── environment switches ────────────────────────────────────────────────
ENV_MODE = "SPOTLIGHT_SEMGREP"  # off | auto | on
ENV_CONFIG = "SPOTLIGHT_SEMGREP_CONFIG"  # overrides DEFAULT_CONFIG

# `p/default` is Semgrep's curated community security ruleset. Beats `auto`
# because auto requires metrics-on (phones home per run), which we don't
# want either in demos or in a bank's env. It IS still a registry id, so it
# is fetched from semgrep.dev on first use — see ENV_CONFIG for air-gapped
# installs.
DEFAULT_CONFIG = "p/default"

# ── run status ──────────────────────────────────────────────────────────
STATUS_NOT_RUN = "not-run"
STATUS_OK = "ok"  # semgrep ran and its output parsed — the only usable one
STATUS_DISABLED = "disabled"  # SPOTLIGHT_SEMGREP=off
STATUS_MISSING = "missing"  # CLI not on PATH
STATUS_SKIPPED = "skipped"  # an earlier run in this process degraded
STATUS_UNREACHABLE = "unreachable"  # registry / network failure
STATUS_TIMEOUT = "timeout"  # subprocess blocked past timeout_s + 15
STATUS_ERROR = "error"  # non-zero exit or unparseable output

# Substrings that mean "semgrep never got its rules", matched against
# stderr. Deliberately narrow: a match takes Semgrep out for the rest of
# the process, so a finding-related message must never trip it.
_NETWORK_ERROR_MARKERS: tuple[str, ...] = (
    "failed to download config",
    "unable to download config",
    "error while loading config",
    "failed to download",
    "could not reach",
    "connection refused",
    "connection reset",
    "connection error",
    "connectionerror",
    "max retries exceeded",
    "name or service not known",
    "temporary failure in name resolution",
    "nodename nor servname",
    "network is unreachable",
    "certificate verify failed",
    "sslerror",
    "proxy error",
    "407 proxy",
    "403 forbidden",
    "502 bad gateway",
    "503 service unavailable",
    "504 gateway",
    "semgrep.dev",
)

# ── process-wide degradation latch ──────────────────────────────────────
# Recon runs one adapter per sweep, so without this the dead wait is paid
# on every sweep for the whole life of the worker.
#
# The latch exists to avoid *dead waits*, so only a slow failure earns it.
# A run that fails in under this many seconds — a malformed planner
# rulepack, a bad local path — costs nothing to retry next sweep, and
# latching on it would blame the network for a config bug.
_SLOW_FAILURE_S = 10.0

_DEGRADED_REASON: str | None = None


def degraded_reason() -> str | None:
    """Why Semgrep is being skipped process-wide, or None while healthy."""
    return _DEGRADED_REASON


def reset_degraded_state() -> None:
    """Clear the latch — for tests, and for workers that want to retry."""
    global _DEGRADED_REASON
    _DEGRADED_REASON = None


def _is_registry_config(config: str) -> bool:
    """True when `config` is fetched from semgrep.dev rather than read off disk."""
    for entry in str(config).split(","):
        entry = entry.strip()
        if not entry:
            continue
        if entry == "auto" or entry.startswith(("p/", "r/", "s/", "http://", "https://")):
            return True
    return False


def _network_failure(stderr: str) -> str:
    """Return the offending stderr line when it names a registry/network failure."""
    lowered = stderr.lower()
    for marker in _NETWORK_ERROR_MARKERS:
        if marker in lowered:
            for line in stderr.splitlines():
                if marker in line.lower():
                    return line.strip()[:200]
            return marker
    return ""


def _first_line(text: str) -> str:
    for line in (text or "").splitlines():
        if line.strip():
            return line.strip()[:200]
    return ""


@dataclass
class SemgrepAdapter:
    """Wraps the semgrep CLI. Instantiate once per sweep.

    `config` and `mode` default to None, meaning "read the environment".
    An explicit constructor argument always wins over the env var, so
    callers that know exactly which rulepack they want (the live test, a
    customer-rules path) are unaffected by operator config.

    `available()` and `scan()` both record why they gave up on `status` /
    `status_detail`; `describe()` renders that for a log line.
    """

    timeout_s: int = 60
    config: str | None = None
    executable: str = "semgrep"
    mode: str | None = None  # off | auto | on
    status: str = field(default=STATUS_NOT_RUN, init=False)
    status_detail: str = field(default="", init=False)
    match_count: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        if self.config is None:
            self.config = os.environ.get(ENV_CONFIG, "").strip() or DEFAULT_CONFIG
        if self.mode is None:
            self.mode = os.environ.get(ENV_MODE, "auto").strip().lower() or "auto"
        if self.mode not in {"off", "auto", "on"}:
            print(f"[semgrep] ignoring unknown {ENV_MODE}={self.mode!r}; using 'auto'")
            self.mode = "auto"

    # ── availability ───────────────────────────────────────────────────
    def available(self) -> bool:
        """True when a scan is worth attempting. Records why when it isn't."""
        if self.mode == "off":
            self.status = STATUS_DISABLED
            self.status_detail = f"{ENV_MODE}=off"
            return False
        if _DEGRADED_REASON is not None and self.mode != "on":
            self.status = STATUS_SKIPPED
            self.status_detail = _DEGRADED_REASON
            return False
        if shutil.which(self.executable) is None:
            self.status = STATUS_MISSING
            self.status_detail = f"{self.executable} not on PATH"
            return False
        return True

    def usable(self) -> bool:
        """True only after a run that actually produced parseable output."""
        return self.status == STATUS_OK

    def describe(self) -> str:
        """One-line status for operators — what really happened, not just
        whether the binary exists."""
        if self.status == STATUS_OK:
            return f"ok — {self.match_count} matches via {self.config}"
        if self.status == STATUS_NOT_RUN:
            return "not run"
        label = {
            STATUS_DISABLED: "off",
            STATUS_MISSING: "unavailable",
            STATUS_SKIPPED: "skipped",
            STATUS_UNREACHABLE: "degraded: registry unreachable",
            STATUS_TIMEOUT: "degraded: timed out",
            STATUS_ERROR: "degraded: error",
        }.get(self.status, self.status)
        return f"{label} ({self.status_detail})" if self.status_detail else label

    # ── scan ───────────────────────────────────────────────────────────
    def scan(
        self,
        root: Path,
        *,
        extra_configs: list[str] | None = None,
    ) -> list[SemgrepMatch]:
        """Run Semgrep against `root`.

        `extra_configs` — additional `--config` values appended after the
        base rulepack. Enables the Planner-authored ephemeral YAML rulepack
        to ride alongside the base config for a single sweep. Silently
        ignored entries that don't resolve to a file or a valid config id
        are semgrep's problem, not ours (its `--config` handling accepts
        broken values and just logs a warning).
        """
        if not self.available():
            return []
        self.match_count = 0
        cmd = [
            self.executable,
            "--config", str(self.config),
            "--json",
            "--quiet",
            "--timeout", str(self.timeout_s),
            "--metrics=off",
            # Independent of --metrics: semgrep pings semgrep.dev for a
            # version check on every invocation, and that ping has no
            # timeout of its own. Measured on a proxied sandbox: a scan
            # whose rules are already local takes 99s with the check and
            # 2s without it. Nothing downstream reads the upgrade notice,
            # so it is off unconditionally.
            "--disable-version-check",
        ]
        for extra in extra_configs or []:
            if extra:
                cmd.extend(["--config", str(extra)])
        cmd.append(str(root))
        started = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_s + 15,
                check=False,
            )
        except subprocess.TimeoutExpired:
            # The registry fetch is the usual culprit: it blocks with no
            # output at all. Either way, a scan that can't finish once
            # won't finish on the next sweep either.
            self._degrade(STATUS_TIMEOUT, f"no result after {self.timeout_s + 15}s")
            return []
        except FileNotFoundError:
            self.status = STATUS_MISSING
            self.status_detail = f"{self.executable} vanished from PATH mid-scan"
            return []

        elapsed = time.monotonic() - started
        stderr = proc.stderr or ""
        network = _network_failure(stderr)
        matches: list[SemgrepMatch] = []
        parsed = False
        if proc.stdout:
            try:
                matches = _extract_matches(json.loads(proc.stdout))
                parsed = True
            except json.JSONDecodeError:
                parsed = False

        if not parsed:
            # `--quiet` suppresses semgrep's own error text, so a blocked
            # registry can arrive as nothing but a non-zero exit and an
            # empty stdout — measured at 98s through a 403ing proxy. A
            # failing exit with no parseable results means semgrep reached
            # no verdict at all, which is a fact about the install rather
            # than the target.
            detail = network or _first_line(stderr) or (
                f"exit {proc.returncode} after {elapsed:.0f}s, no JSON on stdout"
            )
            self.status = STATUS_ERROR
            self.status_detail = detail
            if network or (proc.returncode != 0 and elapsed >= _SLOW_FAILURE_S):
                registry = bool(network) or _is_registry_config(str(self.config))
                self._degrade(STATUS_UNREACHABLE if registry else STATUS_ERROR, detail)
            # Anything else — a fast non-zero exit, or exit 0 with unusable
            # output — is cheap to retry, so it stays a per-run error.
            return []
        if network and not matches:
            # Output parsed, but the rules never loaded — zero matches here
            # means "we learned nothing", not "the repo is clean".
            self._degrade(STATUS_UNREACHABLE, network)
            return []

        self.status = STATUS_OK
        self.status_detail = ""
        self.match_count = len(matches)
        return matches

    def _degrade(self, status: str, detail: str) -> None:
        """Record the failure and latch it for the rest of the process."""
        global _DEGRADED_REASON
        self.status = status
        self.status_detail = detail
        if _DEGRADED_REASON is not None:
            return
        _DEGRADED_REASON = detail
        if _is_registry_config(str(self.config)):
            print(
                f"[semgrep] registry unreachable ({detail}); "
                "continuing without external signals — set "
                f"{ENV_CONFIG} to a local ruleset or {ENV_MODE}=off to skip this wait"
            )
        else:
            print(
                f"[semgrep] scan failed ({detail}); "
                "continuing without external signals"
            )


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


def run_semgrep(
    root: Path, *, timeout_s: int = 60, config: str | None = None
) -> list[SemgrepMatch]:
    """Convenience for callers that don't need to hold an adapter instance.

    `config=None` resolves through `SPOTLIGHT_SEMGREP_CONFIG`, then
    `DEFAULT_CONFIG` — same precedence as the adapter.
    """
    return SemgrepAdapter(timeout_s=timeout_s, config=config).scan(root)
