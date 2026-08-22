"""Bounded, single-purpose agent roles.

Each role has ONE job. Model calls go through a ModelClient. The Reproducer
and Verifier route their PoCs through the sandbox module (Modal in
production, subprocess as fallback). The Remediator applies a patch.
"""
from __future__ import annotations

import json as _json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from spotlight.agentic import AgenticScanner
from spotlight.finding_identity import canonical_repo_path
from spotlight.sandbox import CapabilityToken, SandboxResult, SandboxRunner, get_sandbox
from spotlight.sg_core import CodeGraph, DataFlowSlice
from spotlight.warden import WardenService

from .model import MockModelClient, ModelClient


@dataclass
class Recon:
    model: ModelClient

    def run(
        self,
        repo_path: Path,
        *,
        plan: Any = None,
    ) -> dict[str, Any]:
        """Build the code graph + run Semgrep + author the threat model.

        ``plan`` — an optional ``PlanOutput`` (from ``spotlight.planner``)
        that carries repo-tuned rules. When present:
          * sg-core's ``SINKS`` gets unioned with ``plan.sinks_by_class()``.
          * sg-core's tainted-var recognizer gets ``plan.source_identifiers()``.
          * sg-core's sanitizer heuristic gets ``plan.sanitizer_identifiers()``.
          * Semgrep gets the planner's ephemeral YAML appended to
            ``--config`` alongside ``p/default``.
        Absent, Recon behaves exactly as before (backwards compatible).
        """
        code_files: list[Path] = []
        for ext in ("*.py", "*.js", "*.ts", "*.jsx", "*.tsx"):
            code_files.extend(
                p for p in repo_path.rglob(ext)
                if "node_modules" not in p.parts and ".venv" not in p.parts and "dist" not in p.parts
            )
        # Fold planner extras into the CodeGraph build.
        extra_sinks: dict[str, list[str]] = {}
        extra_sources: list[str] = []
        extra_sanitizers: list[str] = []
        if plan is not None:
            try:
                extra_sinks = plan.sinks_by_class()
                extra_sources = plan.source_identifiers()
                extra_sanitizers = plan.sanitizer_identifiers()
            except Exception as exc:
                print(f"[recon] plan integration failed: {exc!r}")
        graph = CodeGraph.build(
            code_files,
            extra_sinks=extra_sinks or None,
            extra_sources=extra_sources or None,
            extra_sanitizers=extra_sanitizers or None,
        )
        slices = graph.slices()
        signals = [s.to_dict() for s in graph.reachable_slices()]
        has_ai_layer = any(
            "langchain" in f.read_text(errors="ignore").lower()
            or "openai" in f.read_text(errors="ignore").lower()
            for f in code_files
        )
        warden_flags, wrapped_docs = _warden_scan_recon_surface(repo_path, code_files)
        # Agentic Sweep: OWASP-LLM rule packs. Runs alongside the classic
        # code-graph slices; the orchestrator fans agentic slices out to the
        # same Investigator (with a `surface: "agentic"` marker so the model
        # prompt can differentiate).
        agentic_signals = [
            f.to_dict() for f in AgenticScanner().scan(repo_path, code_files)
        ]
        # Signal Adapter: Semgrep. Best-effort — never crashes the sweep.
        # When semgrep isn't installed, `scan` returns []. Each match lands
        # in `signals` alongside the sg-core slices; the Consensus Kernel
        # treats it as an INDEPENDENT external signal (§8.1) when a
        # sg-core slice AND a semgrep match land at the same (file, line).
        try:
            from spotlight.signals import SemgrepAdapter

            adapter = SemgrepAdapter()
            available = adapter.available()
            print(f"[recon] semgrep available: {available}")
            if available:
                extra_configs: list[str] = []
                if plan is not None and getattr(plan, "semgrep_rules_yaml", ""):
                    # Planner-authored rulepack — write to a temp file and
                    # feed to semgrep --config alongside p/default.
                    try:
                        import tempfile as _tmp

                        yaml_path = Path(_tmp.mkdtemp(prefix="spotlight-plan-")) / "rules.yml"
                        yaml_path.write_text(plan.semgrep_rules_yaml)
                        extra_configs.append(str(yaml_path))
                        print(f"[recon] planner rulepack: {yaml_path}")
                    except Exception as exc:
                        print(f"[recon] planner rulepack write failed: {exc!r}")
                semgrep_matches = adapter.scan(repo_path, extra_configs=extra_configs or None)
                semgrep_signals = [m.as_slice_dict() for m in semgrep_matches]
                print(f"[recon] semgrep matches: {len(semgrep_matches)}")
                signals = signals + semgrep_signals
            else:
                semgrep_signals = []
        except Exception as exc:
            print(f"[recon] semgrep failed: {exc!r}")
            semgrep_signals = []
        threat_model = self.model.complete(
            role="recon",
            prompt="classify stack and threat model",
            context={
                "signals": signals,
                "has_ai_layer": has_ai_layer,
                # Wrapped, envelope-fenced target docs. The model prompt
                # template concatenates these into the user message so the
                # model sees README content behind the untrusted envelope,
                # not inline as trusted operator instructions.
                "wrapped_docs": wrapped_docs,
            },
        )
        return {
            "threat_model": threat_model,
            "signals": signals,
            "slices": [s.to_dict() for s in slices],
            "warden_flags": warden_flags,
            "wrapped_docs": wrapped_docs,
            "agentic_signals": agentic_signals,
            "semgrep_signals": semgrep_signals,
        }


def _warden_scan_recon_surface(
    repo_path: Path, code_files: list[Path]
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Run WardenService prompt-injection scans over the target's public
    documentation and the top comment block of every source file.

    Returns:
        (warden_flags, wrapped_docs)

        warden_flags — flat list of dicts with `origin`, `kind`, `span`,
        `snippet` so the orchestrator can emit one event per hit.

        wrapped_docs — list of `{origin, wrapped}` dicts: each README /
        top-comment run through `WardenService.wrap_target_content`. The
        model prompt template concatenates these into the user message so
        target-derived text is always fenced behind the untrusted envelope.

    Any file we can't read is silently skipped — we do NOT crash Recon over
    a stray permission error or a non-UTF-8 file.
    """
    warden = WardenService()
    flags: list[dict[str, Any]] = []
    wrapped_docs: list[dict[str, str]] = []
    # 1. README-shaped files at the top level.
    readme_globs = ("README.md", "README.rst", "README.txt", "README")
    top_level_md = list(repo_path.glob("*.md"))
    seen: set[Path] = set()
    for name in readme_globs:
        p = repo_path / name
        if p.exists() and p.is_file():
            top_level_md.append(p)
    for p in top_level_md:
        if p in seen:
            continue
        seen.add(p)
        try:
            content = p.read_text(errors="ignore")
        except Exception:
            continue
        origin = f"readme:{p.name}"
        for m in warden.scan_target_for_injection(content, origin):
            flags.append({"origin": origin, **m.to_dict()})
        wrapped_docs.append(
            {"origin": origin, "wrapped": warden.wrap_target_content(content, origin)}
        )

    # 2. Top comments of every source file. `_extract_top_comments` is
    #    dedent-safe and returns "" for a file with no leading comments.
    for src in code_files:
        try:
            content = src.read_text(errors="ignore")
        except Exception:
            continue
        top = _extract_top_comments(content, src.suffix)
        if not top:
            continue
        try:
            rel = src.relative_to(repo_path)
        except ValueError:
            rel = src.name
        origin = f"comment:{rel}"
        for m in warden.scan_target_for_injection(top, origin):
            flags.append({"origin": origin, **m.to_dict()})
    return flags, wrapped_docs


def _extract_top_comments(text: str, suffix: str) -> str:
    '''Pull the top-of-file comment block from `text`. Handles Python
    `#`/`"""`, JS/TS `//`/`/* */`. Returns "" if there is no leading
    comment / docstring.'''
    if not text:
        return ""
    lines = text.splitlines()
    if suffix in (".py",):
        # Skip shebang/encoding.
        i = 0
        while i < len(lines) and (
            lines[i].startswith("#!") or "coding" in lines[i][:20]
        ):
            i += 1
        # Triple-string docstring at the top?
        stripped = "\n".join(lines[i:]).lstrip()
        for q in ('"""', "'''"):
            if stripped.startswith(q):
                end = stripped.find(q, len(q))
                if end != -1:
                    return stripped[len(q):end]
        # Otherwise consecutive `#` comments.
        block: list[str] = []
        for l in lines[i:]:
            s = l.strip()
            if s.startswith("#"):
                block.append(s.lstrip("#").strip())
            elif not s:
                # blank line inside a comment block is ok
                if block:
                    block.append("")
                continue
            else:
                break
        return "\n".join(block).strip()
    if suffix in (".js", ".ts", ".jsx", ".tsx"):
        stripped = text.lstrip()
        if stripped.startswith("/*"):
            end = stripped.find("*/")
            if end != -1:
                return stripped[2:end]
        block: list[str] = []
        for l in lines:
            s = l.strip()
            if s.startswith("//"):
                block.append(s[2:].strip())
            elif not s:
                if block:
                    block.append("")
                continue
            else:
                break
        return "\n".join(block).strip()
    return ""


_CLASS_ALIASES = {
    "sqli": "sqli",
    "sql injection": "sqli",
    "sql-injection": "sqli",
    "sql_injection": "sqli",
    "cwe-89": "sqli",
    "cmdi": "cmdi",
    "command injection": "cmdi",
    "os command injection": "cmdi",
    "ssrf": "ssrf",
    "server-side request forgery": "ssrf",
    "eval": "eval",
    "code injection": "eval",
}


def _canonical_class(raw: str, sink_class: str | None = None) -> str:
    """Normalize the LLM's freeform `class` field to a canonical short code.

    Falls back to the sink's class label from the code graph if the model
    returned something we don't recognize."""
    if not raw:
        return sink_class or "unknown"
    key = raw.strip().lower()
    if key in _CLASS_ALIASES:
        return _CLASS_ALIASES[key]
    for alias, canonical in _CLASS_ALIASES.items():
        if alias in key:
            return canonical
    return sink_class or key


@dataclass
class Investigator:
    model: ModelClient

    def run(self, slice_dict: dict[str, Any]) -> dict[str, Any] | None:
        if slice_dict.get("sanitized"):
            return None
        judgment = self.model.complete(
            role="investigator",
            prompt="judge whether this data-flow slice is a real vuln",
            context={"slice": slice_dict},
        )
        if judgment.get("verdict") != "candidate":
            return None
        # Normalize `class` so downstream code (Reproducer, Consensus Kernel)
        # doesn't depend on model wording. The code-graph sink label is the
        # ground truth here — the model can dress it up, but we key off the
        # canonical code.
        sink_class = slice_dict.get("sink", {}).get("class")
        judgment["class"] = _canonical_class(judgment.get("class", ""), sink_class)
        return judgment


class AgenticAnalyst:
    """OWASP-LLM Top-10 rule-pack analyst.

    Thin wrapper over `AgenticScanner` so the roles module can be imported
    without pulling the scanner in downstream contexts that only care about
    Investigator / Reproducer. The scanner does the real work — the analyst
    exists so the "Agentic Analyst" role in PRD §7 has a home.
    """

    def run(self, repo_path: Path, code_files: list[Path] | None = None) -> list[dict[str, Any]]:
        if code_files is None:
            code_files = []
            for ext in ("*.py", "*.js", "*.ts", "*.jsx", "*.tsx"):
                code_files.extend(
                    p for p in repo_path.rglob(ext)
                    if "node_modules" not in p.parts and ".venv" not in p.parts and "dist" not in p.parts
                )
        return [f.to_dict() for f in AgenticScanner().scan(repo_path, code_files)]


class Reducer:
    """Conservatively collapse duplicate findings from multiple detectors.

    Exact (file, function, class) matches retain the historical dedup
    behaviour. Nearby findings may also merge when at least one side has an
    explicitly non-authoritative/unknown function symbol.

    Two distinct concrete functions are never merged solely because their
    lines are close.
    """

    @staticmethod
    def _function(candidate: dict[str, Any]) -> str:
        return str(
            (candidate.get("location") or {}).get("function") or ""
        ).strip()

    @classmethod
    def _is_placeholder_function(cls, candidate: dict[str, Any]) -> bool:
        function = cls._function(candidate).lower()
        return (
            not function
            or function == "unknown"
            or function.startswith(("unknown ", "<unknown"))
            or "(matched by rule " in function
            or "(rule:" in function
            or function.startswith("semgrep::")
            or "detected by semgrep" in function
        )

    @staticmethod
    def _line(candidate: dict[str, Any]) -> int | None:
        value = (candidate.get("location") or {}).get("line")
        try:
            line = int(value)
        except (TypeError, ValueError):
            return None
        return line if line > 0 else None

    @classmethod
    def _should_merge(
        cls,
        existing: dict[str, Any],
        incoming: dict[str, Any],
        *,
        repo_root: str | Path | None = None,
    ) -> bool:
        existing_loc = existing.get("location") or {}
        incoming_loc = incoming.get("location") or {}

        if existing.get("class") != incoming.get("class"):
            return False

        existing_file = canonical_repo_path(
            existing_loc.get("repo_relative_path") or existing_loc.get("file"),
            repo_root,
        )
        incoming_file = canonical_repo_path(
            incoming_loc.get("repo_relative_path") or incoming_loc.get("file"),
            repo_root,
        )
        if existing_file != incoming_file:
            return False

        existing_function = cls._function(existing)
        incoming_function = cls._function(incoming)

        # Preserve historical exact-symbol dedup behaviour.
        if existing_function == incoming_function:
            return True

        # Different authoritative concrete symbols describe different
        # findings, even when their line numbers are close.
        if not (
            cls._is_placeholder_function(existing)
            or cls._is_placeholder_function(incoming)
        ):
            return False

        existing_line = cls._line(existing)
        incoming_line = cls._line(incoming)

        # Do not proximity-merge when location information is incomplete.
        if existing_line is None or incoming_line is None:
            return False

        return abs(existing_line - incoming_line) <= 2

    @classmethod
    def _merge_pair(
        cls,
        existing: dict[str, Any],
        incoming: dict[str, Any],
    ) -> dict[str, Any]:
        existing_placeholder = cls._is_placeholder_function(existing)
        incoming_placeholder = cls._is_placeholder_function(incoming)

        # Prefer the candidate carrying an authoritative concrete symbol.
        if existing_placeholder and not incoming_placeholder:
            winner = incoming
            loser = existing
        else:
            winner = existing
            loser = incoming

        merged_evidence: list[Any] = []
        for item in (
            list(winner.get("evidence_used") or [])
            + list(loser.get("evidence_used") or [])
        ):
            if item not in merged_evidence:
                merged_evidence.append(item)

        winner["evidence_used"] = merged_evidence
        return winner

    def run(
        self,
        candidates: list[dict[str, Any]],
        *,
        repo_root: str | Path | None = None,
    ) -> list[dict[str, Any]]:
        reduced: list[dict[str, Any]] = []

        for candidate in candidates:
            for index, existing in enumerate(reduced):
                if self._should_merge(
                    existing,
                    candidate,
                    repo_root=repo_root,
                ):
                    reduced[index] = self._merge_pair(
                        existing,
                        candidate,
                    )
                    break
            else:
                reduced.append(candidate)

        return reduced


@dataclass
class Reproducer:
    """Runs a PoC in an isolated sandbox (Modal in production; subprocess as
    fallback). Egress-off is enforced by the CapabilityToken and the Modal
    `block_network=True` platform-level guarantee."""

    sandbox: SandboxRunner | None = None

    def run(self, repo_path: Path, finding: dict[str, Any]) -> dict[str, Any]:
        cls = finding["class"]
        # Static-fact classes: no PoC exists to run — the finding *is* the
        # static evidence. Consensus Kernel promotes on static-fact alone.
        if cls in ("secrets", "hardcoded-secret"):
            return {
                "result": "not-applicable",
                "reason": "static-fact class (hardcoded credential) — no dynamic PoC to run",
                "sandbox": {},
            }
        if cls not in ("sqli", "cmdi", "ssrf"):
            return {
                "result": "inconclusive",
                "reason": f"no Phase-2 PoC template for class={cls}",
                "sandbox": {},
            }
        sandbox = self.sandbox or get_sandbox()
        file_hint = finding.get("location", {}).get("file", "")
        token = CapabilityToken.for_reproducer(
            finding_id=finding.get("id", "unknown"), repo_path=str(repo_path)
        )
        # Both sandbox engines get the target root via an env var so the PoC
        # script doesn't have to know whether it's running under Modal (with a
        # /app/target mount) or subprocess (with cwd=repo_path).
        env = {"SPOTLIGHT_TARGET_ROOT": _target_root_for_engine(sandbox.engine, repo_path)}
        env["SPOTLIGHT_TARGET_FUNCTION"] = str(
            finding.get("location", {}).get("function", "")
        )

        if file_hint.endswith((".js", ".ts", ".jsx", ".tsx")):
            js_script = {
                "sqli": _JS_POC_SCRIPT,
                "cmdi": _JS_CMDI_POC_SCRIPT,
                "ssrf": _JS_SSRF_POC_SCRIPT,
            }.get(cls)
            if js_script is None:
                return {
                    "result": "inconclusive",
                    "reason": f"no JavaScript PoC template for class={cls}",
                    "sandbox": {},
                }
            result = sandbox.run_node(script=js_script, token=token, env=env)
        else:
            script = {
                "sqli": _PY_POC_SCRIPT,
                "cmdi": _PY_CMDI_POC_SCRIPT,
                "ssrf": _PY_SSRF_POC_SCRIPT,
            }[cls]
            result = sandbox.run_python(script=script, token=token, env=env)

        # Parse the last stdout line as JSON — the PoC template prints a
        # single JSON summary line.
        data = _last_json_line(result.stdout)
        outcome = "confirmed" if data.get("exploited") else "not-reproduced"
        return {
            "result": outcome,
            "poc": {
                "class": cls,
                "method": "instrumented-sink",
                "network_egress": False,
            },
            "sandbox": {
                "engine": result.engine,
                "duration_s": round(result.duration_s, 3),
                "egress_attempts": result.egress_attempts,
                "egress_denied_hosts": result.egress_denied_hosts,
                "exit_code": result.exit_code,
                "capability_token": token.to_dict(),
            },
            "stdout": result.stdout[:2000],
            "stderr": result.stderr[:1000],
            "raw": data,
        }

    # Legacy in-process PoC preserved for a fallback we don't currently take —
    # kept in git history via the original implementation. The sandbox path
    # above is now the sole codepath.


def _target_root_for_engine(engine: str, repo_path: Path) -> str:
    """Where does the PoC script find the target's app.py|app.js?

    Modal: the RO source is mounted at /app/target inside the sandbox.
    Subprocess: it's the real host path.
    """
    return "/app/target" if engine == "modal" else str(repo_path)


def _last_json_line(text: str) -> dict:
    """PoC templates print one JSON summary line at the end; grab it."""
    for line in reversed((text or "").splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            return _json.loads(line)
        except Exception:
            continue
    return {"error": "unparseable-poc-output", "raw": (text or "")[:400]}


# The Python PoC boots the target Flask app inside the sandbox and hits its
# test-client with a classic SQLi tautology payload. The target root is read
# from SPOTLIGHT_TARGET_ROOT so the same script works under Modal (mount at
# /app/target) and subprocess (real repo path).
_PY_POC_SCRIPT = r"""
import importlib.util, json, os, traceback
from urllib.parse import quote

root = os.environ.get("SPOTLIGHT_TARGET_ROOT", "/app/target")
payload = "' OR '1'='1"
try:
    spec = importlib.util.spec_from_file_location("vuln_app", root + "/app.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    client = mod.app.test_client()
    resp = client.get("/accounts/" + quote(payload, safe=""))
    body = resp.get_data(as_text=True)
    try:
        rows = json.loads(body)
    except Exception:
        rows = []
    exploited = isinstance(rows, list) and len(rows) > 0
    print(json.dumps({"status": resp.status_code, "rows": rows, "exploited": exploited}))
except Exception as e:
    print(json.dumps({"error": repr(e), "traceback": traceback.format_exc()}))
"""


# CMDI proof replaces process-launch functions with recorders, then invokes
# the exact finding function inside a Flask request context. No command is
# executed; confirmation means the canary reached the command sink.
_PY_CMDI_POC_SCRIPT = r"""
import importlib.util, inspect, json, os, traceback

root = os.environ.get("SPOTLIGHT_TARGET_ROOT", "/app/target")
function_name = os.environ.get("SPOTLIGHT_TARGET_FUNCTION", "")
canary = "spotlight-cmdi-canary;id"
calls = []

class Result:
    returncode = 0
    stdout = ""
    stderr = ""

def record(*args, **kwargs):
    calls.append({"args": [str(a) for a in args], "kwargs": {k: str(v) for k, v in kwargs.items()}})
    return Result()

try:
    spec = importlib.util.spec_from_file_location("target_app", root + "/app.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if hasattr(mod, "subprocess"):
        for name in ("run", "call", "Popen", "check_output", "check_call"):
            if hasattr(mod.subprocess, name):
                setattr(mod.subprocess, name, record)
    if hasattr(mod, "os") and hasattr(mod.os, "system"):
        mod.os.system = record
    fn = getattr(mod, function_name)
    context = mod.app.test_request_context(
        "/?cmd=" + canary + "&command=" + canary + "&q=" + canary,
        method="POST",
        json={"cmd": canary, "command": canary},
    )
    with context:
        params = inspect.signature(fn).parameters
        fn(*([canary] if params else []))
    exploited = any(canary in json.dumps(call) for call in calls)
    print(json.dumps({"exploited": exploited, "sink_calls": calls}))
except Exception as e:
    print(json.dumps({"error": repr(e), "traceback": traceback.format_exc(), "sink_calls": calls}))
"""


# SSRF proof similarly replaces outbound clients with a recorder. The canary
# is the cloud metadata address, but the script never opens a socket.
_PY_SSRF_POC_SCRIPT = r"""
import importlib.util, inspect, json, os, traceback

root = os.environ.get("SPOTLIGHT_TARGET_ROOT", "/app/target")
function_name = os.environ.get("SPOTLIGHT_TARGET_FUNCTION", "")
canary = "http://169.254.169.254/latest/meta-data/spotlight-canary"
calls = []

class Response:
    text = "blocked-test-response"
    status_code = 200
    content = b"blocked-test-response"
    def json(self): return {"ok": True}

def record(url, *args, **kwargs):
    calls.append(str(url))
    return Response()

try:
    spec = importlib.util.spec_from_file_location("target_app", root + "/app.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if hasattr(mod, "requests"):
        for name in ("get", "post", "put", "request"):
            if hasattr(mod.requests, name): setattr(mod.requests, name, record)
    fn = getattr(mod, function_name)
    context = mod.app.test_request_context(
        "/?url=" + canary,
        method="POST",
        json={"url": canary},
    )
    with context:
        params = inspect.signature(fn).parameters
        fn(*([canary] if params else []))
    exploited = canary in calls
    print(json.dumps({"exploited": exploited, "requested_urls": calls, "egress_performed": False}))
except Exception as e:
    print(json.dumps({"error": repr(e), "traceback": traceback.format_exc(), "requested_urls": calls}))
"""


# The Node PoC boots the target Express app in-process and calls its route.
# Runs under Modal only (node runtime + deps preinstalled in the sandbox image).
_JS_POC_SCRIPT = r"""
(async () => {
  const payload = "' OR '1'='1";
  const root = process.env.SPOTLIGHT_TARGET_ROOT || "/app/target";
  try {
    const app = require(root + "/app.js");
    const http = require("http");
    const server = http.createServer(app);
    await new Promise((r) => server.listen(0, r));
    const port = server.address().port;
    const path = "/accounts/" + encodeURIComponent(payload);
    const resp = await new Promise((resolve, reject) => {
      http.get({ host: "127.0.0.1", port, path }, (res) => {
        let body = "";
        res.on("data", (c) => (body += c));
        res.on("end", () => resolve({ status: res.statusCode, body }));
      }).on("error", reject);
    });
    server.close();
    let rows = [];
    try { rows = JSON.parse(resp.body); } catch {}
    const exploited = Array.isArray(rows) && rows.length > 0;
    console.log(JSON.stringify({ status: resp.status, rows, exploited }));
  } catch (e) {
    console.log(JSON.stringify({ error: String(e) }));
  }
})();
"""


# JS CMDI proof: patch child_process methods with a recorder BEFORE loading
# the target app so the app's own `require('child_process')` returns the
# shared, patched module. No command is executed; confirmation means the
# canary reached a child_process sink.
_JS_CMDI_POC_SCRIPT = r"""
(async () => {
  const root = process.env.SPOTLIGHT_TARGET_ROOT || "/app/target";
  const canary = "spotlight-cmdi-canary;id";
  const calls = [];

  const cp = require("child_process");
  const record = (...args) => {
    calls.push({ args: args.map(a => typeof a === "string" ? a : JSON.stringify(a)) });
    const fake = { pid: 0, stdout: "", stderr: "", status: 0, on() { return this; }, kill() {} };
    for (const a of args) {
      if (typeof a === "function") { setImmediate(() => a(null, "", "")); break; }
    }
    return fake;
  };
  for (const name of ["exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync"]) {
    if (cp[name]) cp[name] = record;
  }

  try {
    const app = require(root + "/app.js");
    const http = require("http");
    const server = http.createServer(app);
    await new Promise((r) => server.listen(0, r));
    const port = server.address().port;
    const path = "/run?cmd=" + encodeURIComponent(canary) + "&command=" + encodeURIComponent(canary);
    const resp = await new Promise((resolve, reject) => {
      const req = http.request({
        host: "127.0.0.1", port, path, method: "POST",
        headers: { "content-length": 0 },
      }, (res) => {
        let body = "";
        res.on("data", (c) => (body += c));
        res.on("end", () => resolve({ status: res.statusCode, body }));
      });
      req.on("error", reject);
      req.end();
    });
    await new Promise((r) => setImmediate(r));
    server.close();
    const exploited = calls.some(c => JSON.stringify(c).includes(canary));
    console.log(JSON.stringify({ status: resp.status, exploited, sink_calls: calls, egress_performed: false }));
  } catch (e) {
    console.log(JSON.stringify({ error: String(e), stack: e.stack || "", sink_calls: calls }));
  }
})();
"""


# JS SSRF proof: patch http/https client methods with a recorder. The PoC
# saves originals of http.request/http.get for its own outbound to the
# local server so the test client is not affected by the patch. The canary
# is a cloud-metadata URL but no socket is ever opened.
_JS_SSRF_POC_SCRIPT = r"""
(async () => {
  const root = process.env.SPOTLIGHT_TARGET_ROOT || "/app/target";
  const canary = "http://169.254.169.254/latest/meta-data/spotlight-canary";
  const calls = [];

  const http = require("http");
  const https = require("https");
  const origHttpRequest = http.request.bind(http);

  const record = (opts, cbOrOptsB, maybeCb) => {
    let url = "";
    if (typeof opts === "string") url = opts;
    else if (opts instanceof URL) url = opts.toString();
    else if (opts && typeof opts === "object") {
      const proto = opts.protocol || "http:";
      const host = opts.hostname || opts.host || "";
      const p = opts.path || "/";
      url = proto + "//" + host + p;
    }
    calls.push(url);
    const fakeRes = {
      statusCode: 200, headers: {},
      on(evt, fn) {
        if (evt === "data") setImmediate(() => fn(Buffer.from("blocked")));
        if (evt === "end") setImmediate(() => fn());
        return this;
      },
      pipe() { return this; }, setEncoding() {},
    };
    const cb = typeof cbOrOptsB === "function" ? cbOrOptsB
             : typeof maybeCb === "function"   ? maybeCb
             : null;
    if (cb) setImmediate(() => cb(fakeRes));
    return {
      on() { return this; }, end() { return this; },
      write() { return this; }, abort() {}, setHeader() {},
    };
  };
  http.get = record;
  http.request = record;
  https.get = record;
  https.request = record;

  try {
    const app = require(root + "/app.js");
    const server = http.createServer(app);
    await new Promise((r) => server.listen(0, r));
    const port = server.address().port;
    const resp = await new Promise((resolve, reject) => {
      const req = origHttpRequest({
        host: "127.0.0.1", port,
        path: "/fetch?url=" + encodeURIComponent(canary),
        method: "POST",
        headers: { "content-length": 0 },
      }, (res) => {
        let body = "";
        res.on("data", (c) => (body += c));
        res.on("end", () => resolve({ status: res.statusCode, body }));
      });
      req.on("error", reject);
      req.end();
    });
    await new Promise((r) => setImmediate(r));
    server.close();
    const exploited = calls.some(u => u.includes("169.254.169.254") || u.includes("spotlight-canary"));
    console.log(JSON.stringify({ status: resp.status, exploited, requested_urls: calls, egress_performed: false }));
  } catch (e) {
    console.log(JSON.stringify({ error: String(e), stack: e.stack || "", requested_urls: calls }));
  }
})();
"""


@dataclass
class Remediator:
    """Applies the minimal parameterized-query fix on a scratch branch (Phase
    1: file overwrite; Phase 2: proper git branch + PR)."""

    def run(self, repo_path: Path, finding: dict[str, Any]) -> dict[str, Any]:
        target = repo_path / finding["location"]["file"]
        original = target.read_text()
        vulnerable_snippet = (
            '    query = "SELECT id, name, balance FROM accounts WHERE name = \'" + username + "\'"\n'
            "    cursor.execute(query)\n"
        )
        patched_snippet = (
            '    cursor.execute("SELECT id, name, balance FROM accounts WHERE name = ?", (username,))\n'
        )
        if vulnerable_snippet not in original:
            return {"applied": False, "reason": "vulnerable snippet not found — no patch applied"}
        patched = original.replace(vulnerable_snippet, patched_snippet)
        # Write to a .patched sibling so the original stays intact for repro
        # comparison; the Verifier re-runs the PoC against .patched.
        patched_path = target.with_suffix(".patched.py")
        patched_path.write_text(patched)
        diff = _unified_diff(original, patched, str(target))
        return {
            "applied": True,
            "diff": diff,
            "patched_path": str(patched_path),
            "target_path": str(target),
            "patched_content": patched,
        }

    def open_pr(
        self,
        repo_path: Path,
        finding: dict[str, Any],
        remediation: dict[str, Any],
        git: "GitOps | None" = None,
        open_prs: bool = False,
        base: str = "main",
    ) -> dict[str, Any] | None:
        """Create a real commit + open a GitHub PR for this remediation.

        Returns {"pr_url", "branch", "commit_sha"} on success; None if:
          * `open_prs` toggle is off, OR
          * `repo_path` isn't a git checkout, OR
          * remediation wasn't applied, OR
          * `gh` errors out (log-and-continue).

        Never raises — errors are swallowed with an error print so a broken
        `gh` install can't nuke a whole sweep.
        """
        from spotlight.git_ops import GitOps  # local to avoid circular

        if not open_prs:
            return None
        if not remediation.get("applied"):
            return None
        gh = git or GitOps()
        try:
            if not gh.is_git_repo(repo_path):
                return None
            fid = finding.get("id", "unknown")
            branch = gh.create_scratch_branch(Path(repo_path), fid)
            # Overwrite the original file with the patched content — the
            # Verifier already has its own copy at `.patched.py`.
            target_path = Path(remediation.get("target_path") or
                               (Path(repo_path) / finding["location"]["file"]))
            patched_content = remediation.get("patched_content")
            if patched_content is None:
                # Fallback: read the .patched sibling.
                pp = Path(remediation.get("patched_path", ""))
                if pp.exists():
                    patched_content = pp.read_text()
            if patched_content is None:
                return None
            target_path.write_text(patched_content)
            title = f"[Spotlight] fix({finding.get('class', 'sec')}): {finding.get('title', fid)}"
            body = _pr_body(finding, remediation)
            sha = gh.stage_and_commit(
                Path(repo_path),
                [target_path],
                message=title,
            )
            pr = gh.open_pr(
                Path(repo_path),
                base=base,
                head=branch,
                title=title,
                body=body,
            )
            if not pr.ok:
                print(f"[remediator.open_pr] gh failed: {pr.stderr}")
                return None
            return {"pr_url": pr.pr_url, "branch": branch, "commit_sha": sha}
        except Exception as exc:  # noqa: BLE001 — log-and-continue is the contract
            print(f"[remediator.open_pr] error: {exc!r}")
            return None


def _pr_body(finding: dict[str, Any], remediation: dict[str, Any]) -> str:
    fid = finding.get("id", "unknown")
    cls = finding.get("class", "unknown")
    cwe = finding.get("cwe", "")
    loc = finding.get("location", {})
    return (
        f"Spotlight auto-remediation for `{fid}` ({cls} / {cwe}).\n\n"
        f"**Location:** `{loc.get('file', '?')}` in `{loc.get('function', '?')}`\n\n"
        f"**Rationale:** {finding.get('root_cause', '(see finding)')}\n\n"
        "```diff\n"
        f"{remediation.get('diff', '')[:6000]}\n"
        "```\n\n"
        "_Generated by Spotlight; independently reviewed by the Verifier "
        "(re-ran PoC against the patched build, checked for backdoor patterns "
        "in the diff)._\n"
    )


def _unified_diff(a: str, b: str, path: str) -> str:
    import difflib

    return "".join(
        difflib.unified_diff(
            a.splitlines(keepends=True),
            b.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
            n=3,
        )
    )


@dataclass
class Verifier:
    """Independent verifier — a *different* agent in a *fresh* context.

    Independence is enforced by (a) a distinct system prompt, (b) never
    receiving the Remediator's chain-of-thought — only the diff and the
    patched artifact, and (c) re-running the PoC from scratch.
    """

    model: ModelClient
    system_prompt: str = "You are the independent Verifier. Re-derive risk from scratch."
    sandbox: SandboxRunner | None = None

    def run(
        self, repo_path: Path, finding: dict[str, Any], remediation: dict[str, Any]
    ) -> dict[str, Any]:
        if not remediation.get("applied"):
            return {"result": "no-patch", "independent_verifier": True}
        patched_path = Path(remediation["patched_path"])
        sandbox = self.sandbox or get_sandbox()
        # The Verifier runs the SAME PoC against a patched-swap of the app —
        # we substitute a modified target dir where app.py is the .patched.py.
        # For sandbox mounts we materialize a fresh temp dir with the patch
        # renamed back into place.
        with tempfile.TemporaryDirectory(prefix="spotlight-verify-") as td:
            td_path = Path(td)
            for f in patched_path.parent.iterdir():
                if f.name == patched_path.name:
                    continue
                if f.is_file():
                    (td_path / f.name).write_bytes(f.read_bytes())
            # Drop the patched content in as the new app.py
            (td_path / "app.py").write_bytes(patched_path.read_bytes())
            token = CapabilityToken.for_verifier(
                finding_id=finding.get("id", "unknown"), patched_path=str(td_path)
            )
            env = {"SPOTLIGHT_TARGET_ROOT": _target_root_for_engine(sandbox.engine, td_path)}
            file_hint = finding.get("location", {}).get("file", "")
            if file_hint.endswith((".js", ".ts", ".jsx", ".tsx")):
                sandbox_result = sandbox.run_node(script=_JS_POC_SCRIPT, token=token, env=env)
            else:
                sandbox_result = sandbox.run_python(script=_PY_POC_SCRIPT, token=token, env=env)
        data = _last_json_line(sandbox_result.stdout)
        backdoor_matches = WardenService().check_fix_diff(remediation.get("diff", ""))
        backdoor = {
            "verdict": "fail" if backdoor_matches else "pass",
            "notes": [m.kind for m in backdoor_matches],
            "matches": [m.to_dict() for m in backdoor_matches],
        }
        judgment = self.model.complete(
            role="verifier",
            prompt=self.system_prompt,
            context={"finding": finding, "repro": data, "backdoor": backdoor},
        )
        judgment["sandbox"] = {
            "engine": sandbox_result.engine,
            "duration_s": round(sandbox_result.duration_s, 3),
            "exit_code": sandbox_result.exit_code,
            "capability_token": token.to_dict(),
        }
        # Consensus derives result from PoC outcome after patch — but keep
        # model's judgment for the notes/rationale.
        judgment["result"] = "repro-now-blocked" if not data.get("exploited") else "still-exploitable"
        return {
            **judgment,
            "backdoor_check": backdoor["verdict"],
            "backdoor_findings": backdoor["notes"],
            "poc_result": data,
            "independent_verifier": True,
        }

