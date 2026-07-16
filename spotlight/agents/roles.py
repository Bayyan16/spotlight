"""Bounded, single-purpose agent roles. Phase 1 vertical slice.

Each role has ONE job. Model calls go through a ModelClient (mocked in Phase
1). The Reproducer runs code in the sandbox module. The Remediator applies a
patch; the Verifier re-runs the PoC in a fresh context.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from spotlight.sg_core import CodeGraph, DataFlowSlice

from .model import MockModelClient, ModelClient


@dataclass
class Recon:
    model: ModelClient

    def run(self, repo_path: Path) -> dict[str, Any]:
        code_files: list[Path] = []
        for ext in ("*.py", "*.js", "*.ts", "*.jsx", "*.tsx"):
            code_files.extend(
                p for p in repo_path.rglob(ext)
                if "node_modules" not in p.parts and ".venv" not in p.parts and "dist" not in p.parts
            )
        graph = CodeGraph.build(code_files)
        slices = graph.slices()
        signals = [s.to_dict() for s in graph.reachable_slices()]
        has_ai_layer = any(
            "langchain" in f.read_text(errors="ignore").lower()
            or "openai" in f.read_text(errors="ignore").lower()
            for f in code_files
        )
        threat_model = self.model.complete(
            role="recon",
            prompt="classify stack and threat model",
            context={"signals": signals, "has_ai_layer": has_ai_layer},
        )
        return {
            "threat_model": threat_model,
            "signals": signals,
            "slices": [s.to_dict() for s in slices],
        }


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


class CognitionAnalyst:
    """Placeholder — Phase 2 fills this in with OWASP-LLM rule packs."""

    def run(self, *args, **kwargs) -> list[dict[str, Any]]:
        return []


class Reducer:
    def run(self, candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen: dict[tuple, dict] = {}
        for c in candidates:
            key = (c["location"]["file"], c["location"]["function"], c["class"])
            if key not in seen:
                seen[key] = c
        return list(seen.values())


@dataclass
class Reproducer:
    """Runs a PoC in an isolated subprocess (Phase 1 substitute for full
    container sandbox). Real sandbox with egress-off comes in Phase 2 via the
    sandbox module."""

    def run(self, repo_path: Path, finding: dict[str, Any]) -> dict[str, Any]:
        cls = finding["class"]
        if cls != "sqli":
            return {"result": "inconclusive", "reason": f"no Phase-1 PoC for class={cls}"}
        # JS targets: skip in-process repro (needs Node runtime + deps installed).
        # Real Modal sandbox lands in Tranche A3.
        file_hint = finding.get("location", {}).get("file", "")
        if file_hint.endswith((".js", ".ts", ".jsx", ".tsx")):
            return {
                "result": "inconclusive",
                "reason": "JS target — offline in-process PoC not available in Phase 1.5; awaits Modal sandbox (Tranche A3)",
                "poc": {"path": "/accounts/' OR '1'='1", "method": "GET"},
            }
        # Load the app in-process and hit it with a classic SQLi payload.
        # Fix (regression 2026-07-16): the previous impl built an inline python
        # script via nested f-strings and used the raw payload "' OR '1'='1"
        # directly in a URL path. On Werkzeug 3.1.x (Flask 3.1.3, Railway's
        # image) unencoded quotes/spaces in the test-client path fail routing
        # and the response body is a 404 HTML page, breaking JSON parsing.
        # We now: (a) write the PoC to a tempfile so there is no shell/f-string
        # escaping surface, (b) pass the payload via env, and (c) URL-encode it
        # before hitting the route so Werkzeug decodes it back correctly.
        app_path = str(repo_path / "app.py")
        payload = "' OR '1'='1"
        script = _POC_SCRIPT_TEMPLATE
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write(script)
            script_path = f.name
        try:
            proc = subprocess.run(
                [sys.executable, script_path],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(repo_path),
                env={
                    **os.environ,
                    "SPOTLIGHT_POC_APP_PATH": app_path,
                    "SPOTLIGHT_POC_PAYLOAD": payload,
                },
            )
        finally:
            try:
                os.unlink(script_path)
            except OSError:
                pass
        stdout = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else "{}"
        import json as _j

        try:
            data = _j.loads(stdout)
        except Exception:
            data = {"error": "unparseable-poc-output", "raw": proc.stdout, "stderr": proc.stderr}
        result = "confirmed" if data.get("exploited") else "not-reproduced"
        return {
            "result": result,
            "poc": {"path": "/accounts/' OR '1'='1", "method": "GET"},
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "raw": data,
        }


_POC_SCRIPT_TEMPLATE = r"""
import importlib.util, json, os, sys, traceback
from urllib.parse import quote

app_path = os.environ["SPOTLIGHT_POC_APP_PATH"]
payload = os.environ["SPOTLIGHT_POC_PAYLOAD"]
try:
    spec = importlib.util.spec_from_file_location("vuln_app", app_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    client = mod.app.test_client()
    # URL-encode the payload so Werkzeug 3.x accepts the path; the route
    # handler receives the decoded value, so the SQLi tautology reaches the
    # vulnerable query unchanged.
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
        return {"applied": True, "diff": diff, "patched_path": str(patched_path)}


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

    def run(
        self, repo_path: Path, finding: dict[str, Any], remediation: dict[str, Any]
    ) -> dict[str, Any]:
        if not remediation.get("applied"):
            return {"result": "no-patch", "independent_verifier": True}
        patched_path = Path(remediation["patched_path"])
        # Re-run the PoC against the patched file. Same tempfile + env-var +
        # URL-encoded payload approach as the Reproducer (see fix note above).
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write(_POC_SCRIPT_TEMPLATE)
            script_path = f.name
        try:
            proc = subprocess.run(
                [sys.executable, script_path],
                capture_output=True,
                text=True,
                timeout=30,
                env={
                    **os.environ,
                    "SPOTLIGHT_POC_APP_PATH": str(patched_path),
                    "SPOTLIGHT_POC_PAYLOAD": "' OR '1'='1",
                },
            )
        finally:
            try:
                os.unlink(script_path)
            except OSError:
                pass
        import json as _j

        try:
            data = _j.loads(proc.stdout.strip().splitlines()[-1])
        except Exception:
            data = {"error": "unparseable", "stdout": proc.stdout, "stderr": proc.stderr}
        backdoor = _backdoor_check(remediation.get("diff", ""))
        judgment = self.model.complete(
            role="verifier",
            prompt=self.system_prompt,
            context={"finding": finding, "repro": data, "backdoor": backdoor},
        )
        return {
            **judgment,
            "backdoor_check": backdoor["verdict"],
            "backdoor_findings": backdoor["notes"],
            "poc_result": data,
            "independent_verifier": True,
        }


def _backdoor_check(diff: str) -> dict[str, Any]:
    """Scan the fix diff for weakening patterns. Phase 1 substring scan;
    Phase 2 Warden module owns this with proper AST diffing."""
    weakenings = [
        ("verify=False", "TLS verification disabled"),
        ("check=False", "Auth check disabled"),
        (".skip(", "Test skipped"),
        ("# noqa", "Lint suppression added"),
        ("auth_required = False", "Auth requirement removed"),
        ("permission=", "Permission scope widened"),
    ]
    hits = [note for pat, note in weakenings if pat in diff]
    return {"verdict": "fail" if hits else "pass", "notes": hits}
