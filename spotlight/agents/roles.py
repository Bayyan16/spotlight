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

from spotlight.sandbox import CapabilityToken, SandboxResult, SandboxRunner, get_sandbox
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
    """Runs a PoC in an isolated sandbox (Modal in production; subprocess as
    fallback). Egress-off is enforced by the CapabilityToken and the Modal
    `block_network=True` platform-level guarantee."""

    sandbox: SandboxRunner | None = None

    def run(self, repo_path: Path, finding: dict[str, Any]) -> dict[str, Any]:
        cls = finding["class"]
        if cls != "sqli":
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

        if file_hint.endswith((".js", ".ts", ".jsx", ".tsx")):
            script = _JS_POC_SCRIPT
            result = sandbox.run_node(script=script, token=token, env=env)
        else:
            script = _PY_POC_SCRIPT
            result = sandbox.run_python(script=script, token=token, env=env)

        # Parse the last stdout line as JSON — the PoC template prints a
        # single JSON summary line.
        data = _last_json_line(result.stdout)
        outcome = "confirmed" if data.get("exploited") else "not-reproduced"
        return {
            "result": outcome,
            "poc": {"path": "/accounts/' OR '1'='1", "method": "GET"},
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
        backdoor = _backdoor_check(remediation.get("diff", ""))
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
