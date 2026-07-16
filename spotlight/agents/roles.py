"""Bounded, single-purpose agent roles. Phase 1 vertical slice.

Each role has ONE job. Model calls go through a ModelClient (mocked in Phase
1). The Reproducer runs code in the sandbox module. The Remediator applies a
patch; the Verifier re-runs the PoC in a fresh context.
"""
from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from spotlight.sg_core import CodeGraph, DataFlowSlice

from .model import MockModelClient, ModelClient


@dataclass
class Recon:
    model: ModelClient

    def run(self, repo_path: Path) -> dict[str, Any]:
        py_files = list(repo_path.rglob("*.py"))
        graph = CodeGraph.build(py_files)
        slices = graph.slices()
        signals = [s.to_dict() for s in graph.reachable_slices()]
        has_ai_layer = any(
            "langchain" in f.read_text(errors="ignore").lower()
            or "openai" in f.read_text(errors="ignore").lower()
            for f in py_files
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
        # Load the app in-process and hit it with a classic SQLi payload.
        script = f"""
import sys, importlib.util, json, traceback
spec = importlib.util.spec_from_file_location('vuln_app', {str(repo_path / 'app.py')!r})
mod = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(mod)
    client = mod.app.test_client()
    # Classic tautology payload — if reflected into SQL, returns all rows.
    payload = "' OR '1'='1"
    resp = client.get(f"/accounts/{{payload}}")
    body = resp.get_data(as_text=True)
    # Vulnerable: returns >1 row for a random username. Fixed: returns [].
    import json as _j
    rows = _j.loads(body)
    exploited = len(rows) > 0
    print(json.dumps({{"status": resp.status_code, "rows": rows, "exploited": exploited}}))
except Exception as e:
    print(json.dumps({{"error": repr(e), "traceback": traceback.format_exc()}}))
"""
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(repo_path),
        )
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
        # Re-run the PoC against the patched file.
        script = f"""
import sys, importlib.util, json, traceback
spec = importlib.util.spec_from_file_location('patched_app', {str(patched_path)!r})
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
client = mod.app.test_client()
payload = "' OR '1'='1"
resp = client.get(f"/accounts/{{payload}}")
body = resp.get_data(as_text=True)
import json as _j
try:
    rows = _j.loads(body)
except Exception:
    rows = []
exploited = len(rows) > 0
print(json.dumps({{"status": resp.status_code, "rows": rows, "exploited": exploited}}))
"""
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=30,
        )
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
