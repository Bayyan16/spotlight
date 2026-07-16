"""Model adapter — Phase 1 is deterministic/mocked.

The real thing (M0 spike) will drive `codex exec` or a direct-loop against a
configured model endpoint. For the vertical slice we use a mock that
generates schema-valid outputs keyed on the fixture, so tests are
reproducible and CI doesn't need model access.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


class ModelClient(Protocol):
    def complete(self, *, role: str, prompt: str, context: dict[str, Any]) -> dict[str, Any]:
        """Return the role's schema-valid output as a dict."""
        ...


@dataclass
class MockModelClient:
    """Deterministic model client. Produces role-appropriate JSON outputs.

    Keyed off the slice/candidate the orchestrator passed in — no LLM call.
    Real ModelClient will honor deployment_tier (T0 hosted / T1 self-hosted).
    """

    family: str = "mock"

    def complete(self, *, role: str, prompt: str, context: dict[str, Any]) -> dict[str, Any]:
        if role == "recon":
            has_ai = context.get("has_ai_layer", False)
            return {
                "stack": {"language": "python", "framework": "flask"},
                "surfaces": ["code"] + (["agentic"] if has_ai else []),
                "signals": context.get("signals", []),
                "threat_model": {
                    "untrusted_sources": ["http_params", "request_body"],
                    "high_impact_sinks": ["sql_execute", "shell_exec", "template_render"],
                },
            }

        if role == "investigator":
            slice_ = context["slice"]
            cls = slice_["sink"]["class"]
            # CWE table covers the code-surface classes AND the agentic classes
            # the Agentic Sweep emits. If the class isn't here we fall back
            # to CWE-693 (protection mechanism failure) rather than KeyError.
            cwe_by_class = {
                "sqli": "CWE-89",
                "cmdi": "CWE-78",
                "ssrf": "CWE-918",
                "eval": "CWE-95",
                "prompt-injection": "CWE-77",
                "excessive-agency": "CWE-269",
                "output-handling": "CWE-79",
                "system-prompt-leak": "CWE-540",
                "rag-surface": "CWE-345",
                "denial-of-wallet": "CWE-400",
            }
            is_agentic = slice_.get("surface") == "agentic"
            root_cause = (
                f"Untrusted `{slice_['source']['name']}` (from "
                f"{slice_['source']['origin']}) flows into {slice_['sink']['callee']} "
                "via string concatenation."
            )
            recommendation = "Use a parameterized query; do not concatenate user input into SQL."
            if is_agentic:
                root_cause = (
                    f"Agentic surface: {slice_.get('reason', '')} "
                    f"({slice_['source']['origin']} → {slice_['sink']['callee']})."
                )
                recommendation = (
                    "Sanitize user input before it reaches the LLM; scope tool "
                    "permissions; validate model output before executing it."
                )
            return {
                "verdict": "candidate",
                "class": cls,
                "cwe": cwe_by_class.get(cls, "CWE-693"),
                "title": f"{cls.upper()} in {slice_['function']}",
                "severity": "high",
                "location": {
                    "file": slice_["file"],
                    "line": slice_["sink"]["line"],
                    "function": slice_["function"],
                },
                "root_cause": root_cause,
                "recommendation": recommendation,
                "evidence_used": ["codegraph:source->sink reachable", slice_["reason"]],
            }

        if role == "verifier":
            return {
                "result": "repro-now-blocked",
                "independent_verifier": True,
                "backdoor_check": "pass",
                "security_regression": "pass",
                "notes": (
                    "Re-derived risk from fresh context; PoC returns HTTP 400 (bound param "
                    "rejected SQL metacharacters). Diff review found no removed control."
                ),
            }

        raise ValueError(f"MockModelClient has no fixture for role={role}")
