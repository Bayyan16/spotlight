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

        if role == "hypothesis-proposer":
            # Deterministic mock proposer: pair the first two candidates that
            # (a) live in the same repo and (b) span two surfaces. Real model
            # will propose free-form chains keyed off classes, function names,
            # and file proximity. The Chainer's rule-validated lane still owns
            # the signed paths; this lane is analyst-review only.
            cands = context.get("candidates", []) or []
            if len(cands) < 2:
                return {"chains": []}
            first, second = cands[0], cands[1]
            return {
                "chains": [
                    {
                        "title": (
                            f"Hypothesis: {first.get('class', '?')} → "
                            f"{second.get('class', '?')} (proposed by model)"
                        ),
                        "rationale": (
                            "Model proposes these two findings compose into a "
                            "single attacker path — no deterministic rule "
                            "matched, review before treating as verified."
                        ),
                        "severity": first.get("severity", "medium"),
                        "step_finding_ids": [
                            first.get("id") or first.get("title"),
                            second.get("id") or second.get("title"),
                        ],
                    }
                ]
            }

        if role == "plain-language":
            # C3 · Plain-language "why this matters" per finding.
            # ≤120 words, no jargon, concrete blast radius. The mock uses
            # canned wording per class so tests + demos stay deterministic;
            # the real model produces bespoke prose grounded in the
            # finding's location + evidence.
            finding = context.get("finding", {}) or {}
            cls = str(finding.get("class") or "").lower()
            location = finding.get("location") or {}
            file_hint = location.get("file", "the target")
            per_class: dict[str, dict[str, str]] = {
                "sqli": {
                    "one_liner": (
                        "An attacker can read (and often modify) the entire "
                        "database without needing a valid login."
                    ),
                    "blast_radius": (
                        "Every account row is dumpable. If the same query "
                        "path is used for writes, balances and passwords "
                        "can be rewritten too."
                    ),
                    "urgency": (
                        "Fix before the next production deploy — the payload "
                        "is a single-URL copy-paste."
                    ),
                },
                "ssrf": {
                    "one_liner": (
                        "The server will fetch any URL an attacker supplies, "
                        "including internal metadata endpoints."
                    ),
                    "blast_radius": (
                        "Cloud IAM credentials (AWS/GCP/Azure) can be stolen "
                        "by pointing the server at its metadata service. "
                        "Internal admin panels become reachable from the "
                        "public internet through this proxy."
                    ),
                    "urgency": "Ship a URL allowlist this sprint.",
                },
                "cmdi": {
                    "one_liner": (
                        "An attacker can run arbitrary shell commands on the "
                        "server through a normal HTTP request."
                    ),
                    "blast_radius": (
                        "Full control of the app process — every secret in "
                        "memory, every file it can read, every credential "
                        "it holds. Effectively RCE."
                    ),
                    "urgency": "Treat as a P0 — patch and rotate creds today.",
                },
                "secrets": {
                    "one_liner": (
                        "A working credential is checked into the source "
                        "tree in plaintext."
                    ),
                    "blast_radius": (
                        "Anyone with repo read access — humans, CI runners, "
                        "leaked backups — has the key. If it's an AWS or "
                        "OpenAI key it can be turned into money."
                    ),
                    "urgency": (
                        "Rotate the credential now. Deleting the file line "
                        "alone is NOT enough — git history retains it."
                    ),
                },
                "prompt-injection": {
                    "one_liner": (
                        "Untrusted text (a user message, a scraped page, a "
                        "support ticket) can rewrite what the AI does."
                    ),
                    "blast_radius": (
                        "Every tool the LLM can call becomes usable by the "
                        "attacker. If those tools have external network or "
                        "shell access, the injection turns into a real "
                        "exploit chain."
                    ),
                    "urgency": (
                        "Fence untrusted input inside a labelled envelope "
                        "before it reaches the model; scope tools to the "
                        "narrowest set that works."
                    ),
                },
                "excessive-agency": {
                    "one_liner": (
                        "The AI has been given a tool with no scope check — "
                        "if it decides to call it with a bad input, no one "
                        "stops it."
                    ),
                    "blast_radius": (
                        "Combines with any prompt-injection or hallucination "
                        "to become a real exploit path. E.g. `requests.get` "
                        "without a URL allowlist chains into SSRF."
                    ),
                    "urgency": (
                        "Add scope guards to the tool (allowlist, argument "
                        "validation) before the next model release."
                    ),
                },
            }
            default = {
                "one_liner": (
                    f"Untrusted data reaches a dangerous operation in "
                    f"`{file_hint}` without validation."
                ),
                "blast_radius": (
                    "Depends on what the sink can do — read data, modify "
                    "state, call out to another service. See the sandbox "
                    "proof for what actually happened when we fired it."
                ),
                "urgency": "Fix in this sprint.",
            }
            block = per_class.get(cls, default)
            return {
                "one_liner": block["one_liner"],
                "blast_radius": block["blast_radius"],
                "urgency": block["urgency"],
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
