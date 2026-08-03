"""The ModelClient protocol — Spotlight's LLM plug-in point.

Every agent role (recon, investigator, planner, verifier, ...) reaches an LLM
only through the ``ModelClient.complete()`` method below. Nothing else in the
codebase talks to a model directly, so this one interface is where you bring
your own provider.

Spotlight ships two implementations:

  * ``MockModelClient`` — deterministic, offline, schema-valid outputs. This is
    the default, and what the whole test suite runs against: no API keys, no
    network, fully reproducible. Great for CI and for trying the pipeline
    end-to-end before you wire up a real model.
  * ``OpenAICompatibleModelClient`` (see ``agents/moonshot.py``) — the
    real-inference adapter. It speaks the OpenAI ``/chat/completions`` wire
    format, so it works against OpenAI, Moonshot/Kimi, Together, Groq, Ollama,
    vLLM, or any OpenAI-compatible endpoint.

To plug in a provider we don't cover, implement this Protocol:

    class MyModelClient:
        family = "my-provider"          # shows up in the signed audit trail
        def complete(self, *, role, prompt, context):
            # call your model however you like, then return the role's
            # schema-valid dict (same shape MockModelClient returns below)
            ...

Then either pass it in explicitly::

    Orchestrator(model=MyModelClient())

or set an env var (``SPOTLIGHT_LLM_API_KEY`` & friends) and let
``agents.moonshot.maybe_from_env()`` pick it up automatically.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


class ModelClient(Protocol):
    """The one interface an LLM provider must satisfy. See module docstring."""

    def complete(self, *, role: str, prompt: str, context: dict[str, Any]) -> dict[str, Any]:
        """Return the role's schema-valid output as a dict."""
        ...


@dataclass
class MockModelClient:
    """Deterministic, offline model client — the default when no API key is set.

    Produces role-appropriate JSON keyed off the slice/candidate the
    orchestrator passed in, with no LLM call. This is what keeps the test
    suite hermetic. Swap in a real provider via ``Orchestrator(model=...)`` or
    the ``SPOTLIGHT_LLM_*`` env vars (see ``agents/moonshot.py``).
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
                # New sinks — CWE-94 family and related.
                "ssti": "CWE-1336",
                "dynamic-import": "CWE-94",
                "deserialization": "CWE-502",
                "path-traversal": "CWE-22",
                "weak-hash": "CWE-327",
                "verify-disabled": "CWE-295",
                "prompt-injection": "CWE-77",
                "excessive-agency": "CWE-269",
                "output-handling": "CWE-79",
                "system-prompt-leak": "CWE-540",
                "rag-surface": "CWE-345",
                "denial-of-wallet": "CWE-400",
            }
            # Parent CWE family lookup — surfaces on the finding so an
            # auditor can group by the umbrella category (e.g., "show me
            # every CWE-94 finding" catches CWE-95 eval AND CWE-1336 SSTI
            # AND CWE-94 dynamic-import all at once).
            cwe_family_by_class = {
                "eval": "CWE-94",
                "ssti": "CWE-94",
                "dynamic-import": "CWE-94",
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
                # Parent CWE family (if any) — auditor-facing grouping key.
                # Empty for classes that don't belong to an umbrella family.
                "cwe_family": cwe_family_by_class.get(cls, ""),
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

        if role == "planner":
            # Deterministic mock planner: reads the index, produces a small
            # set of framework-generic rules keyed off decorator patterns
            # visible in the index. The real Moonshot / OpenAI planner will
            # be much more specific — this mock exists so tests + demos
            # produce a plausible plan without a live model.
            index = str(context.get("index", ""))
            framework = "flask" if "@app.route" in index else (
                "fastapi" if "@app.get" in index or "@router" in index else
                "express" if "app.get(" in index or "app.post(" in index else
                "unknown"
            )
            # A small always-emitted rulepack — these are conservative
            # enough to fire on most Python repos we've swept and give
            # tests something to key off.
            rules = [
                {
                    "identifier": "yaml.unsafe_load",
                    "role": "sink",
                    "target_class": "deserialization",
                    "cwe": "CWE-502",
                    "description": "yaml.unsafe_load treats the input as executable code.",
                },
                {
                    "identifier": "pickle.load",
                    "role": "sink",
                    "target_class": "deserialization",
                    "cwe": "CWE-502",
                    "description": "pickle.load deserializes arbitrary Python objects.",
                },
                {
                    "identifier": "html_escape",
                    "role": "sanitizer",
                    "target_class": "xss",
                    "cwe": "CWE-79",
                    "description": "Assumed HTML-escape helper.",
                },
            ]
            return {
                "framework": framework,
                "rules": rules,
                "semgrep_rules_yaml": "",
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
