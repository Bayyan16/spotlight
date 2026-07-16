"""Moonshot (Kimi) model client — OpenAI-compatible chat.completions endpoint.

Used as a T0 real-inference path so we can move off the MockModelClient. The
Investigator, Recon, and Verifier roles get real reasoning; everything else
(the code graph, the reproducer, the remediator, the verifier's PoC run) is
already real code.

Contract: returns a schema-valid dict for the role. The prompt asks Moonshot
to emit JSON; we then json.loads it. Fallback to a schema-safe stub if the
model returns malformed JSON (Phase-1 policy per PRD §13.7 — "malformed output
→ mark inconclusive and continue").
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any

import httpx

from .model import MockModelClient


@dataclass
class MoonshotModelClient:
    api_key: str
    base_url: str = "https://api.moonshot.cn/v1"
    model: str = "moonshot-v1-128k"
    family: str = "moonshot"
    timeout_s: float = 45.0

    def complete(self, *, role: str, prompt: str, context: dict[str, Any]) -> dict[str, Any]:
        system, user = _prompts_for(role, prompt, context)
        try:
            resp = httpx.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "temperature": 0.2,
                    "response_format": {"type": "json_object"},
                },
                timeout=self.timeout_s,
            )
            resp.raise_for_status()
            body = resp.json()
            content = body["choices"][0]["message"]["content"]
            return _parse_json_safely(content, role, context)
        except Exception as e:
            # Never let a model hiccup break the sweep. Fall back to the mock
            # for schema-safety, tag it in the audit trail.
            fallback = MockModelClient().complete(role=role, prompt=prompt, context=context)
            fallback["_model_error"] = repr(e)[:200]
            fallback["_fallback"] = True
            return fallback


def _prompts_for(role: str, prompt: str, ctx: dict[str, Any]) -> tuple[str, str]:
    if role == "recon":
        return (
            "You are Spotlight's Recon agent. Classify the target's stack and threat model. "
            "Reply as strict JSON with keys: stack{language,framework}, surfaces (array), "
            "signals (array — pass through), threat_model{untrusted_sources,high_impact_sinks}.",
            f"Signals detected by sg-core:\n{json.dumps(ctx.get('signals', []))[:6000]}\n\n"
            f"Has AI/agent/RAG layer: {ctx.get('has_ai_layer', False)}\n\n"
            f"Return the JSON classification.",
        )

    if role == "investigator":
        slice_ = ctx["slice"]
        return (
            "You are Spotlight's Investigator agent. You are given a data-flow slice from "
            "sg-core showing an untrusted source reaching a dangerous sink. Judge whether "
            "this is a real vulnerability. Reply as strict JSON with keys: verdict ('candidate' "
            "or 'reject'), class, cwe, title, severity ('critical'|'high'|'medium'|'low'), "
            "location{file,line,function}, root_cause, recommendation, evidence_used (array).",
            f"Slice:\n{json.dumps(slice_, indent=2)}\n\n"
            "If the slice is a real vuln, verdict=candidate and fill the fields. "
            "If sg-core already marked it sanitized, verdict=reject.",
        )

    if role == "verifier":
        return (
            "You are Spotlight's independent Verifier. You are given a finding and the "
            "reproduction result AFTER a patch was applied, plus a backdoor-check report. "
            "Reply as strict JSON with keys: result ('repro-now-blocked'|'still-exploitable'|"
            "'inconclusive'), independent_verifier (bool, true), backdoor_check ('pass'|'fail'), "
            "security_regression ('pass'|'fail'), notes.",
            f"Finding:\n{json.dumps(ctx.get('finding', {}), indent=2)[:4000]}\n\n"
            f"Post-patch repro:\n{json.dumps(ctx.get('repro', {}), indent=2)[:2000]}\n\n"
            f"Backdoor scan:\n{json.dumps(ctx.get('backdoor', {}), indent=2)}\n\n"
            "Re-derive risk from scratch. Was the exploit path closed?",
        )

    raise ValueError(f"MoonshotModelClient has no prompt template for role={role}")


def _parse_json_safely(content: str, role: str, ctx: dict[str, Any]) -> dict[str, Any]:
    """Model output is JSON per response_format, but be defensive."""
    content = content.strip()
    # Strip possible ```json fences.
    if content.startswith("```"):
        content = re.sub(r"^```(?:json)?\s*|\s*```$", "", content, flags=re.MULTILINE).strip()
    try:
        return json.loads(content)
    except Exception:
        fallback = MockModelClient().complete(role=role, prompt="", context=ctx)
        fallback["_parse_error"] = True
        fallback["_raw"] = content[:400]
        return fallback


def maybe_from_env() -> "MoonshotModelClient | None":
    key = os.environ.get("MOONSHOT_API_KEY")
    if not key:
        return None
    return MoonshotModelClient(
        api_key=key,
        base_url=os.environ.get("MOONSHOT_BASE_URL", "https://api.moonshot.cn/v1"),
        model=os.environ.get("MOONSHOT_MODEL", "moonshot-v1-128k"),
    )
