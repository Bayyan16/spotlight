"""Hypothesis Path Proposer — Tranche B5.

The Chainer is deterministic: it composes ExploitPath objects only when a
pre-authored rule matches (LLM01+LLM06+SSRF, LLM05→eval/cmdi, secrets
pairing). That gives us signed, auditable, reproducible chains — the
attestation lane.

Real repos produce chains outside those three patterns. The
HypothesisProposer runs ONE LLM call per sweep against the reduced
candidate set and asks the model to propose plausible cross-surface
paths. Each proposal:

  * is tagged `tier="hypothesis"` and `origin="llm-proposal"`
  * is dedup'd against Chainer verified paths (same finding-id set)
  * is validated: every referenced step id must exist in `candidates`
  * NEVER lands in the signed exploit_paths block of an attestation

The Console shows verified + hypothesis in two visually separate lanes.
Analysts promote hypotheses by authoring a new rule in
`chainer.py` — that's how our rule library grows.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from spotlight.agents.model import ModelClient


_MAX_CHAINS = 5
_MAX_STEPS = 4


@dataclass
class HypothesisProposer:
    """Proposes speculative exploit paths from a candidate pool.

    Stateless. One instance per orchestrator run.
    """

    model: ModelClient

    def propose(
        self,
        candidates: list[dict[str, Any]],
        verified: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Return a list of hypothesis-tagged ExploitPath dicts.

        Args:
            candidates: reduced Investigator/AgenticAnalyst candidates.
            verified: paths the Chainer already emitted — used to
                deduplicate. Passed by fingerprint (rule + step ids), so a
                hypothesis that mirrors a verified path is dropped.

        Empty inputs return `[]`. Any exception from the model client is
        swallowed and returns `[]` — hypothesis paths are a corroborator,
        not a gate.
        """
        if len(candidates) < 2:
            return []

        cand_by_id = _index_by_id(candidates)
        verified_fingerprints = _verified_fingerprints(verified or [])

        try:
            resp = self.model.complete(
                role="hypothesis-proposer",
                prompt=(
                    "You are the ExploitPath Hypothesis Proposer. Given a set "
                    "of security findings, propose plausible attack chains. "
                    "Each chain lists step_finding_ids in execution order."
                ),
                context={"candidates": candidates},
            )
        except Exception as exc:
            print(f"[hypothesis] proposer failed: {exc!r}")
            return []

        raw_chains = resp.get("chains", []) or []
        paths: list[dict[str, Any]] = []
        seen: set[tuple[str, ...]] = set()

        for idx, ch in enumerate(raw_chains[:_MAX_CHAINS], start=1):
            step_ids = [str(s) for s in (ch.get("step_finding_ids") or [])[:_MAX_STEPS]]
            if len(step_ids) < 2:
                continue

            # Every referenced id MUST resolve to a real candidate. Silent
            # drop otherwise — we won't let the model invent findings.
            resolved: list[dict[str, Any]] = []
            valid = True
            for sid in step_ids:
                c = cand_by_id.get(sid) or cand_by_id.get(sid.lower())
                if c is None:
                    valid = False
                    break
                resolved.append(c)
            if not valid:
                continue

            # Dedup vs. verified paths — same finding-id set means the
            # deterministic Chainer already owns this chain.
            fp = tuple(sorted(step_ids))
            if fp in verified_fingerprints or fp in seen:
                continue
            seen.add(fp)

            surfaces = {_surface_of(c) for c in resolved}
            steps = [_step(i + 1, c, resolved) for i, c in enumerate(resolved)]

            paths.append({
                "id": f"H-EP-{idx:04d}",
                "title": ch.get("title") or _default_title(resolved),
                "severity": ch.get("severity") or _max_sev(resolved),
                "cross_surface": ("code" in surfaces and "agentic" in surfaces),
                "steps": steps,
                "reproduced": False,
                "rationale": ch.get("rationale") or "",
                # Non-negotiable — hypothesis lane is unsigned.
                "tier": "hypothesis",
                "origin": "llm-proposal",
            })
        return paths


def _index_by_id(candidates: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for c in candidates:
        for key in ("id", "finding_id", "title"):
            v = c.get(key)
            if v:
                out.setdefault(str(v), c)
    return out


def _verified_fingerprints(verified: list[dict[str, Any]]) -> set[tuple[str, ...]]:
    out: set[tuple[str, ...]] = set()
    for ep in verified:
        step_ids = tuple(sorted(str(s.get("finding_id", "")) for s in ep.get("steps", [])))
        if step_ids:
            out.add(step_ids)
    return out


def _surface_of(c: dict[str, Any]) -> str:
    surf = str(c.get("surface") or "").strip().lower()
    if surf:
        return surf
    cls = str(c.get("class") or "").strip().lower()
    agentic_prefixes = ("prompt-", "excessive-", "output-", "system-", "rag-", "denial-", "llm0")
    return "agentic" if any(cls.startswith(p) for p in agentic_prefixes) else "code"


def _step(order: int, cand: dict[str, Any], all_steps: list[dict[str, Any]]) -> dict[str, Any]:
    loc = cand.get("location") or {}
    return {
        "order": order,
        "finding_id": cand.get("id") or cand.get("finding_id") or cand.get("title") or "",
        "surface": _surface_of(cand),
        "class": str(cand.get("class") or ""),
        "cwe": cand.get("cwe", ""),
        "file": loc.get("file", ""),
        "line": int(loc.get("line", 0) or 0),
        "edge": (
            "step 1 — attacker entry point" if order == 1
            else f"enables step {order}"
        ),
    }


def _default_title(cands: list[dict[str, Any]]) -> str:
    classes = [str(c.get("class") or "?") for c in cands]
    return f"Hypothesis: {' → '.join(classes)}"


def _max_sev(cands: list[dict[str, Any]]) -> str:
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    best = ("low", 0)
    for c in cands:
        s = str(c.get("severity") or "").strip().lower()
        r = rank.get(s, 0)
        if r > best[1]:
            best = (s, r)
    return best[0]
