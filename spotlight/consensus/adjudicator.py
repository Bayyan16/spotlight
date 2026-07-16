"""Adjudicator — PRD §8.3.

When two corroborators disagree, we don't average their opinions. A
fresh-context agent — different system prompt from the Investigator — reads
BOTH positions and the Code Graph slice, picks a side, and stores its
reasoning. Disagreement is signal, not noise.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


ADJUDICATOR_SYSTEM_PROMPT = (
    "You are Spotlight's Adjudicator. Two positions disagree about whether "
    "a flagged code path is a real vulnerability. Read both. Take a side and "
    "explain in 2 sentences why the losing side is wrong. Return strict JSON "
    "with keys: decision, rationale, side_taken."
)


@dataclass
class Adjudicator:
    """Resolves disagreement between two evidence positions.

    Consumes a ModelClient with the standard `.complete(role, prompt, context)`
    signature so tests can pass a stub. In prod the orchestrator wires in the
    same client used by the other roles (Moonshot / mock).
    """

    role: str = "adjudicator"

    def adjudicate(
        self,
        candidate: dict[str, Any],
        positions: list[dict[str, Any]],
        code_graph_slice: dict | None,
        model: Any,
    ) -> dict[str, Any]:
        """Return `{decision, rationale, side_taken}` per PRD §8.3.

        decision   — 'promote' | 'reject' | 'needs-review'
        rationale  — 2-sentence explanation of why the losing side is wrong
        side_taken — human-readable identifier of the winning position
                     (e.g. 'static_analysis_fact' or 'independent_agent')
        """
        prompt = _build_prompt(candidate, positions, code_graph_slice)
        context = {
            "candidate": candidate,
            "positions": positions,
            "code_graph_slice": code_graph_slice or {},
            "system_prompt": ADJUDICATOR_SYSTEM_PROMPT,
        }

        if model is None:
            return _heuristic_decision(candidate, positions)

        # Some ModelClients don't know the 'adjudicator' role. Try the real
        # call; fall back to the heuristic on any error rather than crashing
        # the whole promotion path.
        try:
            raw = model.complete(role=self.role, prompt=prompt, context=context)
        except Exception:
            return _heuristic_decision(candidate, positions)

        if not isinstance(raw, dict):
            return _heuristic_decision(candidate, positions)

        # Accept either a strict JSON reply already parsed by the client, or
        # a wrapped envelope with `content` we still have to json.loads.
        parsed = _normalize_output(raw)
        if parsed is None:
            return _heuristic_decision(candidate, positions)
        return parsed


def _build_prompt(
    candidate: dict[str, Any],
    positions: list[dict[str, Any]],
    code_graph_slice: dict | None,
) -> str:
    return (
        "Candidate finding:\n"
        f"{json.dumps(candidate, indent=2)[:4000]}\n\n"
        "Positions (each side of the disagreement):\n"
        f"{json.dumps(positions, indent=2)[:4000]}\n\n"
        "Code graph slice:\n"
        f"{json.dumps(code_graph_slice or {}, indent=2)[:4000]}\n\n"
        "Decide. Return strict JSON: "
        '{"decision": ..., "rationale": ..., "side_taken": ...}'
    )


def _normalize_output(raw: dict[str, Any]) -> dict[str, Any] | None:
    """The model may return the JSON directly or nested under `content`.

    We accept:
      - a dict with `decision`/`rationale`/`side_taken` keys already
      - a dict with a `content` string that itself is JSON
    """
    if all(k in raw for k in ("decision", "rationale", "side_taken")):
        return {
            "decision": str(raw["decision"]),
            "rationale": str(raw["rationale"]),
            "side_taken": str(raw["side_taken"]),
        }
    content = raw.get("content")
    if isinstance(content, str):
        try:
            inner = json.loads(content)
        except Exception:
            return None
        if isinstance(inner, dict) and all(
            k in inner for k in ("decision", "rationale", "side_taken")
        ):
            return {
                "decision": str(inner["decision"]),
                "rationale": str(inner["rationale"]),
                "side_taken": str(inner["side_taken"]),
            }
    return None


def _heuristic_decision(
    candidate: dict[str, Any], positions: list[dict[str, Any]]
) -> dict[str, Any]:
    """Fallback used when no model is available or the model errored.

    The heuristic favors the strongest modality: dynamic_reproduction wins,
    then static_analysis_fact, then independent_agent. This is the same
    ordering PRD §8.1 uses to describe evidence strength.
    """
    priority = {
        "dynamic_reproduction": 3,
        "static_analysis_fact": 2,
        "independent_agent": 1,
        "external_signal": 1,
    }
    if not positions:
        return {
            "decision": "needs-review",
            "rationale": (
                "No positions were provided to the adjudicator; the caller "
                "should treat this finding as ambiguous and route to human."
            ),
            "side_taken": "none",
        }
    ranked = sorted(
        positions,
        key=lambda p: priority.get(p.get("modality", ""), 0),
        reverse=True,
    )
    winner = ranked[0]
    result = winner.get("result", "")
    winner_says_yes = result in ("confirmed", "positive", "yes", "flagged") or (
        winner.get("modality") == "static_analysis_fact"
        and result not in ("sanitized", "not-confirmed", "refuted")
    )
    decision = "promote" if winner_says_yes else "reject"
    side = winner.get("modality", "unknown")
    other = next(
        (p for p in ranked[1:] if p.get("modality") != side),
        None,
    )
    if other is None:
        losing_desc = "the other side had no stronger modality to appeal to"
    else:
        losing_desc = (
            f"the {other.get('modality')} position ({other.get('result')}) "
            "carries less evidential weight than the winning modality"
        )
    rationale = (
        f"The {side} evidence is the strongest modality per PRD 8.1 and "
        f"asserts {result or 'the vulnerability'}. In this disagreement, "
        f"{losing_desc}."
    )
    return {
        "decision": decision,
        "rationale": rationale,
        "side_taken": side,
    }
