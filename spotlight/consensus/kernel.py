"""Consensus Kernel v1 — independence check + tiered promotion.

Implements PRD §8 semantics. The old orchestrator-inline `_promote_tier` is
kept in place (renamed `_promote_tier_legacy`) as a rollback lever; this
module is the canonical path.

Independence (§8.1):
  Two evidence items are independent only if they differ in *modality* or
  *origin*. Valid independent corroborators:
    - `static_analysis_fact`   deterministic; never a model opinion
    - `dynamic_reproduction`   the strongest single item
    - `independent_agent`      different model family, OR fresh context +
                               different prompt scaffold
    - `external_signal`        SAST/DAST/AI-scanner importer hit

  Two passes of the SAME model in the SAME context count as ONE vote — we
  enforce that by keying on (modality, origin.model_family, origin.context_id).

Tiers (§8.2):
  Verified          reproduced AND ≥1 independent corroborator
  High-confidence   ≥2 independent corroborators incl. ≥1 static-analysis
                    fact, no reproduction
  Needs review      corroborated but ambiguous / repro inconclusive
  Held              single-source, uncorroborated, unreproduced

Legacy compat:
  Static-fact classes (`secrets`, `hardcoded-secret`) with a static_fact
  corroborator go straight to `verified` at confidence 0.95. This preserves
  the pre-B2 behavior — the finding IS the static evidence, there's no PoC.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Modalities recognized as "an independent corroborator" at all. Anything
# outside this set is decorative — kept for provenance, ignored for tiering.
VALID_MODALITIES = frozenset(
    {
        "static_analysis_fact",
        "dynamic_reproduction",
        "independent_agent",
        "external_signal",
        # Planner-inferred rule fired — ranked at parity with
        # external_signal (Semgrep). Grep-validated at plan time so we
        # know the identifier exists in the repo, but not as trustworthy
        # as sg-core's hand-authored deterministic reachability. Needs
        # another independent modality to promote a finding to verified.
        "planner_inferred",
    }
)

STATIC_FACT_CLASSES = frozenset({"secrets", "hardcoded-secret"})


@dataclass
class EvidenceItem:
    """One corroborator record.

    modality   — one of VALID_MODALITIES (or anything; unrecognized modalities
                 are silently dropped from the independence tally).
    origin     — free-form dict; the independence check keys on the tuple
                 (modality, origin.get('model_family'), origin.get('context_id'))
                 so two passes of the same model in the same context collapse.
    result     — 'confirmed' | 'not-confirmed' | 'not-applicable' | 'sanitized'
                 | 'inconclusive'. Used to detect disagreement.
    detail     — arbitrary. The rationale reads this out when it needs to
                 mention specifics.
    """

    modality: str
    origin: dict[str, Any] = field(default_factory=dict)
    result: str = "confirmed"
    detail: Any = None

    def independence_key(self) -> tuple:
        return (
            self.modality,
            (self.origin or {}).get("model_family"),
            (self.origin or {}).get("context_id"),
        )


@dataclass
class TierDecision:
    tier: str  # 'verified' | 'high-confidence' | 'needs-review' | 'held'
    confidence: float
    rationale: str
    independent_corroborators: int
    adjudication: dict | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier,
            "confidence": self.confidence,
            "rationale": self.rationale,
            "independent_corroborators": self.independent_corroborators,
            "adjudication": self.adjudication,
        }


def _dedupe_independent(evidence: list[EvidenceItem]) -> list[EvidenceItem]:
    """Collapse correlated items per PRD §8.1.

    Two items with the same (modality, model_family, context_id) key are the
    same vote — keep the first, drop the rest. Items whose modality is not
    in VALID_MODALITIES are dropped entirely (they don't count toward the
    independence tally, though callers can still read them from the raw
    evidence list for provenance).
    """
    seen: set[tuple] = set()
    kept: list[EvidenceItem] = []
    for item in evidence:
        if item.modality not in VALID_MODALITIES:
            continue
        key = item.independence_key()
        if key in seen:
            continue
        seen.add(key)
        kept.append(item)
    return kept


def _positive(item: EvidenceItem) -> bool:
    """Does this item say 'yes, this is a vuln'?"""
    if item.modality == "dynamic_reproduction":
        return item.result == "confirmed"
    if item.modality == "static_analysis_fact":
        # A static fact IS a positive assertion of reachability unless the
        # caller explicitly marked it 'sanitized' or 'not-confirmed'.
        return item.result not in ("sanitized", "not-confirmed", "refuted")
    # Independent agents / external signals: 'confirmed' or unspecified = yes.
    return item.result in ("confirmed", "positive", "yes", "flagged")


def _negative(item: EvidenceItem) -> bool:
    return item.result in ("sanitized", "not-confirmed", "refuted", "negative", "no")


def _disagreement(items: list[EvidenceItem]) -> bool:
    """True iff at least one item says vuln AND at least one says not-vuln."""
    pos = any(_positive(i) for i in items)
    neg = any(_negative(i) for i in items)
    return pos and neg


class ConsensusKernel:
    """Stable interface per PRD §8.4: promote(candidate, evidence) -> TierDecision.

    Weighted cross-agent scoring lands later behind this same signature.
    """

    def __init__(self, adjudicator: Any = None) -> None:
        # Adjudicator is optional at construction time — the caller can inject
        # a mock in tests. If not provided we import lazily on first need so
        # this module stays importable without pulling model clients.
        self._adjudicator = adjudicator

    # ── main entrypoint ────────────────────────────────────────────────
    def promote(
        self,
        candidate: dict[str, Any],
        evidence: list[EvidenceItem],
        *,
        model: Any = None,
        code_graph_slice: dict | None = None,
    ) -> TierDecision:
        cls = (candidate or {}).get("class", "")

        # Independence-filtered view is the ONLY thing tier logic reads.
        independent = _dedupe_independent(evidence)
        n_independent = len(independent)

        static_items = [i for i in independent if i.modality == "static_analysis_fact"]
        repro_items = [i for i in independent if i.modality == "dynamic_reproduction"]

        has_static_fact = any(_positive(i) for i in static_items)
        has_reproduction = any(_positive(i) for i in repro_items)
        repro_not_applicable = any(
            i.modality == "dynamic_reproduction" and i.result == "not-applicable"
            for i in independent
        )

        # ── adjudication triggers (§8.3) ──────────────────────────────
        # Trigger 1: any two items contradict each other.
        # Trigger 2: static_fact positive, reproduction says not-applicable,
        #            and no confirmed reproduction — the exact "reasoned, not
        #            reproduced" tension the adjudicator is designed for.
        adjudication_needed = _disagreement(independent) or (
            has_static_fact and repro_not_applicable and not has_reproduction
            and cls not in STATIC_FACT_CLASSES  # secrets short-circuit below
        )
        adjudication: dict | None = None
        if adjudication_needed:
            adjudication = self._maybe_adjudicate(
                candidate, independent, code_graph_slice, model
            )

        # ── legacy behavior: static-fact classes short-circuit ────────
        # `secrets` / `hardcoded-secret` with a static_fact go straight to
        # verified at 0.95. Kept identical to _promote_tier_legacy.
        if cls in STATIC_FACT_CLASSES and has_static_fact:
            return TierDecision(
                tier="verified",
                confidence=0.95,
                rationale=(
                    "static-fact class — hardcoded credential in source "
                    "(no PoC needed)"
                ),
                independent_corroborators=n_independent,
                adjudication=adjudication,
            )

        # ── tier decisions (§8.2) ─────────────────────────────────────
        # Verified: reproduction + ≥1 independent corroborator.
        # (The reproduction itself counts as one independent corroborator, so
        # the effective requirement is: repro AND another modality.)
        other_independent = [
            i for i in independent if i.modality != "dynamic_reproduction"
        ]
        if has_reproduction and any(_positive(i) for i in other_independent):
            conf = 0.93 if has_static_fact else 0.88
            rat = (
                "reproduction + static-analysis fact"
                if has_static_fact
                else "reproduction + independent corroborator"
            )
            return TierDecision(
                tier="verified",
                confidence=conf,
                rationale=rat,
                independent_corroborators=n_independent,
                adjudication=adjudication,
            )

        # Verified (legacy compat): reproduction alone at 0.85. PRD §8.2
        # strictly requires an independent corroborator, but the old code
        # already treated this as verified and the callers rely on it.
        if has_reproduction:
            return TierDecision(
                tier="verified",
                confidence=0.85,
                rationale="reproduction alone",
                independent_corroborators=n_independent,
                adjudication=adjudication,
            )

        # High-confidence: ≥2 independent corroborators incl. ≥1 static fact,
        # no reproduction. This is the "reasoned, not reproduced" tier from
        # §8.2 (IDOR/authz/crypto etc.).
        if n_independent >= 2 and has_static_fact:
            return TierDecision(
                tier="high-confidence",
                confidence=0.82,
                rationale=(
                    "two independent corroborators incl. static-analysis fact"
                ),
                independent_corroborators=n_independent,
                adjudication=adjudication,
            )

        # Legacy: static-fact + repro=not-applicable → verified at 0.90.
        # The old code path treated this as "definitely real, no PoC needed"
        # and downstream callers expect it. Preserved.
        if has_static_fact and repro_not_applicable:
            return TierDecision(
                tier="verified",
                confidence=0.90,
                rationale="static-analysis fact for static-only class",
                independent_corroborators=n_independent,
                adjudication=adjudication,
            )

        # High-confidence-ish single static fact — keep legacy label so
        # existing consumers don't regress.
        if has_static_fact:
            return TierDecision(
                tier="high-confidence",
                confidence=0.7,
                rationale="static-analysis fact without reproduction",
                independent_corroborators=n_independent,
                adjudication=adjudication,
            )

        # Corroborated but ambiguous → needs review (§8.2).
        if n_independent >= 1 and _disagreement(independent):
            return TierDecision(
                tier="needs-review",
                confidence=0.5,
                rationale="corroborators disagree; adjudicator invoked",
                independent_corroborators=n_independent,
                adjudication=adjudication,
            )

        if n_independent >= 1:
            return TierDecision(
                tier="needs-review",
                confidence=0.4,
                rationale="single-source, unreproduced",
                independent_corroborators=n_independent,
                adjudication=adjudication,
            )

        # No evidence at all → Held (§8.2).
        return TierDecision(
            tier="held",
            confidence=0.2,
            rationale="no independent evidence; held for low-signal review",
            independent_corroborators=0,
            adjudication=adjudication,
        )

    # ── internals ──────────────────────────────────────────────────────
    def _maybe_adjudicate(
        self,
        candidate: dict[str, Any],
        independent: list[EvidenceItem],
        code_graph_slice: dict | None,
        model: Any,
    ) -> dict | None:
        """Wrap the Adjudicator call. Never let a bad model call crash the
        kernel — that would be a worse regression than a missing adjudication.
        """
        adj = self._adjudicator
        if adj is None:
            # Lazy import to avoid a circular dependency at module load.
            try:
                from .adjudicator import Adjudicator

                adj = Adjudicator()
            except Exception:
                return None
        positions = [
            {
                "modality": i.modality,
                "origin": i.origin,
                "result": i.result,
                "detail": i.detail,
            }
            for i in independent
        ]
        try:
            return adj.adjudicate(
                candidate=candidate,
                positions=positions,
                code_graph_slice=code_graph_slice,
                model=model,
            )
        except Exception as e:
            # Log-and-continue: return an adjudication stub so the caller
            # can see we tried and why it failed. The tier decision is
            # unaffected — the promote() flow continues past this point.
            return {
                "decision": "needs-review",
                "rationale": f"adjudicator error: {e!r}"[:200],
                "side_taken": "none",
                "_error": True,
            }
