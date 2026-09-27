"""Calibration — turning a ledger of outcomes into defensible numbers.

This is the only place the Cortex does inference, and it does it with
arithmetic rather than a model. That is a deliberate constraint: a learned
policy has to be explainable to a bank's audit committee, reproducible from
the ledger head, and identical on every replay. A Beta posterior satisfies
all three; an LLM asked "how much should we trust SQLi findings?" satisfies
none of them.

What a cohort measures
----------------------
A cohort is ``(class, evidence_signature)`` — "SQLi supported by a code-graph
fact plus one agent opinion", "SSTI supported by an agent opinion alone". For
each cohort we count labelled rows only (see `experience.py` on why unlabeled
rows are excluded rather than assumed negative) and estimate precision:

* ``precision_mean`` — Jeffreys posterior mean, ``(tp + 0.5) / (n + 1)``.
  Beta(0.5, 0.5) is the reference prior for a binomial rate: it neither
  assumes a cohort is good (Beta(1,1) leans optimistic at low n) nor punishes
  a small cohort into silence.
* ``precision_lower`` — Wilson score lower bound at 95%. This is the number
  any *down*ward decision uses, because a decision to trust something less
  should be made on the pessimistic end of the interval, and a decision to
  trust it more (see `policy.py`) should never be made on the optimistic one.

Support gate
------------
A cohort with fewer than ``min_support`` labelled rows produces no policy
effect at all. Three false positives on a Friday is an anecdote, and a system
that retunes itself on anecdotes oscillates. The default (5) is low enough to
learn inside one real repo's review cycle and high enough that a single
mislabelled review cannot move a tier.
"""
from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable

from .experience import (
    FALSE_POSITIVE,
    SOURCE_ANALYST,
    TRUE_POSITIVE,
    Experience,
)

# Minimum labelled rows before a cohort may influence anything.
DEFAULT_MIN_SUPPORT = 5

# Wilson z for a 95% one-sided bound.
_Z = 1.959963984540054


def _wilson_lower(successes: int, n: int, z: float = _Z) -> float:
    """Wilson score interval, lower bound. Returns 0.0 for n == 0."""
    if n <= 0:
        return 0.0
    p = successes / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = p + z2 / (2 * n)
    margin = z * math.sqrt((p * (1 - p) + z2 / (4 * n)) / n)
    return max(0.0, (center - margin) / denom)


def _jeffreys_mean(successes: int, n: int) -> float:
    """Posterior mean under Beta(0.5, 0.5). Returns 0.5 for n == 0."""
    if n <= 0:
        return 0.5
    return (successes + 0.5) / (n + 1.0)


@dataclass
class CohortStats:
    """Per-cohort evidence reliability. Everything here is auditable math."""

    cohort: str
    class_: str
    signature: str
    n_labeled: int = 0
    tp: int = 0
    fp: int = 0
    unknown: int = 0
    weak_negatives: int = 0
    human_tp: int = 0          # TP labels sourced from an analyst, not a PoC
    human_fp: int = 0
    precision_mean: float = 0.5
    precision_lower: float = 0.0
    min_support: int = DEFAULT_MIN_SUPPORT

    @property
    def actionable(self) -> bool:
        """Enough labelled evidence for this cohort to change a decision."""
        return self.n_labeled >= self.min_support

    @property
    def label_coverage(self) -> float:
        """Share of rows in the cohort that carry a label at all.

        Low coverage is the signal to go build a Reproducer template for the
        class — not to retune its confidence.
        """
        total = self.n_labeled + self.unknown
        return (self.n_labeled / total) if total else 0.0

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["actionable"] = self.actionable
        d["label_coverage"] = round(self.label_coverage, 4)
        return d


@dataclass
class Calibration:
    """The full picture derived from one ledger state."""

    ledger_head: str
    cohorts: dict[str, CohortStats] = field(default_factory=dict)
    total_rows: int = 0
    labeled_rows: int = 0
    min_support: int = DEFAULT_MIN_SUPPORT

    def actionable(self) -> dict[str, CohortStats]:
        return {k: v for k, v in self.cohorts.items() if v.actionable}

    def to_dict(self) -> dict[str, Any]:
        return {
            "ledger_head": self.ledger_head,
            "total_rows": self.total_rows,
            "labeled_rows": self.labeled_rows,
            "min_support": self.min_support,
            "cohorts": {k: v.to_dict() for k, v in sorted(self.cohorts.items())},
        }


def calibrate(
    experiences: Iterable[Experience],
    *,
    ledger_head: str = "",
    min_support: int = DEFAULT_MIN_SUPPORT,
) -> Calibration:
    """Aggregate experiences into per-cohort reliability estimates.

    Callers should pass ``ledger.latest_by_finding().values()`` rather than
    every row: one finding re-judged on fifty CI sweeps is one piece of
    evidence about the cohort, not fifty. Passing raw rows would let sweep
    frequency — an operational detail — outweigh analyst verdicts.
    """
    cal = Calibration(ledger_head=ledger_head, min_support=min_support)
    for exp in experiences:
        cal.total_rows += 1
        stats = cal.cohorts.get(exp.cohort)
        if stats is None:
            stats = CohortStats(
                cohort=exp.cohort,
                class_=exp.class_,
                signature=exp.signature,
                min_support=min_support,
            )
            cal.cohorts[exp.cohort] = stats
        if exp.label == TRUE_POSITIVE:
            stats.tp += 1
            stats.n_labeled += 1
            cal.labeled_rows += 1
            if exp.label_source == SOURCE_ANALYST:
                stats.human_tp += 1
        elif exp.label == FALSE_POSITIVE:
            stats.fp += 1
            stats.n_labeled += 1
            cal.labeled_rows += 1
            if exp.label_source == SOURCE_ANALYST:
                stats.human_fp += 1
        else:
            stats.unknown += 1
        if exp.weak_negative:
            stats.weak_negatives += 1

    for stats in cal.cohorts.values():
        stats.precision_mean = round(_jeffreys_mean(stats.tp, stats.n_labeled), 6)
        stats.precision_lower = round(_wilson_lower(stats.tp, stats.n_labeled), 6)
    return cal
