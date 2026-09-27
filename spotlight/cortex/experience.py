"""The unit of learning — one `Experience` per judged finding.

Spotlight is a careful reasoner with no memory. Every sweep re-derives every
judgment from scratch: the Planner's validated rules are discarded at
teardown, the Verifier's gold labels evaporate with the tempdir, and an
analyst's signed `false-positive` verdict is filed and never read again. The
Cortex exists to close that loop, and this module defines what it is allowed
to learn *from*.

An Experience is a single row: the shape of the evidence that was available,
the tier the Consensus Kernel decided, and — when and only when something
authoritative said so — a label.

Labelling policy (the epistemic core; read this before changing anything)
------------------------------------------------------------------------
Authority is ordered, and only these three sources may label a row:

1. ``analyst-review``  — a human verdict. ``false-positive`` → FALSE_POSITIVE;
   ``accepted`` / ``risk-accepted`` → TRUE_POSITIVE. A human always wins.
2. ``reproduction``    — the Reproducer exploited it in the sandbox
   (``result == "confirmed"``) → TRUE_POSITIVE. A demonstrated exploit is
   proof, not opinion.
3. ``static-fact``     — a static-fact class (`secrets`) corroborated by a
   static fact → TRUE_POSITIVE. The committed literal *is* the proof.

Everything else is ``unknown`` — deliberately, and this is the rule that
keeps the learning honest:

* ``not-reproduced`` is NOT a false positive. It means "we could not build a
  PoC for this class/shape yet", which is a statement about our Reproducer,
  not about the code. Counting it as an FP would teach the Cortex to bury
  exactly the classes it is worst at — authz, IDOR, crypto misuse — and
  precision would look wonderful while recall quietly collapsed.
* ``inconclusive`` / ``not-applicable`` likewise label nothing.

Such rows are still recorded (with ``weak_negative=True``) because the
*absence* of a label is itself useful observability: a cohort that is 90%
unlabeled tells you to go build a Reproducer template, not to retune
confidence.

Features are structural only — class, surface, framework, sink callee, source
origin, path prefix. No target file content ever enters an Experience: the
ledger is replayed into prompts downstream, so anything that lands here is a
persistent prompt-injection surface (see `lessons.py`).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

# ── labels ───────────────────────────────────────────────────────────────
TRUE_POSITIVE = "true-positive"
FALSE_POSITIVE = "false-positive"
UNKNOWN = "unknown"

LABELS = frozenset({TRUE_POSITIVE, FALSE_POSITIVE, UNKNOWN})

# Label sources, most authoritative first. `_SOURCE_RANK` is what makes
# re-labelling monotone: a later row from a weaker source can never overwrite
# a stronger verdict (see `Experience.supersedes`).
SOURCE_ANALYST = "analyst-review"
SOURCE_REPRODUCTION = "reproduction"
SOURCE_STATIC_FACT = "static-fact"
SOURCE_UNLABELED = "unlabeled"

_SOURCE_RANK = {
    SOURCE_ANALYST: 3,
    SOURCE_REPRODUCTION: 2,
    SOURCE_STATIC_FACT: 1,
    SOURCE_UNLABELED: 0,
}

# Analyst review states as written by `POST /findings/{id}/review`.
_ANALYST_TRUE = frozenset({"accepted", "risk-accepted"})
_ANALYST_FALSE = frozenset({"false-positive"})

# Classes whose committed literal is itself the proof (mirrors
# `consensus.kernel.STATIC_FACT_CLASSES` — kept as its own frozenset so a
# change there is a deliberate change here too).
STATIC_FACT_CLASSES = frozenset({"secrets", "hardcoded-secret"})

# Reproducer results that assert exploitation.
_REPRO_CONFIRMED = frozenset({"confirmed"})
# Reproducer results that assert nothing (see module docstring).
_REPRO_SILENT = frozenset({"not-reproduced", "inconclusive", "not-applicable", ""})


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def evidence_signature(modalities: list[str] | tuple[str, ...]) -> str:
    """Canonical, order-independent name for a shape of evidence.

    ``["independent_agent", "static_analysis_fact"]`` and the reverse both
    render as ``"independent_agent+static_analysis_fact"``. This string is
    half of every cohort key, so it must be stable across sweeps or the
    Cortex would learn a different lesson per agent scheduling order.
    """
    return "+".join(sorted({str(m).strip() for m in modalities if str(m).strip()}))


def cohort_key(class_: str, signature: str) -> str:
    """The unit calibration and policy are keyed on.

    A cohort answers exactly one question: *"when a finding of class C is
    supported by evidence shape S, how often was it real?"* That is the only
    thing the Cortex is permitted to learn, because it is the only thing the
    ledger can actually measure.
    """
    return f"{str(class_).strip().lower()}|{signature}"


@dataclass
class Experience:
    """One judged finding, reduced to what is safe and useful to remember."""

    sweep_id: str
    finding_key: str          # `finding_identity()` fingerprint — stable across sweeps
    class_: str
    cohort: str               # cohort_key(class_, evidence_signature)
    signature: str            # evidence_signature(...)
    tier: str                 # tier the Consensus Kernel decided
    confidence: float
    label: str = UNKNOWN
    label_source: str = SOURCE_UNLABELED
    label_reason: str = ""
    weak_negative: bool = False   # repro ran and did not fire — informational only
    repro_result: str = ""
    verify_result: str = ""
    backdoor_check: str = ""
    surface: str = "code"
    cwe: str = ""
    features: dict[str, Any] = field(default_factory=dict)
    repo: str = ""
    commit_sha: str = ""
    ts: str = field(default_factory=_utc_now)

    # ── derived ──────────────────────────────────────────────────────
    @property
    def labeled(self) -> bool:
        return self.label in (TRUE_POSITIVE, FALSE_POSITIVE)

    @property
    def authority(self) -> int:
        return _SOURCE_RANK.get(self.label_source, 0)

    def supersedes(self, other: "Experience") -> bool:
        """True when this row should replace `other` for the same finding.

        Strictly by source authority: a human verdict overrides a
        reproduction, a reproduction overrides a static fact, and nothing
        overrides a verdict from an equal-or-stronger source. Without this,
        a later unlabeled re-sweep would erase an analyst's false-positive
        call and the Cortex would re-learn the mistake it was corrected on.
        """
        if self.finding_key != other.finding_key:
            return False
        return self.authority > other.authority

    def content_hash(self) -> str:
        """Content address over the semantic fields (not `ts`).

        Two identical judgments recorded twice collapse to one row, so a
        retried sweep cannot inflate a cohort's counts — the single most
        likely way for this system to fool itself.
        """
        body = {
            "sweep_id": self.sweep_id,
            "finding_key": self.finding_key,
            "cohort": self.cohort,
            "tier": self.tier,
            "label": self.label,
            "label_source": self.label_source,
        }
        blob = json.dumps(body, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["experience_id"] = self.content_hash()
        return d

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Experience":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in raw.items() if k in known})


# ── labelling ────────────────────────────────────────────────────────────


def label_for(
    *,
    class_: str,
    repro_result: str | None,
    review_state: str | None,
    has_static_fact: bool,
    review_reason: str = "",
) -> tuple[str, str, str]:
    """Resolve ``(label, label_source, reason)`` under the authority order.

    Pure function, no I/O — the whole labelling policy is auditable here and
    unit-tested against each branch.
    """
    state = str(review_state or "").strip().lower()
    if state in _ANALYST_FALSE:
        return FALSE_POSITIVE, SOURCE_ANALYST, (review_reason or "analyst marked false-positive")
    if state in _ANALYST_TRUE:
        return TRUE_POSITIVE, SOURCE_ANALYST, (review_reason or f"analyst {state}")

    repro = str(repro_result or "").strip().lower()
    if repro in _REPRO_CONFIRMED:
        return TRUE_POSITIVE, SOURCE_REPRODUCTION, "exploit reproduced in sandbox"

    if str(class_).strip().lower() in STATIC_FACT_CLASSES and has_static_fact:
        return TRUE_POSITIVE, SOURCE_STATIC_FACT, "static-fact class; literal is the proof"

    # Everything else stays unlabeled. `not-reproduced` deliberately lands
    # here: see the module docstring.
    return UNKNOWN, SOURCE_UNLABELED, "no authoritative label available"


def is_weak_negative(repro_result: str | None) -> bool:
    """The Reproducer ran and did not fire. Informational, never an FP."""
    return str(repro_result or "").strip().lower() in (_REPRO_SILENT - {""})
