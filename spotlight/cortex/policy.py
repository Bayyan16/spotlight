"""The policy — what the Cortex is allowed to change, and what it never is.

A learned policy is a small, immutable, content-addressed artifact that sits
*after* the Consensus Kernel's decision and may nudge it. It is deliberately
not a model, not a prompt, and not code: it is a table of per-cohort
directives that any auditor can read in a minute and any replay can reproduce
exactly from the ledger head it pins.

The constitution (invariants that no amount of learning can amend)
------------------------------------------------------------------
These are enforced twice — once when a policy is validated for activation,
and again inside ``apply()`` at runtime, so a hand-edited policy file on disk
still cannot exceed them.

* **I1 · No manufactured proof.** A policy may never raise a tier. The only
  tier transition it can cause is *into* ``needs-review``. Promotion to
  ``verified`` remains the exclusive result of reproduction plus independent
  corroboration, decided by the Consensus Kernel. Learning cannot invent
  evidence.
* **I2 · Bounded movement.** Confidence moves by at most
  ``MAX_CONFIDENCE_DELTA`` (0.15) per decision and stays inside
  ``[0.05, 0.95]``. The Cortex can express "trust this shape less", not
  "erase this shape".
* **I3 · Nothing disappears.** A policy can never yield ``held``, never drop
  a finding, and never suppress a class. The worst thing it can do to a real
  vulnerability is route it to a human.
* **I4 · Out of scope by construction.** There is no field here that can
  touch Warden, the injection detector, the backdoor scan, the redaction
  chokepoints, sandbox egress, or capability tokens. Safety controls are not
  learnable parameters; the policy schema simply has nowhere to put such a
  change, and ``validate()`` rejects unknown action verbs.
* **I5 · Agents may not certify themselves.** Any directive that *raises*
  confidence requires at least one analyst-sourced true positive in its
  cohort. The system can earn more trust from a human's confirmation, never
  from its own agreement with itself.
* **I6 · Immutable and pinned.** ``policy_id`` is a hash of the body. Policies
  are never edited — a change is a new version with ``derived_from`` set, and
  rollback means activating an earlier id. Every sweep records the id it ran
  under, so an attestation from six months ago can be re-derived exactly.

Why "route to review" is the strong action
-----------------------------------------
The instinct for a self-tuning scanner is to suppress noisy cohorts. That is
the one thing this design refuses. A suppressed finding is invisible and
un-auditable; a routed finding costs an analyst thirty seconds and stays in
the record. So the Cortex's most aggressive available move is to say: *"this
shape of evidence has been wrong often enough that a person should look."*
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .calibrate import Calibration, CohortStats

# ── constitutional bounds (I2) ───────────────────────────────────────────
MAX_CONFIDENCE_DELTA = 0.15
CONFIDENCE_FLOOR = 0.05
CONFIDENCE_CAP = 0.95

# Tier the policy is allowed to route into (I1/I3). Note the absence of
# "verified", "high-confidence" and "held" — by design.
ROUTE_TIER = "needs-review"
# Tiers a route-to-review directive may act on.
ROUTABLE_FROM = frozenset({"verified", "high-confidence"})

ACTION_NONE = "none"
ACTION_ADJUST = "adjust-confidence"
ACTION_ROUTE = "route-to-review"
VALID_ACTIONS = frozenset({ACTION_NONE, ACTION_ADJUST, ACTION_ROUTE})

# A cohort whose pessimistic precision sits at or below this has been wrong
# about as often as it has been right; that is the bar for pulling a human in.
ROUTE_PRECISION_CEILING = 0.5
# Below this many labelled rows nothing happens (mirrors calibrate's gate).
POLICY_SCHEMA_VERSION = 1


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


@dataclass(frozen=True)
class CohortDirective:
    """One learned statement about one evidence shape.

    Carries its own evidence (``n_labeled``, ``tp``, ``fp``, the two precision
    estimates) so the directive is self-justifying: an analyst reading a
    downgraded finding sees the counts that caused it without opening the
    ledger.
    """

    cohort: str
    action: str = ACTION_NONE
    target_confidence: float = 0.0
    n_labeled: int = 0
    tp: int = 0
    fp: int = 0
    human_tp: int = 0
    precision_mean: float = 0.5
    precision_lower: float = 0.0
    rationale: str = ""

    @property
    def can_raise_confidence(self) -> bool:
        """Whether this directive could move confidence *up* for some decision.

        The single definition of the rule that I5 and the governance gate both
        read. It keys on ``target_confidence`` — what ``apply()`` actually uses
        — rather than on the cohort statistic, so a hand-written policy file is
        judged by its effect and not by the numbers it claims.

        A target above the mid-point can exceed the confidence of a low-tier
        decision even if every historical row it touched moved down, so such a
        directive needs human sign-off however conservative the shadow replay
        looked. A directive that can only lower confidence needs none — that
        asymmetry is what lets the Cortex evolve unattended in the safe
        direction.
        """
        return (
            self.action == ACTION_ADJUST
            and self.target_confidence > ROUTE_PRECISION_CEILING
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PolicyAdjustment:
    """Audit record of one applied nudge. Lands in the attestation."""

    cohort: str
    action: str
    tier_before: str
    tier_after: str
    confidence_before: float
    confidence_after: float
    rationale: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PolicyEffect:
    """Result of applying a policy to one consensus decision."""

    tier: str
    confidence: float
    rationale: str
    adjustments: tuple[PolicyAdjustment, ...] = ()

    @property
    def changed(self) -> bool:
        return bool(self.adjustments)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier,
            "confidence": self.confidence,
            "rationale": self.rationale,
            "adjustments": [a.to_dict() for a in self.adjustments],
        }


@dataclass(frozen=True)
class CortexPolicy:
    """An immutable, content-addressed set of cohort directives."""

    version: int = 0
    ledger_head: str = "0" * 64
    created_at: str = field(default_factory=_utc_now)
    derived_from: str = ""
    min_support: int = 5
    directives: dict[str, CohortDirective] = field(default_factory=dict)
    notes: str = ""
    schema_version: int = POLICY_SCHEMA_VERSION

    # ── identity ─────────────────────────────────────────────────────
    def body(self) -> dict[str, Any]:
        """The hashed part: everything that changes behaviour.

        ``created_at`` is excluded so two policies derived from the same
        ledger with the same directives are the same policy — re-deriving
        must be idempotent, or every nightly run would mint a new id and the
        history would become unreadable.
        """
        return {
            "schema_version": self.schema_version,
            "version": self.version,
            "ledger_head": self.ledger_head,
            "min_support": self.min_support,
            "directives": {
                k: v.to_dict() for k, v in sorted(self.directives.items())
            },
        }

    @property
    def policy_id(self) -> str:
        blob = json.dumps(self.body(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]

    @property
    def is_identity(self) -> bool:
        """True when this policy changes nothing (the bootstrap state)."""
        return not any(d.action != ACTION_NONE for d in self.directives.values())

    # ── validation (the constitution, checked before activation) ─────
    def validate(self) -> list[str]:
        """Return a list of invariant violations. Empty means activatable."""
        problems: list[str] = []
        for key, d in self.directives.items():
            if d.cohort != key:
                problems.append(f"{key}: directive cohort mismatch ({d.cohort})")
            if d.action not in VALID_ACTIONS:
                problems.append(f"{key}: unknown action {d.action!r} (I4)")
                continue
            if d.action == ACTION_NONE:
                continue
            if d.n_labeled < self.min_support:
                problems.append(
                    f"{key}: {d.n_labeled} labelled rows < min_support {self.min_support}"
                )
            if d.action == ACTION_ADJUST:
                if not (CONFIDENCE_FLOOR <= d.target_confidence <= CONFIDENCE_CAP):
                    problems.append(
                        f"{key}: target_confidence {d.target_confidence} outside "
                        f"[{CONFIDENCE_FLOOR}, {CONFIDENCE_CAP}] (I2)"
                    )
                # I5 — an upward-capable directive needs a human confirmation
                # in its cohort. See `CohortDirective.can_raise_confidence`.
                if d.can_raise_confidence and d.human_tp < 1:
                    problems.append(
                        f"{key}: raises confidence with no analyst-confirmed "
                        f"true positive in cohort (I5)"
                    )
            if d.action == ACTION_ROUTE and d.precision_lower > ROUTE_PRECISION_CEILING:
                problems.append(
                    f"{key}: route-to-review with precision_lower "
                    f"{d.precision_lower} > {ROUTE_PRECISION_CEILING}"
                )
        return problems

    # ── application (the constitution, checked again at runtime) ─────
    def apply(
        self,
        *,
        tier: str,
        confidence: float,
        rationale: str,
        cohort: str,
    ) -> PolicyEffect:
        """Nudge one consensus decision. Pure; never raises.

        Runtime re-enforcement of I1/I2/I3 is not redundant paranoia: the
        policy file is on disk, and an attacker who can write it should still
        be unable to make Spotlight promote a finding or hide one.
        """
        directive = self.directives.get(cohort)
        if directive is None or directive.action == ACTION_NONE:
            return PolicyEffect(tier=tier, confidence=confidence, rationale=rationale)

        # I4 — an action verb this module does not implement is a no-op, never a
        # fall-through to the nearest similar behaviour. A policy file someone
        # edited to say `disable-warden` must do nothing at all, and must not be
        # quietly reinterpreted as a confidence adjustment.
        if directive.action not in VALID_ACTIONS:
            print(f"[cortex.policy] ignoring unknown action {directive.action!r} for {cohort}")
            return PolicyEffect(tier=tier, confidence=confidence, rationale=rationale)

        if directive.n_labeled < self.min_support:
            # Under-supported directive on disk — ignore it rather than trust it.
            return PolicyEffect(tier=tier, confidence=confidence, rationale=rationale)

        evidence = {
            "n_labeled": directive.n_labeled,
            "tp": directive.tp,
            "fp": directive.fp,
            "precision_mean": directive.precision_mean,
            "precision_lower": directive.precision_lower,
            "policy_id": self.policy_id,
            "policy_version": self.version,
        }

        if directive.action == ACTION_ROUTE:
            # I1/I3 — routing only ever moves *into* needs-review, and only
            # from a promoted tier. Anything already at needs-review or held
            # is left exactly as the kernel decided it.
            if tier not in ROUTABLE_FROM:
                return PolicyEffect(tier=tier, confidence=confidence, rationale=rationale)
            new_conf = round(
                _clamp(
                    min(confidence, confidence - MAX_CONFIDENCE_DELTA),
                    CONFIDENCE_FLOOR,
                    CONFIDENCE_CAP,
                ),
                6,
            )
            adj = PolicyAdjustment(
                cohort=cohort,
                action=ACTION_ROUTE,
                tier_before=tier,
                tier_after=ROUTE_TIER,
                confidence_before=confidence,
                confidence_after=new_conf,
                rationale=directive.rationale or "cohort precision below review threshold",
                evidence=evidence,
            )
            return PolicyEffect(
                tier=ROUTE_TIER,
                confidence=new_conf,
                rationale=f"{rationale} · cortex: routed to review ({directive.rationale})",
                adjustments=(adj,),
            )

        # ACTION_ADJUST (the only verb left) — move confidence toward the
        # cohort's measured precision, by at most MAX_CONFIDENCE_DELTA, clamped
        # to the band.
        # Tier is never touched here (I1): a confidence nudge is a statement
        # about calibration, not about proof.
        target = _clamp(directive.target_confidence, CONFIDENCE_FLOOR, CONFIDENCE_CAP)
        delta = _clamp(target - confidence, -MAX_CONFIDENCE_DELTA, MAX_CONFIDENCE_DELTA)
        new_conf = round(_clamp(confidence + delta, CONFIDENCE_FLOOR, CONFIDENCE_CAP), 6)
        if abs(new_conf - confidence) < 1e-9:
            return PolicyEffect(tier=tier, confidence=confidence, rationale=rationale)
        adj = PolicyAdjustment(
            cohort=cohort,
            action=ACTION_ADJUST,
            tier_before=tier,
            tier_after=tier,
            confidence_before=confidence,
            confidence_after=new_conf,
            rationale=directive.rationale or "recalibrated from ledger outcomes",
            evidence=evidence,
        )
        direction = "raised" if new_conf > confidence else "lowered"
        return PolicyEffect(
            tier=tier,
            confidence=new_conf,
            rationale=f"{rationale} · cortex: confidence {direction} ({directive.rationale})",
            adjustments=(adj,),
        )

    # ── serialization ────────────────────────────────────────────────
    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "policy_id": self.policy_id,
            "created_at": self.created_at,
            "derived_from": self.derived_from,
            "notes": self.notes,
            "is_identity": self.is_identity,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "CortexPolicy":
        directives = {
            k: CohortDirective(**v) for k, v in (raw.get("directives") or {}).items()
        }
        return cls(
            version=int(raw.get("version", 0)),
            ledger_head=str(raw.get("ledger_head") or "0" * 64),
            created_at=str(raw.get("created_at") or _utc_now()),
            derived_from=str(raw.get("derived_from") or ""),
            min_support=int(raw.get("min_support", 5)),
            directives=directives,
            notes=str(raw.get("notes") or ""),
            schema_version=int(raw.get("schema_version", POLICY_SCHEMA_VERSION)),
        )

    @classmethod
    def bootstrap(cls) -> "CortexPolicy":
        """Version 0 — the identity policy a fresh install runs under.

        A new Spotlight behaves exactly as it does today until it has seen
        enough labelled outcomes to say something defensible.
        """
        return cls(version=0, notes="bootstrap — no learned directives yet")


def derive_policy(
    calibration: Calibration,
    *,
    previous: CortexPolicy | None = None,
) -> CortexPolicy:
    """Turn a Calibration into a candidate policy. Deterministic.

    Two directive types come out of this, and nothing else:

    * ``route-to-review`` when the cohort's *pessimistic* precision is at or
      below 0.5 — the shape has demonstrably been wrong about half the time.
    * ``adjust-confidence`` otherwise, targeting the cohort's posterior mean,
      so a stated 0.88 that empirically runs at 0.74 stops overstating itself.

    Under-supported cohorts produce no directive at all.
    """
    previous = previous or CortexPolicy.bootstrap()
    directives: dict[str, CohortDirective] = {}
    for key, stats in sorted(calibration.actionable().items()):
        directives[key] = _directive_for(stats)
    return CortexPolicy(
        version=previous.version + 1,
        ledger_head=calibration.ledger_head,
        derived_from=previous.policy_id,
        min_support=calibration.min_support,
        directives=directives,
        notes=(
            f"derived from {calibration.labeled_rows} labelled rows across "
            f"{len(calibration.cohorts)} cohorts"
        ),
    )


def _directive_for(stats: CohortStats) -> CohortDirective:
    if stats.precision_lower <= ROUTE_PRECISION_CEILING and stats.fp > stats.tp:
        return CohortDirective(
            cohort=stats.cohort,
            action=ACTION_ROUTE,
            target_confidence=_clamp(stats.precision_mean, CONFIDENCE_FLOOR, CONFIDENCE_CAP),
            n_labeled=stats.n_labeled,
            tp=stats.tp,
            fp=stats.fp,
            human_tp=stats.human_tp,
            precision_mean=stats.precision_mean,
            precision_lower=stats.precision_lower,
            rationale=(
                f"{stats.fp}/{stats.n_labeled} labelled findings in this evidence "
                f"shape were false positives; a human should confirm"
            ),
        )
    # I5 — a cohort with no analyst-confirmed TP may only be argued downward.
    target = _clamp(stats.precision_mean, CONFIDENCE_FLOOR, CONFIDENCE_CAP)
    if target > ROUTE_PRECISION_CEILING and stats.human_tp < 1:
        return CohortDirective(
            cohort=stats.cohort,
            action=ACTION_NONE,
            n_labeled=stats.n_labeled,
            tp=stats.tp,
            fp=stats.fp,
            human_tp=stats.human_tp,
            precision_mean=stats.precision_mean,
            precision_lower=stats.precision_lower,
            rationale=(
                "cohort looks reliable but has no analyst-confirmed true "
                "positive; holding at kernel confidence (I5)"
            ),
        )
    return CohortDirective(
        cohort=stats.cohort,
        action=ACTION_ADJUST,
        target_confidence=target,
        n_labeled=stats.n_labeled,
        tp=stats.tp,
        fp=stats.fp,
        human_tp=stats.human_tp,
        precision_mean=stats.precision_mean,
        precision_lower=stats.precision_lower,
        rationale=(
            f"observed precision {stats.precision_mean:.2f} over "
            f"{stats.n_labeled} labelled findings"
        ),
    )


class PolicyStore:
    """Versioned, immutable on-disk policy history plus an active pointer.

    Files are ``policies/v{version:04d}-{policy_id}.json`` and never rewritten;
    ``policies/active.json`` holds ``{policy_id, version, activated_at,
    approver}``. Rollback is a pointer move, which is the only rollback story
    an auditor will accept: the artifact that produced last quarter's
    attestations is still on disk, byte-identical.
    """

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root) / "policies"
        self.root.mkdir(parents=True, exist_ok=True)
        self.active_path = self.root / "active.json"

    def _path_for(self, policy: CortexPolicy) -> Path:
        return self.root / f"v{policy.version:04d}-{policy.policy_id}.json"

    def save(self, policy: CortexPolicy) -> Path:
        path = self._path_for(policy)
        if not path.exists():
            path.write_text(json.dumps(policy.to_dict(), indent=2, sort_keys=True))
        return path

    def history(self) -> list[CortexPolicy]:
        out: list[CortexPolicy] = []
        for path in sorted(self.root.glob("v*.json")):
            try:
                out.append(CortexPolicy.from_dict(json.loads(path.read_text())))
            except Exception as exc:  # pragma: no cover — corrupt file
                print(f"[cortex.policy] skipping unreadable {path.name}: {exc!r}")
        return out

    def load(self, policy_id: str) -> CortexPolicy | None:
        for policy in self.history():
            if policy.policy_id == policy_id:
                return policy
        return None

    def active_pointer(self) -> dict[str, Any]:
        if not self.active_path.exists():
            return {}
        try:
            return json.loads(self.active_path.read_text())
        except Exception:  # pragma: no cover
            return {}

    def active(self) -> CortexPolicy:
        """The policy sweeps run under. Bootstrap when nothing is activated."""
        pointer = self.active_pointer()
        pid = str(pointer.get("policy_id") or "")
        if pid:
            found = self.load(pid)
            if found is not None:
                return found
        return CortexPolicy.bootstrap()

    def activate(
        self, policy: CortexPolicy, *, approver: str, signature: dict | None = None
    ) -> dict[str, Any]:
        """Point `active.json` at `policy`. Caller owns the gating."""
        self.save(policy)
        pointer = {
            "policy_id": policy.policy_id,
            "version": policy.version,
            "ledger_head": policy.ledger_head,
            "activated_at": _utc_now(),
            "approver": approver,
            "signature": signature,
        }
        self.active_path.write_text(json.dumps(pointer, indent=2, sort_keys=True))
        return pointer
