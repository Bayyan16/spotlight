"""Spotlight Cortex — the layer that makes the security engineer improve itself.

Spotlight reasons well and remembers nothing. Every sweep re-derives every
judgment from zero: the Planner's repo-tuned rules are discarded at teardown,
the Verifier's gold labels die with the tempdir, and the analyst who signs
"false positive — this template string is a constant" is corrected exactly
once, for exactly one sweep. The Cortex closes that loop. It is the difference
between a tool that is as good on its thousandth run as its first, and one that
is measurably better on its hundredth because it has been *corrected* ninety-
nine times.

Four pieces, in the order a run touches them:

* **`ledger`** — an append-only, hash-chained, Ed25519-signed record of every
  judgment and its outcome. The ledger is the only thing the Cortex learns
  from, so it is built to be tamper-evident offline against the public key
  already published at ``/verify-key``.
* **`calibrate`** — Beta/Wilson arithmetic over labelled rows, per
  ``(class, evidence-shape)`` cohort. Arithmetic, not a model: a learned change
  must be reproducible from the ledger head and explainable to an auditor.
* **`policy`** — a small immutable table of directives that may nudge the
  Consensus Kernel's output, under six invariants no amount of learning can
  amend. The strongest thing it can do is route a finding to a human; it can
  never promote one, and it can never suppress one.
* **`governance`** — the gate. A candidate policy is replayed against the
  labelled history it came from, and activated only if it would not have
  buried a single confirmed-real finding. Strictly conservative changes may be
  activated by the Cortex itself; anything that makes Spotlight more assertive
  needs a named human approver, signed.

Plus **`lessons`** — templated, injection-scanned corrections fed back into the
Investigator's prompt as advisory observations, which is how the agent gets
better at *this* codebase without any model retraining.

Responsibility, concretely
--------------------------
"Responsible" here is not a posture, it is a set of things the code cannot do:

* It cannot get quieter about a real vulnerability — zero true-positive
  demotions is a hard gate, and the only class of label it accepts as negative
  is a human's verdict (a failed reproduction proves nothing about the code,
  only about our Reproducer).
* It cannot manufacture confidence — promotion to ``verified`` stays welded to
  reproduction plus independent corroboration, and any upward move at all
  requires a human's confirmation somewhere in the cohort.
* It cannot hide what it did — every sweep pins the policy id it ran under,
  every activation is signed with an actor, and an agent's self-approval is
  recorded under the Cortex's own actor id, never a person's.
* It cannot be talked into a lesson — memory that re-enters a prompt is
  templated from structured fields, redacted, and injection-scanned, because
  the ledger is otherwise a persistent prompt-injection channel into every
  future sweep.
* It cannot be irreversible — policies are immutable and content-addressed;
  rollback is a pointer move that needs no gate at all.

Opt-in by construction. ``Cortex.from_env()`` returns ``None`` unless
``SPOTLIGHT_CORTEX_DIR`` is set, and an Orchestrator without a Cortex behaves
exactly as it did before this package existed.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .calibrate import DEFAULT_MIN_SUPPORT, Calibration, CohortStats, calibrate
from .experience import (
    FALSE_POSITIVE,
    TRUE_POSITIVE,
    UNKNOWN,
    Experience,
    cohort_key,
    evidence_signature,
    label_for,
)
from .governance import (
    SELF_APPROVER,
    ActivationResult,
    GovernanceGates,
    GovernanceLog,
    Governor,
    PolicyProposal,
    ShadowReport,
    shadow_replay,
)
from .harvest import (
    experience_from_finding,
    experience_from_review,
    experiences_from_sweep,
    modalities_from_finding,
)
from .ledger import ExperienceLedger, LedgerVerification
from .lessons import Lesson, LessonBook
from .policy import (
    CohortDirective,
    CortexPolicy,
    PolicyAdjustment,
    PolicyEffect,
    PolicyStore,
    derive_policy,
)

ENV_DIR = "SPOTLIGHT_CORTEX_DIR"
ENV_AUTONOMY = "SPOTLIGHT_CORTEX_AUTONOMY"

__all__ = [
    "Cortex",
    "EvolutionReport",
    "Experience",
    "ExperienceLedger",
    "LedgerVerification",
    "Calibration",
    "CohortStats",
    "CohortDirective",
    "CortexPolicy",
    "PolicyAdjustment",
    "PolicyEffect",
    "PolicyStore",
    "PolicyProposal",
    "GovernanceGates",
    "GovernanceLog",
    "Governor",
    "ShadowReport",
    "Lesson",
    "LessonBook",
    "TRUE_POSITIVE",
    "FALSE_POSITIVE",
    "UNKNOWN",
    "SELF_APPROVER",
    "calibrate",
    "cohort_key",
    "derive_policy",
    "evidence_signature",
    "experience_from_finding",
    "experience_from_review",
    "experiences_from_sweep",
    "label_for",
    "modalities_from_finding",
    "shadow_replay",
]


@dataclass
class EvolutionReport:
    """One evolution cycle: what was proposed, and what happened to it."""

    proposal: PolicyProposal
    activation: ActivationResult
    lessons_refreshed: int = 0
    lessons_quarantined: int = 0
    ledger_head: str = ""
    # Set when the cycle dropped an already-active policy that had become
    # harmful as new evidence arrived. Always unattended — see
    # `Governor.retract_if_harmful`.
    retraction: ActivationResult | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "proposal": self.proposal.to_dict(),
            "activation": self.activation.to_dict(),
            "retraction": self.retraction.to_dict() if self.retraction else None,
            "lessons_refreshed": self.lessons_refreshed,
            "lessons_quarantined": self.lessons_quarantined,
            "ledger_head": self.ledger_head,
        }


@dataclass
class Cortex:
    """Façade over the ledger, policy store, lesson book and governor.

    One object per workspace root. Cheap to construct — everything is read
    lazily off disk — so a sweep can hold one for the duration of its run and
    an API request can build one per call without ceremony.
    """

    root: Path
    signer: Any = None
    min_support: int = DEFAULT_MIN_SUPPORT
    gates: GovernanceGates = field(default_factory=GovernanceGates)
    autonomy: bool = True

    ledger: ExperienceLedger = field(init=False)
    policies: PolicyStore = field(init=False)
    lessons: LessonBook = field(init=False)
    governance: GovernanceLog = field(init=False)

    def __post_init__(self) -> None:
        self.root = Path(self.root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.ledger = ExperienceLedger(self.root, signer=self.signer)
        self.policies = PolicyStore(self.root)
        self.lessons = LessonBook(self.root)
        self.governance = GovernanceLog(self.root, signer=self.signer)

    # ── construction ─────────────────────────────────────────────────
    @classmethod
    def from_env(cls, *, signer: Any = None) -> "Cortex | None":
        """Build from ``SPOTLIGHT_CORTEX_DIR``, or return None when unset.

        Opt-in is the right default for a component that changes how findings
        are tiered: an operator turns memory on deliberately, and a workspace
        that never sets the variable keeps today's behaviour byte for byte.
        """
        root = os.environ.get(ENV_DIR, "").strip()
        if not root:
            return None
        autonomy = os.environ.get(ENV_AUTONOMY, "on").strip().lower() not in (
            "0", "off", "false", "no",
        )
        return cls(root=Path(root), signer=signer, autonomy=autonomy)

    # ── read side (what a sweep needs) ───────────────────────────────
    def active_policy(self) -> CortexPolicy:
        return self.policies.active()

    def served_lessons(self) -> list[Lesson]:
        return [l for l in self.lessons.load() if not l.quarantined]

    def lessons_for(self, *, class_: str, path: str) -> list[Lesson]:
        return self.lessons.for_slice(class_=class_, path=path)

    def pin(self) -> dict[str, Any]:
        """The block a sweep stamps into its attestation.

        Pinning the policy id *and* the ledger head is what makes a tier
        decision re-derivable months later: both inputs to the nudge are named,
        immutable, and independently verifiable.
        """
        policy = self.active_policy()
        pointer = self.policies.active_pointer()
        return {
            "policy_id": policy.policy_id,
            "policy_version": policy.version,
            "policy_is_identity": policy.is_identity,
            "directives": len(policy.directives),
            "ledger_head": self.ledger.head(),
            "ledger_records": self.ledger.count(),
            "activated_by": pointer.get("approver", ""),
            "activated_at": pointer.get("activated_at", ""),
            "autonomy": self.autonomy,
            "lessons_served": len(self.served_lessons()),
        }

    # ── write side (what a finished sweep / review produces) ─────────
    def record_sweep(self, sweep_result: Any, *, commit_sha: str = "") -> int:
        """Append one Experience per finding. Returns rows written."""
        rows = experiences_from_sweep(sweep_result, commit_sha=commit_sha)
        before = self.ledger.count()
        self.ledger.extend(rows)
        return self.ledger.count() - before

    def record_review(
        self, finding: dict[str, Any], *, review_state: str, reason: str = "", sweep_id: str = ""
    ) -> Experience:
        """Append the human verdict and refresh lessons from it immediately.

        Refreshing here rather than on the next evolution cycle is deliberate:
        a correction an analyst files today should shape the next sweep, not the
        next policy activation, because lessons are advisory and carry no tier
        authority of their own.
        """
        exp = experience_from_review(
            finding, review_state=review_state, reason=reason, sweep_id=sweep_id
        )
        self.ledger.append(exp)
        try:
            self.lessons.refresh(self.ledger.latest_by_finding().values())
        except Exception as exc:  # pragma: no cover — memory is best-effort
            print(f"[cortex] lesson refresh failed: {exc!r}")
        return exp

    # ── evolution ────────────────────────────────────────────────────
    def _governor(self) -> Governor:
        return Governor(
            self.policies, self.governance, gates=self.gates, min_support=self.min_support
        )

    def propose(self, *, record: bool = True) -> PolicyProposal:
        """Derive and gate a candidate policy without activating anything.

        Lets a caller show an approver exactly what they are about to sign
        before any side effect happens — the alternative (activate, then
        discover the ledger moved) is an activation nobody asked for.
        """
        rows = list(self.ledger.latest_by_finding().values())
        return self._governor().propose(
            rows, ledger_head=self.ledger.head(), record=record
        )

    def evolve(self, *, approver: str | None = None) -> EvolutionReport:
        """One full cycle: calibrate → propose → gate → maybe activate.

        With no ``approver``, only a strictly conservative proposal activates
        (and only when ``autonomy`` is on). A proposal that would make
        Spotlight more assertive is returned un-activated, with the reason, for
        a human to approve explicitly.
        """
        rows = list(self.ledger.latest_by_finding().values())
        head = self.ledger.head()
        governor = self._governor()

        # Before deriving anything new: is the policy we are *already* running
        # still safe against today's labels? A cohort that was all false
        # positives in March can hold a sandbox-confirmed exploit by June, and
        # the directive routing it is now demoting something real. Retraction
        # back to evidence-only tiering needs no gate and no human — it can only
        # restore what the evidence decided.
        retraction, _ = governor.retract_if_harmful(rows)

        proposal = governor.propose(rows, ledger_head=head)

        if approver:
            activation = governor.activate(proposal, approver=approver)
        elif proposal.auto_activatable and self.autonomy:
            activation = governor.activate(proposal)
        else:
            reason = (
                "autonomy disabled"
                if not self.autonomy and proposal.auto_activatable
                else "; ".join(
                    proposal.invariant_violations
                    or proposal.gate_failures
                    or ["awaiting a named human approver"]
                )
            )
            self.governance.append(
                "policy.withheld",
                {"policy_id": proposal.policy.policy_id, "reason": reason},
                actor="cortex",
            )
            activation = ActivationResult(
                activated=False,
                reason=reason,
                policy_id=proposal.policy.policy_id,
                version=proposal.policy.version,
            )

        all_lessons = self.lessons.derive(rows)
        served = self.lessons.refresh(rows)
        return EvolutionReport(
            proposal=proposal,
            activation=activation,
            retraction=retraction,
            lessons_refreshed=len(served),
            lessons_quarantined=sum(1 for l in all_lessons if l.quarantined),
            ledger_head=head,
        )

    def rollback(self, policy_id: str, *, approver: str) -> ActivationResult:
        return self._governor().rollback(policy_id, approver=approver)

    # ── observability ────────────────────────────────────────────────
    def audit_active_policy(self) -> ShadowReport:
        """Replay the active policy against today's labels, changing nothing."""
        rows = list(self.ledger.latest_by_finding().values())
        return self._governor().audit_active(rows)

    def verify(self) -> LedgerVerification:
        public_key = getattr(self.signer, "public_key", None)
        return self.ledger.verify(public_key)

    def status(self) -> dict[str, Any]:
        rows = list(self.ledger.latest_by_finding().values())
        cal = calibrate(rows, ledger_head=self.ledger.head(), min_support=self.min_support)
        labeled = sum(1 for r in rows if r.labeled)
        # Standing audit of the policy currently in force. Non-zero
        # `tp_demoted` here means the next evolution cycle will retract it;
        # surfacing the number means an operator does not have to wait for that
        # to find out.
        active_audit = shadow_replay(self.active_policy(), rows).to_dict()
        return {
            "active_policy_audit": active_audit,
            "root": str(self.root),
            "autonomy": self.autonomy,
            "policy": self.active_policy().to_dict(),
            "pin": self.pin(),
            "ledger": {
                "records": self.ledger.count(),
                "distinct_findings": len(rows),
                "labeled": labeled,
                "unlabeled": len(rows) - labeled,
                "head": self.ledger.head(),
            },
            "cohorts": {
                "total": len(cal.cohorts),
                "actionable": len(cal.actionable()),
            },
            "lessons": {
                "served": len(self.served_lessons()),
                "quarantined": sum(1 for l in self.lessons.load() if l.quarantined),
            },
            "governance_entries": len(self.governance.entries()),
        }
