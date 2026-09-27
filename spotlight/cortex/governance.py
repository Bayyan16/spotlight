"""Governance — the gate every learned change has to pass.

"The agent improves itself" is the easy half. The half that decides whether a
bank can run it is: *what stops an improvement from being a regression, and
who is accountable when it is?* This module is that half.

A candidate policy is never activated because it looks reasonable. It is
activated only after it is replayed against the labelled history it came from,
and only if the replay shows it would not have buried a single finding a human
or a sandbox had confirmed was real.

The shadow replay
-----------------
Every labelled experience carries the tier and confidence it was actually
decided at. Re-applying the candidate policy to those recorded decisions gives
a counterfactual: *had this policy been active, what would have happened to the
findings we already know the truth about?* Four outcomes matter:

* ``tp_demoted`` — a confirmed-real finding routed to review. **Hard zero.**
  This is the regression that matters: a self-tuning scanner that trades recall
  for a quieter inbox is worse than no scanner, because the silence is
  indistinguishable from safety.
* ``fp_demoted`` — a known false positive routed to review. The benefit.
* ``tp_boosted`` / ``fp_boosted`` — confidence raised on a real / unreal
  finding. The second is a **hard zero** as well: a policy may never become
  more sure about something it was wrong about.
* ``tp_confidence_loss`` — total confidence shaved off confirmed findings,
  capped, so "no demotions" can't be satisfied by death of a thousand cuts.

Bounded autonomy
----------------
This is where "evolves independently" gets its precise meaning. The Cortex may
activate a policy **on its own** when the change is strictly conservative — it
lowers confidence or routes to review, never raises anything, passes every
gate, and violates no invariant. Anything that would make Spotlight *more*
assertive requires a named human approver, and the approval is signed.

That asymmetry is the whole design: unattended evolution is allowed in the
direction where a mistake costs an analyst's time, and forbidden in the
direction where a mistake costs a missed vulnerability or an overstated claim.

Everything here is recorded. Proposals, rejections with their reasons, and
activations with their approver land in a signed, append-only governance log
next to the ledger, so "why did the tier change between these two
attestations?" has an answer that does not depend on anyone's memory.
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .calibrate import DEFAULT_MIN_SUPPORT, Calibration, calibrate
from .experience import FALSE_POSITIVE, TRUE_POSITIVE, Experience
from .policy import (
    ROUTE_TIER,
    CortexPolicy,
    PolicyStore,
    derive_policy,
)

# The actor id the Cortex uses when it approves its own conservative change.
SELF_APPROVER = "cortex-autonomous"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass(frozen=True)
class GovernanceGates:
    """Thresholds a candidate policy must clear. Conservative by default."""

    max_true_positive_demotions: int = 0
    max_false_positive_boosts: int = 0
    max_true_positive_confidence_loss: float = 0.10
    min_beneficial_effects: int = 1

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ShadowReport:
    """Counterfactual outcome of a candidate policy over labelled history."""

    rows_replayed: int = 0
    labeled_rows: int = 0
    tp_demoted: int = 0
    fp_demoted: int = 0
    tp_boosted: int = 0
    fp_boosted: int = 0
    tp_confidence_loss: float = 0.0
    fp_confidence_loss: float = 0.0
    unchanged: int = 0
    demoted_true_positive_keys: list[str] = field(default_factory=list)

    @property
    def beneficial_effects(self) -> int:
        """Changes that make the system more honest: FPs demoted or de-rated."""
        return self.fp_demoted + (1 if self.fp_confidence_loss > 0 else 0)

    @property
    def raises_anything(self) -> bool:
        return (self.tp_boosted + self.fp_boosted) > 0

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["beneficial_effects"] = self.beneficial_effects
        d["raises_anything"] = self.raises_anything
        d["tp_confidence_loss"] = round(self.tp_confidence_loss, 6)
        d["fp_confidence_loss"] = round(self.fp_confidence_loss, 6)
        return d


@dataclass
class PolicyProposal:
    """A candidate policy plus everything needed to decide on it."""

    policy: CortexPolicy
    calibration: Calibration
    shadow: ShadowReport
    gates: GovernanceGates
    invariant_violations: list[str] = field(default_factory=list)
    gate_failures: list[str] = field(default_factory=list)
    previous_policy_id: str = ""

    @property
    def admissible(self) -> bool:
        """Safe to activate at all (by a human or otherwise)."""
        return not self.invariant_violations and not self.gate_failures

    @property
    def requires_human(self) -> bool:
        """True when a named person must sign off.

        Any policy that raises confidence anywhere, and any policy that is not
        a pure no-op-or-downgrade, needs a human. See module docstring.
        """
        if not self.admissible:
            return True
        if self.shadow.raises_anything:
            return True
        # A directive that *could* raise confidence on a future decision needs a
        # person, even when it lowered every historical row in the replay.
        return any(d.can_raise_confidence for d in self.policy.directives.values())

    @property
    def auto_activatable(self) -> bool:
        return self.admissible and not self.requires_human and not self.policy.is_identity

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy": self.policy.to_dict(),
            "previous_policy_id": self.previous_policy_id,
            "calibration": self.calibration.to_dict(),
            "shadow": self.shadow.to_dict(),
            "gates": self.gates.to_dict(),
            "invariant_violations": list(self.invariant_violations),
            "gate_failures": list(self.gate_failures),
            "admissible": self.admissible,
            "requires_human": self.requires_human,
            "auto_activatable": self.auto_activatable,
        }


def shadow_replay(policy: CortexPolicy, experiences: Iterable[Experience]) -> ShadowReport:
    """Replay a candidate policy over decisions whose truth we know.

    Only labelled rows can score a gate — an unlabeled row has no truth to
    regress against — but every row is counted in ``rows_replayed`` so the
    report shows how much of the history actually constrained the decision.
    """
    report = ShadowReport()
    for exp in experiences:
        report.rows_replayed += 1
        effect = policy.apply(
            tier=exp.tier,
            confidence=float(exp.confidence or 0.0),
            rationale="",
            cohort=exp.cohort,
        )
        if not effect.changed:
            report.unchanged += 1
            continue
        if not exp.labeled:
            # A change to an unlabeled row is neither credit nor debit.
            continue
        report.labeled_rows += 1
        demoted = effect.tier == ROUTE_TIER and exp.tier != ROUTE_TIER
        delta = effect.confidence - float(exp.confidence or 0.0)
        if exp.label == TRUE_POSITIVE:
            if demoted:
                report.tp_demoted += 1
                report.demoted_true_positive_keys.append(exp.finding_key)
            if delta < 0:
                report.tp_confidence_loss += -delta
            elif delta > 0:
                report.tp_boosted += 1
        elif exp.label == FALSE_POSITIVE:
            if demoted:
                report.fp_demoted += 1
            if delta < 0:
                report.fp_confidence_loss += -delta
            elif delta > 0:
                report.fp_boosted += 1
    return report


def check_gates(shadow: ShadowReport, gates: GovernanceGates) -> list[str]:
    """Return gate failures, most serious first."""
    failures: list[str] = []
    if shadow.tp_demoted > gates.max_true_positive_demotions:
        failures.append(
            f"would demote {shadow.tp_demoted} confirmed true positive(s) "
            f"(limit {gates.max_true_positive_demotions}): "
            f"{', '.join(shadow.demoted_true_positive_keys[:5])}"
        )
    if shadow.fp_boosted > gates.max_false_positive_boosts:
        failures.append(
            f"would raise confidence on {shadow.fp_boosted} known false "
            f"positive(s) (limit {gates.max_false_positive_boosts})"
        )
    if shadow.tp_confidence_loss > gates.max_true_positive_confidence_loss:
        failures.append(
            f"cumulative confidence loss on true positives "
            f"{shadow.tp_confidence_loss:.3f} exceeds "
            f"{gates.max_true_positive_confidence_loss}"
        )
    if shadow.beneficial_effects < gates.min_beneficial_effects:
        failures.append(
            "no measurable benefit — policy changes nothing a labelled "
            "false positive would have felt"
        )
    return failures


class GovernanceLog:
    """Append-only, signed record of proposals, rejections and activations.

    Separate from the experience ledger on purpose: one answers "what did we
    observe", the other "what did we decide, and who decided it". Mixing them
    would make a decision look like an observation.
    """

    FILENAME = "governance.jsonl"

    def __init__(self, root: str | Path, signer: Any = None) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / self.FILENAME
        self._signer = signer

    def append(self, action: str, payload: dict[str, Any], *, actor: str) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "ts": _utc_now(),
            "action": action,
            "actor": actor,
            "payload": payload,
        }
        if self._signer is not None:
            try:
                entry["signature"] = self._signer.sign(
                    actor_kind="human" if actor not in (SELF_APPROVER, "cortex") else "agent",
                    actor_id=actor,
                    action=f"cortex.{action}",
                    payload=payload,
                )
            except Exception as exc:  # pragma: no cover
                print(f"[cortex.governance] signing failed: {exc!r}")
        line = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return entry

    def entries(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        out: list[dict[str, Any]] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out


@dataclass
class ActivationResult:
    activated: bool
    reason: str
    policy_id: str = ""
    version: int = 0
    approver: str = ""
    pointer: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class Governor:
    """Proposes, evaluates and (conditionally) activates learned policy."""

    def __init__(
        self,
        store: PolicyStore,
        log: GovernanceLog,
        *,
        gates: GovernanceGates | None = None,
        min_support: int = DEFAULT_MIN_SUPPORT,
    ) -> None:
        self.store = store
        self.log = log
        self.gates = gates or GovernanceGates()
        self.min_support = min_support

    # ── propose ──────────────────────────────────────────────────────
    def propose(
        self,
        experiences: list[Experience],
        *,
        ledger_head: str,
        previous: CortexPolicy | None = None,
        record: bool = True,
    ) -> PolicyProposal:
        """Derive and gate a candidate policy. Activates nothing.

        ``record=False`` skips the governance-log entry, for callers that only
        need to *look* at the candidate (an approver checking what they are
        about to sign). Derivation is deterministic, so a look costs nothing and
        should not leave a second `policy.proposed` row next to the real one.
        """
        previous = previous or self.store.active()
        cal = calibrate(experiences, ledger_head=ledger_head, min_support=self.min_support)
        candidate = derive_policy(cal, previous=previous)
        shadow = shadow_replay(candidate, experiences)
        violations = candidate.validate()
        failures = check_gates(shadow, self.gates)
        proposal = PolicyProposal(
            policy=candidate,
            calibration=cal,
            shadow=shadow,
            gates=self.gates,
            invariant_violations=violations,
            gate_failures=failures,
            previous_policy_id=previous.policy_id,
        )
        if not record:
            return proposal
        self.log.append(
            "policy.proposed",
            {
                "policy_id": candidate.policy_id,
                "version": candidate.version,
                "ledger_head": ledger_head,
                "directives": len(candidate.directives),
                "shadow": shadow.to_dict(),
                "invariant_violations": violations,
                "gate_failures": failures,
                "auto_activatable": proposal.auto_activatable,
            },
            actor="cortex",
        )
        return proposal

    # ── activate ─────────────────────────────────────────────────────
    def activate(
        self, proposal: PolicyProposal, *, approver: str | None = None
    ) -> ActivationResult:
        """Activate a proposal, refusing anything the gates didn't clear.

        ``approver`` must be a named human for a proposal that
        ``requires_human``; the Cortex may only self-approve strictly
        conservative changes, and it does so under its own actor id so the
        audit trail never shows an agent's decision as a person's.
        """
        policy = proposal.policy
        if proposal.invariant_violations:
            return self._refuse(
                proposal, f"invariant violations: {'; '.join(proposal.invariant_violations)}"
            )
        if proposal.gate_failures:
            return self._refuse(
                proposal, f"gate failures: {'; '.join(proposal.gate_failures)}"
            )
        if policy.is_identity:
            return self._refuse(proposal, "identity policy — nothing to activate")

        if proposal.requires_human:
            named = (approver or "").strip()
            if not named or named in (SELF_APPROVER, "cortex"):
                return self._refuse(
                    proposal,
                    "policy raises confidence or is non-conservative; a named "
                    "human approver is required",
                )
            actor = named
        else:
            actor = (approver or "").strip() or SELF_APPROVER

        signature = None
        if self.log._signer is not None:
            try:
                signature = self.log._signer.sign(
                    actor_kind="agent" if actor == SELF_APPROVER else "human",
                    actor_id=actor,
                    action="cortex.policy.activated",
                    payload={
                        "policy_id": policy.policy_id,
                        "version": policy.version,
                        "ledger_head": policy.ledger_head,
                    },
                )
            except Exception as exc:  # pragma: no cover
                print(f"[cortex.governance] activation signing failed: {exc!r}")

        pointer = self.store.activate(policy, approver=actor, signature=signature)
        self.log.append(
            "policy.activated",
            {
                "policy_id": policy.policy_id,
                "version": policy.version,
                "ledger_head": policy.ledger_head,
                "autonomous": actor == SELF_APPROVER,
                "shadow": proposal.shadow.to_dict(),
            },
            actor=actor,
        )
        return ActivationResult(
            activated=True,
            reason="activated",
            policy_id=policy.policy_id,
            version=policy.version,
            approver=actor,
            pointer=pointer,
        )

    def _refuse(self, proposal: PolicyProposal, reason: str) -> ActivationResult:
        self.log.append(
            "policy.rejected",
            {
                "policy_id": proposal.policy.policy_id,
                "version": proposal.policy.version,
                "reason": reason,
            },
            actor="cortex",
        )
        return ActivationResult(
            activated=False,
            reason=reason,
            policy_id=proposal.policy.policy_id,
            version=proposal.policy.version,
        )

    # ── retraction ───────────────────────────────────────────────────
    def audit_active(self, experiences: list[Experience]) -> ShadowReport:
        """Replay the *currently active* policy against today's labels.

        The activation gate asks "would this policy have hurt us?" once, at
        activation. Evidence keeps arriving afterwards: a cohort that was 6/6
        false positives in March can contain a sandbox-confirmed exploit by
        June, and the policy routing that cohort is now demoting something real.
        This is the check that notices.
        """
        return shadow_replay(self.store.active(), experiences)

    def retract_if_harmful(
        self, experiences: list[Experience]
    ) -> tuple[ActivationResult | None, ShadowReport | None]:
        """Drop back to evidence-only tiering if the active policy now harms.

        Retraction is the one change that is *always* safe to make unattended:
        returning to the identity policy can only restore what the evidence
        alone decided, never hide anything. So it needs no gate and no human —
        the asymmetry runs the other way from activation, and deliberately so.

        Returns ``(result, shadow)``; ``(None, shadow)`` when nothing was wrong.
        """
        active = self.store.active()
        if active.is_identity:
            return None, None
        shadow = shadow_replay(active, experiences)
        harmful = shadow.tp_demoted > 0 or shadow.fp_boosted > 0
        if not harmful:
            return None, shadow

        identity = CortexPolicy.bootstrap()
        self.store.save(identity)
        pointer = self.store.activate(identity, approver=SELF_APPROVER, signature=None)
        self.log.append(
            "policy.retracted",
            {
                "retracted_policy_id": active.policy_id,
                "retracted_version": active.version,
                "restored_policy_id": identity.policy_id,
                "reason": (
                    f"active policy now demotes {shadow.tp_demoted} confirmed true "
                    f"positive(s) and boosts {shadow.fp_boosted} known false "
                    f"positive(s) against the current ledger"
                ),
                "demoted_true_positive_keys": shadow.demoted_true_positive_keys[:20],
                "shadow": shadow.to_dict(),
            },
            actor=SELF_APPROVER,
        )
        return (
            ActivationResult(
                activated=True,
                reason=(
                    f"retracted v{active.version}: it now demotes "
                    f"{shadow.tp_demoted} confirmed true positive(s)"
                ),
                policy_id=identity.policy_id,
                version=identity.version,
                approver=SELF_APPROVER,
                pointer=pointer,
            ),
            shadow,
        )

    # ── rollback ─────────────────────────────────────────────────────
    def rollback(self, policy_id: str, *, approver: str) -> ActivationResult:
        """Re-point at an earlier policy. Always allowed, always human-named.

        Rollback is never gated: the ability to undo has to be strictly easier
        than the ability to change, or nobody will let the thing evolve at all.
        """
        target = self.store.load(policy_id)
        if target is None:
            return ActivationResult(activated=False, reason=f"unknown policy_id {policy_id}")
        named = (approver or "").strip()
        if not named:
            return ActivationResult(activated=False, reason="rollback requires a named approver")
        pointer = self.store.activate(target, approver=named, signature=None)
        self.log.append(
            "policy.rolled-back",
            {"policy_id": target.policy_id, "version": target.version},
            actor=named,
        )
        return ActivationResult(
            activated=True,
            reason="rolled back",
            policy_id=target.policy_id,
            version=target.version,
            approver=named,
            pointer=pointer,
        )
