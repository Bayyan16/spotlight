"""Append-only event stream. PRD §13.4.

Everything the Console shows live is derived from this. The orchestrator is
the only writer; subscribers can be the WS hub, the persistence layer, or a
test collector.
"""
from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
from enum import Enum
from time import time
from typing import Any, Callable

from spotlight.redaction import Redactor

# Module-level redactor — cheap to reuse. Detectors are compiled once.
_REDACTOR = Redactor()


class EventType(str, Enum):
    SWEEP_STARTED = "sweep.started"
    SWEEP_PHASE_CHANGED = "sweep.phase.changed"
    SWEEP_PHASE_ILLEGAL = "sweep.phase.illegal"
    SWEEP_BUDGET_EXCEEDED = "sweep.budget.exceeded"
    SWEEP_PAUSED_FOR_REVIEW = "sweep.paused.for-review"
    SWEEP_RESUMED = "sweep.resumed"
    SWEEP_FINISHED = "sweep.finished"
    SWEEP_FAILED = "sweep.failed"
    AGENT_SPAWNED = "agent.spawned"
    AGENT_STATUS = "agent.status"
    AGENT_TOOL_CALL = "agent.tool.call"
    AGENT_FINISHED = "agent.finished"
    RECON_THREAT_MODEL = "recon.threat_model"
    PLAN_RULES_WRITTEN = "plan.rules.written"
    WARDEN_INJECTION_FLAGGED = "warden.injection.flagged"
    WARDEN_BUDGET_TRIPPED = "warden.budget.tripped"
    WARDEN_CAPABILITY_DENIED = "warden.capability.denied"
    CANDIDATE_RAISED = "candidate.raised"
    CANDIDATE_CORROBORATED = "candidate.corroborated"
    FINDING_PROMOTED = "finding.promoted"
    FINDING_HELD = "finding.held"
    PATH_COMPOSED = "path.composed"
    REPRO_STARTED = "repro.started"
    REPRO_RESULT = "repro.result"
    SANDBOX_SPAWNED = "sandbox.spawned"
    SANDBOX_RESULT = "sandbox.result"
    SANDBOX_EGRESS_DENIED = "sandbox.egress.denied"
    REMEDIATION_OPENED = "remediation.opened"
    VERIFY_RESULT = "verify.result"
    ATTESTATION_WRITTEN = "attestation.written"
    # Cortex — the learned-policy / experience-memory layer. Pinned once per
    # sweep, applied per finding, harvested at the end. `lesson.quarantined`
    # is a self-defense event in the Warden sense: something tried to write an
    # instruction into Spotlight's own memory.
    CORTEX_POLICY_PINNED = "cortex.policy.pinned"
    CORTEX_ADJUSTMENT_APPLIED = "cortex.adjustment.applied"
    CORTEX_EXPERIENCE_RECORDED = "cortex.experience.recorded"
    CORTEX_POLICY_ACTIVATED = "cortex.policy.activated"
    CORTEX_LESSON_QUARANTINED = "cortex.lesson.quarantined"


@dataclass
class Event:
    sweep_id: str
    seq: int
    ts: float
    type: str
    actor: str
    payload: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


class EventBus:
    """In-process pub/sub with a persistent log for replay-from-seq.

    Phase 1 uses this in-memory; Phase 2+ persists to Postgres and pipes into
    the WS hub.
    """

    def __init__(self) -> None:
        self._log: list[Event] = []
        self._subscribers: list[Callable[[Event], None]] = []
        self._async_subscribers: list[asyncio.Queue] = []

    def emit(self, sweep_id: str, type_: EventType | str, actor: str, **payload: Any) -> Event:
        # Chokepoint (b): scrub string values in the payload before we
        # persist. The bus is the fan-out point — anything not redacted
        # here lands in Postgres, in the WS stream, and in every log
        # subscriber. Redact once, at the source.
        safe_payload = _REDACTOR.redact_dict(payload)
        evt = Event(
            sweep_id=sweep_id,
            seq=len(self._log),
            ts=time(),
            type=str(type_.value if isinstance(type_, EventType) else type_),
            actor=actor,
            payload=safe_payload,
        )
        self._log.append(evt)
        for cb in self._subscribers:
            cb(evt)
        for q in list(self._async_subscribers):
            try:
                q.put_nowait(evt)
            except asyncio.QueueFull:
                pass
        return evt

    def subscribe(self, cb: Callable[[Event], None]) -> None:
        self._subscribers.append(cb)

    def subscribe_async(self, maxsize: int = 1000) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=maxsize)
        self._async_subscribers.append(q)
        return q

    def replay(self, sweep_id: str, after_seq: int = -1) -> list[Event]:
        return [e for e in self._log if e.sweep_id == sweep_id and e.seq > after_seq]

    def all(self) -> list[Event]:
        return list(self._log)
