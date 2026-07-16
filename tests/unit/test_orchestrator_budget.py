"""Tranche A1 — Orchestrator budget guards + phase state machine.

Covers the state machine that the runtime code path actually exercises:
  * token-cap breach halts fan-out and jumps to Attest
  * wall-cap breach ditto (immediate, since we set the cap to 0)
  * illegal (backwards) phase transition emits `sweep.phase.illegal` and
    does not advance the current phase
  * happy-path finding carries `tokens_used` and `wall_seconds` in its
    audit block — the field the Attestation ships

These tests exist because the runtime state machine — not just the
Investigator or the Reproducer — is the thing that would leak $ or hang
CI if a model went off the rails. Static type checks don't catch a
runaway loop; only exercising the loop does.
"""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from spotlight.orchestrator import Orchestrator
from spotlight.orchestrator.events import EventBus, EventType
from spotlight.profiles import BALANCED

ROOT = Path(__file__).resolve().parents[2]
VULN = ROOT / "targets" / "vuln-bank-api"


# ── budget guards ─────────────────────────────────────────────────────

def _types(bus: EventBus, sweep_id: str) -> list[str]:
    return [e.type for e in bus.replay(sweep_id)]


def test_budget_exceeded_halts_fanout(tmp_path):
    """Profile with `budget_tokens=1` must trip on the first accounting call.

    Recon logs some tokens on its output; the very next budget check (at the
    top of the Investigate loop) has to see the breach and refuse to spawn
    Investigators. The `sweep.budget.exceeded` event must fire, and there
    must be zero investigator agents in the event log.
    """
    tight = replace(BALANCED, budget_tokens=1, budget_wall_seconds=3600)
    bus = EventBus()
    orch = Orchestrator(bus=bus, profile=tight)
    result = orch.run(VULN, out_dir=tmp_path)

    types = _types(bus, result.sweep_id)
    assert EventType.SWEEP_BUDGET_EXCEEDED.value in types, (
        f"expected budget-exceeded event, got: {set(types)}"
    )
    # No investigators should have spawned. Recon may — we allow that; it
    # happens BEFORE the first post-recon budget check.
    inv_spawns = [
        e for e in bus.replay(result.sweep_id)
        if e.type == EventType.AGENT_SPAWNED.value
        and e.payload.get("role") == "investigator"
    ]
    assert inv_spawns == [], (
        f"expected no investigator spawns after breach, got {len(inv_spawns)}"
    )
    # And we still land at Attest — graceful degradation.
    assert result.findings == []
    assert EventType.SWEEP_FINISHED.value in types


def test_wall_clock_budget_halts_fanout(tmp_path):
    """`budget_wall_seconds=0` trips instantly — the first _budget_breach
    check after `_start_wall = monotonic()` sees elapsed >= 0."""
    instant = replace(BALANCED, budget_tokens=10_000_000, budget_wall_seconds=0)
    bus = EventBus()
    orch = Orchestrator(bus=bus, profile=instant)
    result = orch.run(VULN, out_dir=tmp_path)

    types = _types(bus, result.sweep_id)
    breaches = [
        e for e in bus.replay(result.sweep_id)
        if e.type == EventType.SWEEP_BUDGET_EXCEEDED.value
    ]
    assert breaches, f"expected wall-clock budget breach, got: {set(types)}"
    assert breaches[0].payload["kind"] == "wall"
    assert breaches[0].payload["cap"] == 0
    # Zero findings, still finalizes cleanly.
    assert result.findings == []
    assert EventType.SWEEP_FINISHED.value in types


# ── phase state machine ───────────────────────────────────────────────

def test_phase_state_machine_rejects_backward(tmp_path):
    """Backwards jump must not advance state; must emit `sweep.phase.illegal`."""
    bus = EventBus()
    orch = Orchestrator(bus=bus)
    # Bootstrap the state machine as if we were mid-run: set sweep_id + walk
    # forward to `attest`.
    orch._sweep_id = "sw_test_illegal"
    for phase in ("recon", "investigate", "reduce", "attest"):
        assert orch._advance_phase(phase) is True, f"forward-{phase} rejected"
    assert orch._current_phase == "attest"

    # Now try to jump back to recon (definitely illegal — not a repeatable
    # phase). Must return False and NOT advance.
    ok = orch._advance_phase("recon")
    assert ok is False, "backward jump to recon was accepted"
    assert orch._current_phase == "attest", (
        f"phase leaked backwards; now at {orch._current_phase}"
    )

    events = bus.replay("sw_test_illegal")
    illegals = [e for e in events if e.type == EventType.SWEEP_PHASE_ILLEGAL.value]
    assert len(illegals) == 1
    assert illegals[0].payload["from"] == "attest"
    assert illegals[0].payload["to"] == "recon"


def test_phase_state_machine_allows_per_finding_repeat(tmp_path):
    """The per-finding phases (reproduce/remediate/verify) legitimately repeat
    across findings — the state machine must not flag those as illegal."""
    bus = EventBus()
    orch = Orchestrator(bus=bus)
    orch._sweep_id = "sw_test_repeat"

    for phase in ("recon", "investigate", "reduce", "reproduce", "remediate", "verify"):
        assert orch._advance_phase(phase) is True

    # Second finding: back to reproduce is fine.
    assert orch._advance_phase("reproduce", finding="SPOT-0002") is True
    assert orch._advance_phase("remediate", finding="SPOT-0002") is True
    assert orch._advance_phase("verify", finding="SPOT-0002") is True

    events = bus.replay("sw_test_repeat")
    illegals = [e for e in events if e.type == EventType.SWEEP_PHASE_ILLEGAL.value]
    assert illegals == [], "per-finding phase repetition was flagged illegal"


# ── audit block plumbing ──────────────────────────────────────────────

def test_finding_audit_carries_tokens_and_wall(tmp_path):
    """A normal sweep on the vuln fixture must land tokens+wall in the audit."""
    bus = EventBus()
    orch = Orchestrator(bus=bus)
    result = orch.run(VULN, out_dir=tmp_path)
    assert result.findings, "expected at least one finding from vuln fixture"

    audit = result.findings[0]["audit"]
    assert "tokens_used" in audit
    assert "wall_seconds" in audit
    assert isinstance(audit["tokens_used"], int)
    assert audit["tokens_used"] >= 0
    assert isinstance(audit["wall_seconds"], (int, float))
    assert audit["wall_seconds"] > 0, "wall_seconds should be strictly > 0"
