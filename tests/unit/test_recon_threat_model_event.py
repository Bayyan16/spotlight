"""Tranche B5 — Recon threat-model event surfacing.

The orchestrator must emit exactly one `recon.threat_model` event after
Recon completes and before the phase advances to `investigate`. The
event's payload is what the Live Sweep panel reads to render the
threat-model card, so we assert both:
  * exactly one such event fires per sweep,
  * it lands with the payload keys the frontend depends on
    (`threat_model`, `stack`, `signals_count`, `surfaces`),
  * it fires between the AGENT_FINISHED("recon") event and the
    `sweep.phase.changed(investigate)` event — otherwise the panel
    could paint stale data during the wrong phase.

Uses the vuln-bank-api fixture with SPOTLIGHT_SANDBOX=subprocess so the
sweep runs end-to-end without needing Modal.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from spotlight.orchestrator import Orchestrator
from spotlight.orchestrator.events import EventBus, EventType

ROOT = Path(__file__).resolve().parents[2]
VULN = ROOT / "targets" / "vuln-bank-api"


@pytest.fixture(autouse=True)
def _subprocess_sandbox(monkeypatch):
    monkeypatch.setenv("SPOTLIGHT_SANDBOX", "subprocess")
    yield


def _replay(bus: EventBus, sweep_id: str):
    return bus.replay(sweep_id)


def test_recon_threat_model_event_fires_exactly_once(tmp_path):
    """Exactly one `recon.threat_model` event per sweep."""
    bus = EventBus()
    orch = Orchestrator(bus=bus)
    result = orch.run(VULN, out_dir=tmp_path)

    events = _replay(bus, result.sweep_id)
    tm_events = [e for e in events if e.type == EventType.RECON_THREAT_MODEL.value]
    assert len(tm_events) == 1, (
        f"expected exactly 1 recon.threat_model event, got {len(tm_events)}"
    )


def test_recon_threat_model_event_payload_shape(tmp_path):
    """Payload MUST carry the keys the Live Sweep panel reads."""
    bus = EventBus()
    orch = Orchestrator(bus=bus)
    result = orch.run(VULN, out_dir=tmp_path)

    events = _replay(bus, result.sweep_id)
    tm_events = [e for e in events if e.type == EventType.RECON_THREAT_MODEL.value]
    assert tm_events, "no recon.threat_model event fired"
    payload = tm_events[0].payload

    # Frontend reads exactly these keys off the payload.
    for key in ("threat_model", "stack", "signals_count", "surfaces"):
        assert key in payload, f"payload missing {key!r} (got {list(payload)})"

    assert isinstance(payload["signals_count"], int)
    assert payload["signals_count"] >= 0
    assert isinstance(payload["surfaces"], list)
    assert isinstance(payload["stack"], dict)
    assert isinstance(payload["threat_model"], dict)

    # Recon's MockModelClient returns Python + Flask against the fixture.
    stack = payload["stack"]
    assert stack.get("language") == "python"
    assert stack.get("framework") == "flask"
    assert "code" in payload["surfaces"]


def test_recon_threat_model_event_fires_between_recon_finish_and_investigate(tmp_path):
    """Ordering guard: recon.threat_model must land AFTER agent.finished(recon)
    and BEFORE sweep.phase.changed(investigate). If a future refactor moves
    it into the investigate phase, the Live panel would paint stale data
    while investigators are already running."""
    bus = EventBus()
    orch = Orchestrator(bus=bus)
    result = orch.run(VULN, out_dir=tmp_path)

    events = _replay(bus, result.sweep_id)
    seq_recon_finished = None
    seq_tm = None
    seq_investigate = None
    for e in events:
        if (
            e.type == EventType.AGENT_FINISHED.value
            and e.actor == "recon"
            and seq_recon_finished is None
        ):
            seq_recon_finished = e.seq
        if e.type == EventType.RECON_THREAT_MODEL.value and seq_tm is None:
            seq_tm = e.seq
        if (
            e.type == EventType.SWEEP_PHASE_CHANGED.value
            and e.payload.get("phase") == "investigate"
            and seq_investigate is None
        ):
            seq_investigate = e.seq

    assert seq_recon_finished is not None, "no agent.finished(recon) event fired"
    assert seq_tm is not None, "no recon.threat_model event fired"
    assert seq_investigate is not None, "sweep never entered investigate phase"
    assert seq_recon_finished < seq_tm < seq_investigate, (
        f"ordering wrong: recon.finished@{seq_recon_finished}, "
        f"threat_model@{seq_tm}, investigate@{seq_investigate}"
    )
