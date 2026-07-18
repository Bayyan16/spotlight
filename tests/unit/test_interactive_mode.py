"""C2 · Interactive-mode pause/resume.

An interactive sweep pauses after Recon, emits
`sweep.paused.for-review`, and waits for POST /sweeps/{id}/resume. The
resume payload can optionally include `threat_model_edits` that shallow-
merge into the recon output before Investigate spawns.

These tests use short timeouts to keep CI quick.
"""
from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from spotlight.orchestrator import Orchestrator
from spotlight.orchestrator.orchestrator import resume_paused_sweep


def _acme() -> Path:
    root = Path(__file__).resolve().parents[2] / "targets" / "acme-bank"
    if not (root / "app.py").exists():
        pytest.skip("acme-bank fixture missing")
    return root


def test_interactive_sweep_pauses_after_recon():
    """The orchestrator thread must block after Recon until resume fires."""
    acme = _acme()
    orch = Orchestrator()

    events_seen: list[str] = []
    orch.bus.subscribe(lambda e: events_seen.append(e.type))

    def _run():
        orch.run(acme, interactive=True)

    t = threading.Thread(target=_run, daemon=True)
    t.start()

    # Poll for the pause event — recon on acme-bank takes ~2-4s.
    for _ in range(80):
        if any(e == "sweep.paused.for-review" for e in events_seen):
            break
        time.sleep(0.1)
    else:
        raise AssertionError(f"never saw pause; last events={events_seen[-5:]}")

    # Verify the thread is STILL running — pause is real, not a fall-through.
    assert t.is_alive(), "orchestrator thread completed without waiting"

    # Resume it and let it finish.
    sweep_id = next(iter(events_seen))
    # Find the sweep_id via the bus.
    bus_events = orch.bus.all()
    sid = bus_events[0].sweep_id
    resumed = resume_paused_sweep(sid, edits=None)
    assert resumed is True

    t.join(timeout=30)
    assert not t.is_alive(), "sweep never completed after resume"
    assert any(e == "sweep.finished" for e in orch.bus.all() if False) or any(
        e.type == "sweep.finished" for e in orch.bus.all()
    )


def test_resume_edits_merge_into_threat_model():
    """The edits dict shallow-merges into recon_out.threat_model."""
    acme = _acme()
    orch = Orchestrator()

    def _run():
        orch.run(acme, interactive=True)

    t = threading.Thread(target=_run, daemon=True)
    t.start()

    # Wait for pause
    for _ in range(80):
        if any(e.type == "sweep.paused.for-review" for e in orch.bus.all()):
            break
        time.sleep(0.1)

    sid = orch.bus.all()[0].sweep_id
    edits = {
        "surfaces": ["code", "agentic", "user-added-review"],
        "custom_key": "hello",
    }
    assert resume_paused_sweep(sid, edits=edits) is True

    t.join(timeout=30)
    # The RECON_THREAT_MODEL event was re-emitted with `edited=True` after
    # the merge.
    edited_events = [
        e for e in orch.bus.all()
        if e.type == "recon.threat_model" and e.payload.get("edited")
    ]
    assert edited_events, "no edited threat_model event fired"
    payload = edited_events[0].payload
    assert "user-added-review" in payload.get("surfaces", [])


def test_resume_on_unknown_sweep_returns_false():
    assert resume_paused_sweep("sw_does_not_exist", edits=None) is False


def test_non_interactive_sweep_does_not_pause():
    """Sanity: interactive=False (the default) never trips the pause path."""
    acme = _acme()
    orch = Orchestrator()
    result = orch.run(acme)  # blocks synchronously — no pause path
    assert result.findings, "sweep produced no findings"
    assert not any(
        e.type == "sweep.paused.for-review" for e in orch.bus.all()
    )
