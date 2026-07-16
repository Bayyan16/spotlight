"""WardenService surface tests: envelope, sign_action, capability issuance,
event emission."""
from __future__ import annotations

from spotlight.orchestrator.events import EventBus, EventType
from spotlight.warden import InjectionMatch, WardenService


# ── envelope ──────────────────────────────────────────────────────────

def test_envelope_wraps_content_with_origin_tag():
    warden = WardenService()
    wrapped = warden.wrap_target_content("hello world", origin="readme:README.md")
    assert "UNTRUSTED_CONTENT_BEGIN" in wrapped
    assert "origin=readme:README.md" in wrapped
    assert "UNTRUSTED_CONTENT_END" in wrapped
    assert "hello world" in wrapped


def test_envelope_wrap_is_idempotent():
    """Wrapping an already-wrapped string must return it unchanged — the
    same content flows through Recon + Investigator and we don't want
    doubled envelopes at the model prompt."""
    warden = WardenService()
    once = warden.wrap_target_content("README body", origin="readme:R.md")
    twice = warden.wrap_target_content(once, origin="readme:R.md")
    assert once == twice, "wrap_target_content is not idempotent"
    assert warden.is_wrapped(once)


def test_envelope_scrubs_newlines_from_origin_tag():
    warden = WardenService()
    wrapped = warden.wrap_target_content("body", origin="line1\nline2")
    # The origin tag itself must be single-line so the fence stays intact.
    fence_line = wrapped.strip().splitlines()[0]
    assert "line1" in fence_line
    assert "line2" in fence_line
    assert fence_line.count("\n") == 0


# ── sign_action ────────────────────────────────────────────────────────

def test_sign_action_returns_expected_shape():
    warden = WardenService()
    rec = warden.sign_action(
        actor="warden",
        kind="capability.issued",
        payload={"role": "reproducer", "finding_id": "SPOT-0001"},
    )
    assert set(rec.keys()) == {"actor", "kind", "payload", "ts", "hash"}
    assert rec["actor"] == "warden"
    assert rec["kind"] == "capability.issued"
    assert rec["payload"]["role"] == "reproducer"
    assert isinstance(rec["ts"], float)
    assert rec["hash"] and len(rec["hash"]) == 64  # sha256 hex


def test_sign_action_hash_is_stable_over_equal_payloads(monkeypatch):
    """Same actor+kind+payload → same hash (excluding ts). Guarantees the
    audit chain is deterministic when we replay events."""
    from spotlight.warden import service as svc_mod

    monkeypatch.setattr(svc_mod, "time", lambda: 1234567890.0)
    warden = WardenService()
    a = warden.sign_action("warden", "capability.issued", {"x": 1})
    b = warden.sign_action("warden", "capability.issued", {"x": 1})
    assert a["hash"] == b["hash"]


# ── issue_capability ───────────────────────────────────────────────────

def test_issue_capability_reproducer_carries_token_id():
    warden = WardenService()
    tok = warden.issue_capability(
        "reproducer", finding_id="SPOT-0007", repo_path="/tmp/repo"
    )
    assert tok.agent_role == "reproducer"
    assert tok.finding_id == "SPOT-0007"
    assert tok.egress_allowed is False  # default deny — non-negotiable
    assert hasattr(tok, "token_id")
    assert len(tok.token_id) == 32  # uuid4 hex


def test_issue_capability_verifier_carries_token_id():
    warden = WardenService()
    tok = warden.issue_capability(
        "verifier", finding_id="SPOT-0007", patched_path="/tmp/patched"
    )
    assert tok.agent_role == "verifier"
    assert hasattr(tok, "token_id")


def test_issue_capability_generic_role_gets_safe_defaults():
    warden = WardenService()
    tok = warden.issue_capability("agentic-analyst", finding_id=None)
    assert tok.agent_role == "agentic-analyst"
    assert tok.egress_allowed is False
    assert hasattr(tok, "token_id")


def test_issue_capability_token_ids_are_unique():
    warden = WardenService()
    ids = {
        warden.issue_capability("reproducer", "F1", repo_path="/tmp").token_id
        for _ in range(20)
    }
    assert len(ids) == 20, "token_id collisions — uuid should be unique"


# ── event emission ─────────────────────────────────────────────────────

def test_emit_injection_flags_pushes_events_per_match():
    warden = WardenService()
    bus = EventBus()
    matches = [
        InjectionMatch(kind="ignore_instructions", span=(0, 5), snippet="ignore"),
        InjectionMatch(kind="zero_width", span=(10, 11), snippet="hi\u200bworld"),
    ]
    n = warden.emit_injection_flags(bus, "sw_test", "readme:R.md", matches)
    assert n == 2
    events = [e for e in bus.all() if e.type == EventType.WARDEN_INJECTION_FLAGGED.value]
    assert len(events) == 2
    kinds = {e.payload["kind"] for e in events}
    assert kinds == {"ignore_instructions", "zero_width"}
    assert all(e.payload["origin"] == "readme:R.md" for e in events)


def test_emit_injection_flags_accepts_dict_matches():
    warden = WardenService()
    bus = EventBus()
    n = warden.emit_injection_flags(
        bus,
        "sw_test",
        "comment:app.py",
        [{"kind": "you_are_now", "span": [0, 10], "snippet": "you are now"}],
    )
    assert n == 1


def test_emit_injection_flags_empty_is_noop():
    warden = WardenService()
    bus = EventBus()
    assert warden.emit_injection_flags(bus, "sw_test", "readme", []) == 0
    assert bus.all() == []
