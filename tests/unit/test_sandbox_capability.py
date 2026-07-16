"""Unit tests for the capability-token layer.

We're locking the DEFAULTS here — anything that changes the security posture
(egress default, timeout default, memory cap) must go through a code review
of these tests."""
from __future__ import annotations

from spotlight.sandbox import CapabilityToken


def test_default_egress_is_denied():
    tok = CapabilityToken(agent_role="probe")
    assert tok.egress_allowed is False, (
        "Default capability token MUST deny outbound network. This is the "
        "'swarm cannot be turned against you' guarantee."
    )
    assert tok.egress_allowlist == []


def test_reproducer_token_grants_ro_repo_and_denies_egress():
    tok = CapabilityToken.for_reproducer(finding_id="F-1", repo_path="/tmp/target")
    assert tok.agent_role == "reproducer"
    assert tok.finding_id == "F-1"
    assert "/tmp/target" in tok.ro_paths
    assert tok.rw_paths == ["/tmp"]
    assert tok.egress_allowed is False
    assert tok.timeout_s <= 120  # sanity cap
    assert tok.memory_mb <= 4096


def test_verifier_token_matches_reproducer_shape():
    tok = CapabilityToken.for_verifier(finding_id="F-1", patched_path="/tmp/patched")
    assert tok.agent_role == "verifier"
    assert tok.egress_allowed is False
    assert "/tmp/patched" in tok.ro_paths


def test_capability_token_serializes():
    tok = CapabilityToken.for_reproducer(finding_id="F-1", repo_path="/tmp/target")
    d = tok.to_dict()
    for key in (
        "agent_role", "finding_id", "ro_paths", "rw_paths",
        "egress_allowed", "egress_allowlist", "cpu", "memory_mb", "timeout_s",
    ):
        assert key in d


def test_capability_token_output_bytes_capped():
    """Log-bomb DoS guardrail."""
    tok = CapabilityToken(agent_role="probe")
    assert tok.max_output_bytes <= 1024 * 1024
