"""Capability tokens — Warden precursor.

Every sandbox invocation carries a token declaring exactly what the running
agent is allowed to do: which paths it can read, which it can write, whether
it can call the network, its CPU/mem/time cap. This is the object the
Warden module (Phase 2 proper) will issue and enforce; landing it here now
means when Warden lands we don't have to rewrite the interface.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CapabilityToken:
    """A per-agent-job capability grant."""

    agent_role: str  # reproducer | verifier | remediator | investigator
    finding_id: str | None = None  # tie the grant to a specific finding

    # Filesystem scoping
    ro_paths: list[str] = field(default_factory=list)  # read-only mounts
    rw_paths: list[str] = field(default_factory=list)  # writable overlays (scratch)

    # Network policy
    egress_allowed: bool = False  # Default: DENY ALL outbound. Non-negotiable.
    egress_allowlist: list[str] = field(default_factory=list)  # e.g. ["pypi.org"] for a bootstrap

    # Resource caps
    cpu: float = 1.0
    memory_mb: int = 512
    timeout_s: int = 60
    max_output_bytes: int = 512 * 1024  # 512 KB — prevent log-bomb DoS

    # Command budget — how many exec calls this token allows.
    max_exec_calls: int = 10

    def to_dict(self) -> dict:
        return {
            "agent_role": self.agent_role,
            "finding_id": self.finding_id,
            "ro_paths": self.ro_paths,
            "rw_paths": self.rw_paths,
            "egress_allowed": self.egress_allowed,
            "egress_allowlist": self.egress_allowlist,
            "cpu": self.cpu,
            "memory_mb": self.memory_mb,
            "timeout_s": self.timeout_s,
            "max_output_bytes": self.max_output_bytes,
            "max_exec_calls": self.max_exec_calls,
        }

    @classmethod
    def for_reproducer(cls, finding_id: str, repo_path: str) -> "CapabilityToken":
        """Reproducer runs untrusted code in-sandbox to demonstrate an
        exploit. Egress-off is non-negotiable — the demo of 'the swarm
        cannot be turned against you' depends on it."""
        return cls(
            agent_role="reproducer",
            finding_id=finding_id,
            ro_paths=[repo_path],
            rw_paths=["/tmp"],
            egress_allowed=False,
            cpu=1.0,
            memory_mb=512,
            timeout_s=60,
        )

    @classmethod
    def for_verifier(cls, finding_id: str, patched_path: str) -> "CapabilityToken":
        """Verifier re-runs the same PoC against the patched code — same
        constraints as the Reproducer, plus explicit fresh-context flag."""
        return cls(
            agent_role="verifier",
            finding_id=finding_id,
            ro_paths=[patched_path],
            rw_paths=["/tmp"],
            egress_allowed=False,
            cpu=1.0,
            memory_mb=512,
            timeout_s=60,
        )
