"""Chain-of-custody helper — a signed, append-only list of actor actions.

Attach one to each ``finding`` under ``finding.audit.chain_of_custody`` so
that when an agent commits a broken diff we can trace every step (Triager
proposed, Remediator patched, Verifier ran the PoC, human clicked approve).
Each entry is independently signed, so any tampering is detectable.
"""
from __future__ import annotations

from typing import Any

from .signing import Signer, verify_action


class ChainOfCustody:
    """Append-only signed log of agent/human actions for a single finding."""

    def __init__(self, signer: Signer | None = None) -> None:
        # Hold the signer so we don't re-load the workspace key per append.
        self._signer = signer or Signer()
        self._entries: list[dict[str, Any]] = []

    def add_agent_action(
        self, actor_id: str, action: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        entry = self._signer.sign("agent", actor_id, action, payload)
        self._entries.append(entry)
        return entry

    def add_human_action(
        self, actor_id: str, action: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        entry = self._signer.sign("human", actor_id, action, payload)
        self._entries.append(entry)
        return entry

    def to_list(self) -> list[dict[str, Any]]:
        """Raw list suitable for JSON serialization onto the finding.

        Returns a shallow copy so downstream mutation can't corrupt the
        in-memory chain.
        """
        return list(self._entries)

    def verify_all(self) -> bool:
        """True iff every entry's signature verifies against the workspace key."""
        pub = self._signer.public_key
        for e in self._entries:
            if not verify_action(e, pub):
                return False
        return True

    def __len__(self) -> int:
        return len(self._entries)
