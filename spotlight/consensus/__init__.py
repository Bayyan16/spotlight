"""Spotlight Consensus Kernel — v1 (Phase 2 Tranche B2).

Lifted out of the orchestrator so promotion logic is testable in isolation.
Public surface:

    ConsensusKernel  — the promote() interface described in PRD §8.
    EvidenceItem     — typed corroborator record (modality + origin).
    TierDecision     — the return value of promote().

See PRD §8.1 (independence — defined, not assumed), §8.2 (tiers), and
§8.3 (adjudication) for the exact semantics implemented here.
"""
from .kernel import ConsensusKernel, EvidenceItem, TierDecision

__all__ = ["ConsensusKernel", "EvidenceItem", "TierDecision"]
