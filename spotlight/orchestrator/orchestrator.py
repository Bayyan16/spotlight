"""Quorum Protocol orchestrator — Phase 1 slice.

Runs the vertical Sweep: Recon → Investigate → Reduce → Reproduce → Remediate
→ Verify → Attest. Consensus Kernel logic is inlined here for Phase 1; Phase
2 lifts it into `consensus/`.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

from concurrent.futures import ThreadPoolExecutor, as_completed

from spotlight.agents import Investigator, Recon, Reducer, Remediator, Reproducer, Verifier
from spotlight.agents.model import MockModelClient, ModelClient
from spotlight.agents.moonshot import maybe_from_env
from spotlight.profiles import Profile, get_profile

from .events import EventBus, EventType


@dataclass
class SweepResult:
    sweep_id: str
    repo_path: str
    threat_model: dict[str, Any]
    signals: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    attestations: list[dict[str, Any]]
    events_log: list[dict[str, Any]] = field(default_factory=list)


def _finding_id(i: int) -> str:
    return f"SPOT-{i:04d}"


def _promote_tier(finding: dict[str, Any], repro: dict[str, Any] | None) -> tuple[str, float, str]:
    """Consensus Kernel v0 (§8.2) — reproduction + independent corroborator = verified."""
    static_fact = "codegraph:source->sink reachable" in finding.get("evidence_used", [])
    reproduced = bool(repro and repro.get("result") == "confirmed")
    if reproduced and static_fact:
        return "verified", 0.93, "reproduction + static-analysis fact"
    if reproduced:
        return "verified", 0.85, "reproduction alone"
    if static_fact:
        return "high-confidence", 0.7, "static-analysis fact without reproduction"
    return "needs-review", 0.4, "single-source, unreproduced"


class Orchestrator:
    def __init__(
        self,
        model: ModelClient | None = None,
        bus: EventBus | None = None,
        profile: Profile | None = None,
    ) -> None:
        # Priority: explicit model > Moonshot from env > mock.
        self.model = model or maybe_from_env() or MockModelClient()
        self.bus = bus or EventBus()
        self.profile = profile or get_profile(None)

    def run(self, repo_path: str | Path, out_dir: str | Path | None = None) -> SweepResult:
        repo_path = Path(repo_path).resolve()
        sweep_id = f"sw_{uuid4().hex[:12]}"
        out_dir = Path(out_dir) if out_dir else Path.cwd() / "sweep-run" / sweep_id
        out_dir.mkdir(parents=True, exist_ok=True)

        emit = lambda t, actor, **p: self.bus.emit(sweep_id, t, actor, **p)
        emit(EventType.SWEEP_STARTED, "orchestrator", repo=str(repo_path))

        # 1. Recon
        emit(EventType.SWEEP_PHASE_CHANGED, "orchestrator", phase="recon")
        emit(EventType.AGENT_SPAWNED, "orchestrator", role="recon")
        recon_out = Recon(self.model).run(repo_path)
        emit(EventType.AGENT_FINISHED, "recon", signals=len(recon_out["signals"]))

        # 2. Investigate — parallel fan-out under Profile.max_agents.
        emit(EventType.SWEEP_PHASE_CHANGED, "orchestrator", phase="investigate")
        candidates: list[dict[str, Any]] = []
        slices = recon_out["signals"]
        # Filter slices by the Profile's class set — if a profile targets only
        # `sqli`, don't spawn Investigators for XSS/SSRF signals.
        allowed_classes = set(self.profile.classes)
        active_slices = [
            s for s in slices if s["sink"]["class"] in allowed_classes
        ] if allowed_classes else slices

        def _investigate(idx_slice):
            idx, slice_ = idx_slice
            emit(
                EventType.AGENT_SPAWNED,
                "orchestrator",
                role="investigator",
                slice=slice_,
                worker=f"inv-{idx}",
            )
            judgment = Investigator(self.model).run(slice_)
            if not judgment:
                emit(EventType.AGENT_FINISHED, f"inv-{idx}", verdict="reject")
                return None
            existing = judgment.get("evidence_used", []) or []
            judgment["evidence_used"] = [
                "codegraph:source->sink reachable",
                slice_["reason"],
                *existing,
            ]
            emit(EventType.AGENT_FINISHED, f"inv-{idx}", verdict="candidate")
            emit(EventType.CANDIDATE_RAISED, f"inv-{idx}", candidate=judgment)
            return judgment

        max_workers = max(1, min(self.profile.max_agents, max(1, len(active_slices))))
        if max_workers > 1 and len(active_slices) > 1:
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                for judgment in pool.map(_investigate, enumerate(active_slices)):
                    if judgment:
                        candidates.append(judgment)
        else:
            for pair in enumerate(active_slices):
                judgment = _investigate(pair)
                if judgment:
                    candidates.append(judgment)

        # 3. Reduce
        emit(EventType.SWEEP_PHASE_CHANGED, "orchestrator", phase="reduce")
        reduced = Reducer().run(candidates)

        # 4. Reproduce → Remediate → Verify → Attest — per finding
        findings: list[dict[str, Any]] = []
        for i, cand in enumerate(reduced, start=1):
            fid = _finding_id(i)
            emit(EventType.SWEEP_PHASE_CHANGED, "orchestrator", phase="reproduce", finding=fid)
            emit(EventType.REPRO_STARTED, "reproducer", finding=fid)
            repro = Reproducer().run(repo_path, cand)
            sandbox_info = repro.get("sandbox", {})
            if sandbox_info:
                emit(
                    EventType.SANDBOX_SPAWNED,
                    "reproducer",
                    finding=fid,
                    engine=sandbox_info.get("engine"),
                    capability_token=sandbox_info.get("capability_token"),
                )
                emit(
                    EventType.SANDBOX_RESULT,
                    "reproducer",
                    finding=fid,
                    engine=sandbox_info.get("engine"),
                    duration_s=sandbox_info.get("duration_s"),
                    exit_code=sandbox_info.get("exit_code"),
                )
                if sandbox_info.get("egress_attempts", 0) > 0:
                    emit(
                        EventType.SANDBOX_EGRESS_DENIED,
                        "reproducer",
                        finding=fid,
                        hosts=sandbox_info.get("egress_denied_hosts", []),
                    )
            emit(EventType.REPRO_RESULT, "reproducer", finding=fid, result=repro["result"])

            emit(EventType.SWEEP_PHASE_CHANGED, "orchestrator", phase="remediate", finding=fid)
            remediation = Remediator().run(repo_path, cand)
            if remediation.get("applied"):
                (out_dir / f"{fid}.diff").write_text(remediation["diff"])
                emit(EventType.REMEDIATION_OPENED, "remediator", finding=fid)

            emit(EventType.SWEEP_PHASE_CHANGED, "orchestrator", phase="verify", finding=fid)
            verify = Verifier(self.model).run(repo_path, cand, remediation)
            emit(EventType.VERIFY_RESULT, "verifier", finding=fid, result=verify.get("result"))

            tier, confidence, tier_reason = _promote_tier(cand, repro)
            state = "confirmed-fixed" if (
                verify.get("result") == "repro-now-blocked" and verify.get("backdoor_check") == "pass"
            ) else "candidate"

            finding = {
                "id": fid,
                "surface": "code",
                "title": cand["title"],
                "severity": cand["severity"],
                "class": cand["class"],
                "cwe": cand["cwe"],
                "location": cand["location"],
                "state": state,
                "tier": tier,
                "confidence": confidence,
                "owner": "unassigned",
                "exploit_path": None,
                "evidence": {
                    "detected_by": ["investigator-1", "codegraph:source->sink reachable"],
                    "corroboration": [
                        {"type": "static-fact", "detail": cand["evidence_used"]},
                        {
                            "type": "reproduction",
                            "result": repro["result"],
                            "path": f"repro/{fid}/",
                        },
                    ],
                    "root_cause": cand["root_cause"],
                    "fix": {"diff": f"{fid}.diff" if remediation.get("applied") else None,
                            "approach": cand["recommendation"]},
                    "verification": {
                        **verify,
                        "path": f"verify/{fid}.json",
                    },
                    "sandbox": {
                        "reproducer": repro.get("sandbox", {}),
                        "verifier": verify.get("sandbox", {}),
                    },
                    "threat_model": {
                        "author": "recon",
                        "profile": self.profile.id,
                        "surfaces": recon_out["threat_model"].get("surfaces", self.profile.surfaces),
                        "untrusted_sources": recon_out["threat_model"]
                            .get("threat_model", {})
                            .get("untrusted_sources", []),
                        "high_impact_sinks": recon_out["threat_model"]
                            .get("threat_model", {})
                            .get("high_impact_sinks", []),
                        "stack": recon_out["threat_model"].get("stack", {}),
                    },
                },
                "consensus": {
                    "tier": tier,
                    "independent_corroborators": 2 if repro["result"] == "confirmed" else 1,
                    "decision": "promote" if tier in ("verified", "high-confidence") else "hold",
                    "rationale": tier_reason,
                },
                "audit": {
                    "model": self.model.family,
                    "deployment_tier": "t0-mock",
                    "profile": self.profile.id,
                    "profile_name": self.profile.name,
                    "commit": "<dev>",
                    "timestamp": None,
                },
            }
            findings.append(finding)
            (out_dir / f"verify_{fid}.json").write_text(json.dumps(verify, indent=2))
            emit(EventType.FINDING_PROMOTED, "consensus", finding=fid, tier=tier)

        # 5. Attest
        emit(EventType.SWEEP_PHASE_CHANGED, "orchestrator", phase="attest")
        attestation = {
            "sweep_id": sweep_id,
            "repo": str(repo_path),
            "findings": findings,
            "threat_model": recon_out["threat_model"],
        }
        (out_dir / "attestation.json").write_text(json.dumps(attestation, indent=2))
        (out_dir / "findings.json").write_text(json.dumps(findings, indent=2))
        (out_dir / "threat_model.json").write_text(json.dumps(recon_out["threat_model"], indent=2))
        (out_dir / "signals.json").write_text(json.dumps(recon_out["signals"], indent=2))
        emit(EventType.ATTESTATION_WRITTEN, "reporter", path=str(out_dir / "attestation.json"))
        emit(EventType.SWEEP_FINISHED, "orchestrator", findings=len(findings))

        result = SweepResult(
            sweep_id=sweep_id,
            repo_path=str(repo_path),
            threat_model=recon_out["threat_model"],
            signals=recon_out["signals"],
            findings=findings,
            attestations=[attestation],
            events_log=[e.to_dict() for e in self.bus.replay(sweep_id)],
        )
        (out_dir / "events.jsonl").write_text(
            "\n".join(json.dumps(e) for e in result.events_log)
        )
        return result
