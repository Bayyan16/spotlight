"""Quorum Protocol orchestrator — Phase 1 slice.

Runs the vertical Sweep: Recon → Investigate → Reduce → Reproduce → Remediate
→ Verify → Attest. Consensus Kernel logic is inlined here for Phase 1; Phase
2 lifts it into `consensus/`.

Phase-2 Tranche A1 adds two production guards:
  * Budget cap: token & wall-clock. On breach we jump to Attest with a
    partial result rather than crash — bill safety without losing work.
  * Phase state machine: rejects backwards jumps in `sweep.phase.changed`.
    A backwards jump is always a bug; we log + emit `sweep.phase.illegal`
    and refuse to advance, but don't crash the sweep.
"""
from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

from concurrent.futures import ThreadPoolExecutor, as_completed

from spotlight.agents import Investigator, Recon, Reducer, Remediator, Reproducer, Verifier
from spotlight.agents.model import MockModelClient, ModelClient
from spotlight.agents.moonshot import maybe_from_env
from spotlight.consensus import ConsensusKernel, EvidenceItem
from spotlight.finding_identity import canonical_repo_path, finding_identity, stable_finding_id
from spotlight.profiles import Profile, get_profile

from .chainer import Chainer
from .events import EventBus, EventType
from .hypothesis import HypothesisProposer


# C2 · Interactive-mode pause registry — one entry per paused sweep.
# The orchestrator (a background thread) blocks on `event`; the API worker
# sets `edits` then calls `event.set()` to unblock. Cleanup on wake so the
# registry doesn't grow forever.
_pause_registry: dict[str, dict[str, Any]] = {}


def _register_pause(sweep_id: str) -> None:
    import threading

    _pause_registry[sweep_id] = {"event": threading.Event(), "edits": None}


def _wait_for_resume(sweep_id: str, *, timeout_s: int = 1800) -> dict | None:
    """Called from inside the orchestrator thread. Returns any threat-model
    edits the user provided at /resume, or None if the wait timed out."""
    entry = _pause_registry.get(sweep_id)
    if entry is None:
        _register_pause(sweep_id)
        entry = _pause_registry[sweep_id]
    entry["event"].wait(timeout=timeout_s)
    edits = entry.get("edits")
    _pause_registry.pop(sweep_id, None)
    return edits


def resume_paused_sweep(sweep_id: str, edits: dict | None) -> bool:
    """Called from the API worker. Returns True iff a sweep was actually
    waiting on this signal — False means the sweep either never paused, or
    already resumed."""
    entry = _pause_registry.get(sweep_id)
    if entry is None:
        return False
    entry["edits"] = edits or None
    entry["event"].set()
    return True


_TMPDIR_PREFIX_RE = None


def _repo_relative_path(file_hint: str, repo_root: Path) -> str:
    """Strip the ephemeral tmpdir clone prefix from a file path so the
    Console can display a stable repo-relative path AND build a GitHub
    blob link. Examples:

        /tmp/spotlight-clone-abc123/src/redshift_connector/foo.py
        → redshift_connector/foo.py

        /Users/x/Spotlight/targets/acme-bank/app.py  (fixture)
        → app.py                                       (relative to repo_root)
    """
    import re

    global _TMPDIR_PREFIX_RE
    if _TMPDIR_PREFIX_RE is None:
        _TMPDIR_PREFIX_RE = re.compile(
            r"^/tmp/spotlight-clone-[^/]+/src/", re.IGNORECASE
        )
    if not file_hint:
        return ""
    stripped = _TMPDIR_PREFIX_RE.sub("", file_hint)
    if stripped != file_hint:
        return stripped
    # Fixture path — fall back to `path.relative_to(repo_root)`.
    try:
        return str(Path(file_hint).resolve().relative_to(repo_root.resolve()))
    except (ValueError, OSError):
        # Not under repo_root — return basename so at least the filename
        # is stable. Rare enough that this isn't a big loss.
        return Path(file_hint).name


def _capture_code_preview(
    file_hint: str, *, line: int, context: int = 6
) -> dict[str, Any] | None:
    """Read `file_hint` and return a snippet around `line` for the Console.

    Returns None when the file can't be read (deleted, binary, permission
    denied). The snippet is capped at 40 lines total to keep finding
    payloads small in the WebSocket + persistence pipelines.
    """
    if not file_hint or not line:
        return None
    try:
        p = Path(file_hint)
        if not p.exists() or not p.is_file():
            return None
        raw = p.read_text(errors="replace")
    except Exception:
        return None
    all_lines = raw.splitlines()
    if not all_lines:
        return None
    line = max(1, min(int(line), len(all_lines)))
    start = max(1, line - context)
    end = min(len(all_lines), line + context)
    # Cap at 40 lines total.
    if end - start > 40:
        end = start + 40
    snippet = "\n".join(all_lines[start - 1 : end])
    return {
        "language": _guess_language(p.suffix),
        "start_line": start,
        "end_line": end,
        "highlight_line": line,
        "content": snippet,
    }


def _guess_language(suffix: str) -> str:
    return {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".go": "go",
        ".rs": "rust",
        ".java": "java",
        ".rb": "ruby",
        ".php": "php",
        ".c": "c",
        ".cpp": "cpp",
        ".cs": "csharp",
    }.get(suffix.lower(), "plain")


class _TrackingModel:
    """Transparent proxy around a ModelClient that records token usage per
    call. Two accumulators land on the parent orchestrator:

      * ``_usage_by_role``  — aggregate rollup per agent role. Answers
        "how many tokens did the Investigator role burn this sweep?".
      * ``_usage_events``  — one entry per call. Answers "how many tokens
        did SPOT-0001's Verifier cost?".

    Every LLM-facing role that goes through ``self.model.complete()`` is
    recorded. Non-LLM paths (sg-core, Warden regex, Semgrep) are not — by
    definition they burn zero model tokens.
    """

    _EVENT_CAP = 500

    def __init__(self, inner: Any, orch: "Orchestrator") -> None:
        self._inner = inner
        self._orch = orch

    @property
    def family(self) -> str:
        return getattr(self._inner, "family", "unknown")

    def complete(self, *, role: str, prompt: str, context: dict[str, Any]) -> dict[str, Any]:
        started = time.monotonic()
        resp = self._inner.complete(role=role, prompt=prompt, context=context)
        try:
            pt, ct, tt = _extract_prompt_completion_tokens(resp)
            # Fall back to a char-based estimate when the model didn't
            # thread usage — keeps a rough number rather than showing zero.
            if pt == 0 and ct == 0 and tt == 0:
                tt = _estimate_tokens(resp)
                ct = tt
            model_name = _extract_model_name(resp) or self.family
            elapsed = time.monotonic() - started

            self._record_role(role, model_name, pt, ct, tt)
            self._record_event(role, model_name, pt, ct, tt, elapsed, context, resp)
        except Exception as exc:  # noqa: BLE001 — accounting must never crash a sweep
            print(f"[token-track] failed to record {role}: {exc!r}")
        return resp

    def _record_role(
        self, role: str, model: str, pt: int, ct: int, tt: int
    ) -> None:
        bucket = self._orch._usage_by_role.setdefault(
            role,
            {
                "role": role,
                "model": model,
                "calls": 0,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
            },
        )
        bucket["calls"] += 1
        bucket["prompt_tokens"] += int(pt)
        bucket["completion_tokens"] += int(ct)
        bucket["total_tokens"] += int(tt)
        # If the same role runs against multiple models in one sweep
        # (e.g., you swap the verifier to a different family mid-run),
        # record every model name that appeared.
        if bucket["model"] != model:
            bucket["model"] = f"{bucket['model']}, {model}"

    def _record_event(
        self,
        role: str,
        model: str,
        pt: int,
        ct: int,
        tt: int,
        elapsed_s: float,
        context: dict[str, Any],
        resp: dict[str, Any],
    ) -> None:
        events = self._orch._usage_events
        if len(events) >= self._EVENT_CAP:
            return  # cap so attestation stays bounded on huge repos
        # Sub-agent id — the caller can pass worker_id in context so we
        # tag this event with something more granular than the role
        # (e.g., "inv-3" or "verifier@SPOT-0007"). Falls back to role.
        subagent = (
            context.get("worker_id")
            or context.get("finding_id")
            or context.get("subagent_id")
            or role
        )
        events.append(
            {
                "role": role,
                "subagent": str(subagent),
                "model": model,
                "prompt_tokens": int(pt),
                "completion_tokens": int(ct),
                "total_tokens": int(tt),
                "elapsed_s": round(elapsed_s, 3),
                "ts": time.time(),
                "fallback": bool(resp.get("_fallback")),
            }
        )


def _extract_prompt_completion_tokens(payload: Any) -> tuple[int, int, int]:
    """Return (prompt, completion, total). Handles the Moonshot / OpenAI
    usage-block shape plus the top-level `total_tokens` some clients set."""
    if not isinstance(payload, dict):
        return (0, 0, 0)
    usage = payload.get("usage") or payload.get("_usage") or {}
    if isinstance(usage, dict):
        pt = int(usage.get("prompt_tokens") or 0)
        ct = int(usage.get("completion_tokens") or 0)
        tt = int(usage.get("total_tokens") or 0)
        if tt == 0:
            tt = pt + ct
        if pt or ct or tt:
            return (pt, ct, tt)
    tt = int(payload.get("total_tokens") or 0)
    return (0, 0, tt)


def _snapshot_token_usage(orch: "Orchestrator") -> dict[str, Any]:
    """Snapshot of the orchestrator's accumulated token usage.

    Shape:
        {
            "by_role": [ { role, model, calls, prompt_tokens,
                           completion_tokens, total_tokens }, … ],
            "totals":  { calls, prompt_tokens, completion_tokens,
                         total_tokens },
            "events_count": int,
        }

    Cheap — just walks the two accumulators the tracking proxy fills.
    """
    by_role = list(orch._usage_by_role.values())
    totals = {
        "calls": sum(b["calls"] for b in by_role),
        "prompt_tokens": sum(b["prompt_tokens"] for b in by_role),
        "completion_tokens": sum(b["completion_tokens"] for b in by_role),
        "total_tokens": sum(b["total_tokens"] for b in by_role),
    }
    return {
        "by_role": by_role,
        "totals": totals,
        "events_count": len(orch._usage_events),
    }


def _extract_model_name(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""
    for k in ("model", "_model", "model_name"):
        v = payload.get(k)
        if v:
            return str(v)
    return ""


_CWE_FAMILY_BY_CLASS: dict[str, str] = {
    # CWE-94 (Improper Control of Generation of Code) — parent family for
    # every code-execution class. Advisories (GHSA / NVD) usually tag at
    # this level; we surface it alongside our more specific child CWE so
    # exact-advisory matching works both ways.
    "eval": "CWE-94",
    "ssti": "CWE-94",
    "dynamic-import": "CWE-94",
}


def _cwe_family_for_class(cls: str) -> str:
    return _CWE_FAMILY_BY_CLASS.get((cls or "").strip().lower(), "")


def _get_signer() -> Any:
    """Lazy import of the workspace signer so tests/importers that don't need
    signing don't pay the crypto init cost. Any failure returns None — the
    per-finding loop degrades to an empty chain of custody rather than
    breaking the sweep."""
    try:
        from spotlight.non_repudiation import Signer

        return Signer()
    except Exception as exc:  # noqa: BLE001 — signing must never crash a sweep
        print(f"[chain_of_custody] signer init failed: {exc!r}")
        return None


def _maybe_cortex(signer: Any = None) -> Any:
    """Build the Cortex from the environment, or return None.

    Memory is opt-in: with ``SPOTLIGHT_CORTEX_DIR`` unset this returns None and
    the sweep behaves exactly as it did before the Cortex existed. Any failure
    to construct it also returns None — a workspace whose memory directory is
    unreadable must still get its findings.
    """
    try:
        from spotlight.cortex import Cortex

        return Cortex.from_env(signer=signer)
    except Exception as exc:  # noqa: BLE001 — memory must never crash a sweep
        print(f"[cortex] disabled: {exc!r}")
        return None


def _new_coc(signer: Any) -> Any:
    """Materialize a ChainOfCustody bound to the workspace signer, or None
    if signing is unavailable. Callers must tolerate None (see _coc_append)."""
    if signer is None:
        return None
    try:
        from spotlight.non_repudiation import ChainOfCustody

        return ChainOfCustody(signer)
    except Exception as exc:
        print(f"[chain_of_custody] new_coc failed: {exc!r}")
        return None


def _coc_append(coc: Any, actor_id: str, action: str, payload: dict) -> None:
    """Append one signed agent entry. Silently no-ops if `coc` is None."""
    if coc is None:
        return
    try:
        coc.add_agent_action(actor_id, action, payload)
    except Exception as exc:
        print(f"[chain_of_custody] append({actor_id}, {action}) failed: {exc!r}")


def _coc_finalize(coc: Any, *, actor: str, action: str, payload: dict) -> list[dict]:
    """Append the final entry and return the signed list. If signing was
    unavailable throughout, returns an empty list — the finding still ships,
    but external verifiers see no chain of custody (a deliberate signal to
    reject the finding until the workspace key is provisioned)."""
    if coc is None:
        return []
    _coc_append(coc, actor, action, payload)
    try:
        return coc.to_list()
    except Exception:
        return []


# Canonical phase order for the state machine. Per-finding phases (reproduce,
# remediate, verify) can repeat inside the finding loop — that's not a
# backward jump, it's the loop rolling forward across findings.
_PHASE_ORDER = [
    # Plan → Recon → Investigate.
    # Plan reads a lightweight repo index (file tree + imports + decorator
    # histogram) and writes repo-tuned rules — extra sinks, sources, and
    # sanitizers PLUS an ephemeral Semgrep YAML rulepack. Recon then feeds
    # those into sg-core's SINKS override and Semgrep's --config so a
    # single downstream pass sees BOTH the generic patterns AND the
    # repo-native ones. Running Plan after Recon would waste a full sg-core
    # + Semgrep pass on default rules only.
    "plan",
    "recon",
    "investigate",
    "reduce",
    "reproduce",
    "remediate",
    "verify",
    "attest",
]
_PHASE_RANK = {name: i for i, name in enumerate(_PHASE_ORDER)}
_REPEATABLE_PHASES = {"reproduce", "remediate", "verify", "attest"}


@dataclass
class SweepResult:
    sweep_id: str
    repo_path: str
    threat_model: dict[str, Any]
    signals: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    attestations: list[dict[str, Any]]
    events_log: list[dict[str, Any]] = field(default_factory=list)
    # Tranche B4 — cross-surface exploit paths composed from reduced
    # candidates. Empty when the Chainer finds no matching pair.
    exploit_paths: list[dict[str, Any]] = field(default_factory=list)
    # Per-agent + per-sub-agent token accounting. `by_role` aggregates,
    # `events` is the per-call log. Populated by the _TrackingModel proxy.
    token_usage: dict[str, Any] = field(default_factory=dict)
    usage_events: list[dict[str, Any]] = field(default_factory=list)


def _promote_tier_legacy(finding: dict[str, Any], repro: dict[str, Any] | None) -> tuple[str, float, str]:
    """DEPRECATED (Phase 2 Tranche B2) — kept as a rollback for the old
    orchestrator-inline promotion path.

    The canonical logic now lives in `spotlight.consensus.ConsensusKernel`.
    Do not add new callers. This function stays here so we can toggle back
    quickly if the kernel misbehaves in a live sweep — nothing more.

    Original semantics: Consensus Kernel v0 (§8.2) — reproduction +
    independent corroborator = verified. Static-fact classes (`secrets`,
    `hardcoded-secret`) with a static_fact go straight to `verified` at 0.95.
    """
    static_fact = "codegraph:source->sink reachable" in finding.get("evidence_used", [])
    reproduced = bool(repro and repro.get("result") == "confirmed")
    not_applicable = bool(repro and repro.get("result") == "not-applicable")
    cls = finding.get("class", "")
    if cls in ("secrets", "hardcoded-secret") and static_fact:
        return "verified", 0.95, "static-fact class — hardcoded credential in source (no PoC needed)"
    if reproduced and static_fact:
        return "verified", 0.93, "reproduction + static-analysis fact"
    if reproduced:
        return "verified", 0.85, "reproduction alone"
    if static_fact and not_applicable:
        return "verified", 0.90, "static-analysis fact for static-only class"
    if static_fact:
        return "high-confidence", 0.7, "static-analysis fact without reproduction"
    return "needs-review", 0.4, "single-source, unreproduced"


def _merge_semgrep_into_slices(
    slices: list[dict[str, Any]], semgrep_signals: list[dict[str, Any]]
) -> None:
    """Fold Semgrep matches into the sg-core slices they corroborate.

    Matching rule: same file (basename) + same class + ±3 lines from the
    slice's sink line. When they match, append a `signal:semgrep:<check_id>`
    entry to the slice's `reason` string, which the Investigator forwards
    into evidence_used. Loose enough to catch scoring drift, tight enough
    to reject unrelated coincidences.

    Semgrep matches with NO corresponding sg-core slice remain as their own
    entries in the signals list (they retain `external_signal: True`), so
    the Investigator still judges them — recall stays intact.
    """
    import os

    for sig in list(semgrep_signals):
        sig_file = os.path.basename(sig["file"])
        sig_line = int(sig["sink"]["line"])
        sig_class = sig["sink"]["class"]
        sig_check = sig["sink"]["callee"]
        for sl in slices:
            if sl.get("external_signal"):
                continue
            if os.path.basename(sl["file"]) != sig_file:
                continue
            if sl["sink"]["class"] != sig_class:
                continue
            slice_line = int(sl["sink"]["line"])
            if abs(slice_line - sig_line) > 3:
                continue
            marker = f"signal:semgrep:{sig_check}"
            if marker not in sl.get("reason", ""):
                sl["reason"] = f"{sl.get('reason', '')} · {marker}"
            break


def _build_evidence(
    candidate: dict[str, Any],
    repro: dict[str, Any] | None,
    model_family: str,
    sweep_id: str,
) -> list[EvidenceItem]:
    """Construct the evidence list the ConsensusKernel expects from the data
    the orchestrator already has: the Investigator's evidence_used array and
    the Reproducer's result.

    - `static_analysis_fact` when sg-core marked the slice reachable
      (the "codegraph:source->sink reachable" sentinel in evidence_used).
    - `independent_agent` for the Investigator's own opinion, keyed on the
      model family + a per-finding context id so a same-model re-run wouldn't
      double-count.
    - `dynamic_reproduction` for the Reproducer, always its own modality.
    """
    evidence: list[EvidenceItem] = []
    evidence_used = candidate.get("evidence_used", []) or []
    if "codegraph:source->sink reachable" in evidence_used:
        evidence.append(
            EvidenceItem(
                modality="static_analysis_fact",
                origin={"tool": "sg-core", "context_id": f"{sweep_id}:codegraph"},
                result="confirmed",
                detail=evidence_used,
            )
        )
    # Tranche B3 — agentic sweep slices count as static-analysis facts too.
    # The AgenticScanner produces AST-derived agentic slices with the same
    # "reachable from source to sink" semantics as the code-graph; the
    # ConsensusKernel treats them identically for tier decisions.
    if "agentic:source->llm-sink" in evidence_used:
        evidence.append(
            EvidenceItem(
                modality="static_analysis_fact",
                origin={"tool": "agentic-scanner", "context_id": f"{sweep_id}:agentic"},
                result="confirmed",
                detail=evidence_used,
            )
        )
    # Signal Adapter — Semgrep. When any evidence_used entry starts with
    # `signal:semgrep:` we've got an INDEPENDENT external tool flagging
    # the same location. Different rule-authoring convention, different
    # engine, different vendor — the Consensus Kernel treats this as a
    # first-class independent corroborator per PRD §8.1.
    semgrep_hits = [
        e for e in evidence_used
        if isinstance(e, str) and "signal:semgrep" in e
    ]
    if semgrep_hits:
        evidence.append(
            EvidenceItem(
                modality="external_signal",
                origin={"tool": "semgrep", "context_id": f"{sweep_id}:semgrep"},
                result="confirmed",
                detail=semgrep_hits,
            )
        )
    # The Investigator's own verdict counts as an independent-agent vote for
    # the model that produced it. Two passes of the same model in the same
    # sweep would share the (family, context_id) key and collapse to one.
    evidence.append(
        EvidenceItem(
            modality="independent_agent",
            origin={
                "model_family": model_family,
                "context_id": f"{sweep_id}:investigator:{candidate.get('title', '')}",
                "role": "investigator",
            },
            result="confirmed",
            detail=candidate.get("root_cause"),
        )
    )
    if repro is not None:
        evidence.append(
            EvidenceItem(
                modality="dynamic_reproduction",
                origin={"tool": "reproducer", "context_id": f"{sweep_id}:repro"},
                result=repro.get("result", "inconclusive"),
                detail=repro.get("notes"),
            )
        )
    return evidence


def _extract_usage_tokens(payload: Any) -> int | None:
    """Pull a Moonshot-style `usage.prompt_tokens + completion_tokens` if present.

    Investigators return a judgment dict; if the model client threaded a
    `usage` block through, honor it. Otherwise return None and the caller
    falls back to a char-based estimate.
    """
    if not isinstance(payload, dict):
        return None
    usage = payload.get("usage") or payload.get("_usage")
    if not isinstance(usage, dict):
        return None
    pt = usage.get("prompt_tokens") or 0
    ct = usage.get("completion_tokens") or 0
    try:
        return int(pt) + int(ct)
    except (TypeError, ValueError):
        return None


def _estimate_tokens(payload: Any) -> int:
    """Conservative char-based estimate when the model didn't report usage."""
    return max(1, len(str(payload)) // 4)


class Orchestrator:
    def __init__(
        self,
        model: ModelClient | None = None,
        bus: EventBus | None = None,
        profile: Profile | None = None,
        cortex: Any = None,
        use_cortex: bool = True,
    ) -> None:
        # Priority: explicit model > Moonshot from env > mock.
        raw_model = model or maybe_from_env() or MockModelClient()
        # Wrap in the token-tracking proxy so every .complete() call lands
        # in _usage_by_role. Zero touches at call sites — the proxy is
        # transparent, forwards return values verbatim.
        self.model = _TrackingModel(raw_model, self)
        self.bus = bus or EventBus()
        self.profile = profile or get_profile(None)
        # Budget bookkeeping (reset at the start of each `run`).
        self._tokens_used: int = 0
        self._start_wall: float = 0.0
        # Per-role usage accumulator — {role: {model, calls, prompt_tokens,
        # completion_tokens, total_tokens}}. Populated by _TrackingModel;
        # aggregated into finding.audit.token_usage and sweep-level
        # metrics.token_usage at finalize time.
        self._usage_by_role: dict[str, dict[str, Any]] = {}
        # Per-sub-agent event log — one entry per model.complete() call.
        # Lets the analyst answer "how many tokens did SPOT-0001's verifier
        # cost?" not just "how many did the verifier role cost across the
        # whole sweep?". Capped at 500 entries per sweep to keep the
        # attestation payload bounded even on very-large repos.
        self._usage_events: list[dict[str, Any]] = []
        # Phase state machine bookkeeping.
        self._current_phase: str | None = None
        # Signing key held once per Orchestrator instance so each finding's
        # ChainOfCustody uses the same workspace key. Instantiated lazily
        # to avoid an import cycle if the non_repudiation module is stripped
        # in tests.
        self._signer: Any = None
        self._sweep_id: str | None = None
        # Cortex — the learned-policy + experience-memory layer.
        #
        #   * Explicit injection wins; otherwise we read SPOTLIGHT_CORTEX_DIR.
        #     None means "no memory", the default, byte-identical to the
        #     pre-Cortex pipeline.
        #   * `use_cortex=False` opts out entirely whatever the environment
        #     says. The eval harness needs that: a benchmark run that both
        #     trains the ledger AND is judged under a policy derived from it is
        #     measuring itself, and that benchmark gates CI.
        #   * The signer is materialized early only when a Cortex will actually
        #     use it (ledger rows are signed on append); the no-memory path
        #     keeps the original lazy-signing behaviour.
        self.cortex: Any = cortex if use_cortex else None
        cortex_dir = os.environ.get("SPOTLIGHT_CORTEX_DIR", "").strip()
        if use_cortex and self.cortex is None and cortex_dir:
            self._signer = _get_signer()
            self.cortex = _maybe_cortex(self._signer)
        elif self.cortex is not None and getattr(self.cortex, "signer", None) is not None:
            # An injected Cortex brings its own signer, and it signs every
            # ledger row with it. Adopt that key for this sweep's chain of
            # custody too: one workspace key must verify the whole sweep, or an
            # external auditor needs two public keys to check one attestation.
            # (In production both would resolve to SPOTLIGHT_SIGNING_KEY anyway;
            # this makes the guarantee hold without depending on that.)
            self._signer = self.cortex.signer
        # Policy pinned for the duration of a run. Pinning matters: a policy
        # activated halfway through a sweep must not tier the second half of
        # the findings differently from the first, or the attestation would
        # describe two different decision procedures under one signature.
        self._cortex_policy: Any = None
        self._cortex_pin: dict[str, Any] = {}
        self._cortex_lessons: list[Any] = []

    # ── budget helpers ────────────────────────────────────────────────
    def _wall_elapsed(self) -> float:
        if self._start_wall <= 0:
            return 0.0
        return time.monotonic() - self._start_wall

    def _budget_breach(self) -> tuple[str, int, int] | None:
        """Return ('tokens'|'wall', used, cap) if breached, else None."""
        if self._tokens_used >= self.profile.budget_tokens:
            return ("tokens", self._tokens_used, self.profile.budget_tokens)
        if self._wall_elapsed() >= self.profile.budget_wall_seconds:
            return ("wall", int(self._wall_elapsed()), self.profile.budget_wall_seconds)
        return None

    def _account_usage(self, judgment: Any) -> None:
        """Increment token counter from a judgment/model output."""
        used = _extract_usage_tokens(judgment)
        if used is None:
            used = _estimate_tokens(judgment)
        self._tokens_used += int(used)

    # ── cortex helpers ────────────────────────────────────────────────
    def _lessons_for_slice(self, slice_: dict[str, Any]) -> list[str]:
        """Prior-review observations relevant to one slice, as prompt strings.

        Advisory only, and capped by the LessonBook. Returns [] whenever there
        is no Cortex, no matching lesson, or anything goes wrong: an
        Investigator must never depend on memory being available, or two
        workspaces would judge the same slice differently for reasons nobody
        can see.
        """
        if self.cortex is None or not self._cortex_lessons:
            return []
        try:
            path = str(slice_.get("file") or "")
            cls = str((slice_.get("sink") or {}).get("class") or slice_.get("class_") or "")
            matched = self.cortex.lessons.for_slice(
                class_=cls, path=path, lessons=self._cortex_lessons
            )
            return [l.text for l in matched]
        except Exception as exc:  # noqa: BLE001
            print(f"[cortex] lesson lookup failed: {exc!r}")
            return []

    def _cortex_harvest(self, sweep_id: str, result: Any) -> dict[str, Any]:
        """Record this sweep's outcomes, then evolve if the gates allow.

        Order matters: harvest first so the evolution cycle sees this sweep's
        rows, and evolve *after* the attestation has been pinned to the policy
        that actually ran — a newly activated policy applies to the next sweep,
        never retroactively to this one.
        """
        report: dict[str, Any] = {}
        if self.cortex is None:
            return report
        try:
            written = self.cortex.record_sweep(result)
            report["experiences_recorded"] = written
            self.bus.emit(
                sweep_id, EventType.CORTEX_EXPERIENCE_RECORDED, "cortex",
                recorded=written, ledger_head=self.cortex.ledger.head(),
            )
        except Exception as exc:  # noqa: BLE001
            print(f"[cortex] harvest failed: {exc!r}")
            return report
        try:
            evolution = self.cortex.evolve()
            report["evolution"] = {
                "activated": evolution.activation.activated,
                "reason": evolution.activation.reason,
                "policy_id": evolution.activation.policy_id,
                "policy_version": evolution.activation.version,
                "approver": evolution.activation.approver,
                "shadow": evolution.proposal.shadow.to_dict(),
                "lessons_refreshed": evolution.lessons_refreshed,
                "lessons_quarantined": evolution.lessons_quarantined,
            }
            if evolution.activation.activated:
                self.bus.emit(
                    sweep_id, EventType.CORTEX_POLICY_ACTIVATED, "cortex",
                    policy_id=evolution.activation.policy_id,
                    version=evolution.activation.version,
                    approver=evolution.activation.approver,
                    autonomous=evolution.activation.approver == "cortex-autonomous",
                    shadow=evolution.proposal.shadow.to_dict(),
                )
            if evolution.lessons_quarantined:
                # A quarantined lesson means something tried to write an
                # instruction into our own memory. That is a Warden-class
                # event, not a bookkeeping detail.
                self.bus.emit(
                    sweep_id, EventType.CORTEX_LESSON_QUARANTINED, "cortex",
                    count=evolution.lessons_quarantined,
                )
        except Exception as exc:  # noqa: BLE001
            print(f"[cortex] evolution failed: {exc!r}")
        return report

    # ── phase state machine ───────────────────────────────────────────
    def _advance_phase(self, target: str, **payload: Any) -> bool:
        """Try to advance the phase state machine to `target`.

        Returns True if the transition was accepted and emitted, False if it
        was rejected as an illegal backwards jump. Repeatable per-finding
        phases (reproduce/remediate/verify/attest) can fire again without
        being flagged as backwards.
        """
        assert self._sweep_id is not None, "phase transition outside a run()"
        current = self._current_phase
        target_rank = _PHASE_RANK.get(target)
        if target_rank is None:
            self._emit_illegal(current, target)
            return False

        if current is not None:
            current_rank = _PHASE_RANK.get(current, -1)
            if target_rank < current_rank and target not in _REPEATABLE_PHASES:
                self._emit_illegal(current, target)
                return False

        self._current_phase = target
        self.bus.emit(
            self._sweep_id,
            EventType.SWEEP_PHASE_CHANGED,
            "orchestrator",
            phase=target,
            **payload,
        )
        return True

    def _emit_illegal(self, frm: str | None, to: str) -> None:
        msg = f"[orchestrator] illegal phase transition: {frm} -> {to}"
        print(msg, file=sys.stdout, flush=True)
        assert self._sweep_id is not None
        self.bus.emit(
            self._sweep_id,
            EventType.SWEEP_PHASE_ILLEGAL,
            "orchestrator",
            **{"from": frm, "to": to},
        )

    def _emit_budget_breach(self, kind: str, used: int, cap: int) -> None:
        assert self._sweep_id is not None
        self.bus.emit(
            self._sweep_id,
            EventType.SWEEP_BUDGET_EXCEEDED,
            "orchestrator",
            kind=kind,
            used=used,
            cap=cap,
        )

    # ── main entrypoint ───────────────────────────────────────────────
    def run(
        self,
        repo_path: str | Path,
        out_dir: str | Path | None = None,
        *,
        interactive: bool = False,
        sweep_id: str | None = None,
    ) -> SweepResult:
        repo_path = Path(repo_path).resolve()
        sweep_id = sweep_id or f"sw_{uuid4().hex[:12]}"
        out_dir = Path(out_dir) if out_dir else Path.cwd() / "sweep-run" / sweep_id
        out_dir.mkdir(parents=True, exist_ok=True)

        # Reset budget + phase state for this run.
        self._tokens_used = 0
        self._start_wall = time.monotonic()
        self._current_phase = None
        self._sweep_id = sweep_id

        emit = lambda t, actor, **p: self.bus.emit(sweep_id, t, actor, **p)
        emit(EventType.SWEEP_STARTED, "orchestrator", repo=str(repo_path))

        # 0. Pin the Cortex — one policy and one lesson set for the whole
        #    sweep. A policy activated mid-run must not tier the tail of the
        #    findings differently from the head, or one signed attestation
        #    would describe two decision procedures.
        self._cortex_policy = None
        self._cortex_pin = {}
        self._cortex_lessons = []
        if self.cortex is not None:
            try:
                self._cortex_policy = self.cortex.active_policy()
                self._cortex_pin = self.cortex.pin()
                self._cortex_lessons = self.cortex.served_lessons()
                emit(EventType.CORTEX_POLICY_PINNED, "cortex", **self._cortex_pin)
            except Exception as exc:  # noqa: BLE001 — memory is never fatal
                print(f"[cortex] pin failed: {exc!r}")
                self._cortex_policy = None

        # 1. PLAN — repo-native rule authoring runs BEFORE Recon so the
        #    CodeGraph + Semgrep pass both benefit from the tuned rules.
        #    Failures never crash the sweep — Recon just runs with default
        #    rules if the Planner errors out.
        self._advance_phase("plan")
        plan_out: Any = None
        try:
            from spotlight.planner import Planner

            emit(EventType.AGENT_SPAWNED, "orchestrator", role="planner")
            plan_out = Planner(self.model).plan(repo_path)
            emit(
                EventType.PLAN_RULES_WRITTEN,
                "planner",
                framework=plan_out.framework,
                rules_kept=len(plan_out.validation.kept),
                rules_rejected=len(plan_out.validation.rejected),
                extra_sinks_by_class={
                    k: len(v) for k, v in plan_out.sinks_by_class().items()
                },
            )
            emit(EventType.AGENT_FINISHED, "planner",
                 kept=len(plan_out.validation.kept),
                 rejected=len(plan_out.validation.rejected))
        except Exception as exc:
            print(f"[orchestrator] Planner failed: {exc!r}")
            plan_out = None

        # 2. Recon — check budget FIRST so an already-blown wall/token cap
        #    halts the sweep before we spawn any agent.
        self._advance_phase("recon")
        breach = self._budget_breach()
        if breach:
            self._emit_budget_breach(*breach)
            return self._finalize(
                sweep_id, repo_path, out_dir,
                recon_out={"threat_model": {}, "signals": [], "slices": []},
                findings=[],
            )
        emit(EventType.AGENT_SPAWNED, "orchestrator", role="recon")
        recon_out = Recon(self.model).run(repo_path, plan=plan_out)
        # Stash the plan on recon_out so downstream consumers (attestation,
        # UI) can render it without a second lookup.
        if plan_out is not None:
            recon_out["plan"] = plan_out.to_dict()
        self._account_usage(recon_out.get("threat_model", {}))
        emit(EventType.AGENT_FINISHED, "recon", signals=len(recon_out["signals"]))
        emit(
            EventType.RECON_THREAT_MODEL,
            "recon",
            threat_model=recon_out["threat_model"],
            stack=recon_out.get("threat_model", {}).get("stack", {}),
            signals_count=len(recon_out["signals"]),
            surfaces=recon_out["threat_model"].get("surfaces", []),
        )

        # Warden fan-out: one warden.injection.flagged event per Recon flag.
        # This is the ONE point in the orchestrator that talks to Warden —
        # everything else lives inside the roles.
        for flag in recon_out.get("warden_flags", []) or []:
            emit(
                EventType.WARDEN_INJECTION_FLAGGED,
                "warden",
                **flag,
            )

        # C2 · Interactive mode — pause after Recon so the user can edit the
        # threat model before the swarm goes into Investigate. The pause is
        # implemented as a threading.Event stored in a module-level
        # registry keyed by sweep_id; POST /sweeps/{id}/resume sets it.
        # We time-cap the wait so a browser that closes doesn't hang the
        # background thread forever.
        if interactive:
            emit(
                EventType.SWEEP_PAUSED_FOR_REVIEW,
                "orchestrator",
                threat_model=recon_out["threat_model"],
            )
            edits = _wait_for_resume(sweep_id, timeout_s=1800)
            if edits:
                # Shallow merge — top-level keys in the edited dict replace
                # the auto-generated Recon output. A signed audit entry lands
                # so downstream verifiers see the human diff.
                base = dict(recon_out.get("threat_model") or {})
                base.update(edits)
                recon_out["threat_model"] = base
                emit(
                    EventType.RECON_THREAT_MODEL,
                    "recon+human",
                    threat_model=base,
                    stack=base.get("stack", {}),
                    signals_count=len(recon_out["signals"]),
                    surfaces=base.get("surfaces", []),
                    edited=True,
                )

        # 2. Investigate — parallel fan-out under Profile.max_agents, guarded
        #    by budget. If a breach lands mid-fan-out we stop spawning.
        self._advance_phase("investigate")
        candidates: list[dict[str, Any]] = []
        slices = recon_out["signals"]

        # Signal Adapter merge — Semgrep hits at the same (file, line) as a
        # sg-core slice are folded INTO that slice's `reason` so the
        # Investigator sees them as one signal and _build_evidence attributes
        # the semgrep marker as an independent external corroborator.
        semgrep_signals = recon_out.get("semgrep_signals", []) or []
        _merge_semgrep_into_slices(slices, semgrep_signals)

        allowed_classes = set(self.profile.classes)
        active_slices = [
            s for s in slices if s["sink"]["class"] in allowed_classes
        ] if allowed_classes else slices

        # Agentic slices from the Agentic Sweep. Recon puts them on
        # `agentic_signals`; the Investigator prompt reads the same
        # `source`/`sink` sub-object shape as a classic slice, but each
        # agentic slice carries a `surface: "agentic"` marker so the model
        # (and downstream logic) can differentiate.
        agentic_signals = recon_out.get("agentic_signals", []) or []
        active_agentic = [
            a for a in agentic_signals
            if not allowed_classes or a.get("class_") in allowed_classes
        ]

        halted = False

        def _investigate(idx_slice):
            idx, slice_ = idx_slice
            emit(
                EventType.AGENT_SPAWNED,
                "orchestrator",
                role="investigator",
                slice=slice_,
                worker=f"inv-{idx}",
            )
            judgment = Investigator(self.model).run(
                slice_, lessons=self._lessons_for_slice(slice_)
            )
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

        def _investigate_agentic(idx_slice):
            """Same Investigator, different slice shape. The worker name
            uses `cog-N` so the Console can visually separate agentic
            work from classic AppSec fan-out."""
            idx, slice_ = idx_slice
            emit(
                EventType.AGENT_SPAWNED,
                "orchestrator",
                role="investigator",
                slice=slice_,
                worker=f"cog-{idx}",
            )
            judgment = Investigator(self.model).run(
                slice_, lessons=self._lessons_for_slice(slice_)
            )
            if not judgment:
                emit(EventType.AGENT_FINISHED, f"cog-{idx}", verdict="reject")
                return None
            existing = judgment.get("evidence_used", []) or []
            judgment["evidence_used"] = [
                "agentic:source->llm-sink",
                slice_.get("reason", ""),
                *existing,
            ]
            # Carry the surface marker so the consensus / finding record
            # keeps the code-vs-agentic split.
            judgment["surface"] = "agentic"
            judgment["owasp_llm"] = slice_.get("owasp_llm", "")
            emit(EventType.AGENT_FINISHED, f"cog-{idx}", verdict="candidate")
            emit(EventType.CANDIDATE_RAISED, f"cog-{idx}", candidate=judgment)
            return judgment

        # Budget check before each spawn batch so a runaway model can't keep
        # burning through slices. Parallelism kicks in only when we still have
        # multiple slices and headroom.
        idx = 0
        while idx < len(active_slices):
            breach = self._budget_breach()
            if breach:
                self._emit_budget_breach(*breach)
                halted = True
                break
            remaining = list(enumerate(active_slices))[idx:]
            max_workers = max(1, min(self.profile.max_agents, max(1, len(remaining))))
            if max_workers > 1 and len(remaining) > 1:
                with ThreadPoolExecutor(max_workers=max_workers) as pool:
                    for judgment in pool.map(_investigate, remaining):
                        if judgment:
                            candidates.append(judgment)
                            self._account_usage(judgment)
                idx = len(active_slices)
            else:
                pair = remaining[0]
                judgment = _investigate(pair)
                if judgment:
                    candidates.append(judgment)
                    self._account_usage(judgment)
                idx += 1

        # Now the agentic fan-out — same budget guard, same parallelism cap.
        aidx = 0
        while aidx < len(active_agentic) and not halted:
            breach = self._budget_breach()
            if breach:
                self._emit_budget_breach(*breach)
                halted = True
                break
            remaining = list(enumerate(active_agentic))[aidx:]
            max_workers = max(1, min(self.profile.max_agents, max(1, len(remaining))))
            if max_workers > 1 and len(remaining) > 1:
                with ThreadPoolExecutor(max_workers=max_workers) as pool:
                    for judgment in pool.map(_investigate_agentic, remaining):
                        if judgment:
                            candidates.append(judgment)
                            self._account_usage(judgment)
                aidx = len(active_agentic)
            else:
                pair = remaining[0]
                judgment = _investigate_agentic(pair)
                if judgment:
                    candidates.append(judgment)
                    self._account_usage(judgment)
                aidx += 1

        # 3. Reduce
        self._advance_phase("reduce")
        reduced = Reducer().run(candidates) if candidates else []

        # 3b. Chain — compose reduced candidates into cross-surface
        #     ExploitPath objects (Tranche B4). Runs regardless of whether
        #     the budget later busts on the Reproduce loop; the paths are
        #     derived purely from candidate metadata and cost ~nothing.
        #     The Chainer keys step.finding_id off candidate titles because
        #     it runs BEFORE the finding loop assigns SPOT-XXXX ids — we
        #     rewrite the step ids inside the finding loop below once each
        #     candidate has its concrete finding id.
        exploit_paths = Chainer().compose(reduced) if reduced else []

        # 3c. Hypothesis lane — one LLM call proposes plausible chains the
        #     Chainer didn't rule-match. Tagged tier="hypothesis" and never
        #     enters the signed/attested set. Analysts promote by adding a
        #     new Chainer rule.
        hypothesis_paths: list[dict[str, Any]] = []
        if reduced:
            try:
                hypothesis_paths = HypothesisProposer(self.model).propose(
                    candidates=reduced, verified=exploit_paths,
                )
            except Exception as exc:  # noqa: BLE001 — hypothesis lane must never crash the sweep
                print(f"[orchestrator] hypothesis proposer failed: {exc!r}")
                hypothesis_paths = []

        # Union: hypothesis paths sit alongside verified in the same list, but
        # each carries a `tier` field. Persistence, API, and Console filter/
        # split by `tier` — the reporter's signed attestation excludes any
        # tier != "verified".
        exploit_paths = list(exploit_paths) + list(hypothesis_paths)

        cand_key_to_path_and_step: dict[str, list[tuple[dict, dict]]] = {}
        for ep in exploit_paths:
            for step in ep["steps"]:
                key = step.get("finding_id") or ""
                if not key:
                    continue
                cand_key_to_path_and_step.setdefault(key, []).append((ep, step))

        # If the budget already busted, jump straight to Attest with partial
        # findings (empty here — nothing survived the halt).
        if halted or self._budget_breach() is not None:
            self._advance_phase("attest")
            return self._finalize(
                sweep_id, repo_path, out_dir, recon_out,
                findings=[], exploit_paths=exploit_paths,
            )

        # 4. Reproduce → Remediate → Verify per finding.
        findings: list[dict[str, Any]] = []
        # Instantiate the workspace signer once per sweep. The per-finding
        # ChainOfCustody instances below all use this shared signer so the
        # key_fingerprint on every entry matches — external verifiers only
        # need one public key to check the whole sweep.
        if self._signer is None:
            self._signer = _get_signer()

        for cand in reduced:
            breach = self._budget_breach()
            if breach:
                self._emit_budget_breach(*breach)
                break

            fid = stable_finding_id(cand, repo_root=repo_path)

            # Per-finding chain of custody. Append-only, signed at every
            # stage — a fabricated later entry can't retroactively rewrite
            # an earlier one because every entry is independently signed
            # against the workspace key.
            coc = _new_coc(self._signer)
            _coc_append(coc, "investigator", "candidate-raised", {
                "finding_id": fid,
                "class": cand.get("class"),
                "location": cand.get("location"),
                "evidence_used": cand.get("evidence_used", []),
            })

            self._advance_phase("reproduce", finding=fid)
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
            _coc_append(coc, "reproducer", "reproduction-attempted", {
                "finding_id": fid,
                "result": repro.get("result"),
                "engine": (repro.get("sandbox") or {}).get("engine"),
                "capability_token": (repro.get("sandbox") or {}).get("capability_token"),
                "egress_attempts": (repro.get("sandbox") or {}).get("egress_attempts", 0),
            })

            self._advance_phase("remediate", finding=fid)
            remediator = Remediator()
            remediation = remediator.run(repo_path, cand)
            if remediation.get("applied"):
                (out_dir / f"{fid}.diff").write_text(remediation["diff"])
                emit(EventType.REMEDIATION_OPENED, "remediator", finding=fid)
                _coc_append(coc, "remediator", "patch-generated", {
                    "finding_id": fid,
                    "diff_path": f"{fid}.diff",
                    "target_file": (cand.get("location") or {}).get("file"),
                })

            self._advance_phase("verify", finding=fid)
            verify = Verifier(self.model).run(repo_path, cand, remediation)
            self._account_usage(verify)
            emit(EventType.VERIFY_RESULT, "verifier", finding=fid, result=verify.get("result"))
            _coc_append(coc, "verifier", "reproduction-rechecked-after-patch", {
                "finding_id": fid,
                "result": verify.get("result"),
                "backdoor_check": verify.get("backdoor_check"),
                "backdoor_findings": verify.get("backdoor_findings", []),
                "independent_verifier": verify.get("independent_verifier", True),
            })

            # Optional: open a real PR via `gh`, gated by Profile.open_prs.
            # Only runs on git-cloned targets; log-and-continue on failure.
            pr_info: dict[str, Any] | None = None
            if getattr(self.profile, "open_prs", False) and remediation.get("applied"):
                pr_info = remediator.open_pr(
                    repo_path,
                    {"id": fid, **cand},
                    remediation,
                    open_prs=True,
                )
                if pr_info:
                    emit(
                        EventType.REMEDIATION_OPENED,
                        "remediator",
                        finding=fid,
                        pr_url=pr_info.get("pr_url"),
                        branch=pr_info.get("branch"),
                        commit_sha=pr_info.get("commit_sha"),
                    )

            evidence = _build_evidence(cand, repro, self.model.family, sweep_id)
            decision = ConsensusKernel().promote(
                cand,
                evidence,
                model=self.model,
                code_graph_slice=cand.get("location"),
                policy=self._cortex_policy,
            )
            if decision.cortex and decision.cortex.get("applied"):
                emit(
                    EventType.CORTEX_ADJUSTMENT_APPLIED,
                    "cortex",
                    finding=fid,
                    cohort=decision.cortex.get("cohort"),
                    policy_id=decision.cortex.get("policy_id"),
                    tier_before=decision.cortex.get("tier_before"),
                    tier_after=decision.tier,
                    confidence_before=decision.cortex.get("confidence_before"),
                    confidence_after=decision.confidence,
                    adjustments=decision.cortex.get("adjustments", []),
                )
            tier = decision.tier
            confidence = decision.confidence
            tier_reason = decision.rationale
            cls_ = cand.get("class", "")
            if cls_ in ("secrets", "hardcoded-secret") and tier == "verified":
                # Static-fact classes don't have a "fix" per se — the user has
                # to rotate the credential out-of-band. Label the state so the
                # UI can show the right guidance instead of "confirmed-fixed".
                state = "detected"
            elif verify.get("result") == "repro-now-blocked" and verify.get("backdoor_check") == "pass":
                state = "confirmed-fixed"
            elif tier == "verified" and repro.get("result") == "confirmed":
                state = "confirmed-open"
            else:
                state = "candidate"

            # If this candidate participated in an ExploitPath, tag the
            # finding and rewrite the step's placeholder id to the real
            # SPOT-XXXX so the UI can link both directions.
            cand_key = cand.get("id") or cand.get("finding_id") or cand.get("title") or ""
            exploit_path_id: str | None = None
            for ep, step in cand_key_to_path_and_step.get(cand_key, []):
                step["finding_id"] = fid
                if exploit_path_id is None:
                    exploit_path_id = ep["id"]

            # Normalize location + capture a code preview around the sink
            # BEFORE the tmpdir gets cleaned up. The preview lets the Console
            # render syntax-highlighted vulnerable code inline instead of
            # sending the analyst on a file-fetching detour.
            loc = dict(cand.get("location") or {})
            file_hint = loc.get("file", "")
            repo_relative = canonical_repo_path(file_hint, repo_path)
            loc["repo_relative_path"] = repo_relative
            code_preview = _capture_code_preview(
                file_hint, line=loc.get("line", 0), context=6
            )
            # Persist and expose only the canonical path. The original
            # checkout path is ephemeral and can contain host information.
            loc["file"] = repo_relative

            # Plain-language "why this matters" — best-effort; a model
            # exception falls back to a stub with the class name so the UI
            # can still render a placeholder card.
            plain_language: dict[str, str]
            try:
                plain_language = self.model.complete(
                    role="plain-language",
                    prompt="explain this finding to a non-security engineer",
                    context={"finding": {**cand, "id": fid}},
                ) or {}
                if not isinstance(plain_language, dict):
                    plain_language = {}
            except Exception as exc:
                print(f"[plain-language] failed for {fid}: {exc!r}")
                plain_language = {}

            finding = {
                "id": fid,
                "identity": finding_identity({**cand, "location": loc}),
                "surface": cand.get("surface", "code"),
                "title": cand["title"],
                "severity": cand["severity"],
                "class": cand["class"],
                "cwe": cand["cwe"],
                # Parent CWE family (e.g., CWE-95 rolls up under CWE-94).
                # Auditors and published advisories often tag at the parent
                # level, so we surface it here for exact-advisory matching.
                # Computed from the class label as a fallback when the
                # model didn't thread it (Moonshot's investigator prompt
                # isn't parent-CWE aware yet).
                "cwe_family": (
                    cand.get("cwe_family")
                    or _cwe_family_for_class(cand.get("class", ""))
                    or ""
                ),
                # For agentic findings we surface the OWASP-LLM code so the
                # UI + attestation can render the LLM01..LLM10 chip. Empty
                # for code-surface findings.
                "owasp_llm": cand.get("owasp_llm", ""),
                "location": loc,
                "code_preview": code_preview,
                "state": state,
                "tier": tier,
                "confidence": confidence,
                "owner": "unassigned",
                "exploit_path": exploit_path_id,
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
                    "fix": {
                        "diff": f"{fid}.diff" if remediation.get("applied") else None,
                        # C5 · Inline the diff text so the Console can render
                        # it without needing a file-serving endpoint. Capped
                        # at 32KB to keep the finding payload small in the WS
                        # + persistence pipelines.
                        "diff_content": (remediation.get("diff") or "")[:32_000]
                            if remediation.get("applied") else None,
                        "approach": cand["recommendation"],
                        "pr_url": pr_info.get("pr_url") if pr_info else None,
                        "branch": pr_info.get("branch") if pr_info else None,
                        "commit_sha": pr_info.get("commit_sha") if pr_info else None,
                    },
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
                # C3 · plain-language "why this matters" — surfaced on the
                # finding root so consumers don't have to dig into evidence.
                "plain_language": plain_language,
                "consensus": {
                    "tier": tier,
                    "confidence": confidence,
                    "independent_corroborators": decision.independent_corroborators,
                    "decision": "promote" if tier in ("verified", "high-confidence") else "hold",
                    "rationale": tier_reason,
                    "adjudication": decision.adjudication,
                    # Learned-policy provenance: the cohort this decision fell
                    # into, the immutable policy id that judged it, and exactly
                    # what changed. None when no Cortex was active.
                    "cortex": decision.cortex,
                },
                "audit": {
                    "model": self.model.family,
                    "deployment_tier": "t0-mock",
                    "profile": self.profile.id,
                    "profile_name": self.profile.name,
                    "commit": "<dev>",
                    "timestamp": None,
                    "tokens_used": int(self._tokens_used),
                    "wall_seconds": round(self._wall_elapsed(), 6),
                    # Per-agent token accounting — one snapshot per finding
                    # so downstream views can answer "how many tokens did
                    # SPOT-0001 cost per role?" without re-aggregating.
                    "token_usage": _snapshot_token_usage(self),
                    # Signed chain of custody — every stage that touched this
                    # finding appended one signed entry above. External
                    # verifiers replay against the workspace public key.
                    "chain_of_custody": _coc_finalize(
                        coc, actor="consensus", action="tier-decided",
                        payload={
                            "finding_id": fid,
                            "tier": tier,
                            "confidence": confidence,
                            "independent_corroborators": decision.independent_corroborators,
                            "rationale": tier_reason,
                            # Which learned policy judged this finding, and
                            # whether it changed anything. Signed, so a tier
                            # that differs from the evidence-only reading can
                            # always be traced to a named, immutable artifact.
                            "cortex_policy_id": (decision.cortex or {}).get("policy_id", ""),
                            "cortex_applied": bool((decision.cortex or {}).get("applied")),
                        },
                    ),
                },
            }
            findings.append(finding)
            (out_dir / f"verify_{fid}.json").write_text(json.dumps(verify, indent=2))
            emit(EventType.FINDING_PROMOTED, "consensus", finding=fid, tier=tier)

        # 4b. Emit one path.composed event per composed ExploitPath. We do
        #     this AFTER the finding loop so step.finding_id references have
        #     been rewritten from candidate placeholders to SPOT-XXXX ids.
        for ep in exploit_paths:
            emit(
                EventType.PATH_COMPOSED,
                "chainer",
                path_id=ep["id"],
                title=ep["title"],
                severity=ep["severity"],
                cross_surface=ep["cross_surface"],
                steps=len(ep["steps"]),
                step_finding_ids=[s["finding_id"] for s in ep["steps"]],
            )

        # 5. Attest
        self._advance_phase("attest")
        return self._finalize(
            sweep_id, repo_path, out_dir, recon_out, findings,
            exploit_paths=exploit_paths,
        )

    # ── finalization ──────────────────────────────────────────────────
    def _finalize(
        self,
        sweep_id: str,
        repo_path: Path,
        out_dir: Path,
        recon_out: dict[str, Any],
        findings: list[dict[str, Any]],
        exploit_paths: list[dict[str, Any]] | None = None,
    ) -> SweepResult:
        """Write attestation + supporting artifacts; return the SweepResult.

        Called from the normal happy path and from budget-breach halt paths.
        Idempotent enough: writes the current view of `findings` (possibly
        empty) so the caller always has an attestation on disk.
        """
        if self._current_phase != "attest":
            self._advance_phase("attest")
        exploit_paths = exploit_paths or []
        attestation = {
            "sweep_id": sweep_id,
            "repo": str(repo_path),
            "findings": findings,
            "threat_model": recon_out.get("threat_model", {}),
            # Planner output — auditors read this to see the repo-tuned
            # rules the sweep used. Empty when Planner isn't wired in.
            "plan": recon_out.get("plan", {}),
            "exploit_paths": exploit_paths,
            # Cortex pin — the learned policy id + experience-ledger head this
            # sweep ran under. Both are immutable, so the tier decisions in
            # this attestation stay re-derivable after the policy moves on.
            "cortex": dict(self._cortex_pin),
        }
        (out_dir / "attestation.json").write_text(json.dumps(attestation, indent=2))
        (out_dir / "findings.json").write_text(json.dumps(findings, indent=2))
        (out_dir / "exploit_paths.json").write_text(json.dumps(exploit_paths, indent=2))
        (out_dir / "threat_model.json").write_text(
            json.dumps(recon_out.get("threat_model", {}), indent=2)
        )
        (out_dir / "signals.json").write_text(
            json.dumps(recon_out.get("signals", []), indent=2)
        )
        self.bus.emit(
            sweep_id, EventType.ATTESTATION_WRITTEN, "reporter",
            path=str(out_dir / "attestation.json"),
        )

        result = SweepResult(
            sweep_id=sweep_id,
            repo_path=str(repo_path),
            threat_model=recon_out.get("threat_model", {}),
            signals=recon_out.get("signals", []),
            findings=findings,
            attestations=[attestation],
            events_log=[e.to_dict() for e in self.bus.replay(sweep_id)],
            exploit_paths=exploit_paths,
            token_usage=_snapshot_token_usage(self),
            usage_events=list(self._usage_events),
        )

        # Tranche B6: emit rich attestation + Markdown + PDF via Reporter.
        # Any failure here MUST NOT fail the sweep — the customer's findings
        # already landed. Log and continue.
        try:
            from spotlight.reporter import (
                PdfRenderError,
                Reporter,
                render_json,
                render_markdown,
                render_pdf,
            )

            # Sweep-level chain_of_custody = union of every finding's signed
            # entries, in emission order. External verifiers can spot-check
            # any single entry against the workspace public key without
            # needing the whole sweep tree.
            sweep_entries: list[dict] = []

            # If the Planner ran and produced a validated plan, sign one
            # entry recording exactly which rules were written for this
            # sweep. The plan's `rules_kept` count + `rejected` list are
            # part of the signed payload so an auditor can prove the
            # Planner's output wasn't tampered with after the fact.
            plan_dict = recon_out.get("plan") if recon_out else None
            if plan_dict and self._signer is not None:
                try:
                    plan_entry = self._signer.sign(
                        actor_kind="agent",
                        actor_id="planner",
                        action="plan.rules-written",
                        payload={
                            "framework": plan_dict.get("framework"),
                            "rules_kept": len(plan_dict.get("rules") or []),
                            "rules_rejected": (
                                plan_dict.get("validation", {}).get("rejected_count", 0)
                            ),
                        },
                    )
                    sweep_entries.append(plan_entry)
                except Exception as exc:
                    print(f"[orchestrator] plan-sign failed: {exc!r}")

            for f in result.findings:
                for entry in (f.get("audit") or {}).get("chain_of_custody") or []:
                    sweep_entries.append(entry)
            rich = Reporter().assemble(
                result,
                cortex=dict(self._cortex_pin) or None,
                warden_events=[
                    e for e in result.events_log
                    if e.get("type", "").startswith("warden.")
                    or e.get("type") == "sandbox.egress.denied"
                ],
                chain_of_custody={
                    "entries": sweep_entries,
                    "signature_verified": None,
                },
            )
            (out_dir / "attestation.json").write_text(render_json(rich))
            md = render_markdown(rich)
            (out_dir / "report.md").write_text(md)
            # Overwrite the in-memory attestation so downstream consumers
            # (API, tests) see the rich version.
            result.attestations = [rich]
            try:
                pdf_bytes = render_pdf(md)
                (out_dir / "report.pdf").write_bytes(pdf_bytes)
            except PdfRenderError as pdf_exc:
                # Lean deploy without reportlab — log + move on.
                print(f"[reporter] PDF skipped: {pdf_exc}", flush=True)
        except Exception as exc:
            print(f"[reporter] rich report failed: {exc!r}", flush=True)

        # Learn from what just happened. Runs after the attestation is written
        # so this sweep's record is already sealed under the policy that judged
        # it; anything the Cortex activates here applies to the NEXT sweep.
        cortex_report = self._cortex_harvest(sweep_id, result)
        if cortex_report:
            for att in result.attestations:
                if isinstance(att, dict):
                    block = dict(att.get("cortex") or {})
                    block["harvest"] = cortex_report
                    att["cortex"] = block
            try:
                (out_dir / "attestation.json").write_text(
                    json.dumps(result.attestations[0], indent=2)
                    if result.attestations else "{}"
                )
            except Exception as exc:  # noqa: BLE001
                print(f"[cortex] attestation rewrite failed: {exc!r}")

        self.bus.emit(
            sweep_id, EventType.SWEEP_FINISHED, "orchestrator",
            findings=len(findings),
        )
        # Refresh events log so the persisted JSONL includes sweep.finished.
        result.events_log = [e.to_dict() for e in self.bus.replay(sweep_id)]
        (out_dir / "events.jsonl").write_text(
            "\n".join(json.dumps(e) for e in result.events_log)
        )
        return result
