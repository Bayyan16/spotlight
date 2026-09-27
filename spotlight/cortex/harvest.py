"""Harvest — turning finished work into memory.

Two entry points, matching the two moments truth arrives:

* ``experiences_from_sweep()`` runs at the end of a sweep, when the Reproducer
  and Verifier have said what they can say.
* ``experience_from_review()`` runs when an analyst files a verdict through
  ``POST /findings/{id}/review``, which is the only place a *human* label can
  come from and therefore the most valuable row the ledger will ever hold.

The evidence signature is reconstructed from the finding's own
``evidence.corroboration`` block rather than re-plumbed through the
orchestrator, so a review that arrives weeks later — from a persisted row,
with the sweep long gone — produces exactly the same cohort as the sweep did.
The reconstruction mirrors ``orchestrator._build_evidence``; if a modality is
added there, add it here or the two will silently disagree about which cohort a
finding belongs to. The unit tests in ``tests/unit/test_cortex_harvest.py``
pin the mapping.

Nothing derived from target file contents is recorded. ``code_preview``,
``root_cause`` prose, and diff text are all deliberately left behind: the
ledger feeds prompts, and a prompt-shaped memory of attacker-controlled bytes
is a persistent injection channel (see `lessons.py`).
"""
from __future__ import annotations

from typing import Any, Iterable

from .experience import (
    STATIC_FACT_CLASSES,
    Experience,
    cohort_key,
    evidence_signature,
    is_weak_negative,
    label_for,
)

# Sentinels the Investigator writes into `evidence_used`. Kept here as named
# constants so the coupling with sg-core / the agentic scanner is greppable.
_CODEGRAPH_FACT = "codegraph:source->sink reachable"
_AGENTIC_FACT = "agentic:source->llm-sink"
_SEMGREP_MARKER = "signal:semgrep"


def _corroboration(finding: dict[str, Any]) -> list[dict[str, Any]]:
    evidence = finding.get("evidence") or {}
    items = evidence.get("corroboration") or []
    return [i for i in items if isinstance(i, dict)]


def _evidence_details(finding: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for item in _corroboration(finding):
        detail = item.get("detail")
        if isinstance(detail, str):
            out.append(detail)
        elif isinstance(detail, (list, tuple)):
            out.extend(str(d) for d in detail)
    # Some callers (delta view, review path) only have the flat list.
    for entry in finding.get("evidence_used") or []:
        out.append(str(entry))
    return out


def modalities_from_finding(finding: dict[str, Any]) -> list[str]:
    """Reconstruct the Consensus Kernel's modality set for this finding.

    Deliberately conservative: a modality is only claimed when the finding
    carries its marker. An over-claimed modality would place the row in a
    cohort it did not earn, which is how a calibration table starts lying.
    """
    details = _evidence_details(finding)
    joined = " ".join(details)
    modalities: list[str] = []
    if _CODEGRAPH_FACT in joined or _AGENTIC_FACT in joined:
        modalities.append("static_analysis_fact")
    if _SEMGREP_MARKER in joined:
        modalities.append("external_signal")
    # An Investigator judged every candidate that got this far — that is the
    # one modality present by construction.
    modalities.append("independent_agent")
    if repro_result(finding):
        modalities.append("dynamic_reproduction")
    return modalities


def repro_result(finding: dict[str, Any]) -> str:
    for item in _corroboration(finding):
        if item.get("type") == "reproduction":
            return str(item.get("result") or "")
    sandbox = ((finding.get("evidence") or {}).get("sandbox") or {}).get("reproducer") or {}
    return str(sandbox.get("result") or "")


def _has_static_fact(finding: dict[str, Any]) -> bool:
    return "static_analysis_fact" in modalities_from_finding(finding)


def _features(finding: dict[str, Any]) -> dict[str, Any]:
    """Structural features only — no target file content. See module docstring."""
    location = finding.get("location") or {}
    threat_model = ((finding.get("evidence") or {}).get("threat_model") or {})
    stack = threat_model.get("stack") or {}
    return {
        "path": str(location.get("repo_relative_path") or location.get("file") or ""),
        "function": str(location.get("function") or ""),
        "language": str(stack.get("language") or ""),
        "framework": str(stack.get("framework") or ""),
        "profile": str(threat_model.get("profile") or ""),
        "severity": str(finding.get("severity") or ""),
        "exploit_path": bool(finding.get("exploit_path")),
    }


def _finding_key(finding: dict[str, Any]) -> str:
    identity = finding.get("identity") or {}
    key = str(identity.get("fingerprint") or "")
    if key:
        return key
    # Fall back to deriving identity (older persisted rows predate the field).
    from spotlight.finding_identity import finding_identity

    return finding_identity(finding)["fingerprint"]


def experience_from_finding(
    finding: dict[str, Any],
    *,
    sweep_id: str,
    repo: str = "",
    commit_sha: str = "",
    review_state: str | None = None,
    review_reason: str = "",
) -> Experience:
    """Build one Experience from a finished finding dict."""
    class_ = str(finding.get("class") or "")
    modalities = modalities_from_finding(finding)
    signature = evidence_signature(modalities)
    repro = repro_result(finding)
    verification = (finding.get("evidence") or {}).get("verification") or {}
    review = finding.get("review") or {}
    state = review_state if review_state is not None else review.get("state")
    reason = review_reason or str(review.get("reason") or "")

    label, source, why = label_for(
        class_=class_,
        repro_result=repro,
        review_state=state,
        has_static_fact=("static_analysis_fact" in modalities)
        or (class_ in STATIC_FACT_CLASSES and _has_static_fact(finding)),
        review_reason=reason,
    )
    return Experience(
        sweep_id=sweep_id or str(finding.get("sweep_id") or ""),
        finding_key=_finding_key(finding),
        class_=class_,
        cohort=cohort_key(class_, signature),
        signature=signature,
        tier=str(finding.get("tier") or ""),
        confidence=float(finding.get("confidence") or 0.0),
        label=label,
        label_source=source,
        label_reason=why,
        weak_negative=is_weak_negative(repro),
        repro_result=repro,
        verify_result=str(verification.get("result") or ""),
        backdoor_check=str(verification.get("backdoor_check") or ""),
        surface=str(finding.get("surface") or "code"),
        cwe=str(finding.get("cwe") or ""),
        features=_features(finding),
        repo=repo,
        commit_sha=commit_sha,
    )


def experiences_from_sweep(
    sweep_result: Any, *, repo: str = "", commit_sha: str = ""
) -> list[Experience]:
    """Harvest every finding from a SweepResult (or any object like one)."""
    sweep_id = str(getattr(sweep_result, "sweep_id", "") or "")
    findings: Iterable[dict[str, Any]] = getattr(sweep_result, "findings", []) or []
    repo = repo or str(getattr(sweep_result, "repo_path", "") or "")
    return [
        experience_from_finding(f, sweep_id=sweep_id, repo=repo, commit_sha=commit_sha)
        for f in findings
        if isinstance(f, dict)
    ]


def experience_from_review(
    finding: dict[str, Any],
    *,
    review_state: str,
    reason: str = "",
    sweep_id: str = "",
) -> Experience:
    """Harvest the human verdict — the highest-authority row in the ledger."""
    return experience_from_finding(
        finding,
        sweep_id=sweep_id or str(finding.get("sweep_id") or ""),
        review_state=review_state,
        review_reason=reason,
    )
