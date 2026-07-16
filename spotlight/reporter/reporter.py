"""Attestation v2 assembler + Markdown renderer.

Everything the bank asks for on the "prove it" page lives here:

- Executive summary (findings count, verified count, wall-clock).
- Threat model box (surfaces, untrusted sources, high-impact sinks, stack).
- Per-finding cards — title, tier badge, evidence, sandbox line, and a
  "why you can trust this" paragraph derived from the consensus rationale.
- Exploit paths (if the Reproducer produced any).
- Warden self-defense record — count of injection flags + egress denials.
- Non-repudiation chain of custody with a signature-status line so the
  reader can tell at a glance whether the chain still verifies against the
  workspace key.
- Metrics table (tokens, wall-clock, sandbox duration).

The output is deliberately deterministic-ish: keys are sorted, timestamps go
through a single formatter, and there's no reliance on dict-insertion order
for section content. Two sweeps with the same inputs produce byte-identical
Markdown, which is what makes diffing attestations useful in review.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable


# ── module-level helpers ─────────────────────────────────────────────────

_REPORT_SCHEMA_VERSION = "2.0"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _events_of_type(events: Iterable[dict], type_: str) -> list[dict]:
    return [e for e in events or [] if e.get("type") == type_]


def _sum_sandbox_duration(events: Iterable[dict]) -> float:
    """Sum `duration_s` across every `sandbox.result` payload we've seen.

    A single sweep can spawn multiple sandboxes (one per finding, sometimes
    two — Reproducer + Verifier). We add them all up so the "how much
    compute did this sweep burn?" question has one number to point at.
    """
    total = 0.0
    for evt in _events_of_type(events, "sandbox.result"):
        payload = evt.get("payload") or {}
        raw = payload.get("duration_s")
        if raw is None:
            continue
        try:
            total += float(raw)
        except (TypeError, ValueError):
            continue
    return round(total, 6)


# ── assembly ─────────────────────────────────────────────────────────────


@dataclass
class Reporter:
    """Attestation v2 reporter.

    Stateless — safe to construct once at process start and re-use, or to
    create a fresh instance per sweep. The `assemble` call is where all the
    work happens; the render_* helpers are just formatters that consume the
    assembled dict.
    """

    def assemble(
        self,
        sweep_result: Any,
        warden_events: list[dict] | None = None,
        chain_of_custody: dict | None = None,
    ) -> dict[str, Any]:
        """Build the full attestation dict.

        ``sweep_result`` can be a real :class:`~spotlight.orchestrator.SweepResult`
        or any object exposing the same attributes. We pull ``warden_events``
        + ``chain_of_custody`` separately so this module doesn't have to know
        about the non-repudiation ledger's implementation details.
        """
        findings = list(getattr(sweep_result, "findings", []) or [])
        events = list(getattr(sweep_result, "events_log", []) or [])
        threat_model = getattr(sweep_result, "threat_model", {}) or {}
        sweep_id = getattr(sweep_result, "sweep_id", "")
        repo_path = getattr(sweep_result, "repo_path", "")

        warden_events = list(warden_events or [])
        # Fall back to whatever's on the events_log so callers can pass an
        # empty list and still get accurate counts.
        if not warden_events:
            warden_events = [
                e
                for e in events
                if e.get("type", "").startswith("warden.")
                or e.get("type") == "sandbox.egress.denied"
            ]

        # Pull the profile/audit block off any finding — every finding
        # carries the same profile stamp, so the first one is enough. Fall
        # back to a bare stub if there are no findings (empty sweep).
        first_audit = (findings[0].get("audit") if findings else {}) or {}
        profile_block = {
            "id": first_audit.get("profile", "unknown"),
            "name": first_audit.get("profile_name", first_audit.get("profile", "unknown")),
            "deployment_tier": first_audit.get("deployment_tier", "t0-mock"),
            "model": first_audit.get("model", "unknown"),
        }

        # ── verified count for the exec summary ──────────────────────────
        verified_count = sum(1 for f in findings if f.get("tier") == "verified")

        # ── exploit paths ────────────────────────────────────────────────
        # The Chainer is authoritative for the signed `exploit_paths` block.
        # If it composed zero chains, the attestation reports zero — per-
        # finding reproduction proofs live in `sandbox_proofs` below.
        #
        # Tranche B5 — the Hypothesis Proposer emits speculative chains
        # tagged tier="hypothesis". Those are surfaced separately in
        # `hypothesis_paths` and are NEVER included in the signed
        # `exploit_paths` set (that would grant a signed attestation to a
        # model-invented chain). Attestation viewers must render hypotheses
        # from `hypothesis_paths` under an explicit "unsigned" banner.
        _all_paths: list[dict] = list(
            getattr(sweep_result, "exploit_paths", []) or []
        )
        exploit_paths: list[dict] = [
            ep for ep in _all_paths if (ep.get("tier") or "verified") == "verified"
        ]
        hypothesis_paths: list[dict] = [
            ep for ep in _all_paths if ep.get("tier") == "hypothesis"
        ]

        # ── warden self-defense block ────────────────────────────────────
        warden_block = self._assemble_warden_block(warden_events, events)

        # ── sandbox proofs (per-finding: reproducer + verifier) ──────────
        sandbox_proofs: list[dict] = []
        for f in findings:
            sandbox_bundle = (f.get("evidence") or {}).get("sandbox") or {}
            for phase, payload in sandbox_bundle.items():
                if not payload:
                    continue
                sandbox_proofs.append(
                    {
                        "finding_id": f.get("id"),
                        "phase": phase,
                        "engine": payload.get("engine"),
                        "duration_s": payload.get("duration_s"),
                        "exit_code": payload.get("exit_code"),
                        "capability_token": payload.get("capability_token"),
                        "egress_attempts": payload.get("egress_attempts", 0),
                        "egress_denied_hosts": payload.get("egress_denied_hosts", []) or [],
                    }
                )

        # ── metrics table ────────────────────────────────────────────────
        wall_seconds = 0.0
        tokens_used = 0
        for f in findings:
            audit = f.get("audit") or {}
            wall_seconds = max(wall_seconds, float(audit.get("wall_seconds") or 0))
            tokens_used = max(tokens_used, int(audit.get("tokens_used") or 0))
        sandbox_total = _sum_sandbox_duration(events)

        metrics = {
            "findings_total": len(findings),
            "findings_verified": verified_count,
            "findings_high_confidence": sum(
                1 for f in findings if f.get("tier") == "high-confidence"
            ),
            "findings_needs_review": sum(
                1 for f in findings if f.get("tier") == "needs-review"
            ),
            "wall_seconds": round(wall_seconds, 6),
            "tokens_used": tokens_used,
            "sandbox_duration_s": sandbox_total,
            "events_total": len(events),
        }

        chain_of_custody = chain_of_custody or {"entries": [], "signature_verified": None}

        attestation = {
            # Top-level `sweep_id` is a backward-compat alias for v1 clients.
            # Canonical location is `meta.sweep_id` per v2 schema.
            "sweep_id": sweep_id,
            "meta": {
                "schema_version": _REPORT_SCHEMA_VERSION,
                "generated_at": _utc_now_iso(),
                "reporter": "spotlight.reporter@2.0",
                "sweep_id": sweep_id,
            },
            "target": {
                "repo": repo_path,
            },
            "profile": profile_block,
            "threat_model": threat_model,
            "findings": findings,
            "exploit_paths": exploit_paths,
            "hypothesis_paths": hypothesis_paths,
            "warden": warden_block,
            "chain_of_custody": chain_of_custody,
            "sandbox_proofs": sandbox_proofs,
            "metrics": metrics,
        }
        return attestation

    # ── warden block helper ──────────────────────────────────────────────
    def _assemble_warden_block(
        self, warden_events: list[dict], all_events: list[dict]
    ) -> dict[str, Any]:
        """Roll warden.injection.flagged + sandbox.egress.denied into one block.

        Tranche B6 spec: the Reporter's Warden section must include a count of
        injection flags AND a count of egress denials — the two signals that
        together mean "the swarm tried to attack the target and Warden shut
        it down." Both counts are surfaced separately AND together.
        """
        injection = [e for e in warden_events if e.get("type") == "warden.injection.flagged"]
        egress_denied = [
            e for e in warden_events if e.get("type") == "sandbox.egress.denied"
        ]
        # If the caller passed a filtered warden_events list we may have
        # missed egress denials from the main event stream — sweep those in
        # too so the count is always right.
        if not egress_denied:
            egress_denied = _events_of_type(all_events, "sandbox.egress.denied")

        return {
            "injection_flagged_count": len(injection),
            "egress_denied_count": len(egress_denied),
            "injection_flags": [
                {
                    "seq": e.get("seq"),
                    "actor": e.get("actor"),
                    "payload": e.get("payload", {}),
                }
                for e in injection
            ],
            "egress_denials": [
                {
                    "seq": e.get("seq"),
                    "finding": (e.get("payload") or {}).get("finding"),
                    "hosts": (e.get("payload") or {}).get("hosts", []),
                }
                for e in egress_denied
            ],
        }


# ── renderers ────────────────────────────────────────────────────────────


def render_json(attestation: dict) -> str:
    """Pretty-printed JSON with sorted keys so two runs diff cleanly."""
    return json.dumps(attestation, indent=2, sort_keys=True, default=str)


def _tier_badge(tier: str | None) -> str:
    """A short, printable tier tag. Kept ASCII so the PDF renderer doesn't
    have to fall back to a Unicode font (ReportLab's default Helvetica has
    no glyph coverage for emoji)."""
    label = (tier or "unknown").upper()
    return f"[{label}]"


def _md_escape(text: str | None) -> str:
    """Minimal Markdown escape — only characters that would break the reader
    when printed inside a table cell or a code-adjacent block. Full escaping
    is overkill for our stable, generated content."""
    if text is None:
        return ""
    return str(text).replace("|", "\\|").replace("\n", " ")


def _fmt_kv_list(pairs: list[tuple[str, Any]]) -> str:
    """Render a `- key: value` bullet list. Used inside cards where a two-
    column table would look silly for just three or four values."""
    return "\n".join(f"- **{k}**: {v}" for k, v in pairs if v not in (None, "", []))


def render_markdown(attestation: dict) -> str:
    """Human-readable Markdown report.

    Sections, in order:
      1. Title
      2. Executive summary
      3. Threat model
      4. Findings (one card per finding)
      5. Exploit paths (only if non-empty)
      6. Warden self-defense record
      7. Chain of custody
      8. Metrics table
    """
    meta = attestation.get("meta", {}) or {}
    target = attestation.get("target", {}) or {}
    profile = attestation.get("profile", {}) or {}
    tm = attestation.get("threat_model", {}) or {}
    findings = attestation.get("findings", []) or []
    exploit_paths = attestation.get("exploit_paths", []) or []
    hypothesis_paths = attestation.get("hypothesis_paths", []) or []
    warden = attestation.get("warden", {}) or {}
    coc = attestation.get("chain_of_custody", {}) or {}
    metrics = attestation.get("metrics", {}) or {}

    lines: list[str] = []

    # ── title ────────────────────────────────────────────────────────────
    sweep_id = meta.get("sweep_id", "unknown")
    lines.append(f"# Spotlight Attestation — sweep {sweep_id}")
    lines.append("")
    lines.append(
        f"_Generated at {meta.get('generated_at', 'unknown')} by "
        f"{meta.get('reporter', 'spotlight.reporter')}_"
    )
    lines.append("")
    lines.append(f"**Target**: `{target.get('repo', 'unknown')}`  ")
    lines.append(
        f"**Profile**: {profile.get('name', profile.get('id', 'unknown'))} "
        f"(model: `{profile.get('model', 'unknown')}`, "
        f"tier: `{profile.get('deployment_tier', 'unknown')}`)"
    )
    lines.append("")

    # ── executive summary ────────────────────────────────────────────────
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(
        f"- **Findings**: {metrics.get('findings_total', len(findings))} total"
        f" ({metrics.get('findings_verified', 0)} verified,"
        f" {metrics.get('findings_high_confidence', 0)} high-confidence,"
        f" {metrics.get('findings_needs_review', 0)} needs-review)"
    )
    lines.append(f"- **Wall-clock**: {metrics.get('wall_seconds', 0.0)}s")
    lines.append(f"- **Tokens used**: {metrics.get('tokens_used', 0)}")
    lines.append(
        f"- **Warden self-defense**: {warden.get('injection_flagged_count', 0)}"
        f" injection flags, {warden.get('egress_denied_count', 0)} egress denials"
    )
    lines.append("")

    # ── threat model ─────────────────────────────────────────────────────
    lines.append("## Threat Model")
    lines.append("")
    stack = tm.get("stack") or {}
    surfaces = tm.get("surfaces") or []
    tm_inner = tm.get("threat_model") or {}
    lines.append("> **Threat model at a glance**")
    lines.append(">")
    lines.append(f"> Surfaces: {', '.join(surfaces) if surfaces else 'n/a'}")
    lines.append(">")
    lines.append(
        f"> Untrusted sources: "
        f"{', '.join(tm_inner.get('untrusted_sources', []) or []) or 'n/a'}"
    )
    lines.append(">")
    lines.append(
        f"> High-impact sinks: "
        f"{', '.join(tm_inner.get('high_impact_sinks', []) or []) or 'n/a'}"
    )
    lines.append(">")
    lines.append(
        f"> Stack: {json.dumps(stack, sort_keys=True) if stack else 'n/a'}"
    )
    lines.append("")

    # ── findings ─────────────────────────────────────────────────────────
    lines.append("## Findings")
    lines.append("")
    if not findings:
        lines.append("_No findings promoted in this sweep._")
        lines.append("")
    for f in findings:
        fid = f.get("id", "?")
        title = f.get("title", "(untitled)")
        tier = f.get("tier")
        severity = f.get("severity", "unknown")
        cls = f.get("class", "unknown")
        cwe = f.get("cwe", "unknown")
        loc = f.get("location", {}) or {}
        evidence = f.get("evidence", {}) or {}
        consensus = f.get("consensus", {}) or {}
        sandbox_bundle = evidence.get("sandbox", {}) or {}
        repro_sandbox = sandbox_bundle.get("reproducer") or {}
        verify = evidence.get("verification", {}) or {}

        lines.append(f"### {fid} — {title} {_tier_badge(tier)}")
        lines.append("")
        lines.append(
            _fmt_kv_list(
                [
                    ("severity", severity),
                    ("class", cls),
                    ("CWE", cwe),
                    (
                        "location",
                        f"`{loc.get('file', '?')}:{loc.get('line', '?')}`"
                        f" in `{loc.get('function', '?')}`",
                    ),
                    ("state", f.get("state", "unknown")),
                    ("confidence", f.get("confidence")),
                ]
            )
        )
        lines.append("")

        # Evidence subsection
        lines.append("**Evidence**")
        lines.append("")
        for c in evidence.get("corroboration", []) or []:
            ctype = c.get("type", "?")
            if ctype == "reproduction":
                lines.append(
                    f"- Reproduction: `{c.get('result', 'unknown')}`"
                    f" (artifact: `{c.get('path', '?')}`)"
                )
            elif ctype == "static-fact":
                detail = c.get("detail")
                if isinstance(detail, list):
                    detail = "; ".join(str(x) for x in detail)
                lines.append(f"- Static fact: {detail}")
            else:
                lines.append(f"- {ctype}: {c}")
        lines.append("")

        # Sandbox line — one-liner that tells the auditor the finding was
        # exercised inside a locked-down capability sandbox.
        if repro_sandbox:
            lines.append(
                f"**Sandbox**: engine `{repro_sandbox.get('engine', '?')}`,"
                f" duration {repro_sandbox.get('duration_s', '?')}s,"
                f" exit {repro_sandbox.get('exit_code', '?')},"
                f" capability `{repro_sandbox.get('capability_token', 'n/a')}`"
            )
            lines.append("")

        # Why you can trust this — pulls the consensus rationale forward so
        # the reader doesn't have to read the JSON to know why this promoted.
        rationale = consensus.get("rationale") or "no rationale recorded"
        corroborators = consensus.get("independent_corroborators", 1)
        verified_status = "confirmed" if verify.get("independent_verifier") else "not-verified"
        lines.append(
            "**Why you can trust this**: "
            f"consensus rationale — _{rationale}_. "
            f"Independent corroborators: {corroborators}. "
            f"Verifier status: {verified_status}."
        )
        lines.append("")

    # ── exploit paths ────────────────────────────────────────────────────
    if exploit_paths:
        lines.append("## Exploit Paths")
        lines.append("")
        for ep in exploit_paths:
            loc = ep.get("location") or {}
            lines.append(
                f"- **{ep.get('finding_id')}** — {_md_escape(ep.get('title'))} "
                f"(`{ep.get('class')}` at `{loc.get('file', '?')}:{loc.get('line', '?')}`)"
                f" — reproduced in sandbox `{(ep.get('sandbox') or {}).get('engine', '?')}`,"
                f" verifier said `{ep.get('verification_result', '?')}`"
            )
        lines.append("")

    # ── hypothesis paths (Tranche B5, unsigned) ──────────────────────────
    if hypothesis_paths:
        lines.append("## Hypothesis Paths (unsigned — analyst review required)")
        lines.append("")
        lines.append(
            "> These chains were **proposed by the model** and did not match "
            "a deterministic Chainer rule. They are **not signed** and are "
            "**not** part of the attested finding set. Treat as leads, not "
            "conclusions."
        )
        lines.append("")
        for ep in hypothesis_paths:
            title = _md_escape(ep.get("title") or ep.get("id"))
            severity = ep.get("severity", "?")
            steps = ep.get("steps") or []
            chain_repr = " → ".join(
                f"`{s.get('class', '?')}` ({s.get('finding_id', '?')})" for s in steps
            )
            lines.append(f"- **{ep.get('id')}** — {title} · severity `{severity}` · {chain_repr}")
            if ep.get("rationale"):
                lines.append(f"  - Rationale: {_md_escape(ep['rationale'])}")
        lines.append("")

    # ── warden self-defense ──────────────────────────────────────────────
    lines.append("## Warden Self-Defense Record")
    lines.append("")
    lines.append(
        f"- **Injection flags**: {warden.get('injection_flagged_count', 0)}"
    )
    lines.append(
        f"- **Egress denials**: {warden.get('egress_denied_count', 0)}"
    )
    injection_flags = warden.get("injection_flags") or []
    if injection_flags:
        lines.append("")
        lines.append("**Injection flags**")
        lines.append("")
        for flag in injection_flags:
            payload = flag.get("payload") or {}
            lines.append(
                f"- seq {flag.get('seq', '?')}: {_md_escape(payload.get('rule') or payload.get('pattern') or 'flagged')}"
            )
    egress_denials = warden.get("egress_denials") or []
    if egress_denials:
        lines.append("")
        lines.append("**Egress denials**")
        lines.append("")
        for deny in egress_denials:
            hosts = ", ".join(deny.get("hosts") or []) or "(no hosts recorded)"
            lines.append(
                f"- finding `{deny.get('finding', '?')}`: {hosts}"
            )
    lines.append("")

    # ── chain of custody ─────────────────────────────────────────────────
    lines.append("## Non-Repudiation — Chain of Custody")
    lines.append("")
    entries = coc.get("entries") or []
    sig_ok = coc.get("signature_verified")
    if sig_ok is True:
        sig_line = "**Signature status**: VERIFIED — every entry validates against the workspace Ed25519 key."
    elif sig_ok is False:
        sig_line = "**Signature status**: FAILED — one or more entries did NOT verify."
    else:
        sig_line = "**Signature status**: not-verified (chain not signed for this sweep)"
    lines.append(sig_line)
    lines.append("")
    if entries:
        lines.append("| # | Actor | Kind | Action | Timestamp |")
        lines.append("|---|-------|------|--------|-----------|")
        for i, entry in enumerate(entries, start=1):
            lines.append(
                f"| {i} | {_md_escape(entry.get('actor_id'))} "
                f"| {_md_escape(entry.get('actor_kind'))} "
                f"| {_md_escape(entry.get('action'))} "
                f"| {_md_escape(entry.get('ts'))} |"
            )
    else:
        lines.append("_No chain-of-custody entries recorded for this sweep._")
    lines.append("")

    # ── metrics ──────────────────────────────────────────────────────────
    lines.append("## Metrics")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    for key in [
        "findings_total",
        "findings_verified",
        "findings_high_confidence",
        "findings_needs_review",
        "wall_seconds",
        "tokens_used",
        "sandbox_duration_s",
        "events_total",
    ]:
        lines.append(f"| {key} | {metrics.get(key, 0)} |")
    lines.append("")

    return "\n".join(lines)
