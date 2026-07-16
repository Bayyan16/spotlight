"""Cross-Surface Exploit Path Chainer — Tranche B4.

Composes reduced Investigator/AgenticAnalyst candidates into ExploitPath
objects: linear chains of steps that model how one weakness lets an
attacker reach the next.

The killer chain we're demoing:

  indirect-prompt-injection (LLM01)  →  over-permissioned tool (LLM06)
                                     →  SSRF (CWE-918)
                                     →  data exfil

No scanner today composes across surfaces (agentic and code)
because they don't share a data model. Spotlight does because Recon +
Investigator + AgenticAnalyst all emit the same candidate dict; the
Chainer keys off `class` / `cwe` / repo path / function name.

Chaining rules (§ Phase-2 tranche B4 spec):

  1. agentic → code
     `prompt-injection` (LLM01) + `excessive-agency` (LLM06) on the same
     repo → chain. If the excessive-agency tool is `requests.get`/`fetch`
     and there's an `ssrf` code finding, extend the chain to 3 steps.
     Chain type: LLM01 → LLM06 → CWE-918.

  2. output-handling → code
     `output-handling` (LLM05) + `eval` or `cmdi` code finding on the
     same function name → chain. Chain type: LLM05 → CWE-95 / CWE-78.

  3. secrets → any
     `secrets` finding + ANY other promoted finding in the same repo →
     compose a "credential + primary vuln" pair. Banks care about this
     pairing because a hardcoded credential turns any RCE into
     lateral-movement fuel.

`cross_surface` is True iff steps span both `code` and `agentic`
surfaces. Steps are sorted deterministically: `agentic` first, then by
insertion order.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


# Canonical class labels we key off. Kept in one place so a rename in the
# Investigator/AgenticAnalyst doesn't quietly break the chainer.
_LLM01_CLASSES = {"prompt-injection", "indirect-prompt-injection", "llm01"}
_LLM05_CLASSES = {"output-handling", "insecure-output-handling", "llm05"}
_LLM06_CLASSES = {"excessive-agency", "over-permissioned-tool", "llm06"}
_SSRF_CLASSES = {"ssrf"}
_CODE_INJ_CLASSES = {"eval", "cmdi"}
_SECRETS_CLASSES = {"secrets", "hardcoded-secret"}

# Tools that (a) an agent can invoke and (b) enable SSRF when the URL is
# attacker-controlled. Used to gate the 3-step LLM01→LLM06→SSRF chain.
_SSRF_ENABLING_TOOLS = {"requests.get", "requests.post", "fetch", "http.get", "urllib.urlopen"}


def _norm(s: Any) -> str:
    return str(s or "").strip().lower()


def _cand_class(c: dict[str, Any]) -> str:
    return _norm(c.get("class"))


def _cand_surface(c: dict[str, Any]) -> str:
    surf = _norm(c.get("surface"))
    if surf:
        return surf
    # Agentic candidates carry `surface`; code candidates from the
    # Investigator don't set one — infer from class.
    cls = _cand_class(c)
    if cls in _LLM01_CLASSES | _LLM05_CLASSES | _LLM06_CLASSES:
        return "agentic"
    return "code"


def _cand_repo(c: dict[str, Any]) -> str:
    """Which repo does this candidate live in? Uses `repo` if the agentic
    analyst set it, else derives from the file location's top segment."""
    if c.get("repo"):
        return str(c["repo"])
    loc = c.get("location") or {}
    f = loc.get("file") or ""
    if not f:
        return ""
    # Best-effort: the repo id is usually the file's top directory. Two
    # findings in the same file will always match; two findings across
    # files in the same target both share the empty-repo bucket, which
    # is also what we want for the fixture scenario.
    return str(f).split("/", 1)[0]


def _cand_file(c: dict[str, Any]) -> str:
    return (c.get("location") or {}).get("file", "") or ""


def _cand_line(c: dict[str, Any]) -> int:
    try:
        return int((c.get("location") or {}).get("line", 0) or 0)
    except (TypeError, ValueError):
        return 0


def _cand_function(c: dict[str, Any]) -> str:
    return _norm((c.get("location") or {}).get("function"))


def _cand_id(c: dict[str, Any]) -> str:
    return c.get("id") or c.get("finding_id") or c.get("title") or ""


def _cand_tool(c: dict[str, Any]) -> str:
    """Excessive-agency findings should mention the tool they granted. Look
    in a couple of common places so we don't get boxed in by exact
    schema."""
    for key in ("tool", "tool_name", "callee"):
        v = c.get(key)
        if v:
            return _norm(v)
    return _norm((c.get("location") or {}).get("callee"))


def _order_step_sort(step: dict[str, Any]) -> tuple[int, int]:
    """agentic first, then by insertion order."""
    return (0 if step.get("surface") == "agentic" else 1, int(step.get("order", 0)))


def _severity_rank(sev: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(_norm(sev), 0)


def _max_severity(*cands: dict[str, Any]) -> str:
    best = ("low", 0)
    for c in cands:
        s = _norm(c.get("severity"))
        r = _severity_rank(s)
        if r > best[1]:
            best = (s, r)
    return best[0]


@dataclass
class Chainer:
    """Composes candidates into ExploitPaths.

    Stateless — one instance per orchestrator run is fine, but the
    `compose` call is pure.
    """

    def compose(self, candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not candidates:
            return []

        # Bucket by class for O(1) rule lookups. We iterate the input to
        # preserve deterministic insertion order (Reducer keeps it).
        by_class: dict[str, list[dict[str, Any]]] = {}
        for c in candidates:
            by_class.setdefault(_cand_class(c), []).append(c)

        def find(cls_set: set[str]) -> list[dict[str, Any]]:
            # Preserve insertion order by iterating the original candidate
            # list — set-iteration order is unstable across CPython versions
            # and could make path ids non-deterministic across runs.
            out: list[dict[str, Any]] = []
            for c in candidates:
                if _cand_class(c) in cls_set:
                    out.append(c)
            return out

        paths: list[dict[str, Any]] = []
        # De-dupe fingerprint: (rule_kind, tuple(step_ids)) — same set of
        # candidates should never produce two paths.
        seen: set[tuple] = set()

        def _next_id() -> str:
            return f"EP-{len(paths) + 1:04d}"

        def _add(rule: str, steps: list[dict[str, Any]], title: str,
                 severity: str, rationale: str) -> None:
            steps_sorted = sorted(steps, key=_order_step_sort)
            # Renumber orders so the caller sees 1..N after the sort.
            for i, s in enumerate(steps_sorted, start=1):
                s["order"] = i
            surfaces = {s["surface"] for s in steps_sorted}
            fingerprint = (rule, tuple(s["finding_id"] for s in steps_sorted))
            if fingerprint in seen:
                return
            seen.add(fingerprint)
            paths.append({
                "id": _next_id(),
                "title": title,
                "severity": severity,
                "cross_surface": ("code" in surfaces and "agentic" in surfaces),
                "steps": steps_sorted,
                "reproduced": False,  # repro composition is a later tranche
                "rationale": rationale,
            })

        # ── Rule 1: agentic → code ────────────────────────────────
        # LLM01 + LLM06 (same repo); optionally extend to SSRF.
        llm01s = find(_LLM01_CLASSES)
        llm06s = find(_LLM06_CLASSES)
        ssrfs = find(_SSRF_CLASSES)
        for pi in llm01s:
            for ea in llm06s:
                if _cand_repo(pi) != _cand_repo(ea):
                    continue
                # Try 3-step chain if we have a matching SSRF.
                extended = False
                if _cand_tool(ea) in _SSRF_ENABLING_TOOLS:
                    for ssrf in ssrfs:
                        if _cand_repo(ssrf) != _cand_repo(ea):
                            continue
                        steps = [
                            _step(1, pi, "indirect injection lands in system prompt / tool call"),
                            _step(2, ea, "over-permissioned tool executes attacker-supplied URL"),
                            _step(3, ssrf, "server-side fetch reaches internal / metadata host — data exfil"),
                        ]
                        _add(
                            rule="llm01-llm06-ssrf",
                            steps=steps,
                            title="Indirect prompt injection → over-permissioned tool → SSRF exfil",
                            severity=_max_severity(pi, ea, ssrf),
                            rationale=(
                                "Untrusted content lands in the model's context, "
                                "steers a tool call into an attacker-chosen URL, "
                                "which reaches an SSRF sink — a full cross-surface "
                                "exfil path."
                            ),
                        )
                        extended = True
                if not extended:
                    steps = [
                        _step(1, pi, "indirect injection lands in system prompt / tool call"),
                        _step(2, ea, "over-permissioned tool executes attacker-supplied action"),
                    ]
                    _add(
                        rule="llm01-llm06",
                        steps=steps,
                        title="Indirect prompt injection → over-permissioned tool",
                        severity=_max_severity(pi, ea),
                        rationale=(
                            "Injection controls the model's decisions; the granted "
                            "tool lets those decisions have real-world impact."
                        ),
                    )

        # ── Rule 2: output-handling → code (eval / cmdi, same function) ─
        llm05s = find(_LLM05_CLASSES)
        code_injs = find(_CODE_INJ_CLASSES)
        for oh in llm05s:
            for ci in code_injs:
                # Same function name — this is the key that catches "model
                # output was rendered/evaled unfiltered inside the same
                # handler".
                if _cand_function(oh) and _cand_function(oh) == _cand_function(ci):
                    steps = [
                        _step(1, oh, "unfiltered model output flows into downstream sink"),
                        _step(2, ci, f"attacker-controlled string reaches {_cand_class(ci)} sink"),
                    ]
                    cwe = "CWE-95" if _cand_class(ci) == "eval" else "CWE-78"
                    _add(
                        rule=f"llm05-{_cand_class(ci)}",
                        steps=steps,
                        title=f"Insecure output handling → {_cand_class(ci)} ({cwe})",
                        severity=_max_severity(oh, ci),
                        rationale=(
                            "Model output was passed downstream without validation "
                            f"and reached a {_cand_class(ci)} sink in the same function."
                        ),
                    )

        # ── Rule 3: secrets → any (same repo) ──────────────────────
        secrets = find(_SECRETS_CLASSES)
        # "Another promoted finding" = anything that isn't itself a secrets
        # finding. Iterate candidates (not by_class) so we don't lose
        # secondary findings whose class we don't specifically track.
        for sec in secrets:
            for other in candidates:
                if _cand_class(other) in _SECRETS_CLASSES:
                    continue
                if _cand_repo(sec) != _cand_repo(other):
                    continue
                steps = [
                    _step(1, sec, "hardcoded credential in source"),
                    _step(2, other, "primary vulnerability — credential amplifies blast radius"),
                ]
                _add(
                    rule="secrets-pairing",
                    steps=steps,
                    title=f"Hardcoded credential + {_cand_class(other) or 'primary'} in same repo",
                    severity=_max_severity(sec, other),
                    rationale=(
                        "A hardcoded secret paired with an exploitable primary "
                        "finding is bank-material: any RCE / SSRF / auth bypass "
                        "immediately turns into lateral movement."
                    ),
                )
        return paths


def _step(order: int, cand: dict[str, Any], edge: str) -> dict[str, Any]:
    """Materialize one ExploitPath step from a candidate dict."""
    return {
        "order": order,
        "finding_id": _cand_id(cand),
        "surface": _cand_surface(cand),
        "class": _cand_class(cand),
        "cwe": cand.get("cwe", ""),
        "file": _cand_file(cand),
        "line": _cand_line(cand),
        "edge": edge,
    }
