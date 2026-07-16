"""CognitionScanner — the top-level entrypoint for the Cognition Sweep.

Runs `find_agentic_dataflow` (the AST-driven prompt-injection / output-handling
/ excessive-agency detector) AND additional regex-scoped detectors for the
patterns that don't need a full data-flow slice (system-prompt-leak,
rag-surface, denial-of-wallet).

Returns a list of `CognitionFinding` — a thin wrapper around AgenticDataFlow
that's what Recon merges into `agentic_signals`.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import rules
from .dataflow import AgenticDataFlow, find_agentic_dataflow


@dataclass
class CognitionFinding:
    """One agentic signal — same shape as AgenticDataFlow, plus a `slice`
    accessor so the orchestrator's Investigator fan-out can consume it
    identically to a classic sg_core slice."""

    file: str
    function: str
    source: str
    sink: str
    class_: str
    owasp_llm: str
    reason: str
    sanitized: bool = False
    line: int = 0
    surface: str = "agentic"

    @classmethod
    def from_dataflow(cls, df: AgenticDataFlow) -> "CognitionFinding":
        return cls(
            file=df.file,
            function=df.function,
            source=df.source,
            sink=df.sink,
            class_=df.class_,
            owasp_llm=df.owasp_llm,
            reason=df.reason,
            sanitized=df.sanitized,
            line=df.line,
            surface=df.surface,
        )

    def to_dict(self) -> dict[str, Any]:
        return AgenticDataFlow(
            file=self.file,
            function=self.function,
            source=self.source,
            sink=self.sink,
            class_=self.class_,
            owasp_llm=self.owasp_llm,
            reason=self.reason,
            sanitized=self.sanitized,
            line=self.line,
            surface=self.surface,
        ).to_dict()


class CognitionScanner:
    """Run the OWASP-LLM rule packs over a target repo.

    Usage:
        scanner = CognitionScanner()
        findings = scanner.scan(repo_path, code_files)

    `code_files` is the pre-filtered file list Recon already computed —
    passing it in avoids a second rglob walk.
    """

    def scan(self, repo_path: Path, code_files: list[Path]) -> list[CognitionFinding]:
        results: list[CognitionFinding] = []

        # 1) AST data-flow rules: LLM01 prompt injection, LLM05 output
        #    handling, LLM06 excessive agency.
        for df in find_agentic_dataflow(code_files):
            if df.sanitized:
                # Still report but let the Investigator filter — mirrors
                # sg_core: sanitized slices land in `slices` not
                # `reachable_slices`. We keep them out of `agentic_signals`
                # so the orchestrator fan-out doesn't waste budget on them.
                continue
            results.append(CognitionFinding.from_dataflow(df))

        # 2) File-level regex rules that don't need dataflow.
        for f in code_files:
            if f.suffix != ".py":
                continue
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            results.extend(_scan_system_prompt_leak(f, text))
            results.extend(_scan_rag_surface(f, text))
            results.extend(_scan_denial_of_wallet(f, text))

        return _dedup(results)


# ─────────────────────────────────────────────────────────────────────────────
# LLM07 — system-prompt leak
# ─────────────────────────────────────────────────────────────────────────────

_SYSTEM_MSG_BLOCKS = re.compile(
    r"""
    (?:
        \{\s*['"]role['"]\s*:\s*['"]system['"][^{}]*?['"]content['"]\s*:\s*(['"])(?P<content1>.*?)(?<!\\)\1
        |
        SystemMessage\s*\(\s*(['"])(?P<content2>.*?)(?<!\\)\3
        |
        SystemMessagePromptTemplate\.from_template\s*\(\s*(['"])(?P<content3>.*?)(?<!\\)\5
    )
    """,
    re.VERBOSE | re.DOTALL,
)


def _scan_system_prompt_leak(path: Path, text: str) -> list[CognitionFinding]:
    out: list[CognitionFinding] = []
    for m in _SYSTEM_MSG_BLOCKS.finditer(text):
        content = m.group("content1") or m.group("content2") or m.group("content3") or ""
        line = text.count("\n", 0, m.start()) + 1
        for pat in rules.SECRET_LITERAL_PATTERNS:
            if pat.search(content):
                out.append(
                    CognitionFinding(
                        file=str(path),
                        function="<module>",
                        source="system-prompt literal",
                        sink="model (system role)",
                        class_="system-prompt-leak",
                        owasp_llm="LLM07",
                        reason="system prompt embeds a secret-shaped literal — leak risk",
                        line=line,
                    )
                )
                break

    # Also flag: system prompt content that is a user-controlled expression,
    # not a literal. e.g. `SystemMessage(request.args.get("prompt"))`.
    _sys_ctor = re.compile(
        r"(?:SystemMessage(?:PromptTemplate)?\s*(?:\.from_template)?\s*\(|['\"]role['\"]\s*:\s*['\"]system['\"][^{}]*?['\"]content['\"]\s*:\s*)([^,)}\n]+)",
        re.DOTALL,
    )
    for m in _sys_ctor.finditer(text):
        expr = m.group(1)
        if any(u in expr for u in rules.UNTRUSTED_PY):
            line = text.count("\n", 0, m.start()) + 1
            out.append(
                CognitionFinding(
                    file=str(path),
                    function="<module>",
                    source="request.* (untrusted)",
                    sink="SystemMessage(...)",
                    class_="system-prompt-leak",
                    owasp_llm="LLM07",
                    reason="system prompt content is user-controlled",
                    line=line,
                )
            )
    return out


# ─────────────────────────────────────────────────────────────────────────────
# LLM08 — RAG surface: vector store loaded from an env-var URL not on allowlist
# ─────────────────────────────────────────────────────────────────────────────

def _scan_rag_surface(path: Path, text: str) -> list[CognitionFinding]:
    out: list[CognitionFinding] = []
    for needle in rules.VECTOR_STORE_NEEDLES:
        # Look for the ctor call block with balanced-ish args.
        idx = 0
        while True:
            i = text.find(needle, idx)
            if i < 0:
                break
            idx = i + len(needle)
            block = _capture_call_block(text, i + len(needle) - 1)
            if not block:
                continue
            if not ("os.environ" in block or "os.getenv" in block or "process.env" in block):
                continue
            # Allowlisted URL host in the same block? Then not a finding.
            if any(host in block for host in rules.TRUSTED_VECTOR_HOSTS):
                continue
            line = text.count("\n", 0, i) + 1
            out.append(
                CognitionFinding(
                    file=str(path),
                    function="<module>",
                    source="env-var URL (unpinned)",
                    sink=needle.rstrip("("),
                    class_="rag-surface",
                    owasp_llm="LLM08",
                    reason="vector-store URL read from env with no host allowlist",
                    line=line,
                )
            )
    return out


def _capture_call_block(text: str, open_paren_idx: int) -> str:
    """Return the substring from `(` to its matching `)`, or "" if no match."""
    if open_paren_idx >= len(text) or text[open_paren_idx] != "(":
        return ""
    depth = 0
    for i in range(open_paren_idx, len(text)):
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren_idx : i + 1]
    return ""


# ─────────────────────────────────────────────────────────────────────────────
# LLM10 — denial of wallet: LLM call inside a loop with no budget knob
# ─────────────────────────────────────────────────────────────────────────────

def _scan_denial_of_wallet(path: Path, text: str) -> list[CognitionFinding]:
    """AST-walk: any `for`/`while` whose body contains an LLM sink call AND
    no rate-limit / max-iter / sleep marker.
    """
    out: list[CognitionFinding] = []
    try:
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return out

    for node in ast.walk(tree):
        if not isinstance(node, (ast.For, ast.While, ast.AsyncFor)):
            continue
        try:
            body_src = ast.get_source_segment(text, node) or ""
        except Exception:
            body_src = ""
        if not any(s in body_src for s in rules.LLM_SINK_NEEDLES):
            continue
        if any(k in body_src for k in rules.BUDGET_KNOB_NEEDLES):
            continue
        fn_name = _enclosing_function_name(tree, node) or "<module>"
        out.append(
            CognitionFinding(
                file=str(path),
                function=fn_name,
                source="loop",
                sink="LLM call (loop body)",
                class_="denial-of-wallet",
                owasp_llm="LLM10",
                reason="LLM call inside a loop with no max_iterations / rate limit / sleep",
                line=getattr(node, "lineno", 0),
            )
        )
    return out


def _enclosing_function_name(tree: ast.Module, target: ast.AST) -> str | None:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for child in ast.walk(node):
                if child is target:
                    return node.name
    return None


def _dedup(items: list[CognitionFinding]) -> list[CognitionFinding]:
    seen: dict[tuple, CognitionFinding] = {}
    for f in items:
        key = (f.file, f.function, f.class_, f.line, f.sink)
        if key not in seen:
            seen[key] = f
    return list(seen.values())
