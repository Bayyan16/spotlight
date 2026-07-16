"""Agentic data-flow slice helper.

Mirrors the shape of `sg_core.DataFlowSlice` so downstream Investigator /
Consensus code can treat cognition findings and classic-code findings
identically. The only extra fields we add are:

  * `class_` — canonical taxonomy id (e.g. "prompt-injection")
  * `owasp_llm` — LLM01..LLM10 code
  * `surface` — always "agentic" so the Investigator can distinguish

The `to_dict` output is a superset of DataFlowSlice.to_dict so slicing code
that consumes it doesn't have to branch.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import rules


@dataclass
class AgenticDataFlow:
    file: str
    function: str
    source: str  # human string describing the untrusted origin
    sink: str  # human string describing the LLM/tool sink
    class_: str
    owasp_llm: str
    reason: str
    sanitized: bool = False
    line: int = 0
    surface: str = "agentic"

    def to_dict(self) -> dict[str, Any]:
        # Superset of DataFlowSlice.to_dict — keeps `source`/`sink` as
        # sub-objects so the Investigator template that reads
        # `slice_["sink"]["callee"]` still works.
        return {
            "file": self.file,
            "function": self.function,
            "source": {
                "name": self.source,
                "origin": self.source,
                "line": self.line,
            },
            "sink": {
                "callee": self.sink,
                "class": self.class_,
                "line": self.line,
                "argument": self.sink,
            },
            "sanitized": self.sanitized,
            "reason": self.reason,
            # Agentic-specific
            "class_": self.class_,
            "owasp_llm": self.owasp_llm,
            "surface": self.surface,
        }


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_dotted_name(node.value)}.{node.attr}"
    if isinstance(node, ast.Call):
        return _dotted_name(node.func)
    return ""


def _source_text(source: str, node: ast.AST) -> str:
    try:
        return ast.get_source_segment(source, node) or ""
    except Exception:
        return ""


def find_agentic_dataflow(files: list[Path]) -> list[AgenticDataFlow]:
    """Walk every Python file and emit AgenticDataFlow slices for cognition
    surface. Non-Python files are skipped (JS/TS agentic surface is a Phase-3
    upgrade — LangChain-JS support). Files that can't be parsed are skipped
    silently so a malformed target can't nuke the whole sweep.
    """
    out: list[AgenticDataFlow] = []
    for p in files:
        if p.suffix != ".py":
            continue
        try:
            source = p.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(p))
        except Exception:
            continue
        out.extend(_scan_python_file(p, source, tree))
    return out


def _collect_function_bodies(tree: ast.Module, source: str) -> dict[str, str]:
    """Map `function_name -> body source` so Tool(func=my_fn) can inherit
    my_fn's dangerous-call profile.
    """
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            body = ast.get_source_segment(source, node) or ""
            out[node.name] = body
    return out


def _scan_python_file(path: Path, source: str, tree: ast.Module) -> list[AgenticDataFlow]:
    """Emit agentic slices for one Python file.

    Prompt-injection: request-derived value → LLM sink (LangChain / OpenAI /
    Anthropic). Wrapped-in-sanitizer? mark sanitized=True.

    Output-handling: an identifier whose name suggests LLM output flows into
    a dangerous sink (eval/exec/subprocess/db.execute/.innerHTML).
    """
    out: list[AgenticDataFlow] = []
    function_bodies = _collect_function_bodies(tree, source)
    # Function-level walk so `function` on the slice is accurate.
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
            continue
        fn_name = getattr(node, "name", "<module>")
        fn_line = getattr(node, "lineno", 1)
        # Build the taint dict for this function scope.
        params = [a.arg for a in getattr(getattr(node, "args", None), "args", [])] if hasattr(node, "args") else []
        tainted: dict[str, str] = {}
        for p in params:
            if p in {"self", "cls"}:
                continue
            tainted[p] = f"param:{p}"

        # Track assignments so we can propagate taint AND spot llm-response vars.
        llm_tainted: dict[str, str] = {}
        # Walk children of this function only.
        children = list(ast.walk(node)) if not isinstance(node, ast.Module) else _module_top_level(node)
        for child in children:
            if isinstance(child, ast.Assign):
                rhs_src = _source_text(source, child.value)
                # If the whole RHS is wrapped in a sanitizer, the target
                # value is "clean" for downstream flow — this is the
                # false-positive killer for `q = escape(request.args.get(..))`
                # and similar patterns.
                rhs_sanitized = rules.is_sanitized(rhs_src)
                for target in child.targets:
                    if not isinstance(target, ast.Name):
                        continue
                    if rhs_sanitized:
                        # Sanitizer clears the taint; don't mark the target.
                        # If it was tainted from a prior assignment, keep
                        # the old marking (we only decide propagation on
                        # this one).
                        pass
                    elif rules.references_untrusted_py(rhs_src):
                        tainted[target.id] = "request.*"
                    else:
                        # Propagate from RHS identifiers.
                        refs = _identifiers(rhs_src)
                        if refs & tainted.keys():
                            tainted[target.id] = "request.*"
                    # LLM-taint: is the RHS a call to a model sink?
                    if isinstance(child.value, ast.Call):
                        callee = _dotted_name(child.value.func)
                        if rules.is_llm_sink(callee):
                            llm_tainted[target.id] = callee
                    # Fallback — variable name itself hints at LLM output.
                    if rules.is_llm_tainted_ident(target.id):
                        llm_tainted.setdefault(target.id, "llm-output")

        for child in children:
            if not isinstance(child, ast.Call):
                continue
            callee = _dotted_name(child.func)
            call_line = getattr(child, "lineno", fn_line)

            # ── Prompt injection (LLM01) ──────────────────────────────────
            if rules.is_llm_sink(callee):
                arg_srcs = [_source_text(source, a) for a in child.args] + [
                    _source_text(source, kw.value) for kw in child.keywords
                ]
                joined = "\n".join(arg_srcs)
                hits_untrusted = rules.references_untrusted_py(joined) or any(
                    n in _identifiers(joined) for n in tainted.keys()
                )
                if hits_untrusted:
                    sanitized = rules.is_sanitized(joined)
                    out.append(
                        AgenticDataFlow(
                            file=str(path),
                            function=fn_name,
                            source="request.* (untrusted user input)",
                            sink=callee,
                            class_="prompt-injection",
                            owasp_llm="LLM01",
                            reason=(
                                "user-controlled input reaches LLM sink without sanitizer"
                                if not sanitized
                                else "user input reaches LLM sink but a sanitizer wraps it"
                            ),
                            sanitized=sanitized,
                            line=call_line,
                        )
                    )

            # ── Output handling (LLM05) ──────────────────────────────────
            if rules.is_output_handling_sink(callee):
                arg_srcs = [_source_text(source, a) for a in child.args] + [
                    _source_text(source, kw.value) for kw in child.keywords
                ]
                joined = "\n".join(arg_srcs)
                refs = _identifiers(joined)
                # Either an identifier we tagged as LLM-tainted, OR a raw
                # attribute like `.content` / `.text` off an llm-response ident.
                llm_hits = refs & llm_tainted.keys()
                # Also: any identifier whose name hints at LLM output.
                name_hits = {r for r in refs if rules.is_llm_tainted_ident(r)}
                if llm_hits or name_hits:
                    out.append(
                        AgenticDataFlow(
                            file=str(path),
                            function=fn_name,
                            source=f"llm-output({sorted(llm_hits | name_hits)[0]})",
                            sink=callee,
                            class_="output-handling",
                            owasp_llm="LLM05",
                            reason="model output flows into a dangerous sink without validation",
                            sanitized=False,
                            line=call_line,
                        )
                    )

            # ── Excessive agency (LLM06) — Tool(...) ctor with dangerous fn ──
            if callee.endswith("Tool") or callee.endswith("StructuredTool") or callee.endswith("Tool.from_function"):
                arg_srcs = [_source_text(source, a) for a in child.args] + [
                    _source_text(source, kw.value) for kw in child.keywords
                ]
                joined = "\n".join(arg_srcs)
                # Look for dangerous callables referenced inside the Tool ctor's args.
                dangerous = None
                for needle in rules.EXCESSIVE_AGENCY_CALLEES:
                    if needle in joined:
                        dangerous = needle
                        break
                if dangerous is None:
                    # `open(` as a Tool callable — but be careful not to match
                    # `path.open`. Use a word-boundary regex.
                    if _has_bare_open(joined):
                        dangerous = "open"
                if dangerous is None:
                    # Indirect: `Tool(func=my_fn, ...)` where `my_fn` is
                    # defined in this file and its body contains a dangerous
                    # callable. This catches the LangChain-canonical
                    # pattern of pulling the tool body out into a named fn.
                    for ref in _identifiers(joined):
                        body = function_bodies.get(ref)
                        if not body:
                            continue
                        for needle in rules.EXCESSIVE_AGENCY_CALLEES:
                            if needle in body:
                                dangerous = needle
                                break
                        if dangerous is None and _has_bare_open(body):
                            dangerous = "open"
                        if dangerous is not None:
                            break
                if dangerous is not None:
                    # Scope-restriction heuristic: is there an allowlist var
                    # name mentioned in the Tool ctor's args?
                    has_scope = any(k in joined for k in ("allowlist", "allow_list", "allowed_hosts", "safe_urls", "scope"))
                    if not has_scope:
                        out.append(
                            AgenticDataFlow(
                                file=str(path),
                                function=fn_name,
                                source=f"tool-wrapped-callable({dangerous})",
                                sink=dangerous,
                                class_="excessive-agency",
                                owasp_llm="LLM06",
                                reason=f"LangChain Tool exposes {dangerous} to the agent without scope restriction",
                                sanitized=False,
                                line=call_line,
                            )
                        )

    return _dedup(out)


def _module_top_level(mod: ast.Module) -> list[ast.AST]:
    """For module-level scanning, walk every statement (and their children)."""
    result: list[ast.AST] = []
    for stmt in mod.body:
        # Only include children NOT inside a nested function/async function —
        # those get their own pass in _scan_python_file.
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for child in ast.walk(stmt):
            result.append(child)
    return result


def _identifiers(text: str) -> set[str]:
    import re

    return set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", text or ""))


def _has_bare_open(text: str) -> bool:
    """`open(` as a callable target, not `path.open(`."""
    import re

    return bool(re.search(r"(?<![.\w])open\s*\(", text))


def _dedup(items: list[AgenticDataFlow]) -> list[AgenticDataFlow]:
    """Collapse duplicates on (file, function, class_, line, sink)."""
    seen: dict[tuple, AgenticDataFlow] = {}
    for a in items:
        key = (a.file, a.function, a.class_, a.line, a.sink)
        if key not in seen:
            seen[key] = a
    return list(seen.values())
