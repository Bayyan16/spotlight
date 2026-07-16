"""JS/TS parser + source→sink rule engine for sg-core.

Regex-based first cut for Express / Fastify / Next.js API-route patterns. Not
tree-sitter-grade AST — pragmatic pattern matching that produces the same
DataFlowSlice shape as the Python sg-core so the orchestrator doesn't care
which language the target is in.

Covers:
  * Untrusted sources: `req.params`, `req.query`, `req.body`, `req.headers`,
    request handler args in Express-style `(req, res, next) =>`, `ctx.params`
    (Next.js API routes).
  * Sinks:
      - SQL exec: `db.query`, `.execute`, `.prepare`, `pool.query`,
        `mysql.query`, `pg.query`, better-sqlite `prepare().run/all/get`.
      - Command exec: `child_process.exec` / `execSync` / `spawn`.
      - Eval: `eval`, `new Function`, `Function(`.
      - SSRF: `fetch(`, `axios.get/post/put/delete`.
      - Unsafe HTML: `.innerHTML =`, `dangerouslySetInnerHTML`.

Sanitizer heuristics for SQLi negative case: parameterized `.query(sql, [args])`
or template-literal-safe libraries (`sql.identifier`, tagged template).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .graph import DataFlowSlice, Sink, Source


UNTRUSTED_ATTRS_JS = (
    "req.params",
    "req.query",
    "req.body",
    "req.headers",
    "request.params",
    "request.query",
    "request.body",
    "request.headers",
    "ctx.params",
    "ctx.query",
    "ctx.body",
)

# (regex_pattern, sink_class, canonical_callee) — pattern must capture the arg
# expression as group 1 for the interpolation check.
SINK_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    # SQL: db.query(`...${x}...`) or db.query('SELECT ...' + x)
    (re.compile(r"\b(?:db|pool|conn|connection|client|pg|mysql|sqlite|sql|knex)\.query\s*\(\s*([^)]+?)\)", re.DOTALL), "sqli", "db.query"),
    (re.compile(r"\.execute\s*\(\s*([^)]+?)\)", re.DOTALL), "sqli", ".execute"),
    (re.compile(r"\.prepare\s*\(\s*([^)]+?)\)\s*\.\s*(?:run|all|get)", re.DOTALL), "sqli", ".prepare().*"),
    # Command exec
    (re.compile(r"\b(?:child_process\.)?(?:exec|execSync|spawn|spawnSync)\s*\(\s*([^)]+?)\)", re.DOTALL), "cmdi", "child_process.exec"),
    # eval / new Function
    (re.compile(r"\beval\s*\(\s*([^)]+?)\)", re.DOTALL), "eval", "eval"),
    (re.compile(r"\bnew\s+Function\s*\(\s*([^)]+?)\)", re.DOTALL), "eval", "new Function"),
    # SSRF
    (re.compile(r"\bfetch\s*\(\s*([^,)]+)", re.DOTALL), "ssrf", "fetch"),
    (re.compile(r"\baxios\.(?:get|post|put|delete|patch|request)\s*\(\s*([^,)]+)", re.DOTALL), "ssrf", "axios.*"),
    # Unsafe HTML injection
    (re.compile(r"\.innerHTML\s*=\s*([^;]+)"), "xss", ".innerHTML="),
    (re.compile(r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html:\s*([^}]+)\}", re.DOTALL), "xss", "dangerouslySetInnerHTML"),
]


# Route detection so the finding.location includes the route.
ROUTE_PATTERN = re.compile(
    r"(?:app|router|api)\.(get|post|put|delete|patch|use)\s*\(\s*['\"`]([^'\"`]+)['\"`]"
)


@dataclass
class JsFunctionContext:
    file: str
    body: str
    start_line: int
    # Local variables and their assignment RHS (best-effort).
    assignments: dict[str, str]


def _line_of(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _identifiers(text: str) -> set[str]:
    return set(re.findall(r"[A-Za-z_$][\w$]*", text or ""))


def _is_parameterized_sql_call(arg_source: str) -> bool:
    """Heuristic: the FIRST arg is a bare string literal (no template
    interpolation, no concat) and there is at least one following arg
    (positional param array or `?`-marker query with values). We accept the
    arg block including the params array."""
    s = arg_source.strip()
    # If the arg block has a comma at top level, treat as having params.
    depth = 0
    has_comma_top = False
    for c in s:
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            has_comma_top = True
            break
    if not has_comma_top:
        return False
    first_arg = s.split(",", 1)[0].strip()
    # Must be a bare literal — starts and ends with matching quote, no `${`.
    if len(first_arg) < 2:
        return False
    quote = first_arg[0]
    if quote not in "'\"`":
        return False
    if quote == "`" and "${" in first_arg:
        return False
    if not first_arg.endswith(quote):
        return False
    # No concat
    if "+" in first_arg:
        return False
    return True


def parse_js_ts(path: Path) -> list[DataFlowSlice]:
    """Return the reachable source→sink slices in a JS/TS file.

    Emits slices ONLY when the tainted source expression appears inside the
    sink argument. Sanitizer detection is per-class: SQL parameterized calls
    are marked sanitized=True; others fall through as reachable.
    """
    source = path.read_text(encoding="utf-8", errors="replace")

    # Discover request-handler params: `(req, res, next) =>` or `function (req, res)`.
    # Then treat req.* accessors AND local vars assigned from req.* as tainted.
    slices: list[DataFlowSlice] = []

    # For each route registration, compute a taint set derived from the handler.
    for route_match in ROUTE_PATTERN.finditer(source):
        route_verb = route_match.group(1)
        route_path = route_match.group(2)
        # Body of the handler: naive match — take up to the next
        # matching route registration or end of file (Phase 2 upgrade: real
        # brace matching / AST).
        body_start = route_match.end()
        body_end = _next_route_start(source, body_start)
        handler_body = source[body_start:body_end]
        handler_line = _line_of(source, route_match.start())

        tainted_names = _tainted_vars_in_handler(handler_body)

        for sink_pat, cls_, canonical in SINK_PATTERNS:
            for m in sink_pat.finditer(handler_body):
                arg_src = m.group(1)
                arg_identifiers = _identifiers(arg_src)
                hit = arg_identifiers & tainted_names
                # Also flag if the raw arg_src references req.* directly.
                referenced_req = any(u in arg_src for u in UNTRUSTED_ATTRS_JS)
                if not hit and not referenced_req:
                    continue
                sanitized = False
                reason = f"tainted var(s) {sorted(hit) or '[req.*]'} reach {canonical}"
                if cls_ == "sqli" and _is_parameterized_sql_call(arg_src):
                    sanitized = True
                    reason = (
                        "parameterized query — first arg is a bare literal, "
                        "tainted values passed as bound params"
                    )
                source_name = sorted(hit)[0] if hit else "req"
                source_line = handler_line
                sink_line = _line_of(handler_body, m.start()) + handler_line - 1
                slices.append(
                    DataFlowSlice(
                        file=str(path),
                        function=f"{route_verb.upper()} {route_path}",
                        source=Source(
                            name=source_name,
                            origin=f"express:{route_verb}:{route_path}",
                            line=source_line,
                        ),
                        sink=Sink(
                            callee=canonical,
                            class_=cls_,
                            line=sink_line,
                            argument_source=arg_src.strip()[:200],
                        ),
                        sanitized=sanitized,
                        reason=reason,
                    )
                )
    return slices


def _next_route_start(source: str, from_offset: int) -> int:
    m = ROUTE_PATTERN.search(source, from_offset)
    return m.start() if m else len(source)


ASSIGN_PATTERN = re.compile(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)")
HANDLER_PARAM_PATTERN = re.compile(
    r"(?:async\s+)?\(?\s*(?P<params>[A-Za-z_$][\w$]*(?:\s*,\s*[A-Za-z_$][\w$]*)*)\s*\)?\s*=>"
    r"|function\s*\(\s*(?P<fnparams>[A-Za-z_$][\w$]*(?:\s*,\s*[A-Za-z_$][\w$]*)*)\s*\)"
)


def _tainted_vars_in_handler(handler_body: str) -> set[str]:
    """Compute the taint set for a handler body.

    Base sources: the first two named params of the handler (req/res-shaped).
    Then any `const foo = req.body.x` or destructure `const { id } = req.params`
    propagates taint. Iterate to fixed point.
    """
    tainted: set[str] = set()

    # Extract handler param names (req, res).
    m = HANDLER_PARAM_PATTERN.search(handler_body)
    if m:
        params_str = m.group("params") or m.group("fnparams") or ""
        names = [n.strip() for n in params_str.split(",") if n.strip()]
        # First param is conventionally `req` — treat as tainted vector.
        if names:
            tainted.add(names[0])

    # Destructure of tainted-attr: `const { id } = req.params`
    destructure_pattern = re.compile(
        r"(?:const|let|var)\s*\{\s*([^}]+?)\s*\}\s*=\s*(" + "|".join(re.escape(u) for u in UNTRUSTED_ATTRS_JS) + r")"
    )
    for m in destructure_pattern.finditer(handler_body):
        for name in [n.strip().split(":")[0].strip() for n in m.group(1).split(",")]:
            if name:
                tainted.add(name)

    # Simple `const x = req.body.foo`
    changed = True
    while changed:
        changed = False
        for m in ASSIGN_PATTERN.finditer(handler_body):
            target = m.group(1)
            rhs = m.group(2)
            if target in tainted:
                continue
            if any(u in rhs for u in UNTRUSTED_ATTRS_JS):
                tainted.add(target)
                changed = True
                continue
            refs = _identifiers(rhs)
            if refs & tainted:
                tainted.add(target)
                changed = True
    return tainted
