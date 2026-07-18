"""Extract Python + JavaScript CyberSecEval-Instruct rows that map to
Spotlight's detector classes, and drop each row's `origin_code` into a
standalone file under `snippets/` so sg-core can parse it as a real file.

Also emits a manifest at `snippets/manifest.json` linking each snippet
back to the source row (prompt_id, advisory CWE, expected pattern) for
the run script.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "datasets" / "cybersec_eval_instruct.json"
OUT_DIR = ROOT / "snippets"
MANIFEST = OUT_DIR / "manifest.json"


# CWE families Spotlight's sg-core `SINKS` maps onto today. Rows tagged with
# any CWE in these buckets are the ones we expect to detect; rows outside
# these buckets are filtered out (they're outside our surface — see
# arch-doc §12.6 for the six-gap plan).
TARGET_CWES = {
    "CWE-89",   # sqli
    "CWE-78",   # cmdi
    "CWE-95",   # eval-injection (child of CWE-94)
    "CWE-94",   # improper control of code generation (parent family)
    "CWE-918",  # ssrf
    "CWE-611",  # xxe (Semgrep passthrough only, no sg-core sink)
    "CWE-22",   # path traversal
    "CWE-502",  # deserialization
    "CWE-1336", # ssti (child of CWE-94)
    "CWE-327",  # weak hash
    "CWE-295",  # verify disabled
    "CWE-79",   # xss (partial via dangerouslySetInnerHTML)
}


def _smart_dedent(code: str) -> str:
    """Strip the minimum leading whitespace shared by every non-blank line.

    Handles mixed tab/space by expanding tabs to 4 spaces first. Works
    where `textwrap.dedent` silently gives up (which is why the first
    pass at this scored 5% — most snippets have mixed leading whitespace
    from being extracted mid-method).
    """
    code = code.expandtabs(4)
    lines = code.splitlines()
    non_blank = [l for l in lines if l.strip()]
    if not non_blank:
        return code
    min_indent = min(len(l) - len(l.lstrip(" ")) for l in non_blank)
    if min_indent == 0:
        return code
    return "\n".join(
        (l[min_indent:] if len(l) >= min_indent else l) for l in lines
    )


# Names commonly referenced as tainted inside CyberSecEval snippets. We
# turn them into function parameters of a synthetic `_target(...)` wrapper —
# sg-core's `_tainted_vars` marks every parameter as tainted by default, so
# any reference to these names inside the snippet becomes reachable.
_TAINTED_PARAMS = (
    "data", "sql", "cmd", "url", "path", "user_input", "payload",
    "content", "input", "query", "message", "filename", "arg", "value",
    "text", "params",
)


def _prepare_python(snippet: str, prompt_id: str) -> str | None:
    """Produce a parseable Python file with taint hung on function params.

    Strategy — every candidate wraps the snippet's body inside
    `def _target(data, sql, cmd, ...)`. sg-core marks every parameter as
    tainted by default (`_tainted_vars` in graph.py) so a reference to
    any of those names inside the body is reachable to whatever sink the
    snippet calls.

    Falls through on syntax errors:
      1. Try the dedented snippet as a def body.
      2. Try preserving original indentation as a def body.
      3. Try the raw snippet at module level (some snippets already
         contain their own `def foo(...):`) with the taint names as
         globals.
      4. Give up — the row is dropped, NOT scored as a miss.
    """
    params = ", ".join(_TAINTED_PARAMS)
    dedented = _smart_dedent(snippet).strip("\n")
    if not dedented:
        return None

    # Attempt 1: dedented body under def _target(...).
    body = "\n".join("    " + line for line in dedented.splitlines())
    candidate = f"# prompt_id={prompt_id}\ndef _target({params}):\n{body}\n"
    try:
        ast.parse(candidate)
        return candidate
    except SyntaxError:
        pass

    # Attempt 2: original indentation under def _target(...).
    body = "\n".join("    " + line for line in snippet.expandtabs(4).splitlines())
    candidate = f"# prompt_id={prompt_id}\ndef _target({params}):\n{body}\n"
    try:
        ast.parse(candidate)
        return candidate
    except SyntaxError:
        pass

    # Attempt 3: snippet at module level (snippets that already contain
    # their own def / class). Taint-seed via a module-level function so
    # the params-are-tainted rule fires when the snippet's own function
    # references any of these names.
    seed = f"def _taint_seed({params}):\n    pass\n"
    candidate = f"# prompt_id={prompt_id}\n{seed}\n{dedented}\n"
    try:
        ast.parse(candidate)
        return candidate
    except SyntaxError:
        return None


def _prepare_javascript(snippet: str, prompt_id: str) -> str:
    """sg-core's JavaScript parser only scans SINK_PATTERNS INSIDE Express
    route handlers (see `spotlight/sg_core/js_parser.py`). Raw React/JSX
    or Node library snippets never match a handler, so they produce zero
    slices even when they clearly contain vulnerable sinks like
    `dangerouslySetInnerHTML`.

    To give sg-core's JS parser a chance on non-Express code, we wrap the
    snippet in a synthetic `app.post('/target', (req, res) => { … })` so
    the parser's handler pattern fires. UNTRUSTED_ATTRS_JS in the parser
    include `req.body`, `req.query`, etc. — we also seed a couple of
    tainted vars from those so identifier-in-arg matches lands.
    """
    body = _smart_dedent(snippet).strip("\n")
    seed = (
        "const data = req.body.data;\n"
        "const sql = req.body.sql;\n"
        "const url = req.body.url;\n"
        "const cmd = req.body.cmd;\n"
        "const path = req.body.path;\n"
        "const content = req.body.content;\n"
    )
    wrapped = (
        f"// prompt_id={prompt_id}\n"
        f"app.post('/_target', (req, res) => {{\n"
        f"{seed}\n"
        f"{body}\n"
        f"}});\n"
    )
    return wrapped


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    # Clean any prior run so counts stay honest across regenerations.
    for old in OUT_DIR.glob("*.py"):
        old.unlink()
    for old in OUT_DIR.glob("*.js"):
        old.unlink()
    if MANIFEST.exists():
        MANIFEST.unlink()

    raw = json.loads(RAW.read_text())
    parse_dropped = 0
    kept: list[dict] = []
    dropped_lang = 0
    dropped_cwe = 0

    for r in raw:
        lang = r.get("language", "").lower()
        cwe = r.get("cwe_identifier", "")
        if lang not in ("python", "javascript"):
            dropped_lang += 1
            continue
        if cwe not in TARGET_CWES:
            dropped_cwe += 1
            continue

        prompt_id = str(r["prompt_id"])
        ext = ".py" if lang == "python" else ".js"
        snippet_path = OUT_DIR / f"{prompt_id}{ext}"

        origin = r.get("origin_code", "")
        prepared = (
            _prepare_python(origin, prompt_id)
            if lang == "python"
            else _prepare_javascript(origin, prompt_id)
        )
        if prepared is None:
            # Python snippet that neither raw-parsed nor wrapped-parsed —
            # counted as a filter drop, not scored as a miss. Honest.
            parse_dropped += 1
            continue
        snippet_path.write_text(prepared)

        kept.append({
            "prompt_id": prompt_id,
            "language": lang,
            "cwe_identifier": cwe,
            "pattern_desc": r.get("pattern_desc", "").strip(),
            "pattern_id": r.get("pattern_id", ""),
            "line_number": r.get("line_number"),
            "line_text": r.get("line_text", "").strip(),
            "repo": r.get("repo", ""),
            "file_path": r.get("file_path", ""),
            "snippet_path": str(snippet_path.relative_to(ROOT)),
        })

    MANIFEST.write_text(json.dumps(kept, indent=2))

    print(f"raw rows              : {len(raw)}")
    print(f"dropped (non py/js)   : {dropped_lang}")
    print(f"dropped (CWE off-surface): {dropped_cwe}")
    print(f"dropped (py parse fail): {parse_dropped}")
    print(f"kept                  : {len(kept)}")
    print(f"snippet files written : {len(kept)}  → {OUT_DIR.relative_to(ROOT)}/")

    # Per-CWE breakdown so the reader knows the shape.
    by_cwe: dict[str, dict[str, int]] = {}
    for r in kept:
        by_cwe.setdefault(r["cwe_identifier"], {"python": 0, "javascript": 0})
        by_cwe[r["cwe_identifier"]][r["language"]] += 1
    print("\n── kept rows by CWE × language ──")
    for cwe in sorted(by_cwe):
        c = by_cwe[cwe]
        print(f"  {cwe:12s} python={c['python']:3d}  javascript={c['javascript']:3d}")


if __name__ == "__main__":
    main()
