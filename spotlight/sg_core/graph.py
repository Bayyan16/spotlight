"""Code Graph: source→sink data-flow reachability.

This is the fact layer under the LLM's judgment. The rule is deliberately narrow
for Phase 1: a variable that came from an untrusted source (request param,
Flask/FastAPI arg, `request.args`, `request.form`, `request.json`) reaches a
dangerous sink (cursor.execute, subprocess.*, eval, os.system, requests.get on
a user-tainted URL). Parameterized calls are NOT reachable — that's the
false-positive killer.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .parser import ParsedFile, ParsedFunction, parse_python

UNTRUSTED_ATTRS = (
    "request.args",
    "request.form",
    "request.json",
    "request.values",
    "request.get_json",
    "request.data",
    "flask.request",
)

# Sinks classified by class label.
SINKS: dict[str, tuple[str, ...]] = {
    "sqli": ("cursor.execute", ".execute", "executemany", "execute_string"),
    "cmdi": ("os.system", "subprocess.run", "subprocess.call", "subprocess.Popen"),
    "eval": ("eval", "exec"),
    "ssrf": ("requests.get", "requests.post", "httpx.get", "urlopen"),
}


@dataclass
class Source:
    name: str  # root untrusted var name (before any propagation)
    origin: str  # e.g. "request.args", "param:username"
    line: int
    root: str | None = None  # for derived vars, the ROOT var name; else None


@dataclass
class Sink:
    callee: str
    class_: str  # sqli / cmdi / eval / ssrf
    line: int
    argument_source: str  # raw code of the tainted arg


@dataclass
class DataFlowSlice:
    file: str
    function: str
    source: Source
    sink: Sink
    sanitized: bool
    reason: str  # human-readable "why this is (or isn't) reachable"

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "function": self.function,
            "source": {"name": self.source.name, "origin": self.source.origin, "line": self.source.line},
            "sink": {
                "callee": self.sink.callee,
                "class": self.sink.class_,
                "line": self.sink.line,
                "argument": self.sink.argument_source,
            },
            "sanitized": self.sanitized,
            "reason": self.reason,
        }


def _classify_sink(callee: str) -> str | None:
    for cls, needles in SINKS.items():
        for needle in needles:
            if needle in callee:
                return cls
    return None


def _tainted_vars(fn: ParsedFunction) -> dict[str, Source]:
    """Map every tainted variable in the function (root OR derived) to the
    Source describing the ROOT untrusted entry point. That way sinks report
    "username reached execute", not "query reached execute".
    """
    tainted: dict[str, Source] = {}

    for p in fn.params:
        if p in {"self", "cls"}:
            continue
        tainted[p] = Source(name=p, origin=f"param:{p}", line=fn.line)

    for assign in fn.assigns:
        vs = assign.value_source or ""
        if any(u in vs for u in UNTRUSTED_ATTRS):
            tainted[assign.target] = Source(name=assign.target, origin="request.*", line=assign.line)

    # Fixed-point propagation: derived vars inherit the ROOT source.
    changed = True
    while changed:
        changed = False
        for assign in fn.assigns:
            if assign.target in tainted:
                continue
            refs = _arg_names(assign.value_source)
            hit = refs & tainted.keys()
            if hit:
                root_src = tainted[sorted(hit)[0]]
                tainted[assign.target] = root_src
                changed = True
    return tainted


def _arg_is_parameterized(arg_source: str) -> bool:
    """Is this a safe parameterized query call?

    Heuristic: parameterized DB-API calls look like `execute("SELECT ... WHERE
    x = %s", (val,))` or `execute("... = ?", (val,))`. If the *first* argument
    is a bare string literal with no interpolation, and the call has a second
    argument, treat it as parameterized. That's what the negative fixture uses.
    """
    if not arg_source:
        return False
    stripped = arg_source.strip()
    if stripped.startswith(("f'", 'f"')):
        return False
    if "%" in stripped and "%s" not in stripped:
        return False
    if "+" in stripped or ".format(" in stripped:
        return False
    # Bare literal
    if stripped.startswith(("'", '"')) and stripped.endswith(("'", '"')):
        return True
    return False


def _arg_names(arg_source: str) -> set[str]:
    """Grab identifier-shaped substrings from a raw arg expression."""
    import re

    return set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", arg_source or ""))


@dataclass
class CodeGraph:
    files: list[ParsedFile] = field(default_factory=list)
    _js_paths: list[Path] = field(default_factory=list)
    _secrets_roots: list[Path] = field(default_factory=list)

    @classmethod
    def build(cls, paths: Iterable[str | Path], scan_secrets_in: Iterable[str | Path] | None = None) -> "CodeGraph":
        paths_list = list(paths)
        py_paths = [Path(p) for p in paths_list if str(p).endswith(".py")]
        parsed = [parse_python(p) for p in py_paths]
        js_paths = [Path(p) for p in paths_list if str(p).endswith((".js", ".ts", ".jsx", ".tsx"))]
        graph = cls(files=parsed)
        graph._js_paths = js_paths
        # Secrets scanner: walk any provided root(s). By default we scan
        # each unique parent directory of the input paths so the caller
        # doesn't have to pass a separate arg — that captures the common
        # case (Recon passing every code file from repo_path.rglob).
        if scan_secrets_in is not None:
            graph._secrets_roots = [Path(p) for p in scan_secrets_in]
        else:
            parents = {Path(p).parent for p in paths_list if Path(p).is_file()}
            graph._secrets_roots = sorted(parents)
        return graph

    def slices(self) -> list[DataFlowSlice]:
        results: list[DataFlowSlice] = []
        for pf in self.files:
            for fn in pf.functions:
                tainted = _tainted_vars(fn)
                if not tainted:
                    continue
                source_names = set(tainted.keys())
                for call in fn.calls:
                    cls_ = _classify_sink(call.callee)
                    if not cls_:
                        continue
                    # For SQLi, decide sanitizer status by inspecting the first
                    # arg (the query string): a bare parameterized literal
                    # means later positional args are bound params, not
                    # interpolated. That's the false-positive killer.
                    sqli_parameterized = (
                        cls_ == "sqli"
                        and call.arg_sources
                        and _arg_is_parameterized(call.arg_sources[0])
                    )
                    for idx, arg_src in enumerate(call.arg_sources):
                        identifiers = _arg_names(arg_src)
                        hit = identifiers & source_names
                        if not hit:
                            continue
                        matched_source = tainted[sorted(hit)[0]]
                        sanitized = False
                        reason = f"tainted var(s) {sorted(hit)} reach {call.callee}"
                        if sqli_parameterized:
                            sanitized = True
                            reason = (
                                "first arg is a bare parameterized SQL literal; "
                                "tainted values passed as bound params"
                            )
                        results.append(
                            DataFlowSlice(
                                file=pf.path,
                                function=fn.name,
                                source=matched_source,
                                sink=Sink(
                                    callee=call.callee,
                                    class_=cls_,
                                    line=call.line,
                                    argument_source=arg_src,
                                ),
                                sanitized=sanitized,
                                reason=reason,
                            )
                        )
        # JS/TS slices come from the regex-based scanner; same output shape.
        for js_path in self._js_paths:
            from .js_parser import parse_js_ts

            results.extend(parse_js_ts(js_path))
        # Hardcoded-secret slices: scan all files individually (root walk is
        # done by the Recon caller which passes each root to us).
        if self._secrets_roots:
            from .secrets_scan import scan_secrets

            for root in self._secrets_roots:
                results.extend(scan_secrets(root))
        return results

    def reachable_slices(self) -> list[DataFlowSlice]:
        return [s for s in self.slices() if not s.sanitized]
