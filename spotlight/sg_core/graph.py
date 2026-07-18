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

# Sinks classified by class label. Each entry is a tuple of substring
# needles matched against the callee's dotted name. Kept intentionally
# broad — precision comes from the taint reachability check, not from
# refining these strings.
#
# CWE families each class maps to (see taxonomy.py for authoritative
# mapping):
#   sqli               → CWE-89
#   cmdi               → CWE-78
#   eval               → CWE-95 (parent CWE-94)
#   ssrf               → CWE-918
#   ssti               → CWE-1336 (parent CWE-94) — server-side template injection
#   dynamic-import     → CWE-94 direct — attacker controls what code is loaded
#   deserialization    → CWE-502
#   path-traversal     → CWE-22
#   weak-hash          → CWE-327
#   verify-disabled    → CWE-295
SINKS: dict[str, tuple[str, ...]] = {
    "sqli": ("cursor.execute", ".execute", "executemany", "execute_string"),
    "cmdi": ("os.system", "subprocess.run", "subprocess.call", "subprocess.Popen"),
    "eval": ("eval", "exec"),
    "ssrf": ("requests.get", "requests.post", "httpx.get", "urlopen"),
    # SSTI — Jinja2 / Mako / Chameleon / Django's `mark_safe` when the
    # marked string is user-controlled. Template().render(user) is a
    # canonical remote-code-execution vector on Jinja2 without
    # sandboxing.
    "ssti": (
        "Template",
        "jinja2.Template",
        "env.from_string",
        "Environment.from_string",
        "mako.Template",
        "chameleon.PageTemplate",
        "django.template.Template",
    ),
    # Dynamic imports — attacker fully controls which module gets loaded
    # and its top-level code executes on import. Rare in modern code
    # but catastrophic when present (plugin systems, "dynamic config",
    # eval-by-another-name).
    "dynamic-import": (
        "__import__",
        "importlib.import_module",
        "importlib.util.spec_from_file_location",
    ),
    # Deserialization — pickle / yaml.load without SafeLoader / marshal
    # / dill all treat untrusted bytes as executable code. yaml.safe_load
    # is fine; the vulnerable ones are the bare `.load` variants.
    "deserialization": (
        "pickle.loads",
        "pickle.load",
        "cPickle.loads",
        "dill.loads",
        "marshal.loads",
        "yaml.load",  # yaml.safe_load is intentionally NOT a needle
        "yaml.unsafe_load",
    ),
    # Path traversal — `open()`, `send_file`, `send_from_directory` with
    # user-controlled paths and no allowlist / commonpath containment
    # check. Also covers os.path.join used as if it made the result
    # safe (it doesn't).
    "path-traversal": (
        "open",
        "os.open",
        "pathlib.Path.open",
        "send_file",
        "send_from_directory",
        "shutil.copy",
        "shutil.move",
    ),
    # Weak crypto — md5 / sha1 used in a security context. Precision
    # comes from taint reachability from a security-relevant source
    # (password, token, session_id) — non-security hashing is fine
    # (checksums, cache keys, etc.).
    "weak-hash": (
        "hashlib.md5",
        "hashlib.sha1",
        "hashlib.new",  # e.g. hashlib.new("md5", ...)
        "md5.new",
        "sha.new",
    ),
    # SSL verify disabled — verify=False on requests, CERT_NONE on ssl
    # context, InsecureRequestWarning suppressions. Ships as static-
    # fact (finding IS the code), no PoC needed.
    "verify-disabled": (
        "ssl.CERT_NONE",
        "InsecureRequestWarning",
    ),
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


def _classify_sink(
    callee: str,
    *,
    extra: dict[str, tuple[str, ...]] | None = None,
) -> str | None:
    """Return the class label for `callee` if it matches any known sink.

    `extra` — per-sweep additions from the Planner (see spotlight.planner).
    Extras are checked FIRST so a Planner-defined `acme.utils.load_yaml`
    beats a generic `.load` needle. For Tier-3 rules the class label may
    be `external:planner:<slug>` — same semantics as Semgrep passthrough
    external classes.
    """
    if extra:
        for cls, needles in extra.items():
            for needle in needles:
                if needle and needle in callee:
                    return cls
    for cls, needles in SINKS.items():
        for needle in needles:
            if needle in callee:
                return cls
    return None


def _tainted_vars(
    fn: ParsedFunction,
    *,
    extra_sources: tuple[str, ...] = (),
) -> dict[str, Source]:
    """Map every tainted variable in the function (root OR derived) to the
    Source describing the ROOT untrusted entry point. That way sinks report
    "username reached execute", not "query reached execute".

    `extra_sources` — per-sweep identifier names the Planner tagged as
    untrusted (e.g., a repo-specific ``queue.consume`` helper). Any
    assignment whose value-source references one of these identifiers is
    treated as tainted alongside the built-in ``request.*`` sources.
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
        elif extra_sources and any(u in vs for u in extra_sources):
            tainted[assign.target] = Source(
                name=assign.target, origin="planner:source", line=assign.line
            )

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
    # Per-sweep SINKS override — populated from Planner output. `extra_sinks`
    # maps class label → list of additional needle strings that classify as
    # that class for THIS sweep only. `extra_sources` are identifier names
    # treated as untrusted (in addition to sg-core's UNTRUSTED_ATTRS).
    # `extra_sanitizers` are identifier names that mark a taint flow as
    # sanitized when they appear in the chain.
    _extra_sinks: dict[str, tuple[str, ...]] = field(default_factory=dict)
    _extra_sources: tuple[str, ...] = field(default_factory=tuple)
    _extra_sanitizers: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def build(
        cls,
        paths: Iterable[str | Path],
        scan_secrets_in: Iterable[str | Path] | None = None,
        *,
        extra_sinks: dict[str, Iterable[str]] | None = None,
        extra_sources: Iterable[str] | None = None,
        extra_sanitizers: Iterable[str] | None = None,
    ) -> "CodeGraph":
        paths_list = list(paths)
        py_paths = [Path(p) for p in paths_list if str(p).endswith(".py")]
        parsed = [parse_python(p) for p in py_paths]
        js_paths = [Path(p) for p in paths_list if str(p).endswith((".js", ".ts", ".jsx", ".tsx"))]
        graph = cls(files=parsed)
        graph._js_paths = js_paths
        if extra_sinks:
            graph._extra_sinks = {
                k: tuple(v) for k, v in extra_sinks.items() if v
            }
        graph._extra_sources = tuple(extra_sources or ())
        graph._extra_sanitizers = tuple(extra_sanitizers or ())
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
                tainted = _tainted_vars(fn, extra_sources=self._extra_sources)
                if not tainted:
                    continue
                source_names = set(tainted.keys())
                for call in fn.calls:
                    cls_ = _classify_sink(call.callee, extra=self._extra_sinks)
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
                        elif self._extra_sanitizers and any(
                            san in arg_src for san in self._extra_sanitizers
                        ):
                            # Planner-declared sanitizer appears in the arg
                            # expression — treat the flow as safe. E.g.,
                            # `db.execute(acme.sanitize.html_escape(user_input))`.
                            sanitized = True
                            hit_san = next(
                                san for san in self._extra_sanitizers if san in arg_src
                            )
                            reason = (
                                f"tainted value passes through planner-declared "
                                f"sanitizer {hit_san}"
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
