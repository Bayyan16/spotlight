"""Tree-sitter Python parser wrapper.

Falls back to the stdlib `ast` module when tree-sitter isn't installed so the
sg-core rules remain testable in constrained environments. The two paths return
the same normalized node dicts.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ParsedFunction:
    name: str
    params: list[str]
    body_source: str
    line: int
    calls: list["ParsedCall"] = field(default_factory=list)
    assigns: list["ParsedAssign"] = field(default_factory=list)


@dataclass
class ParsedCall:
    callee: str
    args: list[str]
    line: int
    # Raw source of each argument expression, useful for detecting f-strings /
    # `%` formatting / `+ concat` patterns that produce SQL sinks.
    arg_sources: list[str] = field(default_factory=list)


@dataclass
class ParsedAssign:
    target: str
    value_source: str
    line: int


@dataclass
class ParsedFile:
    path: str
    functions: list[ParsedFunction]
    route_decorators: dict[str, list[str]]  # function name -> list of route paths


def _source_segment(source: str, node: ast.AST) -> str:
    try:
        return ast.get_source_segment(source, node) or ""
    except Exception:
        return ""


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_dotted_name(node.value)}.{node.attr}"
    if isinstance(node, ast.Call):
        return _dotted_name(node.func)
    return ""


def parse_python(path: str | Path) -> ParsedFile:
    """Parse a Python file into the sg-core normalized shape."""
    path = Path(path)
    source = path.read_text(encoding="utf-8", errors="replace")
    tree = ast.parse(source, filename=str(path))

    functions: list[ParsedFunction] = []
    route_decorators: dict[str, list[str]] = {}

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        # Route detection (Flask @app.route / FastAPI @app.get etc.)
        routes: list[str] = []
        for deco in node.decorator_list:
            if isinstance(deco, ast.Call):
                name = _dotted_name(deco.func)
                if any(name.endswith(m) for m in (".route", ".get", ".post", ".put", ".delete", ".patch")):
                    if deco.args and isinstance(deco.args[0], ast.Constant):
                        routes.append(str(deco.args[0].value))
        if routes:
            route_decorators[node.name] = routes

        params = [arg.arg for arg in node.args.args]

        calls: list[ParsedCall] = []
        assigns: list[ParsedAssign] = []

        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                calls.append(
                    ParsedCall(
                        callee=_dotted_name(child.func),
                        args=[_dotted_name(a) for a in child.args],
                        arg_sources=[_source_segment(source, a) for a in child.args],
                        line=child.lineno,
                    )
                )
            elif isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name):
                        assigns.append(
                            ParsedAssign(
                                target=target.id,
                                value_source=_source_segment(source, child.value),
                                line=child.lineno,
                            )
                        )

        functions.append(
            ParsedFunction(
                name=node.name,
                params=params,
                body_source=_source_segment(source, node),
                line=node.lineno,
                calls=calls,
                assigns=assigns,
            )
        )

    return ParsedFile(path=str(path), functions=functions, route_decorators=route_decorators)
