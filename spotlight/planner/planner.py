"""Planner role — reads a repo index, proposes repo-tuned rules.

Two-pass to keep context bounded:
  Pass 1 · a lightweight index (file tree, top-level imports, decorator
           names) is fed to the model. Model returns
           ``{framework, extra_sinks, extra_sanitizers,
             extra_untrusted_sources, semgrep_rules_yaml}``.
  Pass 2 · every proposed rule is validated via ``GrepValidator``.
           Rules whose identifiers don't exist in the repo are DROPPED
           and the reason recorded on the validation report.

The Planner NEVER shortcuts sg-core / Semgrep — it augments them.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from spotlight.agents.model import ModelClient

from .validator import GrepValidator


# CWE → canonical Spotlight class label. Tier-2 mapping: when the Planner
# proposes a novel sink with a CWE we know about, we auto-register it
# under our existing class label. See package docstring for the tiering.
_CWE_TO_CLASS: dict[str, str] = {
    "CWE-89": "sqli",
    "CWE-78": "cmdi",
    "CWE-95": "eval",
    "CWE-94": "eval",  # code-injection family — default to eval unless the model discriminates
    "CWE-918": "ssrf",
    "CWE-1336": "ssti",
    "CWE-502": "deserialization",
    "CWE-22": "path-traversal",
    "CWE-327": "weak-hash",
    "CWE-295": "verify-disabled",
    "CWE-79": "xss",
    "CWE-611": "xxe",
    "CWE-90": "ldap-injection",
    "CWE-643": "xpath-injection",
}


@dataclass
class PlanRule:
    """One planner-proposed callable that should be treated as a sink OR
    an untrusted source OR a sanitizer for this repo.

    ``identifier`` is the dotted callable name (Python) or bare function
    name (JS). ``role`` says which downstream bucket the rule joins.
    ``target_class`` is our canonical Spotlight class label; for Tier-3
    rules it's ``external:planner:<slug>``.
    """

    identifier: str
    role: str  # "sink" | "source" | "sanitizer"
    target_class: str
    cwe: str = ""
    description: str = ""
    tier: int = 1  # 1|2|3 per package docstring

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RuleValidationReport:
    kept: list[PlanRule] = field(default_factory=list)
    rejected: list[dict[str, str]] = field(default_factory=list)


@dataclass
class PlanOutput:
    framework: str
    rules: list[PlanRule]
    semgrep_rules_yaml: str  # raw YAML — Planner authors, we feed to semgrep --config
    validation: RuleValidationReport

    def sinks_by_class(self) -> dict[str, list[str]]:
        """Group sink identifiers by target class for sg-core SINKS augmentation."""
        out: dict[str, list[str]] = {}
        for r in self.rules:
            if r.role != "sink":
                continue
            out.setdefault(r.target_class, []).append(r.identifier)
        return out

    def source_identifiers(self) -> list[str]:
        return [r.identifier for r in self.rules if r.role == "source"]

    def sanitizer_identifiers(self) -> list[str]:
        return [r.identifier for r in self.rules if r.role == "sanitizer"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework,
            "rules": [r.to_dict() for r in self.rules],
            "semgrep_rules_yaml": self.semgrep_rules_yaml,
            "validation": {
                "kept_count": len(self.validation.kept),
                "rejected_count": len(self.validation.rejected),
                "rejected": self.validation.rejected,
            },
        }


@dataclass
class Planner:
    """Repo-native rule authoring role.

    Call ``Planner(model).plan(repo_path)``. Returns a validated
    ``PlanOutput`` ready to be fed to sg-core (via SINKS override),
    Semgrep (via ephemeral YAML), and the Consensus Kernel (as a new
    ``planner_inferred`` modality).
    """

    model: ModelClient
    # Cap on how much of the index we send to the model — a huge repo can't
    # go verbatim. 12KB is comfortable in every deployed context window.
    index_char_cap: int = 12_000

    def plan(self, repo_path: Path) -> PlanOutput:
        repo_path = Path(repo_path).resolve()
        index = self._build_index(repo_path)
        raw = self._call_model(index)
        rules = self._parse_rules(raw)
        semgrep_yaml = str(raw.get("semgrep_rules_yaml", "") or "")

        # Validate every proposed rule against the repo.
        validator = GrepValidator(repo_path)
        kept: list[PlanRule] = []
        rejected: list[dict[str, str]] = []
        for r in rules:
            outcome = validator.check(r.identifier)
            if outcome.found:
                kept.append(r)
            else:
                rejected.append({
                    "identifier": r.identifier,
                    "role": r.role,
                    "reason": "identifier not present in repo (validator drop)",
                })

        framework = str(raw.get("framework", "") or "unknown")
        return PlanOutput(
            framework=framework,
            rules=kept,
            semgrep_rules_yaml=semgrep_yaml,
            validation=RuleValidationReport(kept=kept, rejected=rejected),
        )

    # ── two-pass indexing ──────────────────────────────────────────

    def _build_index(self, repo_path: Path) -> str:
        """Cheap repo summary: file tree + top-level imports + decorator
        occurrences. Kept small enough to fit in the model prompt window
        without truncation on any deployment tier.
        """
        lines: list[str] = []
        files = _list_source_files(repo_path)
        lines.append(f"# Repo: {repo_path.name}")
        lines.append(f"# Total source files (py/js/ts): {len(files)}")
        lines.append("")
        lines.append("## File tree (first 60 files)")
        for f in files[:60]:
            try:
                lines.append("  " + str(f.relative_to(repo_path)))
            except ValueError:
                lines.append("  " + f.name)
        lines.append("")
        lines.append("## Top-level imports (sampled from first 30 files)")
        for f in files[:30]:
            head = _read_head(f, chars=1500)
            imports = _extract_imports(head)
            if imports:
                try:
                    rel = str(f.relative_to(repo_path))
                except ValueError:
                    rel = f.name
                lines.append(f"  {rel}: {', '.join(imports[:8])}")
        lines.append("")
        lines.append("## Decorators observed (top 30 by count)")
        deco_counter = _decorator_histogram(files[:40])
        for name, count in deco_counter[:30]:
            lines.append(f"  @{name}  ({count} files)")
        text = "\n".join(lines)
        return text[: self.index_char_cap]

    def _call_model(self, index: str) -> dict[str, Any]:
        try:
            resp = self.model.complete(
                role="planner",
                prompt=(
                    "You are Spotlight's Planner. Read the repo index below and "
                    "propose rules TUNED TO THIS REPO. Return strict JSON with "
                    "keys: framework, rules[] (each with identifier, role in "
                    "{sink,source,sanitizer}, target_class, cwe, description), "
                    "semgrep_rules_yaml (raw YAML string)."
                ),
                context={"index": index},
            )
            if isinstance(resp, dict):
                return resp
        except Exception as exc:
            print(f"[planner] model call failed: {exc!r}")
        return {"framework": "unknown", "rules": [], "semgrep_rules_yaml": ""}

    def _parse_rules(self, raw: dict[str, Any]) -> list[PlanRule]:
        rules_in = raw.get("rules") or []
        if not isinstance(rules_in, list):
            return []
        out: list[PlanRule] = []
        for r in rules_in:
            if not isinstance(r, dict):
                continue
            identifier = str(r.get("identifier", "") or "").strip()
            role = str(r.get("role", "") or "").strip().lower()
            if not identifier or role not in ("sink", "source", "sanitizer"):
                continue
            cwe = str(r.get("cwe", "") or "").strip()
            target_class, tier = _resolve_class(
                explicit=str(r.get("target_class", "") or "").strip(),
                cwe=cwe,
                identifier=identifier,
            )
            out.append(
                PlanRule(
                    identifier=identifier,
                    role=role,
                    target_class=target_class,
                    cwe=cwe,
                    description=str(r.get("description", "") or "").strip(),
                    tier=tier,
                )
            )
        return out


# ── helpers ─────────────────────────────────────────────────────────


_KNOWN_CLASSES = {
    "sqli", "cmdi", "eval", "ssrf", "ssti", "dynamic-import",
    "deserialization", "path-traversal", "weak-hash", "verify-disabled",
    "xss", "xxe", "ldap-injection", "xpath-injection",
    "secrets", "hardcoded-secret",
}


def _slugify(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-") or "unknown"


def _resolve_class(explicit: str, cwe: str, identifier: str) -> tuple[str, int]:
    """Three-tier resolution — see package docstring for the theory.

    Returns (class_label, tier). Tier 1 = existing class; Tier 2 = new
    class via CWE mapping; Tier 3 = external:planner:<slug>.
    """
    if explicit and explicit in _KNOWN_CLASSES:
        return explicit, 1
    if cwe in _CWE_TO_CLASS:
        return _CWE_TO_CLASS[cwe], 2
    slug = _slugify(explicit) if explicit else _slugify(identifier.split(".")[-1])
    return f"external:planner:{slug}", 3


def _list_source_files(root: Path) -> list[Path]:
    exts = (".py", ".js", ".jsx", ".ts", ".tsx")
    out: list[Path] = []
    for ext in exts:
        for p in root.rglob(f"*{ext}"):
            if any(seg in p.parts for seg in ("node_modules", ".venv", "dist", ".git")):
                continue
            out.append(p)
    return sorted(out, key=lambda p: str(p))


def _read_head(path: Path, chars: int = 1500) -> str:
    try:
        return path.read_text(errors="ignore")[:chars]
    except Exception:
        return ""


_IMPORT_RE_PY = re.compile(r"^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.,\s]+))", re.MULTILINE)
_IMPORT_RE_JS = re.compile(r"""(?:require\(['"]([^'"]+)['"]\)|from\s+['"]([^'"]+)['"])""")
_DECO_RE = re.compile(r"^\s*@(\w[\w.]*)", re.MULTILINE)


def _extract_imports(text: str) -> list[str]:
    seen: list[str] = []
    for m in _IMPORT_RE_PY.finditer(text):
        for g in m.groups():
            if g:
                seen.extend([x.strip().split(" as ")[0] for x in g.split(",")])
    for m in _IMPORT_RE_JS.finditer(text):
        for g in m.groups():
            if g:
                seen.append(g)
    # Dedup preserving order.
    out: list[str] = []
    seen_set: set[str] = set()
    for s in seen:
        if s and s not in seen_set:
            seen_set.add(s)
            out.append(s)
    return out


def _decorator_histogram(files: list[Path]) -> list[tuple[str, int]]:
    from collections import Counter

    c: Counter[str] = Counter()
    for f in files:
        text = _read_head(f, chars=6000)
        for m in _DECO_RE.finditer(text):
            c[m.group(1)] += 1
    return c.most_common()
