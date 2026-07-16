"""Redactor — the run-anything-through-me chokepoint.

Given a string, apply every detector in `detectors.DEFAULT_DETECTORS`
and return `(redacted_text, [RedactionMatch, ...])`. Given a dict,
walk it recursively and redact every str it contains.

Idempotence: `redact(redact(s)[0])[0] == redact(s)[0]`. This matters
because the API-response chokepoint may run over data that was already
redacted at the event or prompt chokepoint.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from .detectors import DEFAULT_DETECTORS, Detector


@dataclass(frozen=True)
class RedactionMatch:
    """One matched secret."""

    kind: str
    span: tuple[int, int]
    token: str


@dataclass
class Redactor:
    """Applies a detector list to strings, dicts, and lists.

    The default is `DEFAULT_DETECTORS` from `detectors.py`. Pass
    `extra_detectors` to add project-specific patterns (e.g. a stripe key
    prefix your target uses) without editing the library.
    """

    detectors: list[Detector] = field(default_factory=lambda: list(DEFAULT_DETECTORS))

    def add(self, detector: Detector) -> None:
        self.detectors.append(detector)

    # --- core: string ---
    def redact(self, text: str) -> tuple[str, list[RedactionMatch]]:
        """Return (redacted, matches). Idempotent."""
        if not isinstance(text, str) or not text:
            return text, []
        out = text
        matches: list[RedactionMatch] = []
        for det in self.detectors:
            new_out, more = _apply_detector(out, det)
            out = new_out
            matches.extend(more)
        return out, matches

    # --- convenience: does the string contain any secret? ---
    def contains_secret(self, text: str) -> bool:
        return bool(self.redact(text)[1])

    # --- dicts / lists (recursive) ---
    def redact_dict(self, obj: Any) -> Any:
        """Return a deep copy with strings redacted.

        Handles dict, list, tuple, set, and primitives. Non-str leaves
        (int, float, bool, None) pass through untouched. Dict keys are
        NOT redacted (paths would break); only values.
        """
        return _walk(obj, self)

    # --- redact a specific nested field ---
    def wrap_dict_field(self, obj: dict, path: list[str]) -> dict:
        """Redact only the value at `path` inside `obj`, in-place.

        Returns the same dict. If any path segment is missing or the
        terminal value is not a string, this is a no-op.
        """
        if not path or not isinstance(obj, dict):
            return obj
        cur: Any = obj
        for key in path[:-1]:
            if not isinstance(cur, dict) or key not in cur:
                return obj
            cur = cur[key]
        last = path[-1]
        if not isinstance(cur, dict) or last not in cur:
            return obj
        val = cur[last]
        if isinstance(val, str):
            cur[last], _ = self.redact(val)
        return obj


# --- module-level convenience ---
_DEFAULT = Redactor()


def redact(text: str) -> tuple[str, list[RedactionMatch]]:
    """Redact using the module-level default Redactor.

    Use this when you don't need to customize detectors — it's the
    fast path most callers want.
    """
    return _DEFAULT.redact(text)


# ---------- internals ----------


def _apply_detector(text: str, det: Detector) -> tuple[str, list[RedactionMatch]]:
    matches: list[RedactionMatch] = []

    def _sub(m: "Any") -> str:
        matches.append(
            RedactionMatch(kind=det.kind, span=(m.start(), m.end()), token=det.token)
        )
        return det.token

    new = det.pattern.sub(_sub, text)
    return new, matches


def _walk(obj: Any, r: Redactor) -> Any:
    if isinstance(obj, str):
        return r.redact(obj)[0]
    if isinstance(obj, dict):
        return {k: _walk(v, r) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_walk(v, r) for v in obj]
    if isinstance(obj, tuple):
        return tuple(_walk(v, r) for v in obj)
    if isinstance(obj, set):
        return {_walk(v, r) for v in obj}
    return obj


def iter_default_kinds() -> Iterable[str]:
    return (d.kind for d in DEFAULT_DETECTORS)
