"""Prompt-injection detector.

Scans target-derived strings (README/comments/AST-visible strings) for known
prompt-injection payloads. Fires per-pattern so downstream Warden events can
report the exact match kind.

Detection kinds (each returns an `InjectionMatch`):

    ignore_instructions      literal "ignore your previous instructions"
    disregard_instructions   "disregard the instructions"
    system_override          "system prompt override" / "SYSTEM OVERRIDE"
    you_are_now              "you are now …" role-hijack
    new_task                 "new task: …" role-hijack
    prompt_leak              "please print your prompt", "repeat the words above"
    zero_width               \u200b \u200c \u200d present in target text
    bidi_flip                \u202e right-to-left override present
    html_comment_smuggling   <!-- IGNORE … --> comment payload
    yaml_role_redef          YAML frontmatter with `role:` field

All detectors are pure string / regex — deliberate. AST-aware detection lands
in a later tranche; substring is enough to stop the demoable attack surface.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass


@dataclass
class InjectionMatch:
    """One prompt-injection hit."""

    kind: str
    span: tuple[int, int]  # [start, end) into the original text
    snippet: str  # ≤80 chars around the match, whitespace-normalized

    def to_dict(self) -> dict:
        d = asdict(self)
        # Tuples don't survive JSON round-trip; make it a list.
        d["span"] = list(self.span)
        return d


# ── pattern table ────────────────────────────────────────────────────────
# Case-insensitive, DOTALL off. Order controls the returned list order but
# not semantics — every pattern that matches produces a match.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "ignore_instructions",
        re.compile(r"ignore\s+your\s+(?:previous\s+|prior\s+)?instructions?", re.IGNORECASE),
    ),
    (
        "disregard_instructions",
        re.compile(r"disregard\s+(?:the\s+|your\s+)?(?:previous\s+|prior\s+)?instructions?",
                   re.IGNORECASE),
    ),
    (
        "system_override",
        re.compile(r"system(?::|\s+prompt)?\s+override", re.IGNORECASE),
    ),
    (
        "you_are_now",
        re.compile(r"you\s+are\s+now\b", re.IGNORECASE),
    ),
    (
        "new_task",
        re.compile(r"new\s+task\s*:", re.IGNORECASE),
    ),
    (
        "prompt_leak",
        re.compile(
            r"(?:please\s+)?print\s+your\s+prompt"
            r"|repeat\s+the\s+words?\s+above"
            r"|reveal\s+your\s+system\s+prompt",
            re.IGNORECASE,
        ),
    ),
    (
        "html_comment_smuggling",
        # HTML comment that carries a role-hijack instruction inside.
        re.compile(
            r"<!--\s*(?:SYSTEM\s+OVERRIDE|IGNORE\b|DISREGARD\b|NEW\s+TASK|you\s+are\s+now\b)"
            r"[^>]*?-->",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "yaml_role_redef",
        # A YAML frontmatter block that (re)defines the assistant's role.
        # We look for the fence + a role: line within a bounded window.
        re.compile(
            r"^---\s*\n(?:[^-].*\n)*?\s*role\s*:\s*\S.*?\n(?:.*\n)*?---",
            re.MULTILINE | re.IGNORECASE,
        ),
    ),
]

# Zero-width / bidi tricks. Handled specially since they're single-char and
# want their own event kind.
_ZW_CHARS = ("\u200b", "\u200c", "\u200d", "\ufeff")
_BIDI_CHARS = ("\u202e", "\u202d", "\u202a", "\u202b")


def _snippet(text: str, start: int, end: int, width: int = 80) -> str:
    """Return a ≤`width`-char window around the match with whitespace
    collapsed. Prefixes/suffixes with '…' when we truncate."""
    span_len = end - start
    if span_len >= width:
        raw = text[start:start + width]
    else:
        pad = (width - span_len) // 2
        s = max(0, start - pad)
        e = min(len(text), end + pad)
        raw = text[s:e]
    # Collapse whitespace runs so a snippet doesn't blow up a log line.
    raw = re.sub(r"\s+", " ", raw).strip()
    if len(raw) > width:
        raw = raw[:width - 1] + "…"
    return raw


def scan(text: str) -> list[InjectionMatch]:
    """Return every injection-pattern hit in `text`. Empty list on clean input."""
    if not text:
        return []
    matches: list[InjectionMatch] = []
    for kind, pat in _PATTERNS:
        for m in pat.finditer(text):
            matches.append(
                InjectionMatch(
                    kind=kind,
                    span=(m.start(), m.end()),
                    snippet=_snippet(text, m.start(), m.end()),
                )
            )
    # Zero-width / bidi as their own kinds. We report *once per kind* per
    # text, not once per character — a payload usually sprays multiple.
    zw_positions = [i for i, c in enumerate(text) if c in _ZW_CHARS]
    if zw_positions:
        first = zw_positions[0]
        matches.append(
            InjectionMatch(
                kind="zero_width",
                span=(first, first + 1),
                snippet=_snippet(text, max(0, first - 20), min(len(text), first + 20)),
            )
        )
    bidi_positions = [i for i, c in enumerate(text) if c in _BIDI_CHARS]
    if bidi_positions:
        first = bidi_positions[0]
        matches.append(
            InjectionMatch(
                kind="bidi_flip",
                span=(first, first + 1),
                snippet=_snippet(text, max(0, first - 20), min(len(text), first + 20)),
            )
        )
    return matches
