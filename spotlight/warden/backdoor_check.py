"""Backdoor / weakening detector.

Runs on a unified diff produced by the Remediator. The Verifier calls this
to catch a "fix" that quietly disables a control, drops an auth check,
suppresses a test, or opens a new egress path.

Substring / regex first — deliberate. Full-fidelity AST diffing lands in a
later tranche; the substring scan is enough to catch the demoable weakening
patterns.

Each match returns a `BackdoorMatch{kind, line, snippet}`:

    tls_verify_disabled       verify=False, rejectUnauthorized: false
    auth_check_removed        auth_required = False, @login_required removed
    permission_widened        scope= added / widened
    test_skipped              .skip(, @pytest.mark.skip, xit(
    lint_suppression_added    # noqa, // eslint-disable-next-line
    eval_sink_added           new eval/exec call in a + line
    new_outbound_url          new http(s):// or fetch/requests call
    secret_logged             logging a secret / token
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass


@dataclass
class BackdoorMatch:
    kind: str
    line: int  # 1-based line number in the diff
    snippet: str  # the raw diff line, trimmed to ≤200 chars

    def to_dict(self) -> dict:
        return asdict(self)


# ── added-line detectors ──────────────────────────────────────────────────
# All patterns run only against added lines (`+` prefix, excluding the
# `+++` file header). Removed patterns are handled separately below.
_ADD_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "tls_verify_disabled",
        re.compile(r"\bverify\s*=\s*False\b|rejectUnauthorized\s*:\s*false", re.IGNORECASE),
        "TLS verification disabled",
    ),
    (
        "auth_check_removed",
        # Auth explicitly turned off in code (not the same as removing the
        # decorator — that's caught by the removed-line scan below).
        re.compile(
            r"\bauth_required\s*=\s*False\b"
            r"|\bcheck\s*=\s*False\b"
            r"|\brequire_auth\s*=\s*False\b",
            re.IGNORECASE,
        ),
        "Auth check disabled",
    ),
    (
        "permission_widened",
        re.compile(
            r"\bscope\s*=\s*[\"'][^\"']*\*"
            r"|\bpermissions?\s*=\s*\[[^\]]*['\"]?\*['\"]?"
            r"|\ballow_all\s*=\s*True",
            re.IGNORECASE,
        ),
        "Permission scope widened",
    ),
    (
        "test_skipped",
        re.compile(
            r"\.skip\s*\("
            r"|@pytest\.mark\.skip"
            r"|@unittest\.skip"
            r"|\bxit\s*\("
            r"|\bxdescribe\s*\("
            r"|\bpytest\.skip\s*\(",
            re.IGNORECASE,
        ),
        "Test skipped",
    ),
    (
        "lint_suppression_added",
        re.compile(
            r"#\s*noqa\b"
            r"|//\s*eslint-disable(?:-next-line|-line)?"
            r"|/\*\s*eslint-disable"
            r"|#\s*type:\s*ignore",
            re.IGNORECASE,
        ),
        "Lint suppression added",
    ),
    (
        "eval_sink_added",
        re.compile(
            r"\beval\s*\("
            r"|\bexec\s*\("
            r"|\bFunction\s*\("
            r"|\bnew\s+Function\s*\(",
        ),
        "New eval/exec sink",
    ),
    (
        "new_outbound_url",
        # Fire only on a URL that clearly points at a non-local host. A bare
        # `requests.get(...)` or `fetch(...)` call is not evidence of a new
        # egress path by itself — the Fix could be replacing the URL, or
        # calling localhost. False positives here erode Verifier trust.
        re.compile(
            r"https?://(?!(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])[\s:/])[A-Za-z0-9.\-]+",
            re.IGNORECASE,
        ),
        "New outbound URL",
    ),
    (
        "secret_logged",
        # A log call that includes a token/secret/key/password reference. We
        # want the co-occurrence — logging by itself is fine.
        re.compile(
            r"(?:log(?:ger|ging)?\.(?:info|debug|warn|warning|error|print)|print|console\.log)"
            r"[^)\n]*\b(?:password|secret|token|api[_-]?key|apikey|access[_-]?token)\b",
            re.IGNORECASE,
        ),
        "Secret exposed in log",
    ),
]

# Patterns that fire on *removed* lines (`-` prefix, not `---`).
_REMOVE_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "auth_check_removed",
        re.compile(
            r"@login_required"
            r"|@require_auth"
            r"|@requires_auth"
            r"|@authenticated",
            re.IGNORECASE,
        ),
        "Auth decorator removed",
    ),
]


def check(diff: str) -> list[BackdoorMatch]:
    """Return every backdoor pattern hit in the diff. Empty list on a clean
    fix. Non-diff input is treated as one big added block.

    Precision guard: if a pattern fires on an added line AND the same
    substring existed on a removed line in the same hunk, we suppress it —
    it's not "new", it's just re-emitted. Prevents flagging fixes like
    `verify=False` → `verify=True` when the URL/library stays.
    """
    if not diff:
        return []
    matches: list[BackdoorMatch] = []
    lines = diff.splitlines()
    is_unified = any(l.startswith(("+++", "---", "@@")) for l in lines)
    removed_bodies: list[str] = [
        l[1:] for l in lines
        if is_unified and l.startswith("-") and not l.startswith("---")
    ]
    for i, line in enumerate(lines, start=1):
        # Skip file / hunk headers so `+++ b/foo.py` doesn't count as an
        # added line.
        if line.startswith(("+++", "---", "@@", "diff ", "index ")):
            continue
        if is_unified:
            if line.startswith("+"):
                body = line[1:]
                for kind, pat, _label in _ADD_PATTERNS:
                    m = pat.search(body)
                    if not m:
                        continue
                    hit = m.group(0)
                    # If the same match already existed in a removed line,
                    # this isn't a NEW backdoor — it's context / a partial
                    # rewrite. Suppress. (Only applies to the URL scan
                    # today; other detectors are precise enough already.)
                    if kind == "new_outbound_url" and any(
                        hit in prev for prev in removed_bodies
                    ):
                        continue
                    matches.append(
                        BackdoorMatch(kind=kind, line=i, snippet=body.strip()[:200])
                    )
            elif line.startswith("-"):
                body = line[1:]
                for kind, pat, _label in _REMOVE_PATTERNS:
                    if pat.search(body):
                        matches.append(
                            BackdoorMatch(kind=kind, line=i, snippet=body.strip()[:200])
                        )
        else:
            # Non-diff — treat every line as "content under review".
            for kind, pat, _label in _ADD_PATTERNS:
                if pat.search(line):
                    matches.append(
                        BackdoorMatch(kind=kind, line=i, snippet=line.strip()[:200])
                    )
    return matches
