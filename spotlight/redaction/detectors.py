"""Detector library — regex + canonical replacement token per secret shape.

Each detector is a compiled `re.Pattern` and a canonical token like
`[REDACTED:aws-key]`. Ordering matters: earlier detectors run first, so
put highly specific shapes (AWS access-key IDs, GitHub PATs) before
generic catch-alls (bearer JWT, kv-form secrets).

If you add a shape, add both positive and negative fixtures to
`tests/unit/test_redaction_detectors.py`. Falsely matching an innocuous
string is annoying; falsely missing a live key is a leak.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Detector:
    kind: str
    pattern: re.Pattern[str]
    token: str

    def replacement(self) -> str:
        return self.token


def _compile(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


# NOTE on ordering:
#   1. Long block-encoded shapes (PEM keys) go first — they contain
#      base64 that other detectors could partially match.
#   2. Vendor-tagged shapes (AKIA, sk-, gh_, xox-) go before generic
#      bearer-JWT and generic kv-secret catch-alls.
#   3. Generic kv-secret goes LAST so specific vendor tokens win first.
DEFAULT_DETECTORS: tuple[Detector, ...] = (
    Detector(
        kind="gcp-private-key",
        pattern=_compile(
            r"-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----"
        ),
        token="[REDACTED:gcp-private-key]",
    ),
    Detector(
        kind="rsa-private-key",
        pattern=_compile(
            r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----"
            r"[\s\S]+?-----END (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----"
        ),
        token="[REDACTED:private-key]",
    ),
    Detector(
        kind="aws-key",
        pattern=_compile(r"AKIA[0-9A-Z]{16}"),
        token="[REDACTED:aws-key]",
    ),
    Detector(
        kind="aws-secret",
        # Quoted secret near an `aws...` label. Consume the closing quote
        # too — we don't want a stray `"` left behind.
        pattern=_compile(
            r"(?i)aws[^'\"\n]{0,40}?['\"][0-9a-zA-Z/+]{40}['\"]"
        ),
        token="[REDACTED:aws-secret]",
    ),
    Detector(
        kind="anthropic-key",
        # Must precede the plain `sk-` shape.
        pattern=_compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"),
        token="[REDACTED:anthropic-key]",
    ),
    Detector(
        kind="openai-key",
        pattern=_compile(r"sk-[A-Za-z0-9]{20,}"),
        token="[REDACTED:openai-key]",
    ),
    Detector(
        kind="github-pat",
        pattern=_compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
        token="[REDACTED:github-pat]",
    ),
    Detector(
        kind="slack-token",
        pattern=_compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
        token="[REDACTED:slack-token]",
    ),
    Detector(
        kind="db-url",
        pattern=_compile(
            r"(?i)(?:postgres|postgresql|mysql|mongodb)(?:\+[a-z]+)?://"
            r"[^:@\s]+:[^@\s]+@[^\s'\"]+"
        ),
        token="[REDACTED:db-url]",
    ),
    Detector(
        kind="jwt",
        pattern=_compile(
            r"eyJ[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+"
        ),
        token="[REDACTED:jwt]",
    ),
    Detector(
        kind="generic-secret",
        # api_key = "..." / password: '...' / token="..."
        # Requires quoted value of length >= 16 to avoid matching short
        # placeholders like password="xxx".
        pattern=_compile(
            r"(?i)(api[_-]?key|secret|password|passwd|pwd|token|access[_-]?key)"
            r"['\"]?\s*[:=]\s*['\"]([^'\"\n]{16,})['\"]"
        ),
        # We replace the whole match (label + separator + quoted value),
        # not just the value, because we lose the "quoted secret" shape
        # entirely once redacted. Downstream code reading the redacted
        # text should not expect the key= prefix to remain.
        token="[REDACTED:generic-secret]",
    ),
)


def all_detectors() -> tuple[Detector, ...]:
    return DEFAULT_DETECTORS
