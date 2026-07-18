"""Semgrep pass-through — matches with CWE/OWASP metadata but no
canonical-class alias now survive filtering.

Previously we filtered every Semgrep match through a tiny ~30-entry
alias table (`_CHECK_ID_MATCHES`) and dropped everything else. That
discarded ~90% of Semgrep's security-metadata matches — the whole point
of running a corroborator with 4000+ community rules was defeated.

The new policy (see `_extract_matches` in semgrep_adapter.py): we keep
any match with `metadata.category == "security"` OR a non-empty
`metadata.cwe` list, regardless of whether we canonicalize it. Matches
we can't canonicalize get `class="external:<slug>"` so downstream code
knows the label is Semgrep's, not ours.
"""
from __future__ import annotations

from spotlight.signals.semgrep_adapter import _extract_matches


def _match(check_id, category=None, cwe=None, owasp=None, vc=None):
    return {
        "check_id": check_id,
        "path": "app.py",
        "start": {"line": 42},
        "end": {"line": 42},
        "extra": {
            "severity": "ERROR",
            "message": "sample",
            "lines": "raise 'x'",
            "metadata": {
                **({"category": category} if category else {}),
                **({"cwe": cwe} if cwe else {}),
                **({"owasp": owasp} if owasp else {}),
                **({"vulnerability_class": vc} if vc else {}),
            },
        },
    }


def test_security_match_without_canonical_alias_survives():
    """CWE-611 (XXE) has no entry in our alias table. Before the fix, this
    Semgrep match would have been silently dropped. Now it survives and is
    tagged `external:xxe`."""
    data = {
        "results": [
            _match(
                "python.lang.security.xxe.xml-etree-fromstring",
                category="security",
                cwe=["CWE-611: Improper Restriction of XML External Entity Reference"],
                vc=["XXE"],
            )
        ]
    }
    matches = _extract_matches(data)
    assert len(matches) == 1
    m = matches[0]
    assert m.class_ == "external:xxe"
    assert m.cwe == ["CWE-611: Improper Restriction of XML External Entity Reference"]


def test_non_security_noise_is_dropped():
    """Style / best-practice rules with no CWE and category != security are
    still filtered out — we corroborate on security, not on lint."""
    data = {
        "results": [
            _match("python.style.line-too-long", category="best-practice"),
            _match("python.style.import-order", category="best-practice"),
        ]
    }
    assert _extract_matches(data) == []


def test_owasp_only_match_survives():
    """A match with an OWASP mapping but no CWE list is still a security
    signal we want to keep."""
    data = {
        "results": [
            _match(
                "javascript.express.csrf.missing-csrf-protection",
                owasp=["A05:2021 - Security Misconfiguration"],
            )
        ]
    }
    matches = _extract_matches(data)
    assert len(matches) == 1
    assert matches[0].owasp == ["A05:2021 - Security Misconfiguration"]


def test_canonical_alias_still_wins_over_external_label():
    """When our alias table matches (sqli), the canonical class wins so
    Chainer + Consensus keep folding matches at the same file:line."""
    data = {
        "results": [
            _match(
                "python.flask.security.injection.tainted-sql-string",
                category="security",
                cwe=["CWE-89: SQL Injection"],
            )
        ]
    }
    matches = _extract_matches(data)
    assert matches[0].class_ == "sqli"  # NOT external:sql-injection
    # CWE metadata still preserved for the attestation / Console.
    assert matches[0].cwe == ["CWE-89: SQL Injection"]


def test_ssti_and_dynamic_import_canonicalize():
    """The two new CWE-94 family classes fold correctly via the expanded
    alias table."""
    data = {
        "results": [
            _match(
                "python.flask.security.jinja2.template-injection",
                category="security",
                cwe=["CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine"],
            ),
            _match(
                "python.lang.security.dynamic-import",
                category="security",
                cwe=["CWE-94"],
            ),
        ]
    }
    matches = _extract_matches(data)
    labels = {m.class_ for m in matches}
    assert "ssti" in labels
    assert "dynamic-import" in labels


def test_slice_dict_carries_cwe_and_owasp():
    """External-classified matches expose Semgrep's own CWE/OWASP through
    the as_slice_dict() payload so the Console + attestation see them."""
    data = {
        "results": [
            _match(
                "python.lang.security.xxe.lxml-parse-unsafe",
                category="security",
                cwe=["CWE-611: XXE"],
                owasp=["A05:2021 - Security Misconfiguration"],
                vc=["XXE"],
            )
        ]
    }
    m = _extract_matches(data)[0]
    slice_ = m.as_slice_dict()
    assert slice_["sink"]["cwe"] == ["CWE-611: XXE"]
    assert slice_["sink"]["owasp"] == ["A05:2021 - Security Misconfiguration"]
