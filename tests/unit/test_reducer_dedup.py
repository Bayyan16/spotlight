from spotlight.agents.roles import Reducer


def _candidate(
    *,
    function: str,
    line: int,
    cls: str = "sqli",
    file: str = "app.py",
    evidence: str = "evidence",
):
    return {
        "id": f"{cls}-{line}-{function}",
        "surface": "code",
        "class": cls,
        "cwe": "CWE-89",
        "title": f"{cls} at {function}",
        "severity": "high",
        "location": {
            "file": file,
            "line": line,
            "function": function,
        },
        "evidence_used": [evidence],
    }


def test_reducer_merges_nearby_placeholder_into_concrete_function():
    candidates = [
        _candidate(
            function="get_account",
            line=27,
            evidence="investigator evidence",
        ),
        _candidate(
            function="unknown (Flask request handler containing the tainted SQL construction)",
            line=26,
            evidence="agentic evidence",
        ),
        _candidate(
            function="unknown (detected by semgrep::sqlalchemy-execute-raw-query)",
            line=27,
            evidence="semgrep evidence",
        ),
    ]

    reduced = Reducer().run(candidates)

    assert len(reduced) == 1

    finding = reduced[0]

    # Prefer the authoritative concrete symbol.
    assert finding["location"]["function"] == "get_account"

    # Preserve evidence contributed by duplicate detectors.
    assert set(finding["evidence_used"]) == {
        "investigator evidence",
        "agentic evidence",
        "semgrep evidence",
    }


def test_reducer_merges_nearby_placeholder_symbols():
    candidates = [
        _candidate(
            function="unknown (Flask request handler)",
            line=26,
            evidence="agentic",
        ),
        _candidate(
            function="unknown (detected by semgrep::sqlalchemy-execute-raw-query)",
            line=27,
            evidence="semgrep",
        ),
    ]

    reduced = Reducer().run(candidates)

    assert len(reduced) == 1
    assert set(reduced[0]["evidence_used"]) == {
        "agentic",
        "semgrep",
    }


def test_reducer_keeps_distinct_concrete_functions():
    candidates = [
        _candidate(
            function="get_account",
            line=27,
        ),
        _candidate(
            function="update_account",
            line=28,
        ),
    ]

    reduced = Reducer().run(candidates)

    assert len(reduced) == 2


def test_reducer_keeps_far_apart_placeholder_findings():
    candidates = [
        _candidate(
            function="unknown (scanner A)",
            line=10,
        ),
        _candidate(
            function="unknown (scanner B)",
            line=100,
        ),
    ]

    reduced = Reducer().run(candidates)

    assert len(reduced) == 2


def test_reducer_keeps_different_classes():
    candidates = [
        _candidate(
            function="unknown (scanner A)",
            line=27,
            cls="sqli",
        ),
        _candidate(
            function="unknown (scanner B)",
            line=27,
            cls="cmdi",
        ),
    ]

    reduced = Reducer().run(candidates)

    assert len(reduced) == 2


def test_reducer_preserves_existing_exact_symbol_dedup():
    candidates = [
        _candidate(
            function="get_account",
            line=27,
            evidence="first",
        ),
        _candidate(
            function="get_account",
            line=27,
            evidence="second",
        ),
    ]

    reduced = Reducer().run(candidates)

    assert len(reduced) == 1


def test_reducer_prefers_concrete_function_when_placeholder_arrives_first():
    candidates = [
        _candidate(
            function="unknown (detected by semgrep::sqlalchemy-execute-raw-query)",
            line=27,
            evidence="semgrep evidence",
        ),
        _candidate(
            function="unknown (Flask request handler containing the tainted SQL construction)",
            line=26,
            evidence="agentic evidence",
        ),
        _candidate(
            function="get_account",
            line=27,
            evidence="investigator evidence",
        ),
    ]

    reduced = Reducer().run(candidates)

    assert len(reduced) == 1

    finding = reduced[0]

    # Arrival order must not leave a placeholder as the canonical symbol.
    assert finding["location"]["function"] == "get_account"

    assert set(finding["evidence_used"]) == {
        "semgrep evidence",
        "agentic evidence",
        "investigator evidence",
    }
