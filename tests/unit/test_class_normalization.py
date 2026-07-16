"""The Investigator normalizes the LLM's freeform `class` field to a
canonical short code (e.g. 'sqli') so downstream code doesn't depend on
model wording. Regression test for the Railway Moonshot drift."""
from spotlight.agents.roles import _canonical_class


def test_canonical_sqli_aliases():
    assert _canonical_class("sqli") == "sqli"
    assert _canonical_class("SQL Injection") == "sqli"
    assert _canonical_class("SQL Injection Vulnerability", sink_class="sqli") == "sqli"
    assert _canonical_class("sql-injection") == "sqli"
    assert _canonical_class("CWE-89") == "sqli"


def test_canonical_command_injection():
    assert _canonical_class("Command Injection") == "cmdi"
    assert _canonical_class("OS Command Injection") == "cmdi"


def test_canonical_ssrf():
    assert _canonical_class("SSRF") == "ssrf"
    assert _canonical_class("Server-Side Request Forgery") == "ssrf"


def test_falls_back_to_sink_class_when_model_output_unknown():
    assert _canonical_class("HypotheticalNewClass", sink_class="sqli") == "sqli"
    assert _canonical_class("", sink_class="sqli") == "sqli"
    assert _canonical_class("", sink_class=None) == "unknown"


def test_investigator_normalizes_moonshot_style_output(monkeypatch):
    """Simulate Moonshot returning 'SQL Injection Vulnerability' as the class
    and verify the Investigator normalizes it to 'sqli' before returning."""
    from spotlight.agents.roles import Investigator

    class FakeModel:
        family = "test"

        def complete(self, *, role, prompt, context):
            return {
                "verdict": "candidate",
                "class": "SQL Injection Vulnerability",  # Moonshot-style
                "cwe": "CWE-89",
                "title": "SQL Injection in accounts",
                "severity": "high",
                "location": {"file": "app.py", "line": 27, "function": "get_account"},
                "root_cause": "concat",
                "recommendation": "parameterize",
                "evidence_used": [],
            }

    slice_dict = {
        "file": "app.py",
        "function": "get_account",
        "source": {"name": "username", "origin": "param:username", "line": 22},
        "sink": {"callee": "cursor.execute", "class": "sqli", "line": 27, "argument_source": "query"},
        "sanitized": False,
        "reason": "reachable",
    }
    result = Investigator(FakeModel()).run(slice_dict)
    assert result is not None
    assert result["class"] == "sqli", f"expected canonical 'sqli', got {result['class']!r}"
