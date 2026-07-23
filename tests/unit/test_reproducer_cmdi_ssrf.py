from pathlib import Path

import pytest

from spotlight.agents.roles import Reproducer
from spotlight.sandbox import SubprocessSandbox


ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    ("target", "class_name", "function_name", "expected"),
    [
        ("vuln-cmdi-api", "cmdi", "run_command", "confirmed"),
        ("clean-cmdi-api", "cmdi", "run_command", "not-reproduced"),
        ("vuln-ssrf-api", "ssrf", "fetch_url", "confirmed"),
        ("clean-ssrf-api", "ssrf", "fetch_url", "not-reproduced"),
    ],
)
def test_instrumented_reproduction_never_executes_or_egresses(
    target, class_name, function_name, expected
):
    repo = ROOT / "targets" / target
    finding = {
        "id": "SPOT-TEST",
        "class": class_name,
        "location": {"file": str(repo / "app.py"), "function": function_name},
    }

    result = Reproducer(sandbox=SubprocessSandbox()).run(repo, finding)

    assert result["result"] == expected
    assert result["poc"]["network_egress"] is False
    if class_name == "ssrf" and result["raw"]:
        assert result["raw"].get("egress_performed", False) is False
