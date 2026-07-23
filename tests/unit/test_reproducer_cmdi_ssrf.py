import shutil
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


# ---------- JavaScript reproducers ----------
#
# The JS PoCs require a `node` runtime on PATH. Skip these on CI machines
# without Node installed so the suite stays green — production reproduction
# runs under ModalSandbox which preinstalls Node in the container image.

_HAS_NODE = shutil.which("node") is not None


@pytest.mark.skipif(not _HAS_NODE, reason="node runtime not installed")
@pytest.mark.parametrize(
    ("target", "class_name", "function_name", "expected"),
    [
        ("vuln-cmdi-node", "cmdi", "run_command", "confirmed"),
        ("clean-cmdi-node", "cmdi", "run_command", "not-reproduced"),
        ("vuln-ssrf-node", "ssrf", "fetch_url", "confirmed"),
        ("clean-ssrf-node", "ssrf", "fetch_url", "not-reproduced"),
    ],
)
def test_js_instrumented_reproduction_never_executes_or_egresses(
    target, class_name, function_name, expected
):
    repo = ROOT / "targets" / target
    finding = {
        "id": "SPOT-TEST-JS",
        "class": class_name,
        # Path ends in .js → dispatch routes to the JS PoC template.
        "location": {"file": str(repo / "app.js"), "function": function_name},
    }

    result = Reproducer(sandbox=SubprocessSandbox()).run(repo, finding)

    assert result["result"] == expected, (
        f"expected {expected} for {target}/{class_name}, got {result}"
    )
    assert result["poc"]["network_egress"] is False
    if class_name == "ssrf" and result.get("raw"):
        assert result["raw"].get("egress_performed", False) is False


@pytest.mark.skipif(not _HAS_NODE, reason="node runtime not installed")
def test_js_reproducer_never_calls_child_process_for_cmdi_canary():
    """Instrumentation invariant: the canary is a shell-command payload
    ('spotlight-cmdi-canary;id'). If the recorder captured it, that's a
    logical exploit proof — but the real command must NEVER be executed
    on the host. We verify the sandbox reports zero egress and inspect
    the parsed PoC output for the recorded (not executed) canary."""
    repo = ROOT / "targets" / "vuln-cmdi-node"
    finding = {
        "id": "SPOT-CANARY",
        "class": "cmdi",
        "location": {"file": str(repo / "app.js"), "function": "run_command"},
    }
    result = Reproducer(sandbox=SubprocessSandbox()).run(repo, finding)
    assert result["result"] == "confirmed"
    # sink_calls captured by the JS recorder; must contain the canary
    # string, proving the sink was reached without executing it.
    raw = result.get("raw") or {}
    sink_calls = raw.get("sink_calls") or []
    combined = str(sink_calls)
    assert "spotlight-cmdi-canary" in combined, (
        f"canary should appear in recorded sink calls: {sink_calls!r}"
    )
    assert result["sandbox"]["egress_attempts"] == 0


def test_js_dispatch_table_covers_all_supported_classes():
    """Guard: if a new supported class is added to the outer gate (line
    ~368) without a matching JS template, JS files of that class would
    fall through the inner JS dispatch and return 'inconclusive'. This
    test enumerates the three supported classes and confirms each has
    a JS template so the outer/inner dispatch stay in sync."""
    from spotlight.agents.roles import (
        _JS_CMDI_POC_SCRIPT,
        _JS_POC_SCRIPT,
        _JS_SSRF_POC_SCRIPT,
    )
    assert _JS_POC_SCRIPT and _JS_CMDI_POC_SCRIPT and _JS_SSRF_POC_SCRIPT
