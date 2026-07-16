"""Live Modal-sandbox integration tests.

Skipped by default because they hit real Modal and consume credits.

Enable with:
  export MODAL_TOKEN_ID=... MODAL_TOKEN_SECRET=... SPOTLIGHT_TEST_MODAL=1
  pytest tests/integration/test_modal_sandbox.py -v

What we prove (once, at Tranche A3 landing time):
  1. A Modal sandbox actually spawns, executes, and terminates.
  2. `block_network=True` denies outbound network — a PoC that tries
     to `curl example.com` fails at the platform level.
  3. Timeout cap trips a runaway PoC cleanly (no hung sandbox).
"""
from __future__ import annotations

import os

import pytest


modal_live = pytest.mark.skipif(
    not (
        os.environ.get("SPOTLIGHT_TEST_MODAL")
        and os.environ.get("MODAL_TOKEN_ID")
        and os.environ.get("MODAL_TOKEN_SECRET")
    ),
    reason="requires SPOTLIGHT_TEST_MODAL=1 + MODAL_TOKEN_ID/SECRET",
)


@modal_live
def test_modal_sandbox_hello_world():
    from spotlight.sandbox import CapabilityToken
    from spotlight.sandbox.modal_sandbox import ModalSandbox

    box = ModalSandbox()
    tok = CapabilityToken(agent_role="test", egress_allowed=False, timeout_s=30)
    result = box.run_python(
        script="print(__import__('json').dumps({'ok': True, 'exploited': False}))",
        token=tok,
    )
    assert result.engine == "modal"
    assert result.exit_code == 0
    assert '"ok": true' in result.stdout


@modal_live
def test_modal_sandbox_denies_outbound_network():
    """The whole 'swarm cannot be turned against you' pitch depends on this
    behavior. When block_network=True (token.egress_allowed=False), a PoC
    that tries to reach the network MUST fail at the platform level."""
    from spotlight.sandbox import CapabilityToken
    from spotlight.sandbox.modal_sandbox import ModalSandbox

    box = ModalSandbox()
    tok = CapabilityToken(agent_role="test", egress_allowed=False, timeout_s=45)
    script = (
        "import urllib.request, json\n"
        "try:\n"
        "  urllib.request.urlopen('https://example.com', timeout=5).read()\n"
        "  print(json.dumps({'egress_worked': True}))\n"
        "except Exception as e:\n"
        "  print(json.dumps({'egress_worked': False, 'err': type(e).__name__}))\n"
    )
    result = box.run_python(script=script, token=tok)
    assert '"egress_worked": false' in result.stdout, (
        f"expected egress to be denied, got: stdout={result.stdout!r} stderr={result.stderr!r}"
    )


@modal_live
def test_modal_sandbox_timeout_kills_runaway_poc():
    from spotlight.sandbox import CapabilityToken
    from spotlight.sandbox.modal_sandbox import ModalSandbox

    box = ModalSandbox()
    # 5s cap on a script that would run 30s
    tok = CapabilityToken(agent_role="test", egress_allowed=False, timeout_s=5)
    script = "import time; time.sleep(30); print('should not print')"
    result = box.run_python(script=script, token=tok)
    # Either a non-zero exit or "should not print" absent — both are OK signals.
    assert "should not print" not in result.stdout
