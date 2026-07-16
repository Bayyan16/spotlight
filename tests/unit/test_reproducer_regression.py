"""Regression tests for the Reproducer subprocess PoC.

These tests exist because of a production bug (2026-07-16) where the
Reproducer's PoC returned ``result="inconclusive"`` on Railway while returning
``"confirmed"`` locally. Root cause: the PoC script was assembled via nested
f-strings and the SQLi payload ``' OR '1'='1`` was interpolated directly into
a URL path passed to ``flask.testing.FlaskClient.get``. Werkzeug 3.1.x (Flask
3.1.3, Railway's installed version) rejects unencoded quotes/spaces in the
test-client path — the request 404s, the response body is HTML, json parsing
fails, ``exploited`` is falsy, tier is downgraded.

We keep the tests independent of the local Werkzeug version by pinning to the
mechanism of the fix:

  1. ``Reproducer.run`` must exploit the vuln fixture and return ``confirmed``.
  2. The PoC script (a) must URL-encode the payload before making the request,
     (b) must not embed the raw payload string into an f-string URL path, and
     (c) must read the payload from an env var / tempfile — no inline shell
     interpolation.
  3. Verifier must reuse the same safe mechanism (both call sites got the bug).
  4. When the payload contains quotes and spaces (as it always does for
     tautology SQLi), the PoC still reaches the vulnerable route.
"""
from __future__ import annotations

from pathlib import Path

from spotlight.agents import roles
from spotlight.agents.model import MockModelClient
from spotlight.agents.roles import Reproducer, Remediator, Verifier

ROOT = Path(__file__).resolve().parents[2]
VULN_FIXTURE = ROOT / "targets" / "vuln-bank-api"
CLEAN_FIXTURE = ROOT / "targets" / "clean-bank-api"


# --------------------------------------------------------------------------
# Behavioral regression: the actual bug the user reported
# --------------------------------------------------------------------------

def test_reproducer_confirms_sqli_on_vuln_fixture():
    """Ships-must-pass. This is exactly what Railway saw fail."""
    finding = {"class": "sqli", "location": {"file": "app.py", "function": "get_account"}}
    result = Reproducer().run(VULN_FIXTURE, finding)
    assert result["result"] == "confirmed", (
        f"expected confirmed, got {result['result']}: "
        f"stdout={result.get('stdout')!r} stderr={result.get('stderr')!r}"
    )
    assert result["raw"]["exploited"] is True
    assert result["raw"]["status"] == 200
    # The vuln fixture seeds two rows; the tautology returns them both.
    assert len(result["raw"]["rows"]) >= 2


def test_reproducer_does_not_falsely_exploit_clean_fixture():
    """Precision negative for the fix itself."""
    finding = {"class": "sqli", "location": {"file": "app.py", "function": "get_account"}}
    result = Reproducer().run(CLEAN_FIXTURE, finding)
    assert result["result"] == "not-reproduced"
    assert result["raw"]["exploited"] is False


# --------------------------------------------------------------------------
# Mechanism regressions: lock the fix so this exact bug can't recur
# --------------------------------------------------------------------------

def test_poc_script_url_encodes_the_payload():
    """The PoC MUST url-encode the payload before hitting the route. If a
    future refactor drops ``quote(...)`` and shoves the raw payload into an
    f-string path, Werkzeug 3.x will 404 and the Reproducer will silently
    downgrade to ``not-reproduced``."""
    template = roles._PY_POC_SCRIPT
    assert "from urllib.parse import quote" in template
    assert "quote(payload" in template


def test_poc_script_does_not_use_fstring_url_interpolation():
    """Regression-lock: the buggy code did ``f"/accounts/{payload}"`` with a
    payload containing quotes + spaces. Never again."""
    template = roles._PY_POC_SCRIPT
    assert 'f"/accounts/{payload}"' not in template
    assert "f'/accounts/{payload}'" not in template


def test_poc_script_resolves_target_root_from_env():
    """Payload is a literal in the script; the *target root* (which differs
    between Modal mount /app/target and subprocess cwd) comes from env so the
    same script runs under both engines. No shell interpolation surface."""
    template = roles._PY_POC_SCRIPT
    assert "SPOTLIGHT_TARGET_ROOT" in template
    assert 'os.environ.get("SPOTLIGHT_TARGET_ROOT"' in template


def test_reproducer_handles_payload_with_quotes_and_spaces(tmp_path):
    """Directly exercise the exact failure mode: the payload has both a
    single quote AND a space, which is what Werkzeug 3.x rejects when
    passed unencoded. If URL-encoding is missing this test fails on any
    modern Werkzeug because the request 404s and rows==[]."""
    # Build a tiny Flask app that echoes back the received username so we
    # can assert the payload survived transport with quotes+spaces intact.
    echo_app = tmp_path / "app.py"
    echo_app.write_text(
        "from flask import Flask, jsonify\n"
        "app = Flask(__name__)\n"
        "@app.route('/accounts/<username>')\n"
        "def get_account(username):\n"
        # Non-empty list only if the tautology payload made it through
        # verbatim (quote + space + quote).
        "    if \"' OR '1'='1\" in username:\n"
        "        return jsonify([[1, username, 0.0], [2, 'x', 0.0]])\n"
        "    return jsonify([])\n"
    )
    finding = {"class": "sqli", "location": {"file": "app.py", "function": "get_account"}}
    result = Reproducer().run(tmp_path, finding)
    assert result["result"] == "confirmed", (
        f"URL-encoding regression: payload with quotes+spaces was not "
        f"delivered to the route. stdout={result.get('stdout')!r} "
        f"stderr={result.get('stderr')!r}"
    )


def test_reproducer_returns_inconclusive_for_non_sqli():
    """Untouched code path — guardrail so the fix didn't perturb it."""
    finding = {"class": "xss", "location": {"file": "app.py", "function": "x"}}
    result = Reproducer().run(VULN_FIXTURE, finding)
    assert result["result"] == "inconclusive"


# --------------------------------------------------------------------------
# Verifier had the SAME bug — lock the fix on that path too
# --------------------------------------------------------------------------

def test_verifier_uses_same_url_safe_poc_mechanism():
    """The Verifier re-runs the PoC against the patched artifact. It had the
    identical f-string bug; if a future refactor reintroduces it there, the
    Verifier's exploited-check will silently succeed (rows == [] because 404)
    and every fix will look 'verified' regardless of whether it actually
    patched the vuln. This test locks the Verifier onto the shared safe
    template."""
    import inspect

    src = inspect.getsource(Verifier)
    assert "_PY_POC_SCRIPT" in src, (
        "Verifier must reuse the shared _PY_POC_SCRIPT template. Do not build "
        "its PoC script via f-string again."
    )
    # And the buggy shape must not reappear inside Verifier.
    assert 'f"/accounts/{{payload}}"' not in src
    assert 'client.get(f"/accounts/{payload}")' not in src


def test_verifier_confirms_patched_fixture_is_not_exploitable(tmp_path):
    """End-to-end sanity through Remediator + Verifier so the fix is
    exercised through both subprocess call sites."""
    finding = {
        "class": "sqli",
        "cwe": "CWE-89",
        "location": {"file": "app.py", "function": "get_account"},
    }
    remediation = Remediator().run(VULN_FIXTURE, finding)
    assert remediation["applied"] is True
    verifier = Verifier(MockModelClient())
    v = verifier.run(VULN_FIXTURE, finding, remediation)
    # Patched app returns [] for the tautology; verifier's result reflects
    # the sandbox-observed exploit outcome, not the model's prose.
    assert v["result"] == "repro-now-blocked"
    assert v["backdoor_check"] == "pass"
    assert v["independent_verifier"] is True
    # Clean up the .patched.py sibling the Remediator dropped in-tree.
    patched_path = Path(remediation["patched_path"])
    if patched_path.exists():
        patched_path.unlink()
