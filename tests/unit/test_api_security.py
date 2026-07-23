from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from spotlight.api.app import app
from spotlight.api.security import (
    create_session_token,
    validate_security_configuration,
    verify_session_token,
)


def test_production_requires_workspace_key(monkeypatch):
    monkeypatch.setenv("SPOTLIGHT_ENV", "production")
    with pytest.raises(RuntimeError, match="SPOTLIGHT_API_KEY"):
        validate_security_configuration()


def test_bearer_key_protects_workspace_routes(monkeypatch):
    monkeypatch.setenv("SPOTLIGHT_AUTH_MODE", "required")
    monkeypatch.setenv("SPOTLIGHT_API_KEY", "test-workspace-key")
    with TestClient(app) as client:
        assert client.get("/healthz").status_code == 200
        denied = client.get("/profiles")
        assert denied.status_code == 401
        allowed = client.get(
            "/profiles", headers={"Authorization": "Bearer test-workspace-key"}
        )
        assert allowed.status_code == 200
        assert allowed.headers["x-content-type-options"] == "nosniff"
        assert allowed.headers["x-frame-options"] == "DENY"


def test_session_cookie_and_csrf_boundary(monkeypatch):
    monkeypatch.setenv("SPOTLIGHT_AUTH_MODE", "required")
    monkeypatch.setenv("SPOTLIGHT_API_KEY", "test-workspace-key")
    with TestClient(app) as client:
        login = client.post("/auth/session", json={"api_key": "test-workspace-key"})
        assert login.status_code == 200
        assert client.get("/profiles").status_code == 200

        denied = client.put("/prefs/workspace/demo", json={"value": True})
        assert denied.status_code == 403
        allowed = client.put(
            "/prefs/workspace/demo",
            json={"value": True},
            headers={"Origin": "http://testserver"},
        )
        assert allowed.status_code == 200


def test_session_token_rejects_tampering():
    token = create_session_token("key", ttl_seconds=60)
    assert verify_session_token(token, "key") == "workspace-user"
    assert verify_session_token(token + "x", "key") is None
    assert verify_session_token(token, "different-key") is None


def test_login_attempts_are_rate_limited(monkeypatch):
    from spotlight.api.security import reset_login_failures

    monkeypatch.setenv("SPOTLIGHT_AUTH_MODE", "required")
    monkeypatch.setenv("SPOTLIGHT_API_KEY", "correct-horse")
    monkeypatch.setenv("SPOTLIGHT_LOGIN_FAILURE_LIMIT", "2")
    reset_login_failures()
    with TestClient(app) as client:
        assert client.post("/auth/session", json={"api_key": "wrong-one"}).status_code == 401
        blocked = client.post("/auth/session", json={"api_key": "wrong-two"})
        assert blocked.status_code == 429
        assert "Retry-After" in blocked.headers
    reset_login_failures()
