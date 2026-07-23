from __future__ import annotations

import pytest

from spotlight.sandbox.router import get_sandbox, validate_sandbox_configuration


def test_production_rejects_subprocess(monkeypatch):
    monkeypatch.setenv("SPOTLIGHT_ENV", "production")
    monkeypatch.setenv("SPOTLIGHT_SANDBOX", "subprocess")
    with pytest.raises(RuntimeError, match="forbidden"):
        validate_sandbox_configuration()
    with pytest.raises(RuntimeError, match="forbidden"):
        get_sandbox()


def test_production_requires_modal_credentials(monkeypatch):
    monkeypatch.setenv("SPOTLIGHT_ENV", "production")
    monkeypatch.setenv("SPOTLIGHT_SANDBOX", "auto")
    monkeypatch.delenv("MODAL_TOKEN_ID", raising=False)
    monkeypatch.delenv("MODAL_TOKEN_SECRET", raising=False)
    with pytest.raises(RuntimeError, match="MODAL_TOKEN_ID"):
        validate_sandbox_configuration()
