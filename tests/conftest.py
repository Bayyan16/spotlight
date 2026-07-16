"""Test config: keep tests deterministic by scrubbing model creds from the env.

The Orchestrator picks up MOONSHOT_API_KEY from env in production. In tests
we always want the MockModelClient (reproducible, no network).
"""
import os

import pytest


@pytest.fixture(autouse=True)
def _no_real_model(monkeypatch):
    for var in ("MOONSHOT_API_KEY", "MOONSHOT_BASE_URL", "MOONSHOT_MODEL"):
        monkeypatch.delenv(var, raising=False)
    yield
