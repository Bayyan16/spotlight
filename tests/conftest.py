"""Test config: keep tests deterministic by scrubbing model creds from the env.

The Orchestrator picks up a real model client from the environment in
production (SPOTLIGHT_LLM_API_KEY / MOONSHOT_API_KEY / OPENAI_API_KEY — see
spotlight/agents/moonshot.py). In tests we always want the MockModelClient:
reproducible, offline, no cost. This autouse fixture strips every LLM-selecting
variable so a contributor's ambient shell (many devs export OPENAI_API_KEY)
can never make the suite hit a real API.
"""
import os

import pytest


@pytest.fixture(autouse=True)
def _no_real_model(monkeypatch):
    for var in (
        # Provider-neutral config.
        "SPOTLIGHT_LLM_API_KEY", "SPOTLIGHT_LLM_BASE_URL",
        "SPOTLIGHT_LLM_MODEL", "SPOTLIGHT_LLM_FAMILY",
        # Moonshot (Kimi) preset.
        "MOONSHOT_API_KEY", "MOONSHOT_BASE_URL", "MOONSHOT_MODEL",
        # Plain-OpenAI convenience.
        "OPENAI_API_KEY", "OPENAI_BASE_URL",
    ):
        monkeypatch.delenv(var, raising=False)
    # Never let a developer's deployment shell make the local test suite
    # behave like production. Individual security tests opt in explicitly.
    for var in (
        "SPOTLIGHT_ENV",
        "RAILWAY_ENVIRONMENT",
        "SPOTLIGHT_AUTH_MODE",
        "SPOTLIGHT_API_KEY",
        "SPOTLIGHT_CORS_ORIGINS",
        "SPOTLIGHT_GIT_HOSTS",
        "SPOTLIGHT_ALLOW_LOCAL_REPOS",
        "SPOTLIGHT_LOCAL_REPO_ROOTS",
        "SPOTLIGHT_MAX_REPO_BYTES",
        "SPOTLIGHT_MAX_REPO_FILES",
        "SPOTLIGHT_MAX_ACTIVE_SWEEPS",
        "SPOTLIGHT_SWEEPS_PER_HOUR",
        "SPOTLIGHT_LOGIN_FAILURE_LIMIT",
        "SPOTLIGHT_LOGIN_WINDOW_SECONDS",
        # Cortex memory. An ambient SPOTLIGHT_CORTEX_DIR would make the suite
        # read and WRITE a developer's real experience ledger — and a learned
        # policy in that ledger would silently change the tiers the tests
        # assert on. Cortex tests construct their own Cortex under tmp_path.
        "SPOTLIGHT_CORTEX_DIR",
        "SPOTLIGHT_CORTEX_AUTONOMY",
    ):
        monkeypatch.delenv(var, raising=False)
    yield
