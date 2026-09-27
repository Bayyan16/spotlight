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
    ):
        monkeypatch.delenv(var, raising=False)
    yield


@pytest.fixture(autouse=True)
def _no_semgrep_registry(monkeypatch):
    """Keep the suite off semgrep.dev.

    `p/default` is downloaded from the registry on first use. Where that
    host is slow or blocked (air-gapped box, restricted CI runner, proxied
    sandbox) every sweep in the suite pays `timeout_s + 15` seconds and
    still gets zero matches — minutes of tests become an hour. Semgrep is a
    corroborator, and no test asserts on its matches, so switch it off by
    default. Opt back in with SPOTLIGHT_TEST_SEMGREP=1 (which also gates the
    live adapter test); tests/unit/test_semgrep_adapter.py overrides this
    fixture's setting because the switches themselves are what it covers.
    """
    from spotlight.signals.semgrep_adapter import reset_degraded_state

    if os.environ.get("SPOTLIGHT_TEST_SEMGREP"):
        # Deliberately running live — respect whichever ruleset the
        # operator pointed us at, including a vendored local one.
        pass
    else:
        monkeypatch.setenv("SPOTLIGHT_SEMGREP", "off")
        monkeypatch.delenv("SPOTLIGHT_SEMGREP_CONFIG", raising=False)
    # The degradation latch is process-wide by design; reset it between
    # tests so one test's simulated outage can't silence another's.
    reset_degraded_state()
    yield
    reset_degraded_state()
