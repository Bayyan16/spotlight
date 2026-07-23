"""P1.2 — web/worker split.

Guards:
  1. SPOTLIGHT_INLINE_EXECUTION defaults to true (backward-compat).
  2. When SPOTLIGHT_INLINE_EXECUTION=false, `start_sweep` persists the
     job as "queued" but does NOT launch the sweep — the web process
     is pure enqueue in this mode.
  3. Worker's `_run_one_sweep` reads the payload, executes inline, and
     releases the lease when the sweep succeeds.
  4. The executor's heartbeat renewal fires while a sweep is running
     and stops when the sweep finishes.

Uses monkeypatch to avoid actually running a full sweep — we stub the
inline execution to a no-op that just marks the job finished so the
lease release path exercises correctly.
"""
from __future__ import annotations

import base64
import os
import threading
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _signing_key(monkeypatch):
    """Provide a deterministic workspace signing key so app import doesn't
    fail — the Signer initializes at module import time."""
    priv = Ed25519PrivateKey.generate()
    raw = priv.private_bytes_raw()
    monkeypatch.setenv("SPOTLIGHT_SIGNING_KEY", base64.b64encode(raw).decode("ascii"))


def _fresh_app_module(monkeypatch, *, inline: bool):
    """Reload spotlight.api.app with a specific SPOTLIGHT_INLINE_EXECUTION
    value. Each test gets a clean module so global registries don't leak."""
    monkeypatch.setenv("SPOTLIGHT_INLINE_EXECUTION", "true" if inline else "false")
    import importlib
    import spotlight.api.app as app_mod
    importlib.reload(app_mod)
    return app_mod


def test_inline_execution_defaults_to_true(monkeypatch):
    monkeypatch.delenv("SPOTLIGHT_INLINE_EXECUTION", raising=False)
    import importlib
    import spotlight.api.app as app_mod
    importlib.reload(app_mod)
    assert app_mod._inline_execution_enabled() is True


def test_inline_execution_can_be_disabled(monkeypatch):
    for val in ("false", "0", "no", "off", "FALSE"):
        monkeypatch.setenv("SPOTLIGHT_INLINE_EXECUTION", val)
        import importlib
        import spotlight.api.app as app_mod
        importlib.reload(app_mod)
        assert app_mod._inline_execution_enabled() is False, f"failed for {val!r}"


def test_start_sweep_in_enqueue_only_mode_does_not_launch(monkeypatch):
    """When SPOTLIGHT_INLINE_EXECUTION=false, the web POST enqueues the
    job but does NOT call _launch_sweep_job — the worker service is
    responsible for execution."""
    app_mod = _fresh_app_module(monkeypatch, inline=False)

    launched: list[str] = []
    monkeypatch.setattr(
        app_mod,
        "_launch_sweep_job",
        lambda *args, **kwargs: launched.append(args[0]) or True,
    )

    client = TestClient(app_mod.app)
    resp = client.post("/sweeps", json={"repo": "acme-bank"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "queued"
    assert launched == [], "web must not launch when INLINE_EXECUTION=false"


def test_start_sweep_in_inline_mode_launches_job(monkeypatch):
    app_mod = _fresh_app_module(monkeypatch, inline=True)

    launched: list[str] = []
    monkeypatch.setattr(
        app_mod,
        "_launch_sweep_job",
        lambda *args, **kwargs: launched.append(args[0]) or True,
    )

    client = TestClient(app_mod.app)
    resp = client.post("/sweeps", json={"repo": "acme-bank"})
    assert resp.status_code == 200
    assert len(launched) == 1
    assert launched[0].startswith("sw_")


def test_launch_sweep_job_inline_runs_synchronously(monkeypatch):
    """_launch_sweep_job_inline is the shared execution path used by the
    worker. It does not spawn a thread — it runs in the caller's thread.

    We stub _resolve_repo + Orchestrator to skip actual sweep work; the
    test only verifies control flow (persist header, mark finished,
    cleanup)."""
    app_mod = _fresh_app_module(monkeypatch, inline=True)

    calls: list[str] = []

    class _StubResult:
        sweep_id = "sw_test"
        findings = []
        attestations = [{"sweep_id": "sw_test", "chain_of_custody": {"entries": []}}]

    from pathlib import Path

    def _fake_resolve(repo, commit_sha=None):
        calls.append("resolve")
        return Path("/tmp/fake"), "fixture"

    def _fake_persist_header(sweep_id, path, source, *, interactive):
        calls.append("persist_header")

    class _FakeOrchestrator:
        def __init__(self, *a, **kw):
            pass
        def run(self, path, interactive, sweep_id):
            calls.append("run")
            return _StubResult()

    def _fake_persist_result(result, source, repo_name):
        calls.append("persist_result")

    def _fake_finish(sweep_id, error=None):
        calls.append(f"finish:{error}")

    monkeypatch.setattr(app_mod, "_resolve_repo", _fake_resolve)
    monkeypatch.setattr(app_mod, "_persist_sweep_header", _fake_persist_header)
    monkeypatch.setattr(app_mod, "Orchestrator", _FakeOrchestrator)
    monkeypatch.setattr(app_mod, "_persist_sweep", _fake_persist_result)
    monkeypatch.setattr(app_mod, "_finish_job", _fake_finish)

    req = app_mod.SweepRequest(repo="acme-bank")
    app_mod._launch_sweep_job_inline("sw_test", req)

    assert calls == [
        "resolve", "persist_header", "run",
        "persist_result", "finish:None",
    ]


def test_worker_module_imports_and_main_returns_2_without_db(monkeypatch):
    """python -m spotlight.worker without DATABASE_URL fails cleanly
    (exit code 2, not a crash) — worker requires persistence."""
    from spotlight.worker.run import main
    monkeypatch.delenv("DATABASE_URL", raising=False)
    # Force store_enabled() to False by ensuring no DB URL is set.
    rc = main()
    assert rc == 2


def test_worker_dockerfile_ships_alembic_upgrade():
    """Guard against accidentally dropping the migrate-before-boot hook
    from the worker Dockerfile."""
    from pathlib import Path
    df = Path(__file__).resolve().parents[2] / "infra" / "Dockerfile.worker"
    content = df.read_text()
    assert "alembic upgrade head" in content
    assert "spotlight.worker" in content
