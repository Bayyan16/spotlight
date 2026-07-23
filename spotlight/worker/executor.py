"""Per-sweep execution — the actual work of running an Orchestrator.

Extracted from spotlight.api.app._launch_sweep_job so it can be called
from either:

  * the web process (dev / tests, when SPOTLIGHT_INLINE_EXECUTION=true)
  * the worker process (`python -m spotlight.worker`, in production)

Both paths converge here so tests can exercise the full sweep pipeline
inline without spinning up a real Postgres + worker service.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from spotlight.orchestrator import EventBus, Orchestrator, SweepResult
from spotlight.profiles import get_profile


log = logging.getLogger(__name__)


@dataclass
class ExecutionResult:
    sweep_id: str
    result: SweepResult | None
    error: str | None
    source: str
    repo_path: Path | None


def execute_sweep(
    sweep_id: str,
    *,
    repo: str,
    profile_id: str | None,
    interactive: bool,
    commit_sha: str | None,
    bus: EventBus,
    resolve_repo: Callable[[str, str | None], tuple[Path, str]],
    persist_header: Callable[[str, Path, str, bool], None],
    persist_result: Callable[[SweepResult, str, str], None],
    mark_failed: Callable[[str, str], None],
    on_success: Callable[[str], None] | None = None,
    on_failure: Callable[[str, str], None] | None = None,
    on_cleanup: Callable[[str, Path | None, str], None] | None = None,
) -> ExecutionResult:
    """Run one sweep synchronously, emitting events through `bus`.

    All persistence + resource-cleanup side effects are dependency-injected
    so this function can be unit-tested against fakes without a live
    database or filesystem. Callers (web process inline path, worker
    process claim loop) supply the callables that fit their environment.

    Returns an ExecutionResult with `error` populated iff the sweep failed.
    The function never raises — every error path is captured and reported
    via `mark_failed` + `on_failure`.
    """
    repo_path: Path | None = None
    source = "unknown"
    try:
        repo_path, source = resolve_repo(repo, commit_sha)
        persist_header(sweep_id, repo_path, source, interactive)
        profile = get_profile(profile_id)
        result = Orchestrator(bus=bus, profile=profile).run(
            repo_path,
            interactive=interactive,
            sweep_id=sweep_id,
        )
        persist_result(result, source, repo_path.name)
        if on_success is not None:
            on_success(sweep_id)
        return ExecutionResult(
            sweep_id=sweep_id, result=result, error=None,
            source=source, repo_path=repo_path,
        )
    except Exception as exc:  # noqa: BLE001 — this is the outer boundary
        reason = repr(exc)[:1000]
        log.exception("sweep %s failed", sweep_id)
        try:
            from spotlight.orchestrator.events import EventType

            bus.emit(sweep_id, EventType.SWEEP_FAILED, "orchestrator", error=reason)
        except Exception:
            pass
        mark_failed(sweep_id, reason)
        if on_failure is not None:
            on_failure(sweep_id, reason)
        return ExecutionResult(
            sweep_id=sweep_id, result=None, error=reason,
            source=source, repo_path=repo_path,
        )
    finally:
        if on_cleanup is not None:
            on_cleanup(sweep_id, repo_path, source)
