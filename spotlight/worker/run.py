"""Sweep-execution worker loop.

Usage:  python -m spotlight.worker

The worker polls `sweep_jobs` via `spotlight.store.leasing.claim_next`,
runs the sweep, releases the lease, and repeats. Signals:

  * SIGTERM / SIGINT — finish the current sweep, then exit cleanly
  * heartbeat — a background thread renews the lease every
    SPOTLIGHT_HEARTBEAT_INTERVAL_SECONDS while the sweep is running

Config (env vars):
  * DATABASE_URL                       — Postgres URL (required)
  * SPOTLIGHT_LEASE_TTL_SECONDS        — default 60
  * SPOTLIGHT_HEARTBEAT_INTERVAL_SECONDS — default 10
  * SPOTLIGHT_WORKER_POLL_INTERVAL_SECONDS — how long to sleep between
    empty-queue polls; default 2
  * SPOTLIGHT_WORKER_EXPIRY_SWEEP_INTERVAL_SECONDS — how often the
    worker also runs sweep_expired_leases (defensive; safe under
    concurrency); default 30

The worker is idempotent under crash-retry: an interrupted sweep whose
lease expires is reclaimed by any worker (including this one on
restart) via `sweep_expired_leases` + `claim_next`.
"""
from __future__ import annotations

import logging
import os
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Callable

from sqlalchemy.exc import SQLAlchemyError

from spotlight.orchestrator import EventBus
from spotlight.store import (
    SweepJobRow,
    get_session,
    init_schema,
    is_enabled as store_enabled,
)
from spotlight.store import leasing as job_leasing


log = logging.getLogger("spotlight.worker")


def _poll_interval() -> float:
    try:
        return float(os.environ.get("SPOTLIGHT_WORKER_POLL_INTERVAL_SECONDS", "2"))
    except (TypeError, ValueError):
        return 2.0


def _expiry_sweep_interval() -> float:
    try:
        return float(os.environ.get("SPOTLIGHT_WORKER_EXPIRY_SWEEP_INTERVAL_SECONDS", "30"))
    except (TypeError, ValueError):
        return 30.0


class _StopSignal:
    """Wraps a threading.Event so signal handlers can request a clean
    shutdown from any thread. The main loop checks .set() between
    sweeps; the heartbeat thread checks it in its sleep cycle."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def set(self) -> None:
        self._event.set()

    def is_set(self) -> bool:
        return self._event.is_set()

    def wait(self, timeout: float) -> bool:
        return self._event.wait(timeout=timeout)


def _install_signal_handlers(stop: _StopSignal) -> None:
    def _handle(_signum, _frame):
        log.info("worker received signal; will exit after current sweep completes")
        stop.set()

    signal.signal(signal.SIGTERM, _handle)
    signal.signal(signal.SIGINT, _handle)


def _heartbeat_loop(
    stop: _StopSignal,
    sweep_id: str,
    interval: float,
) -> None:
    """Renew the lease every `interval` seconds while the sweep runs.
    Exits when `stop` fires (i.e. the sweep completed) or when a renew
    fails (the lease was reclaimed by another worker — the sweep should
    be aborted, but that logic lives in the main loop's inspection)."""
    while not stop.is_set():
        try:
            with get_session() as sess:
                still_ours = job_leasing.renew(sess, sweep_id)
            if not still_ours:
                log.warning(
                    "sweep %s lease was reclaimed by another worker; heartbeat exiting",
                    sweep_id,
                )
                return
        except SQLAlchemyError as exc:
            log.warning("heartbeat renew failed for %s: %r", sweep_id, exc)
        stop.wait(interval)


def _run_one_sweep(sweep_id: str) -> None:
    """Load the sweep-job payload, run the sweep, release the lease."""
    from spotlight.api.app import (
        SweepRequest,
        _finish_job,
        _launch_sweep_job_inline,
    )

    with get_session() as sess:
        job = sess.get(SweepJobRow, sweep_id)
        if job is None:
            log.warning("claimed sweep %s but no job row found", sweep_id)
            return
        payload = dict(job.request or {})

    req = SweepRequest(**payload)
    heartbeat_stop = _StopSignal()
    hb_thread = threading.Thread(
        target=_heartbeat_loop,
        args=(heartbeat_stop, sweep_id, _heartbeat_interval_seconds()),
        daemon=True,
        name=f"heartbeat-{sweep_id}",
    )
    hb_thread.start()
    try:
        _launch_sweep_job_inline(sweep_id, req)
    finally:
        heartbeat_stop.set()
        hb_thread.join(timeout=5)


def _heartbeat_interval_seconds() -> float:
    return job_leasing.heartbeat_interval().total_seconds()


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("SPOTLIGHT_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    if not store_enabled():
        log.error("spotlight.worker requires DATABASE_URL; falling back to memory is not supported")
        return 2

    init_schema()  # idempotent; production also runs alembic upgrade head
    stop = _StopSignal()
    _install_signal_handlers(stop)

    log.info(
        "worker %s starting: lease_ttl=%ss heartbeat=%ss poll=%ss expiry_sweep=%ss",
        job_leasing.worker_id(),
        int(job_leasing.lease_ttl().total_seconds()),
        int(_heartbeat_interval_seconds()),
        _poll_interval(),
        _expiry_sweep_interval(),
    )

    last_expiry_sweep = 0.0
    while not stop.is_set():
        now = time.monotonic()

        # Periodic expired-lease sweep. Safe under concurrent workers;
        # the leasing module uses row-level locks so ties resolve cleanly.
        if now - last_expiry_sweep >= _expiry_sweep_interval():
            try:
                with get_session() as sess:
                    reclaimed = job_leasing.sweep_expired_leases(sess)
                if reclaimed:
                    log.info("reclaimed %d expired-lease sweep jobs", reclaimed)
            except SQLAlchemyError as exc:
                log.warning("expired-lease sweep failed: %r", exc)
            last_expiry_sweep = now

        # Try to claim the next queued job.
        sweep_id: str | None = None
        try:
            with get_session() as sess:
                sweep_id = job_leasing.claim_next(sess)
        except SQLAlchemyError as exc:
            log.warning("claim_next failed: %r", exc)
            stop.wait(_poll_interval())
            continue

        if sweep_id is None:
            # Empty queue — nap.
            stop.wait(_poll_interval())
            continue

        log.info("claimed sweep %s", sweep_id)
        try:
            _run_one_sweep(sweep_id)
            log.info("sweep %s completed", sweep_id)
        except Exception:  # noqa: BLE001
            log.exception("sweep %s crashed in worker loop", sweep_id)

    log.info("worker %s exiting cleanly", job_leasing.worker_id())
    return 0


if __name__ == "__main__":
    sys.exit(main())
