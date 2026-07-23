"""Bounded sweep admission for the single-process control plane.

This is the immediate cost/DoS guard. The durable worker tranche replaces the
in-memory counters with transactional leases, while preserving this interface.
"""
from __future__ import annotations

import os
import threading
import time
from collections import defaultdict, deque
from uuid import uuid4

from fastapi import HTTPException

from .security import is_production


class SweepAdmissionController:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._active: dict[str, str] = {}
        self._starts: dict[str, deque[float]] = defaultdict(deque)

    def _max_active(self) -> int:
        default = "2" if is_production() else "8"
        return max(1, int(os.environ.get("SPOTLIGHT_MAX_ACTIVE_SWEEPS", default)))

    def _starts_per_hour(self) -> int:
        default = "10" if is_production() else "1000"
        return max(1, int(os.environ.get("SPOTLIGHT_SWEEPS_PER_HOUR", default)))

    def admit(self, principal: str) -> str:
        now = time.monotonic()
        with self._lock:
            starts = self._starts[principal]
            while starts and starts[0] <= now - 3600:
                starts.popleft()
            if len(starts) >= self._starts_per_hour():
                retry = max(1, int(3600 - (now - starts[0])))
                raise HTTPException(
                    429,
                    "workspace sweep-start quota exceeded",
                    headers={"Retry-After": str(retry)},
                )
            if len(self._active) >= self._max_active():
                raise HTTPException(
                    429,
                    "maximum active sweeps reached",
                    headers={"Retry-After": "30"},
                )
            token = uuid4().hex
            starts.append(now)
            self._active[token] = principal
            return token

    def release(self, token: str) -> None:
        with self._lock:
            self._active.pop(token, None)

    def active_count(self) -> int:
        with self._lock:
            return len(self._active)

    def reset(self) -> None:
        with self._lock:
            self._active.clear()
            self._starts.clear()


SWEEP_ADMISSION = SweepAdmissionController()
