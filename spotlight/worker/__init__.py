"""Sweep-execution worker (P1.2).

Splits sweep execution out of the FastAPI web process so multiple
worker replicas can pull from the shared `sweep_jobs` queue. The web
process either runs sweeps inline (dev / tests, default) or acts as a
pure enqueue endpoint (production, when SPOTLIGHT_INLINE_EXECUTION is
false), and the worker service claims via
`spotlight.store.leasing.claim_next`, runs the sweep, and releases.

Public surface:
  * spotlight.worker.executor.execute_sweep — the actual per-sweep work,
    reusable from both the web process (inline) and the worker process
    (via the polling loop)
  * spotlight.worker.run — the worker entrypoint (python -m spotlight.worker)
"""
from spotlight.worker.executor import execute_sweep

__all__ = ["execute_sweep"]
