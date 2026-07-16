"""Sandbox router — picks Modal when available, subprocess otherwise.

The decision is per-process: if `MODAL_TOKEN_ID` + `MODAL_TOKEN_SECRET` are
set AND `modal` is importable AND `SPOTLIGHT_SANDBOX=modal` (or unset in
production), we use Modal. Otherwise the subprocess fallback runs.

Tests explicitly opt out by setting `SPOTLIGHT_SANDBOX=subprocess` in
conftest.
"""
from __future__ import annotations

import os

from .base import SandboxRunner


def get_sandbox() -> SandboxRunner:
    choice = os.environ.get("SPOTLIGHT_SANDBOX", "auto")
    if choice == "subprocess":
        from .subprocess_sandbox import SubprocessSandbox

        return SubprocessSandbox()
    if choice == "modal":
        return _try_modal_or_raise()
    # Auto: prefer Modal if creds present, else subprocess.
    if os.environ.get("MODAL_TOKEN_ID") and os.environ.get("MODAL_TOKEN_SECRET"):
        try:
            return _try_modal_or_raise()
        except Exception as e:
            print(f"[sandbox] Modal init failed, falling back to subprocess: {e!r}")
    from .subprocess_sandbox import SubprocessSandbox

    return SubprocessSandbox()


def _try_modal_or_raise() -> SandboxRunner:
    from .modal_sandbox import ModalSandbox

    return ModalSandbox()
