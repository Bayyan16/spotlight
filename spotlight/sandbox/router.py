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


def _is_production() -> bool:
    explicit = os.environ.get("SPOTLIGHT_ENV", "").strip().lower()
    if explicit:
        return explicit in {"prod", "production"}
    return bool(os.environ.get("RAILWAY_ENVIRONMENT"))


def _modal_credentials_present() -> bool:
    return bool(os.environ.get("MODAL_TOKEN_ID") and os.environ.get("MODAL_TOKEN_SECRET"))


def validate_sandbox_configuration() -> None:
    """Fail startup when production could execute target code on the host."""
    if not _is_production():
        return
    choice = os.environ.get("SPOTLIGHT_SANDBOX", "auto").strip().lower()
    if choice == "subprocess":
        raise RuntimeError("SPOTLIGHT_SANDBOX=subprocess is forbidden in production")
    if choice not in {"auto", "modal"}:
        raise RuntimeError("production SPOTLIGHT_SANDBOX must be auto or modal")
    if not _modal_credentials_present():
        raise RuntimeError("production requires MODAL_TOKEN_ID and MODAL_TOKEN_SECRET")


def get_sandbox() -> SandboxRunner:
    choice = os.environ.get("SPOTLIGHT_SANDBOX", "auto")
    if choice == "subprocess":
        if _is_production():
            raise RuntimeError("subprocess sandbox is forbidden in production")
        from .subprocess_sandbox import SubprocessSandbox

        return SubprocessSandbox()
    if choice == "modal":
        return _try_modal_or_raise()
    # Auto: prefer Modal if creds present, else subprocess.
    if _modal_credentials_present():
        try:
            return _try_modal_or_raise()
        except Exception as e:
            if _is_production():
                raise RuntimeError("Modal sandbox initialization failed in production") from e
            print(f"[sandbox] Modal init failed, falling back to subprocess: {e!r}")
    elif _is_production():
        raise RuntimeError("production sandbox unavailable: Modal credentials are missing")
    from .subprocess_sandbox import SubprocessSandbox

    return SubprocessSandbox()


def _try_modal_or_raise() -> SandboxRunner:
    from .modal_sandbox import ModalSandbox

    return ModalSandbox()
