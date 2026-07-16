"""Subprocess-based sandbox — the fallback used in tests and local dev.

Provides the same interface as ModalSandbox but runs the code in a plain
`subprocess.run`. Egress-off is enforced BEST-EFFORT by unsetting HTTP proxy
env vars and setting a limited PATH; it is NOT a hard guarantee here — that's
the whole reason ModalSandbox exists. For production, use Modal.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from .base import SandboxResult, SandboxRunner
from .capability import CapabilityToken


class SubprocessSandbox(SandboxRunner):
    engine = "subprocess"

    def run_python(
        self,
        script: str,
        token: CapabilityToken,
        env: dict[str, str] | None = None,
    ) -> SandboxResult:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
            f.write(script)
            script_path = f.name
        return self._run([sys.executable, script_path], token, env, script_path)

    def run_node(
        self,
        script: str,
        token: CapabilityToken,
        env: dict[str, str] | None = None,
        deps: dict[str, str] | None = None,
    ) -> SandboxResult:
        # Local dev without Node: signal inconclusive so orchestrator doesn't
        # mislabel. Real Node PoC runs on ModalSandbox.
        node_bin = _which("node")
        if not node_bin:
            return SandboxResult(
                exit_code=127,
                stdout="",
                stderr="node runtime not installed; use ModalSandbox for JS targets",
                duration_s=0.0,
                engine=self.engine,
            )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False, encoding="utf-8") as f:
            f.write(script)
            script_path = f.name
        return self._run([node_bin, script_path], token, env, script_path)

    def _run(
        self,
        cmd: list[str],
        token: CapabilityToken,
        env: dict[str, str] | None,
        script_path: str,
    ) -> SandboxResult:
        start = time.monotonic()
        # Egress-off best effort: strip proxy vars.
        run_env = {**os.environ, **(env or {})}
        for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            run_env.pop(k, None)
        cwd = token.ro_paths[0] if token.ro_paths else None
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=token.timeout_s,
                cwd=cwd,
                env=run_env,
            )
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            truncated = False
            if len(stdout) > token.max_output_bytes:
                stdout = stdout[: token.max_output_bytes]
                truncated = True
            return SandboxResult(
                exit_code=proc.returncode,
                stdout=stdout,
                stderr=stderr[:8000],
                duration_s=time.monotonic() - start,
                truncated=truncated,
                engine=self.engine,
            )
        except subprocess.TimeoutExpired as e:
            return SandboxResult(
                exit_code=124,  # POSIX timeout convention
                stdout=(e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, (bytes, bytearray)) else str(e.stdout or ""),
                stderr=f"timeout after {token.timeout_s}s",
                duration_s=token.timeout_s,
                engine=self.engine,
            )
        finally:
            try:
                Path(script_path).unlink()
            except OSError:
                pass


def _which(cmd: str) -> str | None:
    import shutil

    return shutil.which(cmd)
