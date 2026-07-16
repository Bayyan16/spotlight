"""Modal-backed isolated sandbox.

Each PoC / verification runs in an ephemeral Modal container with:
  - `block_network=True` — outbound network denied at the platform level.
    This is the guarantee the pitch depends on ("the swarm cannot be
    turned against you"). Not best-effort, not soft; a firewall rule
    enforced by Modal.
  - CPU/mem/time caps per the CapabilityToken.
  - Source RO-mounted (target repo copied in), scratch overlay writable
    only for the Remediator.
  - Sandbox terminated after wait() — no state persists on the host.

Used when MODAL_TOKEN_ID + MODAL_TOKEN_SECRET are set. Falls back to
SubprocessSandbox otherwise.
"""
from __future__ import annotations

import os
import shlex
import textwrap
import time
from pathlib import Path

from .base import SandboxResult, SandboxRunner
from .capability import CapabilityToken

# Lazy import — we don't want to require modal for anyone running tests.
_MODAL_APP_NAME = "spotlight-sandbox"


class ModalSandbox(SandboxRunner):
    """Real isolated sandbox on Modal. Instantiated per-Sweep and reused
    across findings so the App handle is amortized."""

    engine = "modal"

    def __init__(self) -> None:
        try:
            import modal  # noqa: F401
        except ImportError as e:
            raise RuntimeError("modal SDK not installed") from e
        if not (os.environ.get("MODAL_TOKEN_ID") and os.environ.get("MODAL_TOKEN_SECRET")):
            raise RuntimeError("MODAL_TOKEN_ID / MODAL_TOKEN_SECRET not set")
        self._app = None

    def _get_app(self):
        import modal

        if self._app is None:
            self._app = modal.App.lookup(_MODAL_APP_NAME, create_if_missing=True)
        return self._app

    def run_python(
        self,
        script: str,
        token: CapabilityToken,
        env: dict[str, str] | None = None,
    ) -> SandboxResult:
        import modal

        app = self._get_app()
        image = modal.Image.debian_slim(python_version="3.12").pip_install(
            "flask==3.1.3"
        )
        # Materialize the RO source into the image so the sandbox can read it.
        # We embed via `.add_local_dir` for the first repo path in the token.
        if token.ro_paths:
            image = image.add_local_dir(token.ro_paths[0], remote_path="/app/target")
        # Script comes in via env var to avoid shell escaping surface.
        merged_env = {**(env or {}), "SPOTLIGHT_POC_SCRIPT_B64": _b64(script)}
        start = time.monotonic()
        sb = modal.Sandbox.create(
            "bash",
            "-lc",
            "cd /app/target && echo \"$SPOTLIGHT_POC_SCRIPT_B64\" | base64 -d | python3 -",
            image=image,
            app=app,
            timeout=token.timeout_s,
            cpu=token.cpu,
            memory=token.memory_mb,
            block_network=(not token.egress_allowed),
            secrets=[modal.Secret.from_dict(merged_env)],
        )
        return _finalize(sb, start, self.engine, token)

    def run_node(
        self,
        script: str,
        token: CapabilityToken,
        env: dict[str, str] | None = None,
        deps: dict[str, str] | None = None,
    ) -> SandboxResult:
        import modal

        app = self._get_app()
        # Node image with the requested deps preinstalled.
        pkg_deps = deps or {"express": "^4.19.2", "better-sqlite3": "^11.0.0"}
        pkg_json = _pkg_json(pkg_deps)
        # We build the image by writing package.json then npm-installing.
        image = (
            modal.Image.debian_slim()
            .apt_install("nodejs", "npm")
            .run_commands(
                f"mkdir -p /app && echo '{pkg_json}' > /app/package.json",
                "cd /app && npm install --silent --no-audit --no-fund",
            )
        )
        if token.ro_paths:
            image = image.add_local_dir(token.ro_paths[0], remote_path="/app/target")
        merged_env = {**(env or {}), "SPOTLIGHT_POC_SCRIPT_B64": _b64(script)}
        start = time.monotonic()
        sb = modal.Sandbox.create(
            "bash",
            "-lc",
            "cd /app && echo \"$SPOTLIGHT_POC_SCRIPT_B64\" | base64 -d > /tmp/poc.js && node /tmp/poc.js",
            image=image,
            app=app,
            timeout=token.timeout_s,
            cpu=token.cpu,
            memory=token.memory_mb,
            block_network=(not token.egress_allowed),
            secrets=[modal.Secret.from_dict(merged_env)],
        )
        return _finalize(sb, start, self.engine, token)


def _finalize(sb, start_time: float, engine: str, token: CapabilityToken) -> SandboxResult:
    try:
        sb.wait()
        stdout = sb.stdout.read() if hasattr(sb, "stdout") else ""
        stderr = sb.stderr.read() if hasattr(sb, "stderr") else ""
        rc = sb.returncode if getattr(sb, "returncode", None) is not None else -1
    except Exception as e:
        stdout, stderr, rc = "", f"sandbox wait error: {e!r}", -1
    finally:
        try:
            sb.terminate()
        except Exception:
            pass
    truncated = False
    if len(stdout) > token.max_output_bytes:
        stdout = stdout[: token.max_output_bytes]
        truncated = True
    # Detect egress-denied signals in stderr (network attempts on a blocked
    # sandbox typically fail with EHOSTUNREACH / ENETUNREACH / DNS lookup errors).
    egress_hits: list[str] = []
    for needle in ("EHOSTUNREACH", "ENETUNREACH", "getaddrinfo", "Connection refused", "Network is unreachable"):
        if needle.lower() in stderr.lower() or needle.lower() in stdout.lower():
            egress_hits.append(needle)
    return SandboxResult(
        exit_code=rc,
        stdout=stdout,
        stderr=stderr[:8000],
        duration_s=time.monotonic() - start_time,
        egress_attempts=len(egress_hits),
        egress_denied_hosts=egress_hits,
        truncated=truncated,
        engine=engine,
    )


def _b64(s: str) -> str:
    import base64

    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def _pkg_json(deps: dict[str, str]) -> str:
    import json

    return json.dumps({"name": "spotlight-poc", "version": "0.0.0", "dependencies": deps}).replace("'", "\\'")
