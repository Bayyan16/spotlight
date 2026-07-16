"""Sandbox runner abstract base — Modal and Subprocess implementations
share this shape so the Reproducer / Verifier don't care which one is
actually executing.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from .capability import CapabilityToken


@dataclass
class SandboxResult:
    exit_code: int
    stdout: str
    stderr: str
    duration_s: float
    egress_attempts: int = 0
    egress_denied_hosts: list[str] = field(default_factory=list)
    truncated: bool = False
    engine: str = "unknown"  # modal | subprocess | mock

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    def to_dict(self) -> dict:
        return {
            "exit_code": self.exit_code,
            "stdout": self.stdout[:8000],
            "stderr": self.stderr[:2000],
            "duration_s": self.duration_s,
            "egress_attempts": self.egress_attempts,
            "egress_denied_hosts": self.egress_denied_hosts,
            "truncated": self.truncated,
            "engine": self.engine,
        }


class SandboxRunner(ABC):
    """Abstract sandbox runner. Implementations: ModalSandbox, SubprocessSandbox."""

    engine: str = "abstract"

    @abstractmethod
    def run_python(
        self,
        script: str,
        token: CapabilityToken,
        env: dict[str, str] | None = None,
    ) -> SandboxResult:
        """Run a Python script under the given capability token. Egress is
        blocked by default per token.egress_allowed."""
        raise NotImplementedError

    @abstractmethod
    def run_node(
        self,
        script: str,
        token: CapabilityToken,
        env: dict[str, str] | None = None,
        deps: dict[str, str] | None = None,
    ) -> SandboxResult:
        """Run a Node.js script (Express/JS PoC). `deps` = npm package.json
        dependencies to install before running."""
        raise NotImplementedError
