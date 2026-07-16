"""Scan Profiles — real presets a user picks in the New Scan wizard.

A Profile bundles the config a Sweep runs against: which surfaces (code /
cognition / both), which vulnerability classes to look for, which model,
concurrency and token budget, scope globs. Phase 1.5 ships four opinionated
built-ins; Phase 2 lets the user save custom ones through the API.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Profile:
    id: str
    name: str
    description: str
    surfaces: list[str]  # code | cognition
    classes: list[str]
    languages: list[str]  # python | javascript | typescript
    model: str  # moonshot | mock
    max_agents: int
    budget_tokens: int
    scope_globs: list[str] = field(default_factory=lambda: ["**/*.py", "**/*.js", "**/*.ts"])
    runtime_validate: bool = True
    interactive: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


BALANCED = Profile(
    id="balanced",
    name="Balanced",
    description=(
        "The daily driver. Covers the OWASP-Top-10-shaped classes at real precision. "
        "Parallel Investigators, medium budget, real reproduction where feasible."
    ),
    surfaces=["code"],
    classes=["sqli", "cmdi", "ssrf", "eval", "xss", "authz", "secrets"],
    languages=["python", "javascript", "typescript"],
    model="moonshot",
    max_agents=6,
    budget_tokens=1_500_000,
)

DEEP = Profile(
    id="deep",
    name="Deep",
    description=(
        "Higher-recall pass. Adds crypto misuse, deserialization, race conditions, "
        "prototype pollution. Bigger budget; slower. Use before a release."
    ),
    surfaces=["code"],
    classes=[
        "sqli",
        "cmdi",
        "ssrf",
        "eval",
        "xss",
        "authz",
        "secrets",
        "crypto",
        "deserialization",
        "race",
        "proto-pollution",
        "path-traversal",
    ],
    languages=["python", "javascript", "typescript"],
    model="moonshot",
    max_agents=8,
    budget_tokens=4_000_000,
    interactive=True,
)

COGNITION_ONLY = Profile(
    id="cognition-only",
    name="Cognition (AI/agentic)",
    description=(
        "The LLM/agent-layer sweep. OWASP LLM Top 10 + OWASP Agentic Security "
        "categories. Prompt injection, excessive agency, RAG surface, output "
        "handling. Skips classic AppSec — pair with Balanced for full coverage."
    ),
    surfaces=["cognition"],
    classes=[
        "prompt-injection",
        "excessive-agency",
        "output-handling",
        "rag-surface",
        "system-prompt-leak",
        "denial-of-wallet",
    ],
    languages=["python", "javascript", "typescript"],
    model="moonshot",
    max_agents=6,
    budget_tokens=2_000_000,
    interactive=True,
)

FAST = Profile(
    id="fast",
    name="Fast",
    description=(
        "Under-a-minute pass on the top-two classes. For CI / pre-merge gate — not "
        "for standalone assurance."
    ),
    surfaces=["code"],
    classes=["sqli", "cmdi"],
    languages=["python", "javascript", "typescript"],
    model="moonshot",
    max_agents=4,
    budget_tokens=400_000,
)

BUILT_IN: dict[str, Profile] = {
    "balanced": BALANCED,
    "deep": DEEP,
    "cognition-only": COGNITION_ONLY,
    "fast": FAST,
}

DEFAULT_PROFILE_ID = "balanced"


def get_profile(profile_id: str | None) -> Profile:
    if not profile_id:
        return BUILT_IN[DEFAULT_PROFILE_ID]
    return BUILT_IN.get(profile_id, BUILT_IN[DEFAULT_PROFILE_ID])


def list_profiles() -> list[Profile]:
    return list(BUILT_IN.values())
