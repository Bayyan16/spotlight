"""Scan Profiles — real presets a user picks in the New Scan wizard.

A Profile bundles the config a Sweep runs against: which surfaces (code /
agentic), which vulnerability classes to look for, which model, concurrency
and token budget, scope globs. Phase 1.5 ships four opinionated built-ins;
Phase 2 lets the user save custom ones through the API.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Profile:
    id: str
    name: str
    description: str
    surfaces: list[str]  # code | agentic
    classes: list[str]
    languages: list[str]  # python | javascript | typescript
    model: str  # moonshot | mock
    max_agents: int
    budget_tokens: int
    budget_wall_seconds: int = 600
    scope_globs: list[str] = field(default_factory=lambda: ["**/*.py", "**/*.js", "**/*.ts"])
    runtime_validate: bool = True
    interactive: bool = False
    # Whether the orchestrator should attempt to open a real PR via `gh` after
    # remediation. Default OFF so we don't spam PRs on the demo repos. Deep
    # and Balanced deliberately leave this False; opt in explicitly.
    open_prs: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


BALANCED = Profile(
    id="balanced",
    name="Balanced",
    description=(
        "The daily driver. Covers the OWASP-Top-10-shaped classes at real precision. "
        "Parallel Investigators, medium budget, real reproduction where feasible. "
        "Includes the top three OWASP-LLM classes so teams shipping AI features get "
        "a baseline agentic sweep alongside their code sweep."
    ),
    surfaces=["code", "agentic"],
    classes=[
        "sqli", "cmdi", "ssrf", "eval", "xss", "authz", "secrets",
        # Tranche B3 — top three agentic classes ship with Balanced so the
        # daily driver catches prompt-injection / excessive-agency /
        # output-handling on AI-enabled targets without needing the full
        # Agentic profile.
        "prompt-injection",
        "excessive-agency",
        "output-handling",
    ],
    languages=["python", "javascript", "typescript"],
    model="moonshot",
    max_agents=6,
    budget_tokens=1_500_000,
    budget_wall_seconds=600,
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
    budget_wall_seconds=1800,
    interactive=True,
)

AGENTIC = Profile(
    id="agentic",
    name="Agentic",
    description=(
        "The AI-layer / agent-security sweep. OWASP LLM Top 10 + OWASP Agentic "
        "Security categories: prompt injection, sensitive-info disclosure, model "
        "supply chain, data poisoning, output handling, excessive agency, "
        "system-prompt leak, RAG surface, misinformation, denial of wallet, "
        "plus agent-memory tampering, tool-permission drift, and uncapped agent "
        "loops. Skips classic AppSec — pair with Balanced for full coverage."
    ),
    surfaces=["agentic"],
    # All 13 agentic classes from the taxonomy — the full OWASP LLM Top 10
    # plus the three Agentic Security Initiative categories that don't map
    # 1:1 to LLM Top 10.
    classes=[
        "prompt-injection",
        "sensitive-info-disclosure",
        "model-supply-chain",
        "data-poisoning",
        "output-handling",
        "excessive-agency",
        "system-prompt-leak",
        "rag-surface",
        "misinformation",
        "denial-of-wallet",
        "agent-memory-tampering",
        "tool-permission-drift",
        "agent-loop",
    ],
    languages=["python", "javascript", "typescript"],
    model="moonshot",
    max_agents=6,
    budget_tokens=2_000_000,
    budget_wall_seconds=600,
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
    budget_wall_seconds=120,
)

BUILT_IN: dict[str, Profile] = {
    "balanced": BALANCED,
    "deep": DEEP,
    "agentic": AGENTIC,
    "fast": FAST,
}

DEFAULT_PROFILE_ID = "balanced"


def get_profile(profile_id: str | None) -> Profile:
    if not profile_id:
        return BUILT_IN[DEFAULT_PROFILE_ID]
    return BUILT_IN.get(profile_id, BUILT_IN[DEFAULT_PROFILE_ID])


def list_profiles() -> list[Profile]:
    return list(BUILT_IN.values())
