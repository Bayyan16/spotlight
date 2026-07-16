"""Tranche B4 — Cross-Surface Exploit Path Chainer.

The Chainer's job is to compose reduced candidates into ExploitPath
chains that no single-surface scanner today can produce. The killer
chain we demo is:

    indirect-prompt-injection (LLM01)
        → over-permissioned tool (LLM06)
        → SSRF (CWE-918)
        → data exfil

These tests exercise the actual composition rules — the state machine
that decides which candidates chain, which don't, and how they're
ordered on the path. They aren't just checking the ExploitPath shape.

Coverage:
  * cross-surface 3-step chain (LLM01 + LLM06(requests.get) + SSRF)
  * cross-surface 2-step chain (LLM01 + LLM06 without SSRF)
  * secrets-pairing when no agentic candidates exist
  * deterministic id + step ordering across repeated calls
  * agentic-first step ordering
  * bank-material fixture scenario used by the demo money-shot
"""
from __future__ import annotations

from spotlight.orchestrator.chainer import Chainer


# ── candidate fixtures ──────────────────────────────────────────────────

def _pi_cand(repo: str = "app") -> dict:
    """A prompt-injection candidate from the AgenticAnalyst."""
    return {
        "id": "PI-1",
        "surface": "agentic",
        "class": "prompt-injection",
        "cwe": "LLM01",
        "title": "Indirect prompt injection via README",
        "severity": "high",
        "repo": repo,
        "location": {
            "file": f"{repo}/README.md",
            "line": 12,
            "function": "system_prompt",
        },
    }


def _ea_cand(repo: str = "app", tool: str = "requests.get") -> dict:
    """An excessive-agency candidate — the LLM has a tool granted that
    can reach outbound URLs."""
    return {
        "id": "EA-1",
        "surface": "agentic",
        "class": "excessive-agency",
        "cwe": "LLM06",
        "title": f"Over-permissioned tool: {tool}",
        "severity": "high",
        "repo": repo,
        "tool": tool,
        "location": {
            "file": f"{repo}/agent.py",
            "line": 44,
            "function": "run_tool",
        },
    }


def _ssrf_cand(repo: str = "app") -> dict:
    """A code-side SSRF candidate — the tool URL isn't validated."""
    return {
        "id": "SSRF-1",
        "class": "ssrf",
        "cwe": "CWE-918",
        "title": "SSRF in fetch_url",
        "severity": "high",
        "repo": repo,
        "location": {
            "file": f"{repo}/http.py",
            "line": 88,
            "function": "fetch_url",
        },
    }


def _secrets_cand(repo: str = "app") -> dict:
    return {
        "id": "SEC-1",
        "class": "secrets",
        "cwe": "CWE-798",
        "title": "Hardcoded AWS access key in config",
        "severity": "critical",
        "repo": repo,
        "location": {
            "file": f"{repo}/config.py",
            "line": 3,
            "function": "load_config",
        },
    }


def _sqli_cand(repo: str = "app") -> dict:
    return {
        "id": "SQLI-1",
        "class": "sqli",
        "cwe": "CWE-89",
        "title": "SQLi in accounts route",
        "severity": "high",
        "repo": repo,
        "location": {
            "file": f"{repo}/app.py",
            "line": 27,
            "function": "get_account",
        },
    }


def _cmdi_cand(repo: str = "app", function: str = "handle_message") -> dict:
    return {
        "id": "CMDI-1",
        "class": "cmdi",
        "cwe": "CWE-78",
        "title": "Command injection via subprocess",
        "severity": "high",
        "repo": repo,
        "location": {
            "file": f"{repo}/handler.py",
            "line": 50,
            "function": function,
        },
    }


def _oh_cand(repo: str = "app", function: str = "handle_message") -> dict:
    return {
        "id": "OH-1",
        "surface": "agentic",
        "class": "output-handling",
        "cwe": "LLM05",
        "title": "Model output rendered without sanitization",
        "severity": "high",
        "repo": repo,
        "location": {
            "file": f"{repo}/handler.py",
            "line": 42,
            "function": function,
        },
    }


# ── rule 1 — agentic → code (3 steps: LLM01 + LLM06 + SSRF) ──────────

def test_llm01_llm06_ssrf_makes_three_step_cross_surface_path():
    """The demo money-shot: prompt-injection + over-permissioned
    requests.get + SSRF chain into a single 3-step ExploitPath."""
    cands = [_pi_cand(), _ea_cand(tool="requests.get"), _ssrf_cand()]
    paths = Chainer().compose(cands)

    assert len(paths) == 1, f"expected exactly 1 path, got {paths}"
    p = paths[0]
    assert p["id"] == "EP-0001"
    assert p["cross_surface"] is True
    assert p["reproduced"] is False
    assert len(p["steps"]) == 3

    # Agentic first, then code. `order` field renumbered 1..N.
    assert [s["order"] for s in p["steps"]] == [1, 2, 3]
    assert [s["surface"] for s in p["steps"]] == ["agentic", "agentic", "code"]
    assert [s["class"] for s in p["steps"]] == [
        "prompt-injection", "excessive-agency", "ssrf",
    ]
    # Every step carries an edge explaining why the next step is reachable.
    for s in p["steps"]:
        assert s["edge"], f"step {s} missing edge rationale"

    # CWE labels flow through — the reporter uses these downstream.
    assert p["steps"][0]["cwe"] == "LLM01"
    assert p["steps"][1]["cwe"] == "LLM06"
    assert p["steps"][2]["cwe"] == "CWE-918"


# ── rule 1 fallback — 2-step when no SSRF ──────────────────────────────

def test_llm01_llm06_without_ssrf_makes_two_step_path():
    """No SSRF finding → the chain still composes as LLM01 → LLM06.
    Cross-surface stays True because LLM06 lives on agentic surface but
    the second step describes a real-world impact (tool granted)."""
    cands = [_pi_cand(), _ea_cand(tool="requests.get")]  # no ssrf
    paths = Chainer().compose(cands)

    assert len(paths) == 1
    p = paths[0]
    assert len(p["steps"]) == 2
    assert [s["class"] for s in p["steps"]] == ["prompt-injection", "excessive-agency"]
    # Both steps are agentic → cross_surface must be False.
    assert p["cross_surface"] is False
    assert p["reproduced"] is False


def test_llm01_llm06_with_non_ssrf_tool_makes_two_step_path():
    """LLM06 with a tool that isn't a URL-fetcher shouldn't extend into
    an SSRF chain even if an SSRF candidate is present elsewhere."""
    # LLM06 tool is `shell.exec` — not in _SSRF_ENABLING_TOOLS.
    cands = [_pi_cand(), _ea_cand(tool="shell.exec"), _ssrf_cand()]
    paths = Chainer().compose(cands)

    # We get: (1) the LLM01/LLM06 pair (no SSRF extension because
    # tool isn't a URL fetcher), and (2) NO secrets pairing since
    # there are no secrets. So exactly one path with two steps.
    assert len(paths) == 1
    p = paths[0]
    assert len(p["steps"]) == 2
    assert [s["class"] for s in p["steps"]] == ["prompt-injection", "excessive-agency"]


# ── rule 2 — output-handling → code ─────────────────────────────────────

def test_llm05_plus_eval_in_same_function_makes_path():
    """Insecure output handling + eval in the same function → the model's
    string ends up in an eval call. That's a code-execution primitive."""
    eval_cand = _cmdi_cand(function="render_response")
    eval_cand["class"] = "eval"
    eval_cand["cwe"] = "CWE-95"
    cands = [_oh_cand(function="render_response"), eval_cand]
    paths = Chainer().compose(cands)

    assert len(paths) == 1
    p = paths[0]
    assert p["cross_surface"] is True
    assert [s["class"] for s in p["steps"]] == ["output-handling", "eval"]
    assert "CWE-95" in p["title"]


def test_llm05_plus_cmdi_needs_matching_function_name():
    """If the LLM05 and cmdi live in different functions, the chainer
    must NOT compose them — the model output has to actually flow into
    the sink. Different function → no flow."""
    cands = [
        _oh_cand(function="render_response"),
        _cmdi_cand(function="unrelated_handler"),
    ]
    paths = Chainer().compose(cands)
    # No pair chain, no secrets-pairing (no secrets). Empty.
    assert paths == []


# ── rule 3 — secrets → any ──────────────────────────────────────────────

def test_only_code_findings_produces_secrets_pairing_path():
    """No agentic findings, but a secret + a primary vuln in the same
    repo → the chainer still emits a secrets-pairing path."""
    cands = [_secrets_cand(), _sqli_cand()]
    paths = Chainer().compose(cands)

    assert len(paths) == 1
    p = paths[0]
    assert len(p["steps"]) == 2
    assert p["steps"][0]["class"] == "secrets"
    assert p["steps"][1]["class"] == "sqli"
    # Both are code-surface → no cross-surface tag.
    assert p["cross_surface"] is False
    # Severity propagates the more severe input (secrets is critical here).
    assert p["severity"] == "critical"


def test_secrets_alone_produces_no_path():
    """A lone secrets finding without any other promoted candidate has
    nothing to pair with — the chainer should NOT synthesize a chain."""
    paths = Chainer().compose([_secrets_cand()])
    assert paths == []


def test_secrets_pairing_skips_cross_repo_findings():
    """Secrets in repo A shouldn't pair with a SQLi in repo B — the
    threat only holds inside a single blast radius."""
    cands = [_secrets_cand(repo="A"), _sqli_cand(repo="B")]
    paths = Chainer().compose(cands)
    assert paths == []


# ── determinism ─────────────────────────────────────────────────────────

def test_deterministic_ordering_across_repeat_calls():
    """Chainer must be pure — same input twice, same path ids and same
    step order. The orchestrator reruns can't reshuffle the ids the
    Console links to."""
    cands = [_pi_cand(), _ea_cand(tool="requests.get"), _ssrf_cand()]
    a = Chainer().compose(list(cands))
    b = Chainer().compose(list(cands))
    assert a == b

    # Also stable under a NEW instance — Chainer holds no state.
    c = Chainer().compose(list(cands))
    assert a == c

    # And the ids restart from EP-0001 on each call (per-call, not
    # per-instance, counters — the orchestrator persists these to disk).
    assert a[0]["id"] == "EP-0001"
    assert c[0]["id"] == "EP-0001"


def test_agentic_first_step_ordering():
    """Even if callers pass code candidates before agentic ones, the
    chainer sorts agentic first so the UI story reads left-to-right:
    agentic surfaces the injection, then code amplifies it."""
    cands = [_ssrf_cand(), _ea_cand(tool="requests.get"), _pi_cand()]
    paths = Chainer().compose(cands)
    assert len(paths) == 1
    surfaces = [s["surface"] for s in paths[0]["steps"]]
    assert surfaces == ["agentic", "agentic", "code"]


# ── fixture scenario — the demo money-shot ─────────────────────────────

def test_fixture_scenario_three_candidates_produce_one_cross_surface_path():
    """Synthetic bank-fixture: exactly 3 hand-crafted candidates
    (prompt-injection, excessive-agency, ssrf) go in, exactly ONE
    ExploitPath spanning agentic→code comes out. `cross_surface=True`.
    `reproduced=False` (composition doesn't run PoCs — that's a later
    tranche)."""
    candidates = [
        {
            "id": "PI-README",
            "surface": "agentic",
            "class": "prompt-injection",
            "cwe": "LLM01",
            "title": "Indirect prompt injection in README",
            "severity": "high",
            "repo": "bank-fixture",
            "location": {
                "file": "bank-fixture/README.md",
                "line": 3,
                "function": "system_prompt",
            },
        },
        {
            "id": "EA-URLFETCH",
            "surface": "agentic",
            "class": "excessive-agency",
            "cwe": "LLM06",
            "title": "Over-permissioned tool: requests.get",
            "severity": "high",
            "repo": "bank-fixture",
            "tool": "requests.get",
            "location": {
                "file": "bank-fixture/agent.py",
                "line": 12,
                "function": "invoke_tool",
            },
        },
        {
            "id": "SSRF-METADATA",
            "class": "ssrf",
            "cwe": "CWE-918",
            "title": "SSRF into AWS metadata endpoint",
            "severity": "critical",
            "repo": "bank-fixture",
            "location": {
                "file": "bank-fixture/http.py",
                "line": 40,
                "function": "fetch_url",
            },
        },
    ]

    paths = Chainer().compose(candidates)
    assert len(paths) == 1, f"expected 1 ExploitPath, got {paths}"
    p = paths[0]
    assert p["cross_surface"] is True
    assert p["reproduced"] is False
    assert len(p["steps"]) == 3
    assert p["steps"][0]["surface"] == "agentic"
    assert p["steps"][-1]["surface"] == "code"
    # Severity rolls up to the most severe input.
    assert p["severity"] == "critical"
    # Rationale is non-empty — the reporter needs it for the exec summary.
    assert p["rationale"]


# ── integration with reducer output ─────────────────────────────────────

def test_empty_candidates_yields_empty_paths():
    assert Chainer().compose([]) == []


def test_candidates_with_no_chainable_classes_yields_empty_paths():
    """Two unrelated code findings that don't match any rule → no
    chains. The Chainer must NOT invent connections."""
    cands = [_sqli_cand(), _cmdi_cand()]
    paths = Chainer().compose(cands)
    assert paths == []
