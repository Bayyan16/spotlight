"""Vulnerable LangChain-style agent — seeded target for the Agentic Sweep.

Three planted OWASP-LLM Top-10 weaknesses:

1. Prompt injection (LLM01): raw `request.args.get("q")` reaches
   `chain.invoke(...)` with no sanitizer.
2. Excessive agency (LLM06): a LangChain Tool wraps `requests.get` — no
   URL allowlist. The agent can be steered into SSRF-ing internal metadata.
3. Improper output handling (LLM05): `subprocess.run(llm_response.content,
   shell=True)` — the model's raw output is executed as a shell command.

The precision-negative twin is targets/clean-langchain-agent/ (escaped
input + host-allowlisted tool + validated output).

NOTE: `langchain` / `openai` / `flask` / `requests` are NOT installed for
the fixture. This file only needs to *parse* (Python AST) so the scanner's
walk fires. Every symbol is referenced but never executed at import time —
the `if False:` guard around the runtime block keeps the module import-safe
even without the deps.
"""
from __future__ import annotations

import os
import subprocess


# The scanner only walks AST — the following bindings are placeholders that
# make the module import cleanly if someone does `import app` in a shell.
# Real LangChain imports are what the scanner regexes / AST rules match on.
Flask = request = None  # type: ignore[assignment]
AgentExecutor = Tool = None  # type: ignore[assignment]
ChatOpenAI = ChatPromptTemplate = LLMChain = None  # type: ignore[assignment]
requests = None  # type: ignore[assignment]

try:  # pragma: no cover — deps not installed for fixture
    from flask import Flask, request  # noqa: F811
    from langchain.agents import AgentExecutor, Tool  # noqa: F811
    from langchain.chat_models import ChatOpenAI  # noqa: F811
    from langchain.prompts import ChatPromptTemplate  # noqa: F811
    from langchain.chains import LLMChain  # noqa: F811
    import requests  # noqa: F811
except Exception:
    pass


def _build_chain():
    """LLMChain constructed from a hard-coded prompt template."""
    llm = ChatOpenAI(model="gpt-4o-mini")
    prompt = ChatPromptTemplate.from_template("Answer the user question: {input}")
    return LLMChain(llm=llm, prompt=prompt)


# ── LLM06: over-permissioned tool ────────────────────────────────────────
def _fetch_url(url: str) -> str:
    """The tool body — unrestricted requests.get. Any URL the agent picks."""
    return requests.get(url).text


def build_agent():
    unrestricted_http_tool = Tool(
        name="http_get",
        func=_fetch_url,
        description="GET any URL and return the body.",
    )
    # NOTE: the Tool wraps `requests.get` inside `_fetch_url`; the scanner
    # matches on Tool(...) containing `requests.` in the arg block. If it
    # doesn't fire on the indirection, the direct-reference variant below
    # certainly will.
    direct_http_tool = Tool(
        name="http_get_direct",
        func=lambda url: requests.get(url).text,
        description="GET any URL directly.",
    )
    return AgentExecutor.from_agent_and_tools(
        agent=None,
        tools=[unrestricted_http_tool, direct_http_tool],
        verbose=True,
    )


# ── LLM01: raw user input → LLM sink ─────────────────────────────────────
def ask():
    chain = _build_chain()
    # VULN: request.args.get("q") is fed straight into the prompt template —
    # no escape / no envelope / no sanitizer. Classic prompt injection surface.
    result = chain.invoke({"input": request.args.get("q")})
    return {"answer": result}


# ── LLM05: model output → shell ──────────────────────────────────────────
def run_llm_shell():
    chain = _build_chain()
    llm_response = chain.invoke({"input": "produce a shell command"})
    # VULN: the model's response is executed as-is with shell=True. Anything
    # the model emits (or is prompt-injected into emitting) runs as a shell.
    subprocess.run(llm_response.content, shell=True)
    return {"ok": True}


if __name__ == "__main__":  # pragma: no cover
    pass
