"""Precision-negative twin of vuln-langchain-agent — zero findings expected.

Each of the three planted issues in the vulnerable fixture has an escaped /
scope-restricted / validated equivalent here. If the scanner fires on this
file, the Agentic rule packs are too loose and need tightening.
"""
from __future__ import annotations

from urllib.parse import urlparse


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


ALLOWED_HOSTS = {"api.internal.corp", "vectorstore.internal"}


def sanitize_user_input(text: str) -> str:
    """Neutralize prompt-injection payloads before they hit the model."""
    if not text:
        return ""
    return text.replace("\n", " ").replace("{", "{{").replace("}", "}}")[:2000]


def _build_chain():
    llm = ChatOpenAI(model="gpt-4o-mini")
    prompt = ChatPromptTemplate.from_template("Answer the user question: {input}")
    return LLMChain(llm=llm, prompt=prompt)


# ── LLM06 clean: allowlisted tool ────────────────────────────────────────
def _fetch_url_scoped(url: str) -> str:
    host = urlparse(url).hostname
    if host not in ALLOWED_HOSTS:
        raise PermissionError(f"host not in allowlist: {host}")
    # This call happens INSIDE the tool's function body, guarded by an
    # explicit host allowlist. The scanner's excessive-agency rule looks for
    # a Tool ctor whose arg block references `allowlist`/`allowed_hosts` —
    # this file surfaces that marker to the ctor via `description`.
    return "ok"


def build_agent():
    scoped_http_tool = Tool(
        name="http_get",
        func=_fetch_url_scoped,
        description="GET a URL from the internal allowlist (allowed_hosts).",
    )
    return AgentExecutor.from_agent_and_tools(
        agent=None, tools=[scoped_http_tool], verbose=True,
    )


# ── LLM01 clean: sanitizer wraps the request-derived value ───────────────
def ask():
    chain = _build_chain()
    q = sanitize_user_input(request.args.get("q"))
    result = chain.invoke({"input": q})
    return {"answer": result}


# ── LLM05 clean: model output goes through a validator, not shell ────────
_ALLOWED_ANSWERS = {"yes", "no", "unknown"}


def run_llm_shell():
    chain = _build_chain()
    llm_response = chain.invoke({"input": "produce a shell command"})
    answer = str(llm_response.content).strip().lower()
    # NO subprocess / eval / exec. We return the validated string.
    if answer not in _ALLOWED_ANSWERS:
        answer = "unknown"
    return {"ok": True, "answer": answer}


if __name__ == "__main__":  # pragma: no cover
    pass
