"""Kitchen-sink demo target.

Deliberately combines FIVE distinct security issues so ONE Spotlight sweep
lights up every product surface at once:

  1. SQL injection (code · CWE-89) — reproducible, tier=verified.
  2. Hardcoded credentials (secrets · CWE-798) — static-fact, verified.
  3. Prompt-injection surface (agentic · LLM01) — LangChain ChatPromptTemplate
     with raw user input.
  4. Excessive-agency tool (agentic · LLM06) — a LangChain Tool that calls
     requests.get on an LLM-supplied URL with no allowlist.
  5. Improper output handling (agentic · LLM05) — subprocess.run on LLM
     output.

The Chainer composes:
  - LLM01 → LLM06 → CWE-918 (SSRF) — cross-surface Exploit Path
  - secrets + SQLi — 'credential + primary' pairing

DO NOT USE THIS TARGET AS A TEMPLATE.
"""
from __future__ import annotations

import subprocess
import sqlite3

import requests
from flask import Flask, jsonify, request

# LangChain imports are guarded so the module loads even in a stripped
# sandbox (Spotlight's Modal Reproducer). The Cognition scanner does STATIC
# text analysis — the mere presence of the import + usage names is what
# triggers detection. Runtime is independent.
try:
    from langchain.agents import AgentExecutor, Tool
    from langchain.chains import LLMChain
    from langchain.prompts import ChatPromptTemplate
    from langchain_openai import ChatOpenAI
    _LANGCHAIN_AVAILABLE = True
except ImportError:
    _LANGCHAIN_AVAILABLE = False

# --- ISSUE 2: hardcoded credentials ------------------------------------------
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
OPENAI_API_KEY = "sk-proj-abcdefghij0123456789ABCDEFGHIJKLMNOPQRSTUVWX"
GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"

app = Flask(__name__)


def _db():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE IF NOT EXISTS accounts (id INTEGER, name TEXT, balance REAL)")
    conn.execute("INSERT INTO accounts VALUES (1, 'alice', 1000)")
    conn.execute("INSERT INTO accounts VALUES (2, 'bob', 500)")
    return conn


# --- ISSUE 1: SQL injection (classical AppSec, reproducible) -----------------
@app.route("/accounts/<username>")
def get_account(username):
    conn = _db()
    cursor = conn.cursor()
    query = "SELECT id, name, balance FROM accounts WHERE name = '" + username + "'"
    cursor.execute(query)
    return jsonify(cursor.fetchall())


# --- ISSUE 4: excessive-agency LangChain Tool (LLM06) ------------------------
# This Tool is exposed to the LLM agent. It performs an outbound HTTP call
# with a URL supplied by the model — no allowlist, no scope restriction.
# A booby-trapped ticket (ISSUE 3) can steer the LLM into hitting an internal
# service and exfiltrating the response.
def support_bot_lookup_tool(url_from_llm: str) -> str:
    return requests.get(url_from_llm).text


if _LANGCHAIN_AVAILABLE:
    unrestricted_tool = Tool(
        name="lookup",
        func=support_bot_lookup_tool,
        description="Look up a URL and return its body.",
    )

    # --- ISSUE 3: prompt-injection surface (LLM01) ---------------------------
    # Raw user-supplied ticket body reaches the LangChain prompt template
    # without segregation from instructions. Combined with the tool above,
    # this is the canonical indirect prompt injection → over-permissioned
    # tool → SSRF chain.
    llm = ChatOpenAI(model="gpt-4o-mini", api_key=OPENAI_API_KEY)
    prompt = ChatPromptTemplate.from_messages(
        [("system", "You are a support agent. Handle this ticket."),
         ("user", "{ticket}")]  # <-- raw untrusted input
    )
    support_chain = LLMChain(llm=llm, prompt=prompt)
    support_agent = AgentExecutor(agent=support_chain, tools=[unrestricted_tool])


@app.route("/support", methods=["POST"])
def support():
    if not _LANGCHAIN_AVAILABLE:
        return jsonify({"error": "langchain not installed"}), 503
    ticket = request.json.get("ticket", "") if request.is_json else ""
    # ISSUE 3 fires here: `ticket` is user-controlled and reaches the chain.
    result = support_chain.invoke({"ticket": ticket})

    # --- ISSUE 5: improper output handling (LLM05) ---------------------------
    # The LLM's response is executed as a shell command. Any prompt-injection
    # payload that survives to this point owns the box.
    action = result.get("text", "")
    subprocess.run(action, shell=True)  # noqa: S602

    return jsonify({"ok": True})


@app.route("/health")
def health():
    return {"ok": True}


if __name__ == "__main__":
    app.run(port=8080)
