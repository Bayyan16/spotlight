"""Kitchen-sink demo target.

Deliberately combines FIVE distinct security issues so ONE Spotlight sweep
lights up every product surface at once:

  1. SQL injection (code · CWE-89) — reproducible, will land tier=verified.
  2. Hardcoded AWS credential (secrets · CWE-798) — static-fact, verified.
  3. Prompt-injection surface (agentic · LLM01) — user input to LLM.
  4. Excessive-agency tool (agentic · LLM06) — unrestricted requests.get.
  5. README trap (Warden) — HTML-comment prompt injection at the top of the
     README that Spotlight's Recon MUST detect and refuse.

The Chainer will compose:
  - LLM01 + LLM06 → one cross-surface Exploit Path
  - secrets + SQLi → one "credential + primary" pairing

DO NOT USE THIS TARGET AS A TEMPLATE. It's for demonstration only.
"""
from __future__ import annotations

import sqlite3

import requests
from flask import Flask, jsonify, request

# --- ISSUE 2: hardcoded credentials ------------------------------------------
# These are canonical placeholder shapes that Spotlight's redaction detectors
# match. They are NOT live keys.
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
OPENAI_API_KEY = "sk-proj-abcdefghij0123456789ABCDEFGHIJKLMNOPQRSTUVWX"

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


# --- ISSUE 4: excessive-agency tool (agentic, LLM06) -------------------------
# Any URL from the LLM's tool call is fetched with no allowlist. Combined with
# ISSUE 3 below this becomes a full LLM01→LLM06→SSRF chain.
def support_bot_lookup_tool(url_from_llm: str):
    return requests.get(url_from_llm).text


# --- ISSUE 3: prompt-injection surface (agentic, LLM01) ----------------------
# In a real LangChain app this would be a ChatPromptTemplate.
# The important pattern for the detector is: raw request field → LLM chain.
@app.route("/support", methods=["POST"])
def support():
    ticket = request.json.get("ticket", "") if request.is_json else ""
    # Simulated LLM invocation — the actual chain would live here.
    # An indirect prompt injection embedded in `ticket` will steer the model,
    # and any URL it returns gets fetched with no scope restriction (ISSUE 4).
    fake_llm_response = {"tool_call": {"url": "http://internal-service/secret"}}
    if fake_llm_response.get("tool_call"):
        support_bot_lookup_tool(fake_llm_response["tool_call"]["url"])
    return jsonify({"ok": True})


@app.route("/health")
def health():
    return {"ok": True}


if __name__ == "__main__":
    app.run(port=8080)
