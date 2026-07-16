"""Regex + heuristic patterns for the Cognition Sweep (OWASP LLM Top 10).

These are the source→sink and shape patterns that CognitionScanner walks over.
Each entry pairs:

  * a compiled regex or lightweight matcher
  * a canonical class id from `spotlight.taxonomy`
  * the OWASP-LLM code we map to (LLM01..LLM10)
  * a short human "reason" the finding will carry

Kept in a dedicated module so we can unit-test each pattern in isolation and
so the scanner file stays readable — the scanner orchestrates, this file
defines the rules.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterable


# ─────────────────────────────────────────────────────────────────────────────
# Untrusted-source markers (Python + JS/TS)
# ─────────────────────────────────────────────────────────────────────────────

UNTRUSTED_PY: tuple[str, ...] = (
    "request.args",
    "request.form",
    "request.json",
    "request.values",
    "request.get_json",
    "request.data",
    "flask.request",
    "req.body",
    "req.params",
    "req.query",
)

UNTRUSTED_JS: tuple[str, ...] = (
    "req.body",
    "req.params",
    "req.query",
    "req.headers",
    "request.body",
    "request.params",
    "request.query",
    "ctx.params",
    "ctx.query",
    "ctx.body",
)


# ─────────────────────────────────────────────────────────────────────────────
# LLM sinks — call shapes that indicate "text hits a model"
# ─────────────────────────────────────────────────────────────────────────────

# The scanner walks Python-AST call graphs; these are `callee` name fragments
# (checked with `in`) rather than full regex — mirrors sg_core.graph.SINKS.
LLM_SINK_NEEDLES: tuple[str, ...] = (
    "ChatPromptTemplate",
    "PromptTemplate",
    "LLMChain",
    "AgentExecutor",
    "chain.invoke",
    "chain.run",
    "chat.completions.create",
    "completions.create",
    "messages.create",
    "openai.ChatCompletion.create",
    "llm.invoke",
    "llm.predict",
    "llm.__call__",
)


# LangChain-style Tool constructor names — how agents are wired to tools.
TOOL_CTOR_NEEDLES: tuple[str, ...] = (
    "Tool(",
    "Tool.from_function",
    "StructuredTool",
    "@tool",
)


# Dangerous tool callables that grant excessive agency when handed to an agent
# without an allowlist. `open(` is included but we require the tool context.
EXCESSIVE_AGENCY_CALLEES: tuple[str, ...] = (
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "requests.request",
    "httpx.get",
    "httpx.post",
    "httpx.request",
    "urllib.request.urlopen",
    "urlopen",
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "os.system",
    "os.popen",
)

# `open(` gets its own callee-name so we can match it as an identifier without
# collisions on `open` in e.g. `path.open`.
OPEN_CALLEES: tuple[str, ...] = ("open", "io.open", "pathlib.Path.open")


# ─────────────────────────────────────────────────────────────────────────────
# Improper output handling — sinks that receive model output
# ─────────────────────────────────────────────────────────────────────────────

OUTPUT_HANDLING_SINKS: tuple[str, ...] = (
    "eval",
    "exec",
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "os.system",
    "os.popen",
    "cursor.execute",
    ".execute",
    "db.execute",
    "connection.execute",
    "document.write",
    ".innerHTML",
    "innerHTML",
    "dangerouslySetInnerHTML",
)


# Names that suggest the value on the left of an assignment carries an LLM
# response. If any of these appears in an identifier we treat the identifier
# as "LLM-tainted." Deliberately conservative so we don't tag every `response`.
LLM_TAINT_HINTS: tuple[str, ...] = (
    "llm_response",
    "llm_output",
    "llm_result",
    "completion",
    "chat_completion",
    "chat_response",
    "assistant_message",
    "assistant_response",
    "agent_output",
    "agent_response",
    "model_response",
    "model_output",
    "chain_output",
    "chain_result",
    "prediction",
)


# ─────────────────────────────────────────────────────────────────────────────
# Sanitizer / escape helpers
# ─────────────────────────────────────────────────────────────────────────────

# If any of these functions wraps the tainted expression, treat as sanitized.
SANITIZERS: tuple[str, ...] = (
    "escape_prompt",
    "escape_user_input",
    "sanitize_prompt",
    "sanitize_input",
    "sanitize_user_input",
    "html.escape",
    "shlex.quote",
    "warden.sanitize",
    "warden.wrap_target_content",
    "wrap_target_content",
    "bleach.clean",
)


# ─────────────────────────────────────────────────────────────────────────────
# RAG / vector-store loaders + allow-listable URL schemes
# ─────────────────────────────────────────────────────────────────────────────

VECTOR_STORE_NEEDLES: tuple[str, ...] = (
    "Chroma(",
    "Chroma.from_documents",
    "FAISS(",
    "FAISS.from_documents",
    "FAISS.load_local",
    "Pinecone(",
    "Weaviate(",
    "WeaviateVectorStore",
    "Qdrant(",
    "Milvus(",
    "VectorStoreIndex.from_documents",
    "VectorstoreIndexCreator",
    "PGVector(",
)

TRUSTED_VECTOR_HOSTS: tuple[str, ...] = (
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    ".internal",
    ".svc.cluster.local",
    "chroma-internal",
    "vectorstore.internal",
)


# ─────────────────────────────────────────────────────────────────────────────
# System-prompt-leak indicators
# ─────────────────────────────────────────────────────────────────────────────

# Secret shapes we look for inside a *system* prompt literal. Kept narrow —
# the WardenService owns the general redaction catalog; this is the "would
# a system prompt containing a real key leak that key?" check.
SECRET_LITERAL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key
    re.compile(r"sk-[A-Za-z0-9]{16,}"),  # OpenAI-shape
    re.compile(r"sk-ant-[A-Za-z0-9\-]{16,}"),  # Anthropic-shape
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),  # GitHub PAT
    re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),  # Slack token
    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----"),
    re.compile(r"[A-Za-z0-9]{32,}\.[A-Za-z0-9]{32,}\.[A-Za-z0-9_\-]{16,}"),  # JWT-ish
)


SYSTEM_ROLE_MARKERS: tuple[re.Pattern[str], ...] = (
    # `"role": "system"` alongside a string content — Chat Completions shape.
    re.compile(r"""["']role["']\s*:\s*["']system["']""", re.IGNORECASE),
    # LangChain `SystemMessage("...")` / `SystemMessagePromptTemplate.from_template("...")`.
    re.compile(r"\bSystemMessage(?:PromptTemplate)?\b\s*(?:\.from_template)?\s*\("),
)


# ─────────────────────────────────────────────────────────────────────────────
# Denial-of-wallet — LLM call inside a for/while with no cap
# ─────────────────────────────────────────────────────────────────────────────

# LangChain / OpenAI-SDK knobs that gate the loop.
BUDGET_KNOB_NEEDLES: tuple[str, ...] = (
    "max_iterations",
    "max_execution_time",
    "max_tokens",
    "rate_limit",
    "ratelimit",
    "budget",
    "per_actor_budget",
    "throttle",
    "sleep(",
    "asyncio.sleep",
    "time.sleep",
)


# ─────────────────────────────────────────────────────────────────────────────
# High-level rule catalog — one entry per pattern, so tests can iterate.
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Rule:
    id: str
    class_: str
    owasp_llm: str
    description: str
    matcher: Callable[[str], bool]


def _any_in(needles: Iterable[str]) -> Callable[[str], bool]:
    ns = tuple(needles)
    return lambda text: any(n in text for n in ns)


RULES: tuple[Rule, ...] = (
    Rule(
        id="prompt-injection.raw-user-to-llm",
        class_="prompt-injection",
        owasp_llm="LLM01",
        description="raw request-derived value flows into an LLM sink without sanitizer",
        matcher=_any_in(LLM_SINK_NEEDLES),
    ),
    Rule(
        id="excessive-agency.http-tool",
        class_="excessive-agency",
        owasp_llm="LLM06",
        description="LangChain Tool wraps requests.get/httpx.get with no URL allowlist",
        matcher=lambda text: "Tool(" in text and any(c in text for c in ("requests.", "httpx.")),
    ),
    Rule(
        id="excessive-agency.shell-tool",
        class_="excessive-agency",
        owasp_llm="LLM06",
        description="LangChain Tool wraps subprocess / os.system",
        matcher=lambda text: "Tool(" in text and any(c in text for c in ("subprocess.", "os.system")),
    ),
    Rule(
        id="output-handling.eval-of-llm",
        class_="output-handling",
        owasp_llm="LLM05",
        description="LLM output flows into eval/exec/subprocess/db.execute/innerHTML",
        matcher=_any_in(OUTPUT_HANDLING_SINKS),
    ),
    Rule(
        id="system-prompt-leak.secret-in-system",
        class_="system-prompt-leak",
        owasp_llm="LLM07",
        description="secret-shaped literal appears inside a system-role message",
        matcher=lambda text: any(p.search(text) for p in SECRET_LITERAL_PATTERNS)
        and any(p.search(text) for p in SYSTEM_ROLE_MARKERS),
    ),
    Rule(
        id="rag-surface.untrusted-vector-url",
        class_="rag-surface",
        owasp_llm="LLM08",
        description="vector-store constructor reads a URL from env without an allowlist",
        matcher=lambda text: any(v in text for v in VECTOR_STORE_NEEDLES)
        and ("os.environ" in text or "os.getenv" in text or "process.env" in text),
    ),
    Rule(
        id="denial-of-wallet.loop-llm-no-cap",
        class_="denial-of-wallet",
        owasp_llm="LLM10",
        description="LLM call inside a loop with no max_iterations / rate limit / sleep",
        matcher=lambda text: any(s in text for s in LLM_SINK_NEEDLES)
        and not any(k in text for k in BUDGET_KNOB_NEEDLES),
    ),
)


def is_sanitized(expr: str) -> bool:
    """Does `expr` mention a sanitizer wrapper we recognize?"""
    return any(s in (expr or "") for s in SANITIZERS)


def references_untrusted_py(expr: str) -> bool:
    return any(u in (expr or "") for u in UNTRUSTED_PY)


def references_untrusted_js(expr: str) -> bool:
    return any(u in (expr or "") for u in UNTRUSTED_JS)


def is_llm_sink(callee: str) -> bool:
    return any(n in (callee or "") for n in LLM_SINK_NEEDLES)


def is_output_handling_sink(callee: str) -> bool:
    return any(n in (callee or "") for n in OUTPUT_HANDLING_SINKS)


def is_llm_tainted_ident(name: str) -> bool:
    low = (name or "").lower()
    return any(h in low for h in LLM_TAINT_HINTS)
