"""CognitionScanner unit tests — OWASP LLM Top 10 rule packs.

Two-level coverage:

1. End-to-end on the seeded fixtures:
   * `vuln-langchain-agent` must produce ≥3 findings covering
     prompt-injection, excessive-agency, output-handling.
   * `clean-langchain-agent` must produce 0 findings — precision negative.

2. Per-rule tests: each pattern fires on a positive tiny snippet and
   does NOT fire on the negative twin. This is what stops the "one big
   monolithic scanner test that hides broken rules" failure mode.
"""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from spotlight.cognition import CognitionFinding, CognitionScanner, find_agentic_dataflow
from spotlight.cognition import rules

ROOT = Path(__file__).resolve().parents[2]
VULN_FIXTURE = ROOT / "targets" / "vuln-langchain-agent"
CLEAN_FIXTURE = ROOT / "targets" / "clean-langchain-agent"


# ─────────────────────────────────────────────────────────────────────────────
# Fixture-level tests
# ─────────────────────────────────────────────────────────────────────────────

def _py_files(root: Path) -> list[Path]:
    return [p for p in root.rglob("*.py") if "__pycache__" not in p.parts]


def test_vuln_fixture_produces_three_classes():
    findings = CognitionScanner().scan(VULN_FIXTURE, _py_files(VULN_FIXTURE))
    classes = {f.class_ for f in findings}
    assert "prompt-injection" in classes, (
        f"expected prompt-injection; got classes={classes} findings={[f.__dict__ for f in findings]}"
    )
    assert "excessive-agency" in classes, (
        f"expected excessive-agency; got classes={classes} findings={[f.__dict__ for f in findings]}"
    )
    assert "output-handling" in classes, (
        f"expected output-handling; got classes={classes} findings={[f.__dict__ for f in findings]}"
    )
    assert len(findings) >= 3, f"expected at least 3 findings; got {len(findings)}"


def test_vuln_fixture_owasp_llm_codes_are_set():
    findings = CognitionScanner().scan(VULN_FIXTURE, _py_files(VULN_FIXTURE))
    codes = {f.owasp_llm for f in findings if f.owasp_llm}
    for expected in ("LLM01", "LLM05", "LLM06"):
        assert expected in codes, f"missing {expected} in {codes}"


def test_clean_fixture_produces_zero_findings():
    findings = CognitionScanner().scan(CLEAN_FIXTURE, _py_files(CLEAN_FIXTURE))
    assert findings == [], (
        "clean fixture leaked findings: "
        + str([f.__dict__ for f in findings])
    )


def test_findings_are_serializable_and_carry_surface_agentic():
    findings = CognitionScanner().scan(VULN_FIXTURE, _py_files(VULN_FIXTURE))
    for f in findings:
        d = f.to_dict()
        assert d["surface"] == "agentic"
        assert d["sink"]["callee"]
        assert d["source"]["origin"]
        assert d["class_"]


# ─────────────────────────────────────────────────────────────────────────────
# Per-rule positive / negative tests
# ─────────────────────────────────────────────────────────────────────────────

def _scan_snippet(snippet: str, tmp_path: Path, name: str = "snippet.py") -> list[CognitionFinding]:
    p = tmp_path / name
    p.write_text(textwrap.dedent(snippet))
    return CognitionScanner().scan(tmp_path, [p])


def test_prompt_injection_fires_on_raw_input(tmp_path):
    snippet = """
    from langchain.chains import LLMChain
    from flask import request

    def ask():
        chain = LLMChain()
        return chain.invoke({"input": request.args.get("q")})
    """
    findings = _scan_snippet(snippet, tmp_path)
    classes = [f.class_ for f in findings]
    assert "prompt-injection" in classes


def test_prompt_injection_negative_when_sanitized(tmp_path):
    snippet = """
    from langchain.chains import LLMChain
    from flask import request

    def sanitize_user_input(s):
        return s.replace("{", "{{").replace("}", "}}")

    def ask():
        chain = LLMChain()
        q = sanitize_user_input(request.args.get("q"))
        return chain.invoke({"input": q})
    """
    findings = _scan_snippet(snippet, tmp_path)
    classes = [f.class_ for f in findings]
    assert "prompt-injection" not in classes, (
        f"sanitized input should not fire prompt-injection; got {classes}"
    )


def test_excessive_agency_fires_on_requests_get_tool(tmp_path):
    snippet = """
    from langchain.agents import Tool
    import requests

    def build():
        return Tool(name="get", func=lambda url: requests.get(url).text, description="get")
    """
    findings = _scan_snippet(snippet, tmp_path)
    classes = [f.class_ for f in findings]
    assert "excessive-agency" in classes


def test_excessive_agency_fires_on_subprocess_tool(tmp_path):
    snippet = """
    from langchain.agents import Tool
    import subprocess

    def build():
        return Tool(name="sh", func=lambda cmd: subprocess.run(cmd, shell=True), description="run shell")
    """
    findings = _scan_snippet(snippet, tmp_path)
    classes = [f.class_ for f in findings]
    assert "excessive-agency" in classes


def test_excessive_agency_negative_when_allowlist_named(tmp_path):
    snippet = """
    from langchain.agents import Tool
    import requests

    def build():
        return Tool(
            name="get",
            func=lambda url: requests.get(url).text,
            description="get from allowed_hosts only",
        )
    """
    findings = _scan_snippet(snippet, tmp_path)
    classes = [f.class_ for f in findings]
    assert "excessive-agency" not in classes


def test_output_handling_fires_on_subprocess_of_llm_output(tmp_path):
    snippet = """
    import subprocess
    from langchain.chains import LLMChain

    def go():
        chain = LLMChain()
        llm_response = chain.invoke({"input": "hi"})
        subprocess.run(llm_response.content, shell=True)
    """
    findings = _scan_snippet(snippet, tmp_path)
    classes = [f.class_ for f in findings]
    assert "output-handling" in classes


def test_output_handling_negative_when_validated(tmp_path):
    snippet = """
    from langchain.chains import LLMChain

    _ALLOWED = {"yes", "no"}

    def go():
        chain = LLMChain()
        llm_response = chain.invoke({"input": "hi"})
        answer = str(llm_response.content).strip().lower()
        if answer not in _ALLOWED:
            answer = "unknown"
        return answer
    """
    findings = _scan_snippet(snippet, tmp_path)
    classes = [f.class_ for f in findings]
    assert "output-handling" not in classes


def test_system_prompt_leak_fires_on_secret_in_system_role(tmp_path):
    snippet = '''
    messages = [
        {"role": "system", "content": "Your master key is sk-abc123def456ghi789jklmno"},
        {"role": "user", "content": "hi"},
    ]
    '''
    findings = _scan_snippet(snippet, tmp_path)
    classes = [f.class_ for f in findings]
    assert "system-prompt-leak" in classes


def test_system_prompt_leak_negative_when_no_secret(tmp_path):
    snippet = '''
    messages = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "hi"},
    ]
    '''
    findings = _scan_snippet(snippet, tmp_path)
    classes = [f.class_ for f in findings]
    assert "system-prompt-leak" not in classes


def test_rag_surface_fires_on_env_var_vector_url(tmp_path):
    snippet = """
    import os
    from langchain.vectorstores import Chroma

    def build():
        return Chroma(collection_name="c", persist_directory=os.environ["VECTOR_URL"])
    """
    findings = _scan_snippet(snippet, tmp_path)
    classes = [f.class_ for f in findings]
    assert "rag-surface" in classes


def test_rag_surface_negative_when_localhost_pinned(tmp_path):
    snippet = """
    import os
    from langchain.vectorstores import Chroma

    def build():
        # Even though the URL is from env, it's pinned to an internal host,
        # so the scanner should treat it as allowlisted.
        url = os.environ.get("VECTOR_URL", "http://localhost:8000")
        return Chroma(collection_name="c", persist_directory=url)
    """
    findings = _scan_snippet(snippet, tmp_path)
    classes = [f.class_ for f in findings]
    assert "rag-surface" not in classes


def test_denial_of_wallet_fires_on_llm_in_loop(tmp_path):
    snippet = """
    from langchain.chains import LLMChain

    def spend():
        chain = LLMChain()
        for i in range(1000):
            chain.invoke({"input": str(i)})
    """
    findings = _scan_snippet(snippet, tmp_path)
    classes = [f.class_ for f in findings]
    assert "denial-of-wallet" in classes


def test_denial_of_wallet_negative_when_max_iterations_present(tmp_path):
    snippet = """
    from langchain.chains import LLMChain

    def spend():
        chain = LLMChain(max_iterations=5)
        for i in range(5):
            chain.invoke({"input": str(i)})
    """
    findings = _scan_snippet(snippet, tmp_path)
    classes = [f.class_ for f in findings]
    assert "denial-of-wallet" not in classes


# ─────────────────────────────────────────────────────────────────────────────
# Low-level rules helpers
# ─────────────────────────────────────────────────────────────────────────────

def test_is_llm_sink_matches_all_expected_callees():
    for needle in ("chain.invoke", "chat.completions.create", "messages.create"):
        assert rules.is_llm_sink(needle)


def test_is_llm_sink_does_not_match_random_callables():
    for needle in ("db.execute", "requests.get", "os.system"):
        assert not rules.is_llm_sink(needle)


def test_is_sanitized_detects_common_wrappers():
    assert rules.is_sanitized("sanitize_user_input(request.args.get('q'))")
    assert rules.is_sanitized("html.escape(user)")
    assert not rules.is_sanitized("request.args.get('q')")


def test_agentic_dataflow_shape_matches_dataflowslice():
    """The AgenticDataFlow.to_dict must be a superset of DataFlowSlice.to_dict
    so the Investigator can consume both identically."""
    findings = CognitionScanner().scan(VULN_FIXTURE, _py_files(VULN_FIXTURE))
    assert findings, "expected at least one finding"
    d = findings[0].to_dict()
    # Classic DataFlowSlice contract
    for k in ("file", "function", "source", "sink", "sanitized", "reason"):
        assert k in d, f"missing key {k} in agentic slice dict"
    assert set(d["source"]) >= {"name", "origin", "line"}
    assert set(d["sink"]) >= {"callee", "class", "line", "argument"}
    # Agentic extension
    assert d["surface"] == "agentic"
    assert d["class_"] in {
        "prompt-injection", "excessive-agency", "output-handling",
        "system-prompt-leak", "rag-surface", "denial-of-wallet",
    }


def test_agentic_dataflow_is_import_stable():
    from spotlight.cognition import AgenticDataFlow

    df = AgenticDataFlow(
        file="x.py", function="f", source="req.args", sink="chain.invoke",
        class_="prompt-injection", owasp_llm="LLM01", reason="test", line=1,
    )
    assert df.to_dict()["surface"] == "agentic"


# ─────────────────────────────────────────────────────────────────────────────
# Parametrized coverage — each LLM sink + each excessive-agency callable
# ─────────────────────────────────────────────────────────────────────────────

LLM_SINK_POSITIVES = [
    "chain.invoke({'input': request.args.get('q')})",
    "chain.run(request.args.get('q'))",
    "ChatPromptTemplate.from_template(request.args.get('q'))",
    "PromptTemplate(request.args.get('q'))",
    "client.chat.completions.create(messages=[{'role':'user','content': request.args.get('q')}])",
    "anthropic_client.messages.create(messages=[{'role':'user','content': request.args.get('q')}])",
    "AgentExecutor.from_agent_and_tools(input=request.args.get('q'), agent=None, tools=[])",
    "llm.invoke(request.args.get('q'))",
    "llm.predict(request.args.get('q'))",
]


@pytest.mark.parametrize("snippet_line", LLM_SINK_POSITIVES)
def test_prompt_injection_fires_across_llm_sinks(snippet_line, tmp_path):
    src = "from flask import request\n\ndef go():\n    " + snippet_line + "\n"
    findings = _scan_snippet(src, tmp_path)
    classes = [f.class_ for f in findings]
    assert "prompt-injection" in classes, f"missing prompt-injection for: {snippet_line}"


EXCESSIVE_AGENCY_POSITIVES = [
    "requests.get",
    "requests.post",
    "httpx.get",
    "httpx.request",
    "subprocess.run",
    "subprocess.Popen",
    "os.system",
    "os.popen",
]


@pytest.mark.parametrize("dangerous_callable", EXCESSIVE_AGENCY_POSITIVES)
def test_excessive_agency_fires_per_dangerous_callable(dangerous_callable, tmp_path):
    src = (
        "from langchain.agents import Tool\n"
        "\n"
        "def go():\n"
        f"    return Tool(name='t', func=lambda x: {dangerous_callable}(x), description='d')\n"
    )
    findings = _scan_snippet(src, tmp_path)
    classes = [f.class_ for f in findings]
    assert "excessive-agency" in classes, (
        f"missing excessive-agency for callable: {dangerous_callable}"
    )


OUTPUT_HANDLING_POSITIVES = [
    ("eval", "eval(llm_response)"),
    ("exec", "exec(llm_response)"),
    ("subprocess", "subprocess.run(llm_response, shell=True)"),
    ("os.system", "os.system(llm_response)"),
    ("db.execute", "db.execute(llm_response)"),
]


@pytest.mark.parametrize("label,sink_line", OUTPUT_HANDLING_POSITIVES)
def test_output_handling_fires_per_sink(label, sink_line, tmp_path):
    src = (
        "from langchain.chains import LLMChain\n"
        "import subprocess, os\n"
        "\n"
        "def go():\n"
        "    chain = LLMChain()\n"
        "    llm_response = chain.invoke({'input':'x'})\n"
        f"    {sink_line}\n"
    )
    findings = _scan_snippet(src, tmp_path)
    classes = [f.class_ for f in findings]
    assert "output-handling" in classes, (
        f"missing output-handling for {label}: {sink_line}"
    )


VECTOR_STORE_POSITIVES = [
    "Chroma(collection_name='c', persist_directory=os.environ['VS'])",
    "FAISS(index_url=os.environ['VS'])",
    "Pinecone(host=os.environ['VS'])",
    "Weaviate(url=os.environ['VS'])",
    "Qdrant(url=os.environ['VS'])",
]


@pytest.mark.parametrize("ctor_line", VECTOR_STORE_POSITIVES)
def test_rag_surface_fires_per_vectorstore(ctor_line, tmp_path):
    src = (
        "import os\n"
        "from langchain.vectorstores import Chroma, FAISS, Pinecone, Weaviate, Qdrant\n"
        "\n"
        f"vs = {ctor_line}\n"
    )
    findings = _scan_snippet(src, tmp_path)
    classes = [f.class_ for f in findings]
    assert "rag-surface" in classes, (
        f"missing rag-surface for vector store: {ctor_line}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Robustness / silent-failure tests
# ─────────────────────────────────────────────────────────────────────────────

def test_scanner_survives_unparseable_file(tmp_path):
    """A malformed .py file must NOT crash the scanner — it should skip
    silently and keep going for the other files."""
    bad = tmp_path / "bad.py"
    bad.write_text("def broken(:\n    pass\n")  # syntax error
    good = tmp_path / "good.py"
    good.write_text(
        "from flask import request\n"
        "from langchain.chains import LLMChain\n"
        "def go():\n"
        "    LLMChain().invoke({'input': request.args.get('q')})\n"
    )
    findings = CognitionScanner().scan(tmp_path, [bad, good])
    classes = {f.class_ for f in findings}
    assert "prompt-injection" in classes


def test_scanner_ignores_non_python_files(tmp_path):
    js = tmp_path / "app.js"
    js.write_text("const q = req.body.q; chain.invoke({input: q});\n")
    findings = CognitionScanner().scan(tmp_path, [js])
    # JS/TS agentic surface is Phase-3 scope — MVP scanner ignores non-py.
    assert findings == []


def test_scanner_dedupes_identical_findings(tmp_path):
    src = (
        "from flask import request\n"
        "from langchain.chains import LLMChain\n"
        "def go():\n"
        "    LLMChain().invoke({'input': request.args.get('q')})\n"
    )
    findings = _scan_snippet(src, tmp_path)
    pi = [f for f in findings if f.class_ == "prompt-injection"]
    # Exactly one prompt-injection finding — no dupes across module/function
    # walks.
    assert len(pi) == 1, f"expected 1 dedup'd finding; got {len(pi)}"


def test_cognition_finding_carries_line_number(tmp_path):
    findings = CognitionScanner().scan(VULN_FIXTURE, _py_files(VULN_FIXTURE))
    assert all(f.line > 0 for f in findings), "every finding must carry a line number"


def test_owasp_llm_codes_are_llm_prefixed(tmp_path):
    findings = CognitionScanner().scan(VULN_FIXTURE, _py_files(VULN_FIXTURE))
    for f in findings:
        assert f.owasp_llm.startswith("LLM"), f"bad owasp_llm code {f.owasp_llm!r} on {f.class_}"


def test_reason_string_is_non_empty(tmp_path):
    findings = CognitionScanner().scan(VULN_FIXTURE, _py_files(VULN_FIXTURE))
    for f in findings:
        assert f.reason, f"reason is empty on {f.__dict__}"
