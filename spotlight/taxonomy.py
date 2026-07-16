"""Vulnerability class taxonomy.

Consolidates the industry-recognized weakness catalogs into one canonical
list Spotlight uses everywhere:
  * OWASP Top 10 (2021) — the web-app baseline every AppSec team maps to.
  * OWASP LLM Top 10 (2025) — the AI-layer baseline (LLM01..LLM10).
  * OWASP Agentic Security Initiative — categories layered on top of LLM Top 10.
  * CWE (Common Weakness Enumeration) — MITRE's numbered catalog. Each class
    maps to one primary CWE and often several related CWEs.
  * SANS/CWE Top 25 — the yearly critical-25 subset of CWE.
  * OWASP ASVS categories — how a security engineer thinks about coverage.

Every class carries:
  - `id`: short canonical code (e.g. "sqli", "prompt-injection")
  - `name`: display name
  - `cwe`: primary CWE
  - `owasp`: OWASP Top 10 category (if applicable)
  - `owasp_llm`: OWASP LLM Top 10 category (if applicable)
  - `surface`: "code" | "agentic" | "config" | "crypto" | "authn" | "secrets"
  - `detection`: "reachable" (needs source→sink graph) | "static" (fact-only)
  - `poc_available`: whether a Phase-2 dynamic PoC template exists
  - `default_severity`: baseline severity if the model doesn't override
  - `description`: one-line what it is

Used by: Profiles (whitelist classes), Investigator prompts (normalize),
Consensus Kernel (promotion logic per class), UI (chip labels + tooltips),
Attestation (map to standards for the audit trail).
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class VulnClass:
    id: str
    name: str
    cwe: str
    owasp: str = ""
    owasp_llm: str = ""
    surface: str = "code"
    detection: str = "reachable"  # reachable | static
    poc_available: bool = False
    default_severity: str = "medium"
    description: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# =============================================================================
# CODE surface — classic AppSec / web-app vulnerability classes
# =============================================================================

INJECTION_CLASSES: list[VulnClass] = [
    VulnClass(
        id="sqli",
        name="SQL Injection",
        cwe="CWE-89",
        owasp="A03:2021 Injection",
        detection="reachable",
        poc_available=True,
        default_severity="critical",
        description="User input concatenated into a SQL statement without parameterization.",
    ),
    VulnClass(
        id="nosqli",
        name="NoSQL Injection",
        cwe="CWE-943",
        owasp="A03:2021 Injection",
        default_severity="high",
        description="User input reaches a NoSQL query operator without validation (MongoDB `$where`, etc.).",
    ),
    VulnClass(
        id="cmdi",
        name="OS Command Injection",
        cwe="CWE-78",
        owasp="A03:2021 Injection",
        default_severity="critical",
        description="User input passed to shell/exec without argv-quoting.",
    ),
    VulnClass(
        id="code-injection",
        name="Code Injection / eval",
        cwe="CWE-95",
        owasp="A03:2021 Injection",
        default_severity="critical",
        description="User input reaches `eval`, `exec`, `new Function`, or dynamic import.",
    ),
    VulnClass(
        id="ldap-injection",
        name="LDAP Injection",
        cwe="CWE-90",
        owasp="A03:2021 Injection",
        default_severity="high",
        description="User input inserted into an LDAP filter without escaping.",
    ),
    VulnClass(
        id="xpath-injection",
        name="XPath Injection",
        cwe="CWE-643",
        owasp="A03:2021 Injection",
        default_severity="high",
    ),
    VulnClass(
        id="template-injection",
        name="Server-Side Template Injection",
        cwe="CWE-1336",
        owasp="A03:2021 Injection",
        default_severity="critical",
        description="User input rendered as a template (Jinja2, Handlebars) — leads to RCE.",
    ),
    VulnClass(
        id="header-injection",
        name="HTTP Header/Response Splitting",
        cwe="CWE-113",
        owasp="A03:2021 Injection",
        default_severity="medium",
    ),
    VulnClass(
        id="log-injection",
        name="Log Injection",
        cwe="CWE-117",
        owasp="A09:2021 Logging Failures",
        default_severity="low",
    ),
]

XSS_CLASSES: list[VulnClass] = [
    VulnClass(
        id="xss",
        name="Cross-Site Scripting (reflected/stored)",
        cwe="CWE-79",
        owasp="A03:2021 Injection",
        default_severity="high",
        description="Untrusted string reaches an HTML sink (`innerHTML`, template-render-raw).",
    ),
    VulnClass(
        id="xss-dom",
        name="DOM-based XSS",
        cwe="CWE-79",
        owasp="A03:2021 Injection",
        default_severity="high",
    ),
]

FORGERY_CLASSES: list[VulnClass] = [
    VulnClass(
        id="ssrf",
        name="Server-Side Request Forgery",
        cwe="CWE-918",
        owasp="A10:2021 SSRF",
        default_severity="critical",
        description="User controls the URL of an outbound HTTP call — cloud-metadata / internal-services exposure.",
    ),
    VulnClass(
        id="csrf",
        name="Cross-Site Request Forgery",
        cwe="CWE-352",
        owasp="A01:2021 Broken Access Control",
        default_severity="medium",
    ),
    VulnClass(
        id="xxe",
        name="XML External Entity",
        cwe="CWE-611",
        owasp="A05:2021 Security Misconfiguration",
        default_severity="high",
        description="XML parser resolves external entities — file exfil, SSRF, RCE.",
    ),
    VulnClass(
        id="open-redirect",
        name="Open Redirect",
        cwe="CWE-601",
        owasp="A01:2021 Broken Access Control",
        default_severity="medium",
    ),
]

DESERIALIZATION_CLASSES: list[VulnClass] = [
    VulnClass(
        id="deserialization",
        name="Insecure Deserialization",
        cwe="CWE-502",
        owasp="A08:2021 Software and Data Integrity Failures",
        default_severity="critical",
        description="Untrusted input passed to `pickle.loads`, `unserialize`, `readObject`.",
    ),
    VulnClass(
        id="proto-pollution",
        name="Prototype Pollution",
        cwe="CWE-1321",
        owasp="A08:2021 Software and Data Integrity Failures",
        default_severity="high",
        description="JS `Object.assign` / spread merges attacker-controlled keys onto `__proto__`.",
    ),
]

ACCESS_CONTROL_CLASSES: list[VulnClass] = [
    VulnClass(
        id="idor",
        name="Insecure Direct Object Reference",
        cwe="CWE-639",
        owasp="A01:2021 Broken Access Control",
        detection="reachable",  # heuristic: authz decoupled from object id
        default_severity="high",
        description="Route accesses a resource by an attacker-controlled id without an ownership check.",
    ),
    VulnClass(
        id="missing-authn",
        name="Missing Authentication for Critical Function",
        cwe="CWE-306",
        owasp="A07:2021 Authn Failures",
        default_severity="critical",
    ),
    VulnClass(
        id="missing-authz",
        name="Missing Authorization",
        cwe="CWE-862",
        owasp="A01:2021 Broken Access Control",
        default_severity="high",
    ),
    VulnClass(
        id="broken-authn",
        name="Broken Authentication",
        cwe="CWE-287",
        owasp="A07:2021 Authn Failures",
        default_severity="high",
    ),
    VulnClass(
        id="privilege-escalation",
        name="Privilege Escalation",
        cwe="CWE-269",
        owasp="A01:2021 Broken Access Control",
        default_severity="critical",
    ),
    VulnClass(
        id="excessive-permissions",
        name="Incorrect Default Permissions",
        cwe="CWE-276",
        owasp="A05:2021 Security Misconfiguration",
        default_severity="medium",
    ),
]

FILE_CLASSES: list[VulnClass] = [
    VulnClass(
        id="path-traversal",
        name="Path Traversal / Directory Traversal",
        cwe="CWE-22",
        owasp="A01:2021 Broken Access Control",
        default_severity="high",
        description="User input concatenated into a filesystem path without normalization.",
    ),
    VulnClass(
        id="file-upload",
        name="Unrestricted File Upload",
        cwe="CWE-434",
        owasp="A04:2021 Insecure Design",
        default_severity="high",
    ),
    VulnClass(
        id="zip-slip",
        name="Zip Slip (Path Traversal via Archive)",
        cwe="CWE-22",
        owasp="A01:2021 Broken Access Control",
        default_severity="high",
    ),
]

CRYPTO_CLASSES: list[VulnClass] = [
    VulnClass(
        id="weak-hash",
        name="Use of Weak Hash",
        cwe="CWE-328",
        owasp="A02:2021 Cryptographic Failures",
        detection="static",
        default_severity="medium",
        description="MD5 / SHA1 used where a secure hash is required.",
    ),
    VulnClass(
        id="weak-crypto",
        name="Use of Weak Cryptographic Algorithm",
        cwe="CWE-327",
        owasp="A02:2021 Cryptographic Failures",
        detection="static",
        default_severity="high",
        description="DES / RC4 / ECB mode / no-IV / short RSA key detected.",
    ),
    VulnClass(
        id="hardcoded-key",
        name="Hardcoded Cryptographic Key",
        cwe="CWE-321",
        owasp="A02:2021 Cryptographic Failures",
        surface="secrets",
        detection="static",
        default_severity="high",
    ),
    VulnClass(
        id="predictable-random",
        name="Predictable Pseudo-random Number Generator",
        cwe="CWE-338",
        owasp="A02:2021 Cryptographic Failures",
        detection="static",
        default_severity="medium",
        description="`Math.random()` / `random.random()` used for security-sensitive value.",
    ),
    VulnClass(
        id="missing-tls",
        name="Cleartext Transmission",
        cwe="CWE-319",
        owasp="A02:2021 Cryptographic Failures",
        detection="static",
        default_severity="medium",
    ),
    VulnClass(
        id="verify-disabled",
        name="TLS Certificate Verification Disabled",
        cwe="CWE-295",
        owasp="A02:2021 Cryptographic Failures",
        detection="static",
        default_severity="high",
        description="`verify=False` / `rejectUnauthorized: false`.",
    ),
]

SECRETS_CLASSES: list[VulnClass] = [
    VulnClass(
        id="hardcoded-aws-key",
        name="Hardcoded AWS Access Key",
        cwe="CWE-798",
        surface="secrets",
        detection="static",
        default_severity="critical",
    ),
    VulnClass(
        id="hardcoded-gcp-key",
        name="Hardcoded GCP Service Account Key",
        cwe="CWE-798",
        surface="secrets",
        detection="static",
        default_severity="critical",
    ),
    VulnClass(
        id="hardcoded-github-pat",
        name="Hardcoded GitHub Personal Access Token",
        cwe="CWE-798",
        surface="secrets",
        detection="static",
        default_severity="critical",
    ),
    VulnClass(
        id="hardcoded-openai-key",
        name="Hardcoded OpenAI API Key",
        cwe="CWE-798",
        surface="secrets",
        detection="static",
        default_severity="high",
    ),
    VulnClass(
        id="hardcoded-anthropic-key",
        name="Hardcoded Anthropic API Key",
        cwe="CWE-798",
        surface="secrets",
        detection="static",
        default_severity="high",
    ),
    VulnClass(
        id="hardcoded-slack-token",
        name="Hardcoded Slack Token",
        cwe="CWE-798",
        surface="secrets",
        detection="static",
        default_severity="high",
    ),
    VulnClass(
        id="hardcoded-jwt",
        name="Hardcoded JWT",
        cwe="CWE-798",
        surface="secrets",
        detection="static",
        default_severity="medium",
    ),
    VulnClass(
        id="hardcoded-private-key",
        name="Hardcoded Private Key",
        cwe="CWE-321",
        surface="secrets",
        detection="static",
        default_severity="critical",
        description="RSA / OpenSSH / PGP private key embedded in source.",
    ),
    VulnClass(
        id="hardcoded-db-url",
        name="Hardcoded DB URL with Credentials",
        cwe="CWE-798",
        surface="secrets",
        detection="static",
        default_severity="high",
    ),
    VulnClass(
        id="secrets",
        name="Hardcoded Credentials (generic)",
        cwe="CWE-798",
        owasp="A07:2021 Authn Failures",
        surface="secrets",
        detection="static",
        default_severity="high",
        description="Credential-shaped literal detected in source (catch-all for the sub-classes above).",
    ),
    VulnClass(
        id="secret-in-env-example",
        name="Real Credential in .env.example",
        cwe="CWE-540",
        surface="secrets",
        detection="static",
        default_severity="high",
        description=".env.example / docs commit contains a live-looking key instead of a placeholder.",
    ),
]

CONFIG_CLASSES: list[VulnClass] = [
    VulnClass(
        id="misconfig",
        name="Security Misconfiguration",
        cwe="CWE-16",
        owasp="A05:2021 Security Misconfiguration",
        default_severity="medium",
    ),
    VulnClass(
        id="cors-wildcard",
        name="Overly Permissive CORS",
        cwe="CWE-942",
        owasp="A05:2021 Security Misconfiguration",
        detection="static",
        default_severity="medium",
        description="`Access-Control-Allow-Origin: *` with credentials mode.",
    ),
    VulnClass(
        id="debug-enabled",
        name="Debug Mode Enabled in Production",
        cwe="CWE-489",
        owasp="A05:2021 Security Misconfiguration",
        detection="static",
        default_severity="high",
    ),
    VulnClass(
        id="verbose-errors",
        name="Verbose Error Messages / Stack Traces Exposed",
        cwe="CWE-209",
        owasp="A05:2021 Security Misconfiguration",
        default_severity="low",
    ),
]

RUNTIME_CLASSES: list[VulnClass] = [
    VulnClass(
        id="race",
        name="Race Condition / TOCTOU",
        cwe="CWE-362",
        default_severity="high",
    ),
    VulnClass(
        id="redos",
        name="Regex Denial of Service",
        cwe="CWE-1333",
        default_severity="medium",
    ),
    VulnClass(
        id="null-deref",
        name="Null Pointer Dereference",
        cwe="CWE-476",
        default_severity="medium",
    ),
    VulnClass(
        id="int-overflow",
        name="Integer Overflow / Wraparound",
        cwe="CWE-190",
        default_severity="medium",
    ),
    VulnClass(
        id="use-after-free",
        name="Use After Free",
        cwe="CWE-416",
        default_severity="critical",
    ),
    VulnClass(
        id="buffer-overflow",
        name="Buffer Overflow",
        cwe="CWE-120",
        default_severity="critical",
    ),
    VulnClass(
        id="info-disclosure",
        name="Sensitive Information Disclosure",
        cwe="CWE-200",
        owasp="A01:2021 Broken Access Control",
        default_severity="medium",
    ),
]

# =============================================================================
# AGENTIC surface — OWASP LLM Top 10 (2025) + OWASP Agentic Security Initiative
# =============================================================================

AGENTIC_CLASSES: list[VulnClass] = [
    VulnClass(
        id="prompt-injection",
        name="Prompt Injection",
        cwe="CWE-77",
        owasp_llm="LLM01",
        surface="agentic",
        default_severity="critical",
        description="Untrusted text (user, retrieved doc, ticket body) reaches the model without segregation from instructions.",
    ),
    VulnClass(
        id="sensitive-info-disclosure",
        name="Sensitive Information Disclosure",
        cwe="CWE-200",
        owasp_llm="LLM02",
        surface="agentic",
        default_severity="high",
        description="Model reveals training-data secrets or system-prompt content in its output.",
    ),
    VulnClass(
        id="model-supply-chain",
        name="Model Supply Chain",
        cwe="CWE-829",
        owasp_llm="LLM03",
        surface="agentic",
        default_severity="high",
        description="Untrusted third-party model / adapter loaded without provenance check.",
    ),
    VulnClass(
        id="data-poisoning",
        name="Training Data / RAG Poisoning",
        cwe="CWE-1039",
        owasp_llm="LLM04",
        surface="agentic",
        default_severity="high",
    ),
    VulnClass(
        id="output-handling",
        name="Improper Output Handling",
        cwe="CWE-79",  # closely related to XSS when output → HTML sink
        owasp_llm="LLM05",
        surface="agentic",
        default_severity="high",
        description="Model output flows unvalidated into a sink (shell, SQL, HTML, `eval`, a downstream tool).",
    ),
    VulnClass(
        id="excessive-agency",
        name="Excessive Agency",
        cwe="CWE-269",
        owasp_llm="LLM06",
        surface="agentic",
        default_severity="critical",
        description="An agent can invoke tools beyond its task, with broader privilege than needed, or take high-impact actions with no human gate.",
    ),
    VulnClass(
        id="system-prompt-leak",
        name="System Prompt Leakage",
        cwe="CWE-540",
        owasp_llm="LLM07",
        surface="agentic",
        default_severity="high",
    ),
    VulnClass(
        id="rag-surface",
        name="RAG / Vector Store Weakness",
        cwe="CWE-345",
        owasp_llm="LLM08",
        surface="agentic",
        default_severity="high",
        description="Retrieval from a store that ingests untrusted content without provenance/validation; missing access controls on the vector store.",
    ),
    VulnClass(
        id="misinformation",
        name="Model Misinformation / Overreliance",
        cwe="CWE-1024",
        owasp_llm="LLM09",
        surface="agentic",
        default_severity="medium",
        description="High-impact decisions taken on unverified model output.",
    ),
    VulnClass(
        id="denial-of-wallet",
        name="Unbounded Consumption / Denial of Wallet",
        cwe="CWE-400",
        owasp_llm="LLM10",
        surface="agentic",
        default_severity="high",
        description="No per-actor rate/budget limits on model or tool calls; recursive/looping agent with no cap.",
    ),
    # OWASP Agentic Security Initiative categories that don't map 1:1 to LLM Top 10:
    VulnClass(
        id="agent-memory-tampering",
        name="Agent Memory Tampering",
        cwe="CWE-345",
        surface="agentic",
        default_severity="high",
        description="An agent's persistent memory can be poisoned by an earlier task or an untrusted source.",
    ),
    VulnClass(
        id="tool-permission-drift",
        name="Tool Permission Drift",
        cwe="CWE-732",
        surface="agentic",
        default_severity="high",
        description="Tools granted to an agent have wider scopes than the task requires — reconstruction of least-privilege violation.",
    ),
    VulnClass(
        id="agent-loop",
        name="Uncapped Agent Loop",
        cwe="CWE-835",
        surface="agentic",
        default_severity="medium",
    ),
]


ALL_CLASSES: list[VulnClass] = (
    INJECTION_CLASSES
    + XSS_CLASSES
    + FORGERY_CLASSES
    + DESERIALIZATION_CLASSES
    + ACCESS_CONTROL_CLASSES
    + FILE_CLASSES
    + CRYPTO_CLASSES
    + SECRETS_CLASSES
    + CONFIG_CLASSES
    + RUNTIME_CLASSES
    + AGENTIC_CLASSES
)


BY_ID: dict[str, VulnClass] = {c.id: c for c in ALL_CLASSES}


def get(class_id: str) -> VulnClass | None:
    return BY_ID.get(class_id)


def list_ids() -> list[str]:
    return [c.id for c in ALL_CLASSES]


def list_by_surface(surface: str) -> list[VulnClass]:
    return [c for c in ALL_CLASSES if c.surface == surface]


def counts_by_surface() -> dict[str, int]:
    out: dict[str, int] = {}
    for c in ALL_CLASSES:
        out[c.surface] = out.get(c.surface, 0) + 1
    return out
