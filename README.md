# Spotlight

**An open-source, multi-agent AI security engineer.** Point it at a repository
and it reviews the code, reproduces the vulnerabilities it finds by actually
exploiting them in an isolated sandbox, writes and independently verifies a fix,
and signs every step so the whole chain can be audited later. Not a scanner that
emits alerts — an engineer that hands you evidence.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## What it does

A sweep runs seven stages, gated by a consensus step so only findings that clear
verification are promoted:

1. **Recon** — reads every file, builds a code graph, and marks where untrusted
   input enters and which dangerous sinks it can reach.
2. **Investigate** — agents fan out in parallel, each tracing a different
   source→sink path and checking whether a sanitizer breaks the chain.
3. **Reduce** — deduplicates and classifies findings against a taxonomy of 67
   vulnerability classes mapped to CWE and OWASP.
4. **Reproduce** — spins up an isolated sandbox with **network egress denied**,
   fires a real exploit payload, and confirms the app is actually exploitable.
   A finding that can't be demonstrated is never marked confirmed.
5. **Remediate** — writes the patch and can open a real GitHub pull request.
6. **Verify** — an **independent** agent with a fresh context (it never sees the
   remediator's reasoning) re-runs the exploit against the patched code and
   backdoor-scans the diff (did the "fix" disable a test, drop an auth check,
   log a secret?).
7. **Attest** — emits a signed report (JSON · Markdown · PDF) recording every
   action, offline-verifiable against the workspace's Ed25519 public key.

It also **improves itself**. Every finding's outcome — reproduced, verified, or
called a false positive by an analyst — is recorded in a signed, hash-chained
experience ledger, and Spotlight recalibrates its own confidence from that
history. The **Cortex** may activate a change unattended only when the change is
strictly conservative; anything that would make it *more* assertive requires a
named human approver, and a hard gate blocks any policy that would have demoted a
finding a sandbox or a human confirmed was real. See
[`docs/CORTEX.md`](docs/CORTEX.md). Off unless you set `SPOTLIGHT_CORTEX_DIR`.

Supporting machinery: the **Consensus Kernel** (prices agent agreement by
independence, promotes disagreement to human review instead of averaging it
away), the **Warden** control plane (prompt-injection detection, backdoor
scanning, capability tokens, three-chokepoint secret redaction), a
cross-surface **Chainer** for code + AI-layer exploit paths, and Ed25519
**non-repudiation** on every action. Four scan profiles ship, from a two-class
CI gate (Fast) to a full pre-release audit (Deep).

## Plugging in your LLM

Every agent role reaches a model **only** through the `ModelClient` protocol in
[`spotlight/agents/model.py`](spotlight/agents/model.py) — that one interface is
the plug-in point. Two implementations ship:

- **`MockModelClient`** — deterministic, offline, schema-valid outputs. This is
  the default when no API key is set, and what the entire test suite runs
  against. You can try the whole pipeline end to end with no model at all.
- **`OpenAICompatibleModelClient`** ([`agents/moonshot.py`](spotlight/agents/moonshot.py))
  — the real-inference adapter. It speaks the OpenAI `/chat/completions` format,
  so it works against **any OpenAI-compatible endpoint**: OpenAI, Moonshot/Kimi,
  Together, Groq, OpenRouter, or a local Ollama / vLLM server.

Select a provider with environment variables (copy [`.env.example`](.env.example)
to `.env`):

```bash
# Recommended, provider-neutral:
export SPOTLIGHT_LLM_API_KEY=sk-...
export SPOTLIGHT_LLM_BASE_URL=https://api.openai.com/v1   # default
export SPOTLIGHT_LLM_MODEL=gpt-4o-mini                    # default

# …or a fully local model, no cloud key required:
export SPOTLIGHT_LLM_API_KEY=ollama
export SPOTLIGHT_LLM_BASE_URL=http://localhost:11434/v1
export SPOTLIGHT_LLM_MODEL=llama3.1
```

`MOONSHOT_API_KEY` and `OPENAI_API_KEY` are also honored. To bring a provider
that isn't OpenAI-compatible, implement the protocol and pass it in directly:

```python
class MyModelClient:
    family = "my-provider"          # appears in the signed audit trail
    def complete(self, *, role, prompt, context):
        ...                         # call your model, return the role's dict

from spotlight.orchestrator.orchestrator import Orchestrator
Orchestrator(model=MyModelClient()).run("path/to/repo")
```

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q                                    # runs fully offline (mock model)

# Run a sweep on a bundled vulnerable fixture (no API key needed):
spotlight sweep targets/vuln-bank-api

# API + Console (optional)
uvicorn spotlight.api.app:app --port 8000 &
cd console && npm install && npm run dev      # open http://localhost:5173
```

The test suite is deterministic and offline: **575 passing, 4 skipped**, run
against the `MockModelClient` with no API keys or network. Bundled targets under
[`targets/`](targets/) include matched vulnerable/clean pairs (SQLi, command
injection, SSRF, and an agentic LangChain example) so you can watch Spotlight
confirm a real bug and correctly stay silent on the patched twin.

## Deploy

- **Docker Compose (local):** `docker compose -f infra/docker-compose.yml up` —
  Postgres, Redis, MinIO, API, and Console.
- **Railway:** `railway up` — `railway.json` points at `infra/Dockerfile.api`,
  healthcheck on `/healthz`.
- **CI:** GitHub Actions runs the backend and frontend on every push.

For real sandboxed reproduction, set `MODAL_TOKEN_ID` / `MODAL_TOKEN_SECRET`
(see [`.env.example`](.env.example)); otherwise reproductions run in a local
subprocess sandbox suitable for development.

## Getting smarter over time (optional)

```bash
export SPOTLIGHT_CORTEX_DIR=./.cortex     # turns memory on; off by default
spotlight sweep targets/vuln-bank-api     # records what each finding turned out to be
spotlight cortex status                   # active policy, label coverage, learned directives
spotlight cortex evolve --dry-run         # propose a policy + show the shadow replay
spotlight cortex verify                   # recompute the ledger hash chain and signatures
```

Every sweep stamps the policy id and ledger head it ran under into its
attestation, so a tier decision stays re-derivable months later, and
`spotlight cortex rollback <policy_id> --approver you@example.com` undoes a
change with a pointer move. The full design, including the six invariants no
amount of learning can amend, is in [`docs/CORTEX.md`](docs/CORTEX.md).

## Architecture

See [`docs/SPOTLIGHT_ARCHITECTURE.md`](docs/SPOTLIGHT_ARCHITECTURE.md) for the
full design — the agent roster, the Consensus Kernel, the Warden control plane,
the non-repudiation chain of custody, and the data-flow engine (`sg-core`).
[`docs/CORTEX.md`](docs/CORTEX.md) covers the self-improving layer: the
experience ledger, calibration, the learned policy and its governance gates.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md). Found a security issue? Please read
[SECURITY.md](SECURITY.md) first.

## License

[Apache License 2.0](LICENSE) — Copyright 2026 CMUL8.
