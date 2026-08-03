# Spotlight by CMUL8

The AI security engineer. Phase 1 MVP — vertical slice.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## What Phase 1 ships

- **sg-core**: Python code graph with source→sink data-flow reachability. Deterministic taint propagation, parameterized-query sanitizer detection.
- **Orchestrator**: Recon → Investigate → Reduce → Reproduce → Remediate → Verify → Attest, wired to an event bus.
- **Agent roster**: Recon, Investigator, Reducer, Reproducer (in-process PoC), Remediator (parameterized-query fix), independent Verifier (fresh context + backdoor-check).
- **Fixture targets**: `targets/vuln-bank-api` (planted SQLi) + `targets/clean-bank-api` (precision negative).
- **FastAPI backend**: REST + WebSocket streaming of the sweep event log.
- **Spotlight Console**: React SPA with phase tracker, live swarm grid, event log, findings inbox, "Why you can trust this" evidence detail.
- **CLI**: `spotlight sweep <repo>` end-to-end.

Model calls go through a deterministic **MockModelClient** so Phase-1 tests are reproducible without model access. The M0 spike (real `codex exec` + direct-loop fallback) lands in Phase 2.

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]" flask
pytest -v                                    # 18 tests: sg-core + vertical slice + API

# CLI
python -m spotlight.cli.main sweep targets/vuln-bank-api

# Console
uvicorn spotlight.api.app:app --port 8000 &
cd console && npm install && npm run dev     # open http://localhost:5173
```

## Test bar (from Phase 1 plan)

| Test | Proves |
|---|---|
| `test_vuln_fixture_produces_reachable_sqli_slice` | Recall: sg-core sees the SQLi |
| `test_clean_fixture_produces_zero_reachable_sqli_slices` | Precision: parameterized query is NOT flagged |
| `test_vuln_bank_api_produces_verified_confirmed_fixed_finding` | End-to-end: verified tier, state=confirmed-fixed |
| `test_clean_bank_api_produces_zero_promoted_findings` | Precision at the orchestrator level |
| `test_reproduction_uses_classic_sqli_payload_and_exploits` | The `' OR '1'='1` PoC actually exploits the app |
| `test_reproduction_on_clean_fixture_does_not_exploit` | Same PoC returns [] against the patched app |
| `test_verifier_is_independent_of_remediator` | Fresh context + distinct system prompt |
| `test_event_stream_records_full_sweep` | Every phase transition emits an event |
| `test_websocket_streams_events` | UI can subscribe live |

## Deploy

- **Railway**: `railway up` — `railway.json` points at `infra/Dockerfile.api`, healthcheck on `/healthz`.
- **GitHub Actions**: runs backend + frontend on every push.
- **Local**: `docker compose -f infra/docker-compose.yml up` — Postgres, Redis, MinIO, API, Console.

## Not in Phase 1

Real model wiring (Codex exec / direct loop), Warden, Cognition Sweep, cross-surface Exploit Paths, Postgres persistence, full Consensus Kernel with adjudicator. See `docs/SPOTLIGHT_ARCHITECTURE.md`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md). Found a security issue? Read [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE) — Copyright 2026 CMUL8.
