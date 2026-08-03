# Contributing to Spotlight

Thanks for your interest in Spotlight, the AI security engineer by CMUL8. We welcome contributions from the community.

## Before you start

- This is an **AI security tool** — its output can be wrong. Tests matter more than features. Every change that touches scanner, reproducer, or remediator logic must come with tests that prove both the happy path *and* the failure mode.
- The project currently ships a deterministic `MockModelClient` so tests run without model access. Keep it that way.
- If you're planning a large feature, open an issue first so we can align before you invest the hours.

## Getting set up

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]" flask
pytest -v
```

Console:

```bash
cd console && npm install && npm run dev
```

## Workflow

1. Fork the repo and create a branch from `main`.
2. Make your change. Prefer small, reviewable PRs.
3. Add or update tests. `pytest` is the gate — a PR that breaks tests won't merge.
4. Run the linter: `ruff check .` (line length 100, target py311).
5. Open a pull request against `main` with a description of what you changed and why, plus any test evidence.

## Security-sensitive code

Spotlight redacts secrets, scans untrusted code, and spawns sandboxed processes. If your change touches any of these paths, be extra explicit in the PR about failure modes: what happens when input is malformed, hostile, or empty? If you don't know, say so and we'll work through it together.

## Commit style

Keep commits focused and conventional (`feat:`, `fix:`, `chore:`, `test:`, `docs:`). No need to squash if the history is already tidy; we prefer merge over rebase.

## Code of conduct

All contributors are expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md). Report unacceptable behavior to the maintainers.

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).
