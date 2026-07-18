# Evals

Standalone benchmarks Spotlight is tested against. Each benchmark ships with:

- **`datasets/`** — the raw benchmark data (or a script to fetch it).
- **`scripts/`** — extraction, run, and report tooling.
- **`snippets/`** — extracted per-row source snippets that get scanned.
- **`results/`** — timestamped run outputs (both machine JSON and human MD).

Runs never touch the deployed `spotlight-api-production` — the benchmark bypasses the API and drives `spotlight.sg_core` + Semgrep directly, so results are fast and deterministic and don't depend on Moonshot's rate-limit weather.

## Benchmarks

### 1 · CyberSecEval Instruct (Meta Purple Llama, 2023)

- **Source:** `github.com/meta-llama/PurpleLlama/blob/main/CybersecurityBenchmarks/datasets/instruct/instruct.json`
- **Total rows:** 1,916 across 8 languages (`c`, `cpp`, `csharp`, `java`, `javascript`, `php`, `python`, `rust`)
- **Spotlight-relevant rows (Python + JavaScript, our language surface today):** 600 (351 py + 249 js)
- **What each row is:** a real vulnerable snippet mined from a real repo, tagged with `cwe_identifier`, `pattern_desc`, `pattern_id` (Semgrep rule), and the exact `line_text` at `line_number` in `file_path`.
- **Meta's use:** feed the `test_case_prompt` to an LLM, let it generate code, run their `codeshield` insecure-code-detector on the output, score % insecure.
- **Our use:** run `spotlight.sg_core.CodeGraph` on each `origin_code` directly. Score whether Spotlight independently detects the same CWE Semgrep planted.

Scripts:
- `scripts/filter_py_js.py` — extract py+js rows matching Spotlight's detector classes.
- `scripts/run_sgcore.py` — run the sg-core reachability check against each snippet, tag hits/misses.
- `scripts/report.py` — pretty-print the run into `results/`.

## Adding a new benchmark

1. Drop the raw dataset into `datasets/`.
2. Add a `filter_*.py` (or equivalent) that pulls rows relevant to Spotlight's surface into `snippets/`.
3. Add a `run_*.py` that drives whichever Spotlight engine (sg-core, Semgrep adapter, full orchestrator) makes sense for the benchmark shape.
4. Timestamped output → `results/YYYY-MM-DD_<benchmark>.json` + `.md`.
