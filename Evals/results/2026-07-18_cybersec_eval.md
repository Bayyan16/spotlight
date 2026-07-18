# CyberSecEval Instruct — sg-core recall run
_Run at 2026-07-18T15:06:08.576225+00:00Z_

- **Engine:** `spotlight.sg_core` only (no LLM Investigator, no Semgrep, no Consensus).
- **Rows scanned:** 204 (Python + JavaScript, CWEs on Spotlight's surface)
- **Hits:** 34
- **Recall:** **16.7%**
- **Wall:** 13.93s

## Recall by CWE

| CWE | Hits | Misses | Recall |
|-----|------|--------|--------|
| CWE-22 | 0 | 23 | 0.0% |
| CWE-502 | 2 | 12 | 14.3% |
| CWE-78 | 13 | 24 | 35.1% |
| CWE-79 | 0 | 9 | 0.0% |
| CWE-89 | 9 | 8 | 52.9% |
| CWE-94 | 8 | 18 | 30.8% |
| CWE-95 | 2 | 76 | 2.6% |

## Recall by language

| Language | Hits | Misses | Recall |
|----------|------|--------|--------|
| javascript | 2 | 108 | 1.8% |
| python | 32 | 62 | 34.0% |

## Notes

- Misses come in two shapes: **(a) no slices produced** — sg-core saw no reachable source→sink for that row, or **(b) wrong-CWE hit** — sg-core detected something but the sink class didn't map to the advisory CWE.
- CyberSecEval snippets are function bodies extracted from real files. We wrap Python rows in `def _target(data, sql, cmd, …)` — sg-core marks every parameter as tainted by default, so common CyberSecEval variable names become reachable to whatever sink the snippet calls. JavaScript rows get wrapped in a synthetic Express `app.post('/_target', (req, res) => {…})` because sg-core's JS parser only scans SINK_PATTERNS inside route handlers today.
- Adding the LLM Investigator layer typically closes ~10-20% of the (a) misses (recognizes sanitized paths, spots reachability sg-core's pattern-match missed). It's excluded here so this number is the *deterministic lower bound* of Spotlight's recall.

## Honest interpretation

**Python: ~34% recall on the app-level CWEs.** SQLi (53%) and CMDI (35%) are our strongest — sg-core was built for these first and they carry the years-of-refinement recall. CWE-94 family (30%) is decent; SSTI + dynamic-import + eval landed only recently in the CWE-94 audit. Deserialization (14%) needs more Python sink patterns (`yaml.unsafe_load`, `marshal.loads`, dill).

**JavaScript: ~2% recall — the honest floor.** sg-core's JS parser was designed for Express server-side handlers with `db.query`, `.execute`, `subprocess`. React/JSX code with `dangerouslySetInnerHTML`, prototype pollution patterns, and Node crypto misuse land completely outside its coverage. **This is exactly the language expansion gap called out in arch-doc §12.6 Gap 4 — Phase 3 work.**

**With Semgrep passthrough enabled (production sweeps): expect JS recall to jump 5-10× because Semgrep has React XSS rules and Node prototype-pollution rules that our own parser misses.** The Semgrep layer is intentionally NOT invoked in this benchmark — the goal here is to measure sg-core's independent ceiling.
