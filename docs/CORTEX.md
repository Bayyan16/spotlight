---
title: "Spotlight Cortex — the self-improving layer"
author: "Spotlight · v1 · 2026-09-27"
---

# Cortex — how Spotlight gets better at your codebase

Spotlight reasons carefully and remembers nothing.

Every sweep re-derives every judgment from zero. The Planner's repo-tuned rules
are discarded at teardown. The Verifier's gold labels die with the tempdir. The
analyst who signs *"false positive — that template string is a constant"* is
answered once, for one sweep, and then the same finding comes back next Tuesday
at the same confidence with the same wording. A tool that behaves this way is
exactly as good on its thousandth run as its first.

The Cortex (`spotlight/cortex/`) closes that loop. It is the layer that turns
finished work into memory, memory into a measurable estimate, and an estimate
into a bounded change in how findings are tiered — without ever being able to
make Spotlight quieter about a vulnerability that is real.

It is **opt-in**: with `SPOTLIGHT_CORTEX_DIR` unset there is no memory, no
policy, and no behavioural difference from the pipeline described in
[`SPOTLIGHT_ARCHITECTURE.md`](SPOTLIGHT_ARCHITECTURE.md).

---

## 1 · The shape of the loop

```
 sweep ──► findings ──► Reproducer / Verifier outcome ─┐
                                                       │
 analyst review (accept / false-positive) ─────────────┤
                                                       ▼
                                      ┌────────────────────────────┐
                                      │  Experience ledger         │  append-only
                                      │  hash-chained · signed     │  tamper-evident
                                      └──────────────┬─────────────┘
                                                     │
                                       calibrate (Beta / Wilson)
                                                     │
                                      ┌──────────────▼─────────────┐
                                      │  candidate policy          │  immutable
                                      │  per-cohort directives     │  content-addressed
                                      └──────────────┬─────────────┘
                                                     │
                            shadow replay over labelled history
                            + six invariants + governance gates
                                                     │
                     ┌───────────────────────────────┴───────────────┐
                     │                                               │
          strictly conservative                          would raise confidence
          → Cortex activates it itself                    → named human approver,
            (signed, recorded)                              signed, recorded
                     │                                               │
                     └───────────────────┬───────────────────────────┘
                                         ▼
                        next sweep pins the policy id + ledger head
                        into its attestation and tiers accordingly
```

---

## 2 · What it learns from — and what it refuses to learn from

The unit of memory is an **Experience**: one judged finding reduced to the shape
of the evidence that supported it, the tier the Consensus Kernel decided, and —
only when something authoritative said so — a label.

Three sources may label a row, in descending authority:

| Source | Label | Why it counts |
|---|---|---|
| `analyst-review` | true **or** false positive | A human verdict, signed into the chain of custody. The only source that can produce a *negative* label at all. |
| `reproduction` | true positive | The Reproducer exploited it in an egress-denied sandbox. Proof, not opinion. |
| `static-fact` | true positive | A committed credential. The literal *is* the proof. |

Everything else is `unknown`. In particular:

> **`not-reproduced` is not a false positive.**

It means we have no working PoC template for that class or shape — a statement
about our Reproducer, not about the code. Counting it as a false positive would
teach the Cortex to bury precisely the classes it is weakest at (authz, IDOR,
crypto misuse, business logic) while the precision dashboard looked excellent
and recall quietly collapsed. Those rows are still recorded, flagged
`weak_negative`, because a cohort that is 90 % unlabeled is a signal to go
*build a Reproducer template*, not to retune confidence.

Rows carry structural features only — class, surface, framework, repo-relative
path, function. No target file content, ever: the ledger is replayed into
prompts, and anything stored here becomes a persistent injection surface.

---

## 3 · Cohorts and calibration

A **cohort** is `(class, evidence-shape)`:

```
sqli|dynamic_reproduction+independent_agent+static_analysis_fact
ssti|independent_agent
missing-authz|independent_agent+static_analysis_fact
```

It answers exactly one question: *when a finding of class C was supported by
evidence shape S, how often was it real?* That is the only thing the ledger can
actually measure, so it is the only thing the Cortex is allowed to learn.

Calibration is arithmetic, not a model — a learned change has to be
reproducible from a ledger head and explainable to an audit committee:

* **`precision_mean`** — Jeffreys posterior mean `(tp + 0.5) / (n + 1)`.
  Beta(0.5, 0.5) neither flatters a small cohort nor silences it.
* **`precision_lower`** — Wilson 95 % lower bound. Every *downward* decision
  reads this one; no decision reads the optimistic end.
* **Support gate** — below `min_support` (default 5) labelled rows a cohort has
  no effect at all. Three false positives on a Friday is an anecdote, and a
  system that retunes on anecdotes oscillates.

---

## 4 · The policy, and the six invariants

A policy is a small immutable table: per-cohort directives, a pinned ledger
head, and a content-addressed `policy_id`. Two verbs exist, and no others:

* **`adjust-confidence`** — move confidence toward the cohort's measured
  precision. Tier untouched.
* **`route-to-review`** — move an already-promoted finding to `needs-review`.

The instinct for a self-tuning scanner is to *suppress* noisy cohorts. This
design refuses that outright. A suppressed finding is invisible and
un-auditable; a routed finding costs an analyst thirty seconds and stays in the
record. Routing is the most aggressive move available.

| # | Invariant | Enforced |
|---|---|---|
| **I1** | **No manufactured proof.** A policy can never raise a tier; the only transition it can cause is *into* `needs-review`. Promotion to `verified` stays welded to reproduction + independent corroboration. | `validate()` + `apply()` |
| **I2** | **Bounded movement.** Confidence moves ≤ 0.15 per decision, clamped to `[0.05, 0.95]`. | `validate()` + `apply()` |
| **I3** | **Nothing disappears.** No directive can yield `held`, drop a finding, or suppress a class. | `validate()` + `apply()` |
| **I4** | **Out of scope by construction.** The schema has nowhere to express a change to Warden, the injection detector, the backdoor scan, redaction, sandbox egress or capability tokens. Unknown action verbs are a no-op, never a fall-through. | schema + `apply()` |
| **I5** | **Agents may not certify themselves.** Any directive that raises confidence requires ≥ 1 analyst-confirmed true positive in its cohort. | `validate()` + derivation |
| **I6** | **Immutable and pinned.** `policy_id` hashes the body; policies are never edited. A change is a new version; rollback is activating an earlier id. Every sweep stamps the id it ran under. | `PolicyStore` |

I1–I4 are enforced **twice** — once at activation and again at runtime — so a
policy file an attacker manages to write still cannot promote a finding or hide
one.

---

## 5 · Governance — and what "evolves independently" actually means

A candidate policy is never activated because it looks reasonable. It is
replayed against the labelled history it came from: *had this policy been
active, what would have happened to the findings whose truth we already know?*

| Shadow outcome | Gate |
|---|---|
| `tp_demoted` — a confirmed-real finding routed to review | **hard zero** |
| `fp_boosted` — confidence raised on a known false positive | **hard zero** |
| `tp_confidence_loss` — cumulative shaving off confirmed findings | ≤ 0.10 (so "no demotions" can't be met by a thousand cuts) |
| `fp_demoted` / `fp_confidence_loss` | ≥ 1 required — a policy that benefits nothing is refused |

The same replay runs against the *active* policy on every cycle, not just
against candidates — see **Retraction** below.

Then the asymmetry that defines the autonomy:

* **Strictly conservative** proposal — lowers confidence or routes to review,
  raises nothing, every gate green, no invariant violated → **the Cortex
  activates it itself**, under its own actor id `cortex-autonomous`, signed.
* **Anything that makes Spotlight more assertive** → withheld, with the reason,
  until a **named human** approves it. The Cortex cannot pose as that human;
  its own actor id is rejected as an approver.
* **Rollback is ungated** (a named approver, no gates). The ability to undo has
  to be strictly easier than the ability to change, or nobody will allow the
  thing to evolve at all.

### Retraction — the gate that keeps working after activation

The activation gate runs once. Evidence does not stop arriving. A cohort that
was six-for-six false positives when a policy shipped can hold a
sandbox-confirmed exploit two months later, and the directive routing that
cohort is now demoting something real — a situation the activation gate has
already had its say about and cannot revisit.

So every evolution cycle **audits the policy already in force** before deriving
a new one. If the active policy would now demote a confirmed true positive, or
boost a known false positive, it is **retracted immediately** — back to the
identity policy, i.e. evidence-only tiering — with no gate and no human.

That asymmetry is deliberate and runs the opposite way from activation:
activating a policy can hide something, so it is gated; retracting one can only
restore what the evidence alone decided, so waiting for approval would be the
risky choice. The retraction is signed, recorded as `policy.retracted` with the
finding keys that triggered it, and surfaced by `spotlight cortex status` (which
warns as soon as the standing audit goes non-zero, without waiting for the next
cycle) and in `GET /cortex/status` as `active_policy_audit`.

Proposals, refusals-with-reason, activations and rollbacks all land in a signed,
append-only governance log beside the ledger, so *"why did the tier change
between these two attestations?"* has an answer that does not rely on anyone's
memory.

---

## 6 · Lessons — and the attack they invite

A policy changes arithmetic. A **lesson** changes what the Investigator thinks
about, which is more useful and far more dangerous, because the path

```
target repository → experience → lesson → every future sweep's prompt
```

is a persistent prompt-injection channel. Spotlight's own taxonomy names the
attack: `agent-memory-tampering`. Poison a lesson once and the payload rides
along in every sweep of every repository — past the per-sweep injection scanning
Warden does on target content, because by then the text looks like Spotlight's
own memory.

Three structural defenses:

1. **Templated, never generated.** Lesson text is assembled from structured
   fields — class, repo-relative path, counts, and the analyst's own review
   reason. No model writes a lesson. No bytes of target source enter one.
2. **Scanned and redacted at write time.** Warden's injection detector runs on
   the assembled string and the analyst's reason; a hit **quarantines** the
   lesson (recorded and surfaced to a human, never served) rather than dropping
   it silently. Redaction runs first, so a key pasted into a review comment
   cannot persist into a prompt.
3. **Advisory at read time.** Lessons are injected under a header that states
   they are observations about Spotlight's past mistakes, not instructions and
   not a verdict, and that they may not by themselves reject a finding. Tier
   authority stays with the Consensus Kernel and the policy.

Only analyst false-positive history earns a lesson (≥ 2 verdicts), and a finding
later confirmed real never carries one — that is how a fixed-then-regressed
vulnerability would otherwise get talked out of being reported. Reproduction
outcomes are deliberately never written into a prompt: *"we could not reproduce
this"* is the fastest way to teach a swarm to stop trying.

---

## 7 · Where it plugs in

| Seam | Change |
|---|---|
| `ConsensusKernel.promote(..., policy=…)` | Evidence logic (`_decide`) runs first and unchanged; the policy only sees the finished decision. `policy=None` is byte-identical to the pre-Cortex kernel. |
| `Orchestrator(cortex=…)` | Pins one policy + lesson set per sweep (a policy activated mid-sweep must not tier the tail differently from the head), emits `cortex.*` events, harvests at finalize, then evolves — so anything activated applies to the **next** sweep, never retroactively. |
| `Investigator.run(slice_, lessons=…)` | Advisory context only. |
| Attestation | `cortex` block: policy id, version, ledger head, who activated it, per-finding adjustments, and what the post-sweep harvest recorded. Rendered in the Markdown report too. |
| Chain of custody | The signed `tier-decided` entry carries `cortex_policy_id` and `cortex_applied`. |
| `POST /findings/{id}/review` | Files the human verdict into the ledger — the highest-authority row it will ever hold. |
| `spotlight/eval/paired_cve.py` | Runs `Orchestrator(use_cortex=False)`. A benchmark that both trains the ledger and is judged under a policy derived from it is grading its own homework, and that harness gates CI. |

`use_cortex=False` is the general opt-out: it beats the environment variable, for
any run that must be judged by the evidence pipeline alone.

### Events

`cortex.policy.pinned` · `cortex.adjustment.applied` ·
`cortex.experience.recorded` · `cortex.policy.activated` ·
`cortex.lesson.quarantined`

Governance-log actions: `policy.proposed` · `policy.activated` ·
`policy.rejected` · `policy.withheld` · `policy.retracted` · `policy.rolled-back`

The last one is a self-defense event in the Warden sense: something tried to
write an instruction into Spotlight's own memory.

---

## 8 · Operating it

```bash
export SPOTLIGHT_CORTEX_DIR=/var/lib/spotlight/cortex   # turns memory on
export SPOTLIGHT_SIGNING_KEY=...                        # so rows verify across restarts
export SPOTLIGHT_CORTEX_AUTONOMY=off                    # optional: propose only, never self-activate
                                                        # (retraction still runs — it is safety, not evolution)

spotlight cortex status                 # active policy, directives, label coverage — and a loud
                                        # warning if the policy in force has gone stale
spotlight cortex evolve --dry-run       # propose + gate, activate nothing
spotlight cortex evolve                 # activate if strictly conservative
spotlight cortex evolve --approver you@bank.example
spotlight cortex verify                 # recompute the hash chain and every signature
spotlight cortex rollback <policy_id> --approver you@bank.example
```

HTTP: `GET /cortex/status` · `/cortex/policy` · `/cortex/policy/history` ·
`/cortex/calibration` · `/cortex/lessons` · `/cortex/ledger/verify` ·
`/cortex/governance` — and exactly three writes: `POST /cortex/evolve`,
`/cortex/policy/activate`, `/cortex/policy/rollback`. There is no route that
edits a policy, adds a directive, or relaxes a gate; a learned change can only
come from the ledger, through the governor.

**Without a persistent `SPOTLIGHT_SIGNING_KEY` the ledger's hash chain still
verifies, but its signatures do not survive a restart.** Run production with the
key set.

### On-disk layout

```
$SPOTLIGHT_CORTEX_DIR/
  experiences.jsonl          append-only, hash-chained, signed
  governance.jsonl           proposals · refusals · activations · rollbacks
  lessons.json               served + quarantined
  policies/
    v0000-<id>.json          immutable, never rewritten
    v0001-<id>.json
    active.json              pointer: {policy_id, version, approver, activated_at}
```

---

## 9 · What this is not

* **Not fine-tuning.** No weights move. The learned artifact is a readable
  table, which is what makes it auditable and instantly reversible. (Adapter
  fine-tuning is Phase 4 D4; the ledger is the substrate it would train on.)
* **Not a recall mechanism.** The Cortex cannot find a vulnerability that the
  detectors missed. It makes Spotlight *better calibrated* about what it does
  find, and better informed about where it has been wrong. New recall comes
  from the five coverage layers in `SPOTLIGHT_ARCHITECTURE.md` §12.5.
* **Not a suppression engine.** By construction, the worst thing it can do to a
  real vulnerability is put it in front of a human.
