import { useCallback, useEffect, useState } from "react";
import {
  activateCortexPolicy,
  evolveCortex,
  getCortexGovernance,
  getCortexLessons,
  getCortexPolicyHistory,
  getCortexStatus,
  rollbackCortexPolicy,
  verifyCortexLedger,
  type CortexEvolution,
  type CortexGovernanceEntry,
  type CortexLesson,
  type CortexPolicy,
  type CortexStatus,
} from "../lib/api";
import { Cmul8Mark } from "./Cmul8Mark";
import { IconAlert, IconCheck, IconWarden } from "./Icons";

/**
 * CortexView — what Spotlight has learned, and who allowed it to.
 *
 * The Cortex can activate a strictly conservative policy on its own, so this
 * is the surface that keeps that accountable: the active policy and the counts
 * behind every directive, the shadow replay for the pending proposal, the
 * signed governance log, and a one-click rollback. Anything that would make
 * Spotlight *more* assertive is withheld until someone here types their name.
 */
export function CortexView() {
  const [status, setStatus] = useState<CortexStatus | null>(null);
  const [configured, setConfigured] = useState<boolean>(true);
  const [history, setHistory] = useState<CortexPolicy[]>([]);
  const [lessons, setLessons] = useState<{ served: CortexLesson[]; quarantined: CortexLesson[] }>({
    served: [],
    quarantined: [],
  });
  const [log, setLog] = useState<CortexGovernanceEntry[]>([]);
  const [proposal, setProposal] = useState<CortexEvolution | null>(null);
  const [ledger, setLedger] = useState<{ ok: boolean; reason: string } | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [approver, setApprover] = useState("");

  const load = useCallback(async () => {
    setError(null);
    try {
      const s = await getCortexStatus();
      if (s === null) {
        setConfigured(false);
        return;
      }
      setConfigured(true);
      setStatus(s);
      const [h, l, g, v] = await Promise.all([
        getCortexPolicyHistory(),
        getCortexLessons(),
        getCortexGovernance(40),
        verifyCortexLedger(),
      ]);
      setHistory(h.policies);
      setLessons(l);
      setLog([...g.entries].reverse());
      setLedger(v);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function onEvolve() {
    setBusy(true);
    setError(null);
    try {
      setProposal(await evolveCortex());
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function onApprove() {
    if (!approver.trim()) {
      setError("Type your name — an activation with nobody attached to it is the audit gap.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      setProposal(await activateCortexPolicy(approver.trim()));
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function onRollback(policyId: string) {
    if (!approver.trim()) {
      setError("Type your name before rolling back — rollbacks are signed too.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await rollbackCortexPolicy(policyId, approver.trim());
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  if (!configured) return <NotConfigured />;

  const policy = status?.policy;
  const directives = Object.entries(policy?.directives ?? {}).filter(
    ([, d]) => d.action !== "none",
  );

  return (
    <section className="flex-1 min-w-0 overflow-y-auto bg-paper-50">
      <header className="border-b border-paper-300 px-8 py-5 sticky top-0 bg-paper-50/95 backdrop-blur z-10">
        <div className="flex items-baseline gap-3">
          <h1 className="text-xl text-paper-900 font-semibold tracking-tight">Cortex</h1>
          <span className="text-xs text-paper-500">
            What Spotlight learned from its own outcomes — and who allowed it to.
          </span>
          <button
            onClick={onEvolve}
            disabled={busy}
            className="ml-auto text-xs mono uppercase tracking-wider px-3 py-1.5 rounded-md border border-paper-300 bg-white hover:bg-paper-100 disabled:opacity-50"
          >
            {busy ? "working…" : "run evolution cycle"}
          </button>
        </div>
      </header>

      {/* Standing audit of the policy in force. Non-zero means the next cycle
          retracts it — say so now rather than letting an operator find out
          from a tier that moved. */}
      {(status?.active_policy_audit?.tp_demoted ?? 0) > 0 && (
        <div className="mx-8 mt-5 rounded-lg border border-sev-critical/30 bg-sev-critical/5 px-4 py-2.5 text-sm text-sev-critical">
          The active policy now demotes {status?.active_policy_audit.tp_demoted} confirmed true
          positive(s) against the current ledger. The next evolution cycle will retract it
          automatically — run one now to return to evidence-only tiering.
        </div>
      )}

      {error && (
        <div className="mx-8 mt-5 rounded-lg border border-sev-critical/30 bg-sev-critical/5 px-4 py-2.5 text-sm text-sev-critical">
          {error}
        </div>
      )}

      <div className="px-8 py-5 grid grid-cols-4 gap-3">
        <Tile
          label="Active policy"
          value={policy?.is_identity ? "identity" : `v${policy?.version ?? 0}`}
          hint={policy?.is_identity ? "nothing learned yet" : `${directives.length} directive(s)`}
          icon={<IconWarden size={14} />}
          tone={policy?.is_identity ? "neutral" : "accent"}
        />
        <Tile
          label="Experience ledger"
          value={String(status?.ledger.records ?? 0)}
          hint={`${status?.ledger.labeled ?? 0} labelled · ${status?.ledger.unlabeled ?? 0} unlabelled`}
          icon={<IconCheck size={14} />}
          tone="neutral"
        />
        <Tile
          label="Chain integrity"
          value={ledger?.ok ? "verified" : "FAILED"}
          hint={ledger?.reason ?? "—"}
          icon={ledger?.ok ? <IconCheck size={14} /> : <IconAlert size={14} />}
          tone={ledger?.ok ? "neutral" : "critical"}
        />
        <Tile
          label="Lessons"
          value={String(status?.lessons.served ?? 0)}
          hint={
            (status?.lessons.quarantined ?? 0) > 0
              ? `${status?.lessons.quarantined} quarantined — memory poisoning attempt`
              : "none quarantined"
          }
          icon={(status?.lessons.quarantined ?? 0) > 0 ? <IconAlert size={14} /> : <IconCheck size={14} />}
          tone={(status?.lessons.quarantined ?? 0) > 0 ? "amber" : "neutral"}
        />
      </div>

      {loading && <div className="px-8 text-paper-500 text-sm italic">Loading…</div>}

      {/* Approver identity — used for activation and rollback alike. */}
      <div className="px-8 pb-2">
        <label className="block text-2xs mono uppercase tracking-wider text-paper-500 mb-1">
          Approver (signed into the governance log)
        </label>
        <input
          value={approver}
          onChange={(e) => setApprover(e.target.value)}
          placeholder="you@example.com"
          className="w-[320px] text-sm px-3 py-1.5 rounded-md border border-paper-300 bg-white outline-none focus-visible:ring-2 focus-visible:ring-accent/60"
        />
      </div>

      {/* Pending proposal + its shadow replay. */}
      {proposal && (
        <div className="px-8 py-4">
          <SectionTitle>Pending proposal</SectionTitle>
          <div className="rounded-xl border border-paper-300 bg-white shadow-card p-4 text-sm">
            <div className="flex items-baseline gap-3 mb-3">
              <span className="mono text-2xs text-paper-500">
                v{proposal.proposal.policy.version} · {proposal.proposal.policy.policy_id.slice(0, 16)}
              </span>
              <StatusPill
                ok={proposal.activation.activated}
                label={proposal.activation.activated ? "activated" : "withheld"}
              />
              <span className="text-paper-600 text-xs">{proposal.activation.reason}</span>
              {!proposal.activation.activated && proposal.proposal.admissible && (
                <button
                  onClick={onApprove}
                  disabled={busy}
                  className="ml-auto text-xs mono uppercase tracking-wider px-3 py-1.5 rounded-md border border-accent/40 bg-accent-soft text-accent hover:bg-accent/10 disabled:opacity-50"
                >
                  approve as human
                </button>
              )}
            </div>
            <div className="grid grid-cols-5 gap-3 text-xs">
              <Metric label="Replayed" value={proposal.proposal.shadow.rows_replayed} />
              <Metric label="Labelled" value={proposal.proposal.shadow.labeled_rows} />
              <Metric
                label="True positives demoted"
                value={proposal.proposal.shadow.tp_demoted}
                bad={proposal.proposal.shadow.tp_demoted > 0}
              />
              <Metric label="False positives demoted" value={proposal.proposal.shadow.fp_demoted} good />
              <Metric
                label="False positives boosted"
                value={proposal.proposal.shadow.fp_boosted}
                bad={proposal.proposal.shadow.fp_boosted > 0}
              />
            </div>
            {(proposal.proposal.gate_failures.length > 0 ||
              proposal.proposal.invariant_violations.length > 0) && (
              <ul className="mt-3 space-y-1 text-xs text-sev-critical">
                {[...proposal.proposal.invariant_violations, ...proposal.proposal.gate_failures].map(
                  (v) => (
                    <li key={v}>· {v}</li>
                  ),
                )}
              </ul>
            )}
          </div>
        </div>
      )}

      {/* Learned directives — each one carries the counts that justify it. */}
      <div className="px-8 py-4">
        <SectionTitle>Learned directives</SectionTitle>
        {directives.length === 0 ? (
          <EmptyHint>
            No directive is changing any tier. A cohort needs {policy?.min_support ?? 5} labelled
            findings before it may influence anything — accept or reject findings in the inbox and the
            Cortex starts calibrating.
          </EmptyHint>
        ) : (
          <div className="border border-paper-300 rounded-xl bg-white shadow-card overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-paper-100 border-b border-paper-300 text-2xs uppercase tracking-wider text-paper-500 mono">
                <tr>
                  <th className="text-left px-4 py-2.5 font-medium">Cohort</th>
                  <th className="text-left px-4 py-2.5 font-medium">Action</th>
                  <th className="text-right px-4 py-2.5 font-medium">Labelled</th>
                  <th className="text-right px-4 py-2.5 font-medium">TP / FP</th>
                  <th className="text-right px-4 py-2.5 font-medium">Precision</th>
                  <th className="text-left px-4 py-2.5 font-medium">Why</th>
                </tr>
              </thead>
              <tbody>
                {directives.map(([cohort, d]) => (
                  <tr key={cohort} className="border-b border-paper-200 last:border-none">
                    <td className="px-4 py-2.5 mono text-2xs text-paper-800">{cohort}</td>
                    <td className="px-4 py-2.5">
                      <ActionPill action={d.action} />
                    </td>
                    <td className="px-4 py-2.5 text-right tabular-nums">{d.n_labeled}</td>
                    <td className="px-4 py-2.5 text-right tabular-nums mono text-2xs">
                      {d.tp} / {d.fp}
                    </td>
                    <td className="px-4 py-2.5 text-right tabular-nums mono text-2xs">
                      {d.precision_mean.toFixed(2)} <span className="text-paper-400">≥{d.precision_lower.toFixed(2)}</span>
                    </td>
                    <td className="px-4 py-2.5 text-paper-600 text-xs">{d.rationale}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Quarantined lessons — a memory-poisoning attempt belongs in front of a human. */}
      {lessons.quarantined.length > 0 && (
        <div className="px-8 py-4">
          <SectionTitle>Quarantined lessons</SectionTitle>
          <div className="rounded-xl border border-sev-medium/30 bg-amber-50 p-4 text-sm space-y-2">
            <div className="text-xs text-paper-700">
              These were never served to a model. A lesson trips this check when the text it would
              have carried matches an injection pattern — something tried to write an instruction
              into Spotlight's own memory.
            </div>
            {lessons.quarantined.map((l) => (
              <div key={l.lesson_id} className="text-xs mono text-paper-700">
                [{l.quarantine_kinds.join(", ")}] {l.key}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Policy history — immutable, rollback is a pointer move. */}
      <div className="px-8 py-4">
        <SectionTitle>Policy history</SectionTitle>
        <div className="border border-paper-300 rounded-xl bg-white shadow-card overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-paper-100 border-b border-paper-300 text-2xs uppercase tracking-wider text-paper-500 mono">
              <tr>
                <th className="text-left px-4 py-2.5 font-medium">Version</th>
                <th className="text-left px-4 py-2.5 font-medium">Policy id</th>
                <th className="text-left px-4 py-2.5 font-medium">Derived from ledger</th>
                <th className="text-right px-4 py-2.5 font-medium">Directives</th>
                <th className="text-right px-4 py-2.5 font-medium" />
              </tr>
            </thead>
            <tbody>
              {history.map((p) => (
                <tr key={p.policy_id} className="border-b border-paper-200 last:border-none">
                  <td className="px-4 py-2.5 tabular-nums">
                    v{p.version}
                    {p.is_active && (
                      <span className="ml-2 text-2xs mono uppercase tracking-wider px-2 py-0.5 rounded-full border border-accent/30 bg-accent-soft text-accent">
                        active
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-2.5 mono text-2xs text-paper-600">
                    {p.policy_id.slice(0, 20)}
                  </td>
                  <td className="px-4 py-2.5 mono text-2xs text-paper-500">
                    {p.ledger_head.slice(0, 16)}
                  </td>
                  <td className="px-4 py-2.5 text-right tabular-nums">
                    {Object.keys(p.directives).length}
                  </td>
                  <td className="px-4 py-2.5 text-right">
                    {!p.is_active && (
                      <button
                        onClick={() => onRollback(p.policy_id)}
                        disabled={busy}
                        className="text-2xs mono uppercase tracking-wider px-2 py-1 rounded border border-paper-300 hover:bg-paper-100 disabled:opacity-50"
                      >
                        roll back
                      </button>
                    )}
                  </td>
                </tr>
              ))}
              {history.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-6 text-center text-paper-500 text-sm italic">
                    No policy has been derived yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Governance log — signed, append-only. */}
      <div className="px-8 pb-8 pt-4">
        <SectionTitle>Governance log</SectionTitle>
        <div className="border border-paper-300 rounded-xl bg-white shadow-card overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-paper-100 border-b border-paper-300 text-2xs uppercase tracking-wider text-paper-500 mono">
              <tr>
                <th className="text-left px-4 py-2.5 font-medium">When</th>
                <th className="text-left px-4 py-2.5 font-medium">Action</th>
                <th className="text-left px-4 py-2.5 font-medium">Actor</th>
                <th className="text-left px-4 py-2.5 font-medium">Detail</th>
              </tr>
            </thead>
            <tbody>
              {log.map((e, i) => (
                <tr key={`${e.ts}-${i}`} className="border-b border-paper-200 last:border-none">
                  <td className="px-4 py-2.5 mono text-2xs text-paper-500">{e.ts.slice(0, 19)}</td>
                  <td className="px-4 py-2.5 mono text-2xs text-paper-800">{e.action}</td>
                  <td className="px-4 py-2.5 text-xs">
                    {e.actor}
                    {e.actor === "cortex-autonomous" && (
                      <span className="ml-2 text-2xs mono uppercase tracking-wider text-paper-500">
                        agent
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-2.5 text-xs text-paper-600 truncate max-w-[420px]">
                    {String(e.payload.reason ?? e.payload.policy_id ?? "")}
                  </td>
                </tr>
              ))}
              {log.length === 0 && (
                <tr>
                  <td colSpan={4} className="px-4 py-6 text-center text-paper-500 text-sm italic">
                    Nothing recorded yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}

function SectionTitle({ children }: { children: React.ReactNode }) {
  return (
    <div className="text-2xs uppercase tracking-wider text-paper-500 mono mb-2">{children}</div>
  );
}

function EmptyHint({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-paper-300 bg-white p-4 text-sm text-paper-600">
      {children}
    </div>
  );
}

function Tile({
  label,
  value,
  hint,
  icon,
  tone,
}: {
  label: string;
  value: string;
  hint: string;
  icon: React.ReactNode;
  tone: "accent" | "amber" | "neutral" | "critical";
}) {
  const badge =
    tone === "accent"
      ? "bg-accent-soft text-accent"
      : tone === "amber"
      ? "bg-amber-50 text-sev-medium"
      : tone === "critical"
      ? "bg-sev-critical/10 text-sev-critical"
      : "bg-paper-200 text-paper-600";
  const num =
    tone === "accent"
      ? "text-accent"
      : tone === "amber"
      ? "text-sev-medium"
      : tone === "critical"
      ? "text-sev-critical"
      : "text-paper-900";
  return (
    <div className="rounded-xl border border-paper-300 bg-white p-4 shadow-card">
      <div className="flex items-start justify-between mb-2">
        <span className="text-2xs mono uppercase tracking-wider text-paper-500">{label}</span>
        <span className={`h-7 w-7 rounded-md grid place-items-center ${badge}`}>{icon}</span>
      </div>
      <div className={`text-2xl font-semibold tabular-nums tracking-tight ${num}`}>{value}</div>
      <div className="text-2xs text-paper-500 mt-1 truncate" title={hint}>
        {hint}
      </div>
    </div>
  );
}

function Metric({
  label,
  value,
  good,
  bad,
}: {
  label: string;
  value: number;
  good?: boolean;
  bad?: boolean;
}) {
  const colour = bad ? "text-sev-critical" : good && value > 0 ? "text-accent" : "text-paper-900";
  return (
    <div>
      <div className="text-2xs mono uppercase tracking-wider text-paper-500">{label}</div>
      <div className={`text-lg font-semibold tabular-nums ${colour}`}>{value}</div>
    </div>
  );
}

function ActionPill({ action }: { action: string }) {
  const map: Record<string, { bg: string; text: string; label: string }> = {
    "route-to-review": {
      bg: "bg-amber-50 border-sev-medium/30",
      text: "text-sev-medium",
      label: "route to review",
    },
    "adjust-confidence": {
      bg: "bg-accent-soft border-accent/30",
      text: "text-accent",
      label: "recalibrate",
    },
  };
  const c = map[action] ?? { bg: "bg-paper-200 border-paper-300", text: "text-paper-700", label: action };
  return (
    <span className={`text-2xs mono uppercase tracking-wider px-2 py-0.5 rounded-full border ${c.bg} ${c.text}`}>
      {c.label}
    </span>
  );
}

function StatusPill({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span
      className={`text-2xs mono uppercase tracking-wider px-2 py-0.5 rounded-full border ${
        ok ? "bg-accent-soft border-accent/30 text-accent" : "bg-paper-200 border-paper-300 text-paper-700"
      }`}
    >
      {label}
    </span>
  );
}

function NotConfigured() {
  return (
    <section className="flex-1 min-w-0 overflow-y-auto bg-paper-50">
      <div className="py-24 text-center">
        <div className="mx-auto mb-4 opacity-40 grid place-items-center">
          <Cmul8Mark size={48} />
        </div>
        <div className="text-paper-800 text-base font-medium">Cortex is off for this workspace.</div>
        <div className="text-paper-500 text-sm mt-2 max-w-lg mx-auto">
          Set <span className="mono text-xs">SPOTLIGHT_CORTEX_DIR</span> on the API and Spotlight
          starts recording what each finding turned out to be — reproduced, verified, or called a
          false positive by an analyst — and calibrates its own confidence from that history. It can
          route a finding to a human; it can never promote one and never suppress one.
        </div>
      </div>
    </section>
  );
}
