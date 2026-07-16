import type { Finding } from "../lib/api";
import { IconCheck } from "./Icons";

export function FindingDetail({ finding }: { finding: Finding }) {
  return (
    <section className="flex-1 min-w-0 overflow-y-auto bg-paper-50">
      <header className="border-b border-paper-300 bg-paper-50/80 backdrop-blur px-6 py-4 sticky top-0">
        <div className="flex items-center gap-2 mb-1 text-2xs mono text-paper-500">
          <span>{finding.id}</span>
          <span>·</span>
          <span>{finding.cwe}</span>
          <span>·</span>
          <span>surface {finding.surface}</span>
        </div>
        <h1 className="text-lg text-paper-900 font-semibold tracking-tight">{finding.title}</h1>
        <div className="mt-1 text-xs mono text-paper-600">
          {finding.location.file}:{finding.location.line} · {finding.location.function}
        </div>
      </header>

      {/* Fields row — inspo-2's key-value pills. */}
      <div className="grid grid-cols-2 gap-x-6 gap-y-3 px-6 py-4 border-b border-paper-300 bg-paper-100/50">
        <Field label="Severity" value={<SeverityPill s={finding.severity} />} />
        <Field label="Status" value={<span className="text-paper-800 text-sm">{finding.state}</span>} />
        <Field
          label="Confidence"
          value={<span className="text-paper-800 text-sm">{(finding.confidence * 100).toFixed(0)}%</span>}
        />
        <Field
          label="Tier"
          value={<span className="text-accent text-sm uppercase mono">{finding.tier}</span>}
        />
        <Field
          label="Class"
          value={<span className="mono text-paper-800 text-sm">{finding.class}</span>}
        />
        <Field
          label="Corroborators"
          value={
            <span className="text-paper-800 text-sm">
              {finding.consensus.independent_corroborators} independent
            </span>
          }
        />
      </div>

      <div className="px-6 py-5 space-y-6">
        <Panel title="Why you can trust this">
          <p className="text-sm text-paper-800 leading-relaxed mb-3">{finding.evidence.root_cause}</p>
          <ul className="space-y-1.5">
            {finding.evidence.corroboration.map((c, i) => (
              <li key={i} className="flex items-start gap-2 text-sm">
                <span className="text-accent mt-0.5">
                  <IconCheck />
                </span>
                <span className="mono text-2xs uppercase tracking-wider text-paper-500 pt-0.5 w-24 shrink-0">
                  {c.type}
                </span>
                <span className="text-paper-800 text-xs">
                  {c.result ??
                    (Array.isArray(c.detail) ? c.detail.join(" · ") : String(c.detail ?? ""))}
                </span>
              </li>
            ))}
            <li className="flex items-start gap-2 text-sm">
              <span className="text-accent mt-0.5">
                <IconCheck />
              </span>
              <span className="mono text-2xs uppercase tracking-wider text-paper-500 pt-0.5 w-24 shrink-0">
                consensus
              </span>
              <span className="text-paper-800 text-xs">{finding.consensus.rationale}</span>
            </li>
          </ul>
        </Panel>

        <Panel title="Fix">
          <p className="text-sm text-paper-800 mb-3">{finding.evidence.fix.approach}</p>
          <div className="flex flex-wrap gap-2 text-xs">
            <StatChip
              label="Verifier"
              value={String(finding.evidence.verification.result ?? "")}
              good={finding.evidence.verification.result === "repro-now-blocked"}
            />
            <StatChip
              label="Backdoor scan"
              value={String(finding.evidence.verification.backdoor_check ?? "")}
              good={finding.evidence.verification.backdoor_check === "pass"}
            />
            <StatChip
              label="Independence"
              value={String(finding.evidence.verification.independent_verifier ?? "")}
              good={!!finding.evidence.verification.independent_verifier}
            />
          </div>
        </Panel>

        {finding.evidence.threat_model && (
          <Panel title="Threat model in effect">
            <div className="mb-3 text-xs text-paper-700">
              This finding was judged under the threat model{" "}
              <span className="mono uppercase tracking-wider text-2xs text-accent bg-accent-soft border border-accent/30 rounded px-1.5 py-0.5 mx-0.5">
                {finding.evidence.threat_model.profile}
              </span>{" "}
              (author:{" "}
              <span className="mono">{finding.evidence.threat_model.author}</span>).
              {finding.evidence.threat_model.stack?.language && (
                <>
                  {" "}Stack detected:{" "}
                  <span className="mono text-paper-800">
                    {finding.evidence.threat_model.stack.language}
                    {finding.evidence.threat_model.stack.framework
                      ? ` · ${finding.evidence.threat_model.stack.framework}`
                      : ""}
                  </span>
                  .
                </>
              )}
            </div>
            <div className="grid grid-cols-2 gap-4 text-xs">
              <div>
                <div className="text-2xs uppercase tracking-wider text-paper-500 mono mb-1.5">
                  Untrusted sources
                </div>
                <ul className="space-y-1">
                  {(finding.evidence.threat_model.untrusted_sources ?? []).map((s) => (
                    <li key={s} className="mono text-paper-800 text-2xs bg-paper-100 border border-paper-200 rounded px-2 py-0.5 inline-block mr-1 mb-1">
                      {s}
                    </li>
                  ))}
                  {(finding.evidence.threat_model.untrusted_sources ?? []).length === 0 && (
                    <li className="text-paper-500 text-2xs italic">none</li>
                  )}
                </ul>
              </div>
              <div>
                <div className="text-2xs uppercase tracking-wider text-paper-500 mono mb-1.5">
                  High-impact sinks
                </div>
                <ul className="space-y-1">
                  {(finding.evidence.threat_model.high_impact_sinks ?? []).map((s) => (
                    <li key={s} className="mono text-paper-800 text-2xs bg-paper-100 border border-paper-200 rounded px-2 py-0.5 inline-block mr-1 mb-1">
                      {s}
                    </li>
                  ))}
                  {(finding.evidence.threat_model.high_impact_sinks ?? []).length === 0 && (
                    <li className="text-paper-500 text-2xs italic">none</li>
                  )}
                </ul>
              </div>
            </div>
          </Panel>
        )}

        <Panel title="Audit">
          <dl className="grid grid-cols-2 gap-x-6 gap-y-1.5 text-xs mono">
            {Object.entries(finding.audit ?? {}).map(([k, v]) => (
              <div key={k} className="contents">
                <dt className="text-paper-500 uppercase text-2xs tracking-wider">{k}</dt>
                <dd className="text-paper-800 truncate">{String(v ?? "—")}</dd>
              </div>
            ))}
          </dl>
        </Panel>
      </div>
    </section>
  );
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center gap-3">
      <span className="text-2xs uppercase tracking-wider text-paper-500 mono w-24 shrink-0">
        {label}
      </span>
      {value}
    </div>
  );
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="border border-paper-300 rounded-md bg-white shadow-card">
      <div className="px-4 py-2.5 border-b border-paper-200 text-2xs uppercase tracking-wider text-paper-500 mono">
        {title}
      </div>
      <div className="px-4 py-3">{children}</div>
    </div>
  );
}

function SeverityPill({ s }: { s: string }) {
  const map: Record<string, string> = {
    critical: "bg-sev-critical/15 text-sev-critical border-sev-critical/30",
    high: "bg-sev-high/15 text-sev-high border-sev-high/30",
    medium: "bg-sev-medium/15 text-sev-medium border-sev-medium/30",
    low: "bg-sev-low/15 text-sev-low border-sev-low/30",
  };
  return (
    <span className={`text-2xs uppercase mono px-1.5 py-0.5 rounded border ${map[s] ?? ""}`}>
      {s}
    </span>
  );
}

function StatChip({ label, value, good }: { label: string; value: string; good: boolean }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-1 rounded border mono ${
        good ? "border-accent/40 bg-accent-soft text-accent" : "border-paper-400 text-paper-600"
      }`}
    >
      <span className="text-2xs uppercase text-paper-500">{label}</span>
      {good && <IconCheck size={10} />}
      <span>{value}</span>
    </span>
  );
}
