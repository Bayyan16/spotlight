import type { Finding } from "../lib/api";

export function FindingDetail({ finding }: { finding: Finding }) {
  return (
    <div className="border border-ink-800 rounded-md bg-ink-900 divide-y divide-ink-800">
      <header className="p-4 flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <SeverityChip s={finding.severity} />
            <span className="mono text-xs text-ink-400">{finding.id}</span>
            <span className="mono text-xs text-ink-500">{finding.cwe}</span>
            <TierBadge tier={finding.tier} />
          </div>
          <h2 className="text-lg text-ink-100">{finding.title}</h2>
          <div className="mono text-xs text-ink-500 mt-1">
            {finding.location.file}:{finding.location.line} · {finding.location.function}
          </div>
        </div>
        <div className="text-right">
          <div className="text-xs uppercase text-ink-500 mono">Confidence</div>
          <div className="mono text-2xl text-spot-green">{(finding.confidence * 100).toFixed(0)}%</div>
          <div className="mono text-xs text-ink-400 mt-1">{finding.state}</div>
        </div>
      </header>

      <section className="p-4">
        <div className="text-xs uppercase tracking-wider text-ink-400 mono mb-2">
          Why you can trust this
        </div>
        <div className="text-sm text-ink-200 mb-3">{finding.evidence.root_cause}</div>
        <ul className="space-y-1 text-sm">
          {finding.evidence.corroboration.map((c, i) => (
            <li key={i} className="flex items-start gap-2">
              <span className="text-spot-green mono">✓</span>
              <span className="mono text-xs text-ink-400 uppercase">{c.type}</span>
              <span className="text-ink-300 text-xs">
                {c.result ?? (Array.isArray(c.detail) ? c.detail.join(" · ") : String(c.detail ?? ""))}
              </span>
            </li>
          ))}
          <li className="flex items-start gap-2">
            <span className="text-spot-green mono">✓</span>
            <span className="mono text-xs text-ink-400 uppercase">consensus</span>
            <span className="text-ink-300 text-xs">
              {finding.consensus.rationale} ({finding.consensus.independent_corroborators} independent corroborators)
            </span>
          </li>
        </ul>
      </section>

      <section className="p-4">
        <div className="text-xs uppercase tracking-wider text-ink-400 mono mb-2">Fix</div>
        <div className="text-sm text-ink-300">{finding.evidence.fix.approach}</div>
        <div className="mt-2 flex gap-3 text-xs mono">
          <StatChip
            label="Verifier"
            value={finding.evidence.verification.result as string}
            good={finding.evidence.verification.result === "repro-now-blocked"}
          />
          <StatChip
            label="Backdoor check"
            value={finding.evidence.verification.backdoor_check as string}
            good={finding.evidence.verification.backdoor_check === "pass"}
          />
          <StatChip
            label="Independent"
            value={String(finding.evidence.verification.independent_verifier)}
            good={!!finding.evidence.verification.independent_verifier}
          />
        </div>
      </section>
    </div>
  );
}

function SeverityChip({ s }: { s: string }) {
  const color =
    s === "critical" || s === "high"
      ? "bg-spot-red/20 text-spot-red border-spot-red/40"
      : s === "medium"
      ? "bg-spot-amber/20 text-spot-amber border-spot-amber/40"
      : "bg-ink-700 text-ink-300 border-ink-600";
  return <span className={`mono text-[10px] uppercase px-1.5 py-0.5 rounded border ${color}`}>{s}</span>;
}

function TierBadge({ tier }: { tier: string }) {
  const map: Record<string, string> = {
    verified: "border-spot-green/50 text-spot-green bg-spot-green/10",
    "high-confidence": "border-spot-amber/50 text-spot-amber bg-spot-amber/10",
    "needs-review": "border-ink-600 text-ink-300 bg-ink-800",
    held: "border-ink-700 text-ink-500 bg-ink-900",
  };
  return (
    <span className={`mono text-[10px] uppercase px-1.5 py-0.5 rounded border ${map[tier] ?? ""}`}>
      {tier}
    </span>
  );
}

function StatChip({ label, value, good }: { label: string; value: string; good: boolean }) {
  return (
    <div
      className={`px-2 py-1 rounded border ${
        good ? "border-spot-green/40 text-spot-green" : "border-ink-600 text-ink-400"
      }`}
    >
      <span className="text-ink-500 uppercase text-[10px] mr-1">{label}</span>
      {good ? "✓ " : ""}
      {value}
    </div>
  );
}
