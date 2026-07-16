import type { Finding } from "../lib/api";
import { IconAlert } from "./Icons";

const GROUPS = [
  { key: "critical", label: "Critical" },
  { key: "high", label: "High" },
  { key: "medium", label: "Medium" },
  { key: "low", label: "Low" },
] as const;

export function FindingsList({
  findings,
  active,
  onSelect,
  target,
}: {
  findings: Finding[];
  active: string | null;
  onSelect: (id: string) => void;
  target: string;
}) {
  const grouped = groupBySeverity(findings);
  return (
    <section className="w-[380px] shrink-0 bg-paper-100/60 border-r border-paper-300 flex flex-col">
      <div className="h-11 shrink-0 border-b border-paper-300 px-3 flex items-center gap-2">
        <span className="text-2xs uppercase tracking-wider text-paper-500 mono">Findings</span>
        <span className="text-2xs text-paper-500">·</span>
        <span className="text-xs mono text-paper-700">{target}</span>
        <span className="ml-auto text-2xs mono text-paper-500">
          {findings.length} {findings.length === 1 ? "finding" : "findings"}
        </span>
      </div>

      <div className="overflow-y-auto flex-1">
        {findings.length === 0 && (
          <div className="p-6 text-paper-500 text-sm">
            <div className="mb-1">Nothing promoted yet.</div>
            <div className="text-xs">Start a Sweep to populate this pane.</div>
          </div>
        )}
        {GROUPS.map(({ key, label }) => {
          const bucket = grouped[key] ?? [];
          if (bucket.length === 0) return null;
          return (
            <div key={key}>
              <SeverityHeader label={label} sev={key} count={bucket.length} />
              <ul>
                {bucket.map((f) => (
                  <FindingRow key={f.id} f={f} active={active === f.id} onSelect={onSelect} />
                ))}
              </ul>
            </div>
          );
        })}
      </div>
    </section>
  );
}

function SeverityHeader({ label, sev, count }: { label: string; sev: string; count: number }) {
  const color =
    sev === "critical"
      ? "text-sev-critical"
      : sev === "high"
      ? "text-sev-high"
      : sev === "medium"
      ? "text-sev-medium"
      : "text-sev-low";
  return (
    <div className="sticky top-0 z-10 flex items-center gap-2 px-3 py-1.5 bg-paper-100 border-b border-paper-300">
      <IconAlert size={12} />
      <span className={`text-xs uppercase tracking-wider font-semibold ${color}`}>{label}</span>
      <span className="ml-auto mono text-2xs text-paper-500">#{count}</span>
    </div>
  );
}

function FindingRow({
  f,
  active,
  onSelect,
}: {
  f: Finding;
  active: boolean;
  onSelect: (id: string) => void;
}) {
  return (
    <li>
      <button
        onClick={() => onSelect(f.id)}
        className={`w-full text-left px-3 py-2.5 border-b border-paper-200 flex items-start gap-2.5 transition-colors ${
          active ? "bg-white shadow-card" : "hover:bg-paper-100"
        }`}
      >
        <span className={`h-1.5 w-1.5 mt-1.5 rounded-full shrink-0 ${dotColor(f.severity)}`} />
        <div className="min-w-0 flex-1">
          <div className="text-sm text-paper-900 truncate">{f.title}</div>
          <div className="mt-1 flex items-center gap-2 text-2xs mono text-paper-500">
            <span>{f.id}</span>
            <span>·</span>
            <span>{f.cwe}</span>
            <span>·</span>
            <span className="truncate">
              {short(f.location.file)}:{f.location.line}
            </span>
          </div>
          <div className="mt-1 flex items-center gap-1.5">
            <TierBadge tier={f.tier} />
            <StateBadge state={f.state} />
          </div>
        </div>
      </button>
    </li>
  );
}

function TierBadge({ tier }: { tier: string }) {
  const map: Record<string, string> = {
    verified: "bg-accent-soft text-accent border-accent/30",
    "high-confidence": "bg-amber-50 text-sev-medium border-sev-medium/30",
    "needs-review": "bg-paper-200 text-paper-700 border-paper-400",
    held: "bg-paper-200 text-paper-500 border-paper-300",
  };
  return (
    <span className={`text-2xs mono uppercase px-1.5 py-0.5 rounded border ${map[tier] ?? ""}`}>
      {tier}
    </span>
  );
}

function StateBadge({ state }: { state: string }) {
  const good = state === "confirmed-fixed";
  return (
    <span
      className={`text-2xs mono uppercase px-1.5 py-0.5 rounded border ${
        good ? "border-accent/40 text-accent" : "border-paper-400 text-paper-600"
      }`}
    >
      {state}
    </span>
  );
}

function short(path: string) {
  const parts = path.split("/");
  return parts.slice(-2).join("/");
}

function dotColor(sev: string) {
  switch (sev) {
    case "critical":
      return "bg-sev-critical";
    case "high":
      return "bg-sev-high";
    case "medium":
      return "bg-sev-medium";
    default:
      return "bg-sev-low";
  }
}

function groupBySeverity(findings: Finding[]): Record<string, Finding[]> {
  const out: Record<string, Finding[]> = {};
  for (const f of findings) {
    (out[f.severity] ??= []).push(f);
  }
  return out;
}
