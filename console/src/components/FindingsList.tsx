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
  const map: Record<string, { text: string; bg: string; ring: string }> = {
    critical: { text: "text-sev-critical", bg: "bg-sev-critical/8", ring: "ring-sev-critical/30" },
    high: { text: "text-sev-high", bg: "bg-sev-high/8", ring: "ring-sev-high/30" },
    medium: { text: "text-sev-medium", bg: "bg-sev-medium/8", ring: "ring-sev-medium/30" },
    low: { text: "text-sev-low", bg: "bg-sev-low/8", ring: "ring-sev-low/30" },
  };
  const c = map[sev] ?? map.low;
  return (
    <div className={`sticky top-0 z-10 flex items-center gap-2 px-3 py-2 ${c.bg} border-b border-paper-300`}>
      <span className={`h-1.5 w-1.5 rounded-full ${sev === "critical" ? "bg-sev-critical" : sev === "high" ? "bg-sev-high" : sev === "medium" ? "bg-sev-medium" : "bg-sev-low"}`} />
      <span className={`text-2xs uppercase tracking-wider font-semibold ${c.text} mono`}>{label}</span>
      <span className={`ml-auto text-2xs mono tabular-nums px-1.5 py-0.5 rounded-full bg-white ring-1 ${c.ring} ${c.text}`}>
        {count}
      </span>
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
  const sevBar =
    f.severity === "critical"
      ? "bg-sev-critical"
      : f.severity === "high"
      ? "bg-sev-high"
      : f.severity === "medium"
      ? "bg-sev-medium"
      : "bg-sev-low";
  return (
    <li className="relative">
      {/* Colored left rail = severity, thicker when active */}
      <span
        className={`absolute left-0 top-0 bottom-0 w-1 ${sevBar} ${
          active ? "opacity-100" : "opacity-60"
        }`}
        aria-hidden
      />
      <button
        onClick={() => onSelect(f.id)}
        className={`w-full text-left pl-4 pr-3 py-3 border-b border-paper-200 transition-colors ${
          active ? "bg-white shadow-card" : "hover:bg-paper-100"
        }`}
      >
        <div className="text-sm text-paper-900 leading-snug mb-1.5 line-clamp-2">
          {f.title}
        </div>
        <div className="flex items-center gap-1.5 mb-1.5">
          <TierBadge tier={f.tier} />
          <StateBadge state={f.state} />
          <span className="ml-auto text-2xs mono tabular-nums text-accent font-semibold">
            {(f.confidence * 100).toFixed(0)}%
          </span>
        </div>
        <div className="flex items-center gap-1.5 text-2xs mono text-paper-500">
          <span className="text-paper-700">{f.id}</span>
          <span className="text-paper-400">·</span>
          <span>{f.cwe}</span>
          <span className="text-paper-400">·</span>
          <span className="truncate">
            {short(f.location.file)}:{f.location.line}
          </span>
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
