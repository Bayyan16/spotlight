import { useEffect, useState } from "react";
import { getSweepEvents, listSweeps, type SweepEvent, type SweepSummary } from "../lib/api";
import { Cmul8Mark } from "./Cmul8Mark";
import { IconAlert, IconCheck, IconWarden } from "./Icons";

/**
 * WardenView — the "swarm defends itself" self-defense record.
 *
 * Shows every Warden event across the workspace: injection attempts
 * detected in target content, sandbox egress denials, capability-denied
 * events, and budget trips. This is the audit surface a bank's security
 * reviewer will love.
 */
export function WardenView({ onOpenSweep }: { onOpenSweep: (id: string) => void }) {
  const [events, setEvents] = useState<Array<SweepEvent & { sweep: SweepSummary }>>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    listSweeps()
      .then(async (sweeps) => {
        const list = Array.isArray(sweeps) ? sweeps : [];
        const all: Array<SweepEvent & { sweep: SweepSummary }> = [];
        for (const s of list.slice(0, 10)) {
          const evts = await getSweepEvents(s.sweep_id);
          for (const e of evts) {
            if (e.type.startsWith("warden.") || e.type.startsWith("sandbox.egress")) {
              all.push({ ...e, sweep: s });
            }
          }
        }
        all.sort((a, b) => b.ts - a.ts);
        setEvents(all);
      })
      .catch(() => setEvents([]))
      .finally(() => setLoading(false));
  }, []);

  const grouped = groupByKind(events);
  const totalInjections = grouped.injection.length;
  const totalEgress = grouped.egress.length;
  const totalDenied = grouped.denied.length;

  return (
    <section className="flex-1 min-w-0 overflow-y-auto bg-paper-50">
      <header className="border-b border-paper-300 px-8 py-5 sticky top-0 bg-paper-50/95 backdrop-blur z-10">
        <div className="flex items-baseline gap-3">
          <h1 className="text-xl text-paper-900 font-semibold tracking-tight">Warden</h1>
          <span className="text-xs text-paper-500">
            Self-defense record — the swarm treating your code as hostile input, provably.
          </span>
        </div>
      </header>

      {/* Summary tiles */}
      <div className="px-8 py-5 grid grid-cols-4 gap-3">
        <SummaryTile
          label="Injection attempts flagged"
          value={totalInjections}
          icon={<IconAlert size={14} />}
          color={totalInjections > 0 ? "amber" : "neutral"}
        />
        <SummaryTile
          label="Egress denials"
          value={totalEgress}
          icon={<IconWarden size={14} />}
          color={totalEgress > 0 ? "accent" : "neutral"}
        />
        <SummaryTile
          label="Capability denials"
          value={totalDenied}
          icon={<IconWarden size={14} />}
          color={totalDenied > 0 ? "accent" : "neutral"}
        />
        <SummaryTile
          label="Sweeps monitored"
          value={new Set(events.map((e) => e.sweep_id)).size}
          icon={<IconCheck size={14} />}
          color="neutral"
        />
      </div>

      <div className="px-8 pb-8">
        {loading && <div className="text-paper-500 text-sm italic">Loading…</div>}
        {!loading && events.length === 0 && <EmptyState />}
        {!loading && events.length > 0 && (
          <div className="border border-paper-300 rounded-xl bg-white shadow-card overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-paper-100 border-b border-paper-300 text-2xs uppercase tracking-wider text-paper-500 mono">
                <tr>
                  <th className="text-left px-4 py-2.5 font-medium">Kind</th>
                  <th className="text-left px-4 py-2.5 font-medium">Detail</th>
                  <th className="text-left px-4 py-2.5 font-medium">Origin</th>
                  <th className="text-left px-4 py-2.5 font-medium">Sweep</th>
                  <th className="text-right px-4 py-2.5 font-medium">When</th>
                </tr>
              </thead>
              <tbody>
                {events.map((e) => {
                  const payload = e.payload as {
                    origin?: string;
                    kind?: string;
                    snippet?: string;
                    hosts?: string[];
                  };
                  return (
                    <tr
                      key={`${e.sweep_id}-${e.seq}`}
                      className="border-b border-paper-200 last:border-none hover:bg-paper-100/50 cursor-pointer"
                      onClick={() => onOpenSweep(e.sweep_id)}
                    >
                      <td className="px-4 py-2.5">
                        <KindPill type={e.type} />
                      </td>
                      <td className="px-4 py-2.5 text-paper-800 truncate max-w-[240px]">
                        {payload.kind || (payload.hosts ? payload.hosts.join(", ") : "—")}
                      </td>
                      <td className="px-4 py-2.5 mono text-2xs text-paper-500">
                        {payload.origin || "—"}
                      </td>
                      <td className="px-4 py-2.5">
                        <span className="text-paper-900">{e.sweep.repo_name}</span>{" "}
                        <span className="mono text-2xs text-paper-500">{e.sweep_id.slice(0, 10)}</span>
                      </td>
                      <td className="px-4 py-2.5 text-right mono text-2xs text-paper-500 tabular-nums">
                        {relativeTime(e.ts * 1000)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  );
}

function SummaryTile({
  label,
  value,
  icon,
  color,
}: {
  label: string;
  value: number;
  icon: React.ReactNode;
  color: "accent" | "amber" | "neutral";
}) {
  const accentBg =
    color === "accent"
      ? "bg-accent-soft text-accent"
      : color === "amber"
      ? "bg-amber-50 text-sev-medium"
      : "bg-paper-200 text-paper-600";
  const numColor =
    color === "accent" ? "text-accent" : color === "amber" ? "text-sev-medium" : "text-paper-900";
  return (
    <div className="rounded-xl border border-paper-300 bg-white p-4 shadow-card">
      <div className="flex items-start justify-between mb-2">
        <span className="text-2xs mono uppercase tracking-wider text-paper-500">{label}</span>
        <span className={`h-7 w-7 rounded-md grid place-items-center ${accentBg}`}>{icon}</span>
      </div>
      <div className={`text-3xl font-semibold tabular-nums tracking-tight ${numColor}`}>{value}</div>
    </div>
  );
}

function KindPill({ type }: { type: string }) {
  const map: Record<string, { text: string; bg: string; label: string }> = {
    "warden.injection.flagged": {
      text: "text-sev-medium",
      bg: "bg-amber-50 border-sev-medium/30",
      label: "injection flagged",
    },
    "warden.capability.denied": {
      text: "text-accent",
      bg: "bg-accent-soft border-accent/30",
      label: "capability denied",
    },
    "warden.budget.tripped": {
      text: "text-sev-critical",
      bg: "bg-sev-critical/10 border-sev-critical/30",
      label: "budget tripped",
    },
    "sandbox.egress.denied": {
      text: "text-accent",
      bg: "bg-accent-soft border-accent/30",
      label: "egress denied",
    },
  };
  const c = map[type] ?? { text: "text-paper-700", bg: "bg-paper-200 border-paper-300", label: type };
  return (
    <span
      className={`text-2xs mono uppercase tracking-wider px-2 py-0.5 rounded-full border ${c.bg} ${c.text}`}
    >
      {c.label}
    </span>
  );
}

function groupByKind(events: SweepEvent[]) {
  return {
    injection: events.filter((e) => e.type === "warden.injection.flagged"),
    egress: events.filter((e) => e.type === "sandbox.egress.denied"),
    denied: events.filter((e) => e.type === "warden.capability.denied"),
  };
}

function EmptyState() {
  return (
    <div className="py-16 text-center">
      <div className="mx-auto mb-4 opacity-40 grid place-items-center">
        <Cmul8Mark size={48} />
      </div>
      <div className="text-paper-800 text-base font-medium">No Warden events yet.</div>
      <div className="text-paper-500 text-sm mt-1 max-w-md mx-auto">
        Warden runs during Recon on every target's README + docstrings.
        When a prompt-injection payload lands in target-derived text, the
        detector flags it here — treating your codebase as hostile input,
        provably.
      </div>
    </div>
  );
}

function relativeTime(ms: number): string {
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}
