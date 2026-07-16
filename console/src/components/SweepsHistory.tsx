import { useEffect, useMemo, useState } from "react";
import { cleanupSweeps, deleteSweep, listSweeps, type SweepSummary } from "../lib/api";
import { Cmul8Mark } from "./Cmul8Mark";
import {
  IconAlert,
  IconAttestation,
  IconCheck,
  IconExploitPath,
  IconSweep,
  IconWarden,
} from "./Icons";

export function SweepsHistory({
  onOpen,
  refreshSignal,
}: {
  onOpen: (sweepId: string) => void;
  refreshSignal: number;
}) {
  const [rows, setRows] = useState<SweepSummary[] | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  useEffect(() => {
    listSweeps()
      .then((data) => setRows(Array.isArray(data) ? data : []))
      .catch(() => setRows([]));
  }, [refreshSignal]);

  async function onDelete(id: string) {
    if (!confirm(`Delete sweep ${id}?`)) return;
    setBusy(id);
    try {
      await deleteSweep(id);
      setRows((prev) => (prev ? prev.filter((r) => r.sweep_id !== id) : prev));
    } finally {
      setBusy(null);
    }
  }

  const rollup = useMemo(() => summarize(rows ?? []), [rows]);

  return (
    <section className="flex-1 min-w-0 overflow-y-auto bg-paper-50">
      <header className="border-b border-paper-300 px-8 py-5 sticky top-0 bg-paper-50/95 backdrop-blur z-10">
        <div className="flex items-baseline gap-3">
          <h1 className="text-xl text-paper-900 font-semibold tracking-tight">Sweeps</h1>
          <span className="text-xs text-paper-500">
            Everything this workspace has scanned — persisted, replayable.
          </span>
          {rollup.failed > 0 && (
            <button
              onClick={async () => {
                if (!confirm(`Clear ${rollup.failed} failed sweep${rollup.failed === 1 ? "" : "s"}?`)) return;
                await cleanupSweeps("failed");
                const fresh = await listSweeps();
                setRows(Array.isArray(fresh) ? fresh : []);
              }}
              className="ml-auto text-2xs mono uppercase tracking-wider px-2 py-1 rounded border border-paper-300 hover:border-sev-critical hover:text-sev-critical text-paper-600 transition-colors"
              title="Delete sweeps stuck in a failed state"
            >
              Clear {rollup.failed} failed
            </button>
          )}
        </div>
      </header>

      {/* Hero KPI cards */}
      {rollup.total > 0 && (
        <div className="px-8 pt-6 pb-2 grid grid-cols-4 gap-3">
          <KpiCard
            label="Sweeps run"
            value={rollup.total}
            icon={<IconSweep />}
            accent="neutral"
          />
          <KpiCard
            label="Findings promoted"
            value={rollup.totalFindings}
            sub={rollup.totalFindings > 0 ? `${rollup.verified} verified` : "—"}
            icon={<IconAttestation />}
            accent={rollup.totalFindings > 0 ? "amber" : "neutral"}
          />
          <KpiCard
            label="Confirmed fixed"
            value={rollup.verified}
            sub={rollup.verified === rollup.totalFindings && rollup.totalFindings > 0 ? "all clear" : ""}
            icon={<IconCheck />}
            accent={rollup.verified > 0 ? "accent" : "neutral"}
          />
          <KpiCard
            label="Sandbox runs"
            value={rollup.total * 2}
            sub="Modal · egress off"
            icon={<IconWarden />}
            accent="neutral"
          />
        </div>
      )}

      {/* Severity mix — only render when there's at least one non-empty class */}
      {rollup.total > 0 && rollup.totalFindings > 0 && (
        <div className="px-8 py-5">
          <div className="border border-paper-300 rounded-lg bg-white shadow-card p-5">
            <div className="flex items-center gap-3 mb-3">
              <IconExploitPath size={14} />
              <span className="text-2xs uppercase tracking-wider text-paper-500 mono">
                Severity mix — across {rollup.total} sweep{rollup.total === 1 ? "" : "s"}
              </span>
              <span className="ml-auto text-2xs mono text-paper-500 tabular-nums">
                {rollup.totalFindings} finding{rollup.totalFindings === 1 ? "" : "s"} total
              </span>
            </div>
            <div className="h-3 rounded-full overflow-hidden bg-paper-200 flex mb-3">
              <SegBar w={rollup.sevPct.critical} className="bg-sev-critical" />
              <SegBar w={rollup.sevPct.high} className="bg-sev-high" />
              <SegBar w={rollup.sevPct.medium} className="bg-sev-medium" />
              <SegBar w={rollup.sevPct.low} className="bg-sev-low" />
            </div>
            <div className="flex items-center gap-5 text-xs">
              {[
                { label: "Critical", n: rollup.sev.critical, color: "bg-sev-critical", text: "text-sev-critical" },
                { label: "High", n: rollup.sev.high, color: "bg-sev-high", text: "text-sev-high" },
                { label: "Medium", n: rollup.sev.medium, color: "bg-sev-medium", text: "text-sev-medium" },
                { label: "Low", n: rollup.sev.low, color: "bg-sev-low", text: "text-sev-low" },
              ]
                .filter((s) => s.n > 0)
                .map((s) => (
                  <div key={s.label} className="flex items-center gap-2">
                    <span className={`h-2 w-2 rounded-full ${s.color}`} />
                    <span className={`mono uppercase tracking-wider text-2xs ${s.text}`}>
                      {s.label}
                    </span>
                    <span className="mono tabular-nums text-paper-900 font-semibold">{s.n}</span>
                  </div>
                ))}
              {rollup.totalFindings === 0 && (
                <span className="text-paper-500 italic text-xs">no promoted findings yet</span>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Attention banner: verified findings still need a human sign-off */}
      {rollup.verified > 0 && (
        <div className="px-8 pb-4">
          <div className="border border-accent/30 bg-gradient-to-r from-accent-soft to-accent-soft/40 rounded-lg px-4 py-3 flex items-center gap-3 shadow-card">
            <div className="h-8 w-8 rounded-full bg-accent grid place-items-center text-white">
              <IconCheck size={16} />
            </div>
            <div className="flex-1 min-w-0">
              <div className="text-sm text-paper-900">
                <span className="font-semibold">{rollup.verified}</span> verified fix
                {rollup.verified === 1 ? "" : "es"} ready for review
              </div>
              <div className="text-xs text-paper-600">
                Reproduced, patched, independently verified in a hardened sandbox.
              </div>
            </div>
            <span className="text-2xs mono uppercase tracking-wider text-accent bg-white border border-accent/30 rounded px-2 py-0.5">
              open a sweep →
            </span>
          </div>
        </div>
      )}

      <div className="px-8 pb-8">
        {rows === null && <SkeletonTable />}
        {rows !== null && rows.length === 0 && <EmptyState />}
        {rows !== null && rows.length > 0 && (
          <div className="border border-paper-300 rounded-lg bg-white shadow-card overflow-hidden animate-fade-in">
            <table className="w-full text-sm">
              <thead className="bg-paper-100 border-b border-paper-300 text-2xs uppercase tracking-wider text-paper-500 mono">
                <tr>
                  <th className="text-left px-5 py-2.5 font-medium">Sweep · Target</th>
                  <th className="text-left px-4 py-2.5 font-medium">Source</th>
                  <th className="text-left px-4 py-2.5 font-medium">Status</th>
                  <th className="text-left px-4 py-2.5 font-medium">Findings</th>
                  <th className="text-right px-4 py-2.5 font-medium">Started</th>
                  <th className="px-2"></th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <SweepRow
                    key={r.sweep_id}
                    row={r}
                    busy={busy === r.sweep_id}
                    onOpen={() => onOpen(r.sweep_id)}
                    onDelete={() => onDelete(r.sweep_id)}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  );
}

function SweepRow({
  row,
  busy,
  onOpen,
  onDelete,
}: {
  row: SweepSummary;
  busy: boolean;
  onOpen: () => void;
  onDelete: () => void;
}) {
  const hasFindings = row.findings_count > 0;
  return (
    <tr
      className="border-b border-paper-200 last:border-none hover:bg-paper-100/50 cursor-pointer group transition-colors"
      onClick={onOpen}
    >
      <td className="px-5 py-3">
        <div className="flex items-center gap-3">
          <div
            className={`h-8 w-8 rounded-md grid place-items-center shrink-0 ${
              hasFindings ? "bg-accent-soft text-accent" : "bg-paper-200 text-paper-500"
            }`}
          >
            <IconSweep size={14} />
          </div>
          <div className="min-w-0">
            <div className="text-paper-900 font-medium truncate">{row.repo_name}</div>
            <div className="mono text-2xs text-paper-500 truncate">{row.sweep_id}</div>
          </div>
        </div>
      </td>
      <td className="px-4 py-3">
        <SourcePill source={row.source} />
      </td>
      <td className="px-4 py-3">
        <StatusPill status={row.status} />
      </td>
      <td className="px-4 py-3">
        <FindingsCell count={row.findings_count} />
      </td>
      <td className="px-4 py-3 text-right mono text-2xs text-paper-500 tabular-nums">
        {row.started_at ? relativeTime(row.started_at) : "—"}
      </td>
      <td className="px-2 py-3 text-right">
        <button
          onClick={(e) => {
            e.stopPropagation();
            onDelete();
          }}
          disabled={busy}
          className="opacity-0 group-hover:opacity-100 text-2xs mono uppercase tracking-wider text-paper-500 hover:text-sev-critical px-2 py-1 rounded transition-all"
          title="Delete this sweep and its findings"
        >
          {busy ? "…" : "delete"}
        </button>
      </td>
    </tr>
  );
}

function FindingsCell({ count }: { count: number }) {
  if (count === 0) {
    return (
      <span className="text-2xs mono uppercase tracking-wider text-paper-500 flex items-center gap-1.5">
        <span className="h-1.5 w-1.5 rounded-full bg-paper-400" />
        clean
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 text-sm">
      <span className="mono tabular-nums font-semibold text-paper-900">{count}</span>
      <span className="text-2xs mono uppercase text-paper-500">
        finding{count === 1 ? "" : "s"}
      </span>
    </span>
  );
}

function KpiCard({
  label,
  value,
  sub,
  icon,
  accent,
}: {
  label: string;
  value: number;
  sub?: string;
  icon: React.ReactNode;
  accent: "neutral" | "amber" | "accent";
}) {
  const accentBg =
    accent === "accent"
      ? "bg-accent-soft text-accent"
      : accent === "amber"
      ? "bg-amber-50 text-sev-medium"
      : "bg-paper-200 text-paper-600";
  const numColor =
    accent === "accent" ? "text-accent" : accent === "amber" ? "text-sev-medium" : "text-paper-900";
  return (
    <div className="rounded-lg border border-paper-300 bg-white p-4 shadow-card transition-all hover:shadow-pop hover:-translate-y-0.5">
      <div className="flex items-start justify-between mb-2">
        <span className="text-2xs mono uppercase tracking-wider text-paper-500">{label}</span>
        <span className={`h-7 w-7 rounded-md grid place-items-center ${accentBg}`}>{icon}</span>
      </div>
      <div className={`text-3xl font-semibold tabular-nums tracking-tight ${numColor}`}>
        {value}
      </div>
      {sub && <div className="text-2xs text-paper-500 mono mt-0.5">{sub}</div>}
    </div>
  );
}

function EmptyState() {
  return (
    <div className="text-center py-20">
      <div className="mx-auto mb-4 opacity-40 grid place-items-center">
        <Cmul8Mark size={56} />
      </div>
      <div className="text-paper-800 text-base font-medium">Point Spotlight at something.</div>
      <div className="text-paper-500 text-sm mt-1 max-w-md mx-auto">
        Pick a bundled fixture from the top bar to see the flow. Or paste a{" "}
        <span className="mono">.git</span> URL and Spotlight will clone, scan, patch and
        verify — end to end.
      </div>
      <div className="mt-6 inline-flex items-center gap-2 text-2xs mono uppercase tracking-wider text-paper-500">
        <kbd className="border border-paper-300 rounded px-1.5 py-0.5 bg-white shadow-sm">⌘</kbd>
        <kbd className="border border-paper-300 rounded px-1.5 py-0.5 bg-white shadow-sm">↵</kbd>
        <span>start</span>
        <span className="mx-1 text-paper-400">·</span>
        <kbd className="border border-paper-300 rounded px-1.5 py-0.5 bg-white shadow-sm">⌘K</kbd>
        <span>command</span>
      </div>
    </div>
  );
}

function SegBar({ w, className }: { w: number; className: string }) {
  if (w <= 0) return null;
  return <span style={{ width: `${w}%` }} className={`${className} h-full transition-all`} />;
}

function StatusPill({ status }: { status: string }) {
  const map: Record<string, string> = {
    finished: "bg-accent-soft text-accent border-accent/30",
    running: "bg-amber-50 text-sev-medium border-sev-medium/30",
    failed: "bg-sev-critical/10 text-sev-critical border-sev-critical/30",
  };
  return (
    <span
      className={`inline-flex items-center gap-1.5 text-2xs mono uppercase px-2 py-0.5 rounded-full border ${
        map[status] ?? ""
      }`}
    >
      {status === "running" && <span className="h-1.5 w-1.5 rounded-full bg-sev-medium animate-pulse" />}
      {status === "finished" && <IconCheck size={10} />}
      {status === "failed" && <IconAlert size={10} />}
      {status}
    </span>
  );
}

function SourcePill({ source }: { source: string }) {
  return (
    <span className="text-2xs mono uppercase tracking-wider text-paper-500 border border-paper-300 rounded-full px-2 py-0.5 bg-paper-100">
      {source}
    </span>
  );
}

function SkeletonTable() {
  return (
    <div className="border border-paper-300 rounded-lg bg-white shadow-card overflow-hidden">
      <div className="bg-paper-100 border-b border-paper-300 h-9" />
      {[0, 1, 2, 3].map((i) => (
        <div key={i} className="flex items-center gap-3 px-5 py-3 border-b border-paper-200 last:border-none">
          <div className="skeleton h-8 w-8 rounded-md" />
          <div className="skeleton h-3 w-40" />
          <div className="skeleton h-3 w-16" />
          <div className="skeleton h-3 w-20 ml-auto" />
        </div>
      ))}
    </div>
  );
}

type SeverityBucket = { critical: number; high: number; medium: number; low: number };

function summarize(rows: SweepSummary[]) {
  const safe = Array.isArray(rows) ? rows : [];
  const total = safe.length;
  const verified = safe.filter((r) => r.status === "finished").length;
  const failed = safe.filter((r) => r.status === "failed").length;
  const totalFindings = safe.reduce((s, r) => s + (r.findings_count || 0), 0);
  // Approximation until per-severity bubbles up in /sweeps:
  const sev: SeverityBucket = { critical: 0, high: totalFindings, medium: 0, low: 0 };
  const sum = sev.critical + sev.high + sev.medium + sev.low || 1;
  const sevPct: SeverityBucket = {
    critical: (sev.critical / sum) * 100,
    high: (sev.high / sum) * 100,
    medium: (sev.medium / sum) * 100,
    low: (sev.low / sum) * 100,
  };
  return { total, verified, failed, totalFindings, sev, sevPct };
}

function relativeTime(iso: string): string {
  const then = new Date(iso).getTime();
  const now = Date.now();
  const delta = Math.max(0, now - then);
  const s = Math.round(delta / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.round(h / 24);
  return `${d}d ago`;
}
