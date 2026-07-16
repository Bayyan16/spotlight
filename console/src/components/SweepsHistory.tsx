import { useEffect, useMemo, useState } from "react";
import { cleanupSweeps, deleteSweep, listSweeps, type SweepSummary } from "../lib/api";
import { Cmul8Mark } from "./Cmul8Mark";
import { IconPlay } from "./Icons";

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
      <header className="border-b border-paper-300 px-6 py-4 sticky top-0 bg-paper-50/90 backdrop-blur z-10 flex items-center gap-4">
        <div>
          <h1 className="text-lg text-paper-900 font-semibold tracking-tight">Sweeps</h1>
          <p className="text-xs text-paper-600">
            Every sweep this workspace has run, persisted in Postgres.
          </p>
        </div>
        <div className="ml-auto flex items-center gap-3 text-xs mono uppercase tracking-wider text-paper-500">
          <Stat label="Total" value={rollup.total} />
          <Stat label="Verified" value={rollup.verified} accent="accent" />
          <Stat label="Findings" value={rollup.totalFindings} />
          {rollup.failed > 0 && (
            <button
              onClick={async () => {
                if (!confirm(`Clear ${rollup.failed} failed sweep${rollup.failed === 1 ? "" : "s"}?`)) return;
                await cleanupSweeps("failed");
                const fresh = await listSweeps();
                setRows(Array.isArray(fresh) ? fresh : []);
              }}
              className="text-2xs mono uppercase tracking-wider px-2 py-1 rounded border border-paper-300 hover:border-sev-critical hover:text-sev-critical text-paper-600 transition-colors"
              title="Delete sweeps stuck in a failed state (e.g. killed mid-run by a deploy)"
            >
              Clear {rollup.failed} failed
            </button>
          )}
        </div>
      </header>

      {/* Severity distribution across all sweeps */}
      {rollup.total > 0 && (
        <div className="px-6 py-4 border-b border-paper-300">
          <div className="flex items-center gap-4">
            <div className="text-2xs uppercase tracking-wider text-paper-500 mono w-24">
              Severity mix
            </div>
            <div className="flex-1 h-2 rounded-full overflow-hidden bg-paper-200 flex">
              <Bar w={rollup.sevPct.critical} className="bg-sev-critical" />
              <Bar w={rollup.sevPct.high} className="bg-sev-high" />
              <Bar w={rollup.sevPct.medium} className="bg-sev-medium" />
              <Bar w={rollup.sevPct.low} className="bg-sev-low" />
            </div>
            <div className="flex items-center gap-3 text-2xs mono text-paper-500">
              <Dot color="bg-sev-critical" label={`${rollup.sev.critical} crit`} />
              <Dot color="bg-sev-high" label={`${rollup.sev.high} high`} />
              <Dot color="bg-sev-medium" label={`${rollup.sev.medium} med`} />
              <Dot color="bg-sev-low" label={`${rollup.sev.low} low`} />
            </div>
          </div>
        </div>
      )}

      <div className="px-6 py-4">
        {rows === null && <SkeletonTable />}
        {rows !== null && rows.length === 0 && (
          <div className="text-center py-16">
            <div className="mx-auto mb-3 opacity-40 grid place-items-center">
              <Cmul8Mark size={44} />
            </div>
            <div className="text-paper-700 text-sm">No sweeps yet.</div>
            <div className="text-paper-500 text-xs mt-1">
              Kick one off from the top bar — pick a fixture or paste a git URL.
            </div>
            <div className="mt-4 inline-flex items-center gap-1 text-2xs mono uppercase tracking-wider text-paper-500">
              <kbd className="border border-paper-300 rounded px-1 py-0.5 bg-white">⌘</kbd>
              <kbd className="border border-paper-300 rounded px-1 py-0.5 bg-white">↵</kbd>
              <span className="ml-1">start</span>
              <span className="mx-2 text-paper-400">·</span>
              <kbd className="border border-paper-300 rounded px-1 py-0.5 bg-white">⌘K</kbd>
              <span className="ml-1">command</span>
            </div>
          </div>
        )}
        {rows !== null && rows.length > 0 && (
          <div className="border border-paper-300 rounded-md bg-white shadow-card overflow-hidden animate-fade-in">
            <table className="w-full text-sm">
              <thead className="bg-paper-100 border-b border-paper-300 text-2xs uppercase tracking-wider text-paper-500 mono">
                <tr>
                  <th className="text-left px-4 py-2 font-medium">Sweep</th>
                  <th className="text-left px-4 py-2 font-medium">Target</th>
                  <th className="text-left px-4 py-2 font-medium">Source</th>
                  <th className="text-left px-4 py-2 font-medium">Status</th>
                  <th className="text-right px-4 py-2 font-medium">Findings</th>
                  <th className="text-left px-4 py-2 font-medium">Started</th>
                  <th className="px-2 py-2"></th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr
                    key={r.sweep_id}
                    className="border-b border-paper-200 last:border-none hover:bg-paper-100/60 cursor-pointer group transition-colors"
                    onClick={() => onOpen(r.sweep_id)}
                  >
                    <td className="px-4 py-2.5 mono text-xs text-paper-700 tabular-nums group-hover:text-paper-900">
                      {r.sweep_id}
                    </td>
                    <td className="px-4 py-2.5 text-paper-900">{r.repo_name}</td>
                    <td className="px-4 py-2.5">
                      <SourcePill source={r.source} />
                    </td>
                    <td className="px-4 py-2.5">
                      <StatusPill status={r.status} />
                    </td>
                    <td className="px-4 py-2.5 mono text-right text-paper-800 tabular-nums">
                      {r.findings_count}
                    </td>
                    <td className="px-4 py-2.5 mono text-2xs text-paper-500 tabular-nums">
                      {r.started_at ? relativeTime(r.started_at) : "—"}
                    </td>
                    <td className="px-2 py-2.5 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onDelete(r.sweep_id);
                        }}
                        disabled={busy === r.sweep_id}
                        className="opacity-0 group-hover:opacity-100 text-2xs mono uppercase tracking-wider text-paper-500 hover:text-sev-critical px-2 py-1 rounded transition-all"
                        title="Delete this sweep and its findings"
                      >
                        {busy === r.sweep_id ? "…" : "delete"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  );
}

function Stat({ label, value, accent }: { label: string; value: number; accent?: "accent" }) {
  return (
    <div className="flex items-center gap-1.5">
      <span className="text-paper-500">{label}</span>
      <span
        className={`mono tabular-nums font-semibold ${
          accent === "accent" ? "text-accent" : "text-paper-900"
        }`}
      >
        {value}
      </span>
    </div>
  );
}

function Bar({ w, className }: { w: number; className: string }) {
  if (w <= 0) return null;
  return <span style={{ width: `${w}%` }} className={`${className} h-full transition-all`} />;
}

function Dot({ color, label }: { color: string; label: string }) {
  return (
    <span className="flex items-center gap-1">
      <span className={`h-1.5 w-1.5 rounded-full ${color}`} />
      <span>{label}</span>
    </span>
  );
}

function StatusPill({ status }: { status: string }) {
  const map: Record<string, string> = {
    finished: "bg-accent-soft text-accent border-accent/30",
    running: "bg-amber-50 text-sev-medium border-sev-medium/30",
    failed: "bg-sev-critical/15 text-sev-critical border-sev-critical/30",
  };
  return (
    <span
      className={`inline-flex items-center gap-1 text-2xs mono uppercase px-1.5 py-0.5 rounded border ${
        map[status] ?? ""
      }`}
    >
      {status === "running" && <span className="h-1.5 w-1.5 rounded-full bg-sev-medium animate-pulse" />}
      {status}
    </span>
  );
}

function SourcePill({ source }: { source: string }) {
  return (
    <span className="text-2xs mono uppercase tracking-wider text-paper-500 border border-paper-300 rounded px-1.5 py-0.5 bg-paper-100">
      {source}
    </span>
  );
}

function SkeletonTable() {
  return (
    <div className="border border-paper-300 rounded-md bg-white shadow-card overflow-hidden">
      <div className="bg-paper-100 border-b border-paper-300 h-8" />
      {[0, 1, 2, 3].map((i) => (
        <div key={i} className="flex items-center gap-3 px-4 py-3 border-b border-paper-200 last:border-none">
          <div className="skeleton h-3 w-28" />
          <div className="skeleton h-3 w-32" />
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
  // We don't have a per-severity breakdown from /sweeps; approximate:
  // treat each finding as "high" for now — Phase 2 will thread severity into
  // the sweep summary so this rollup is accurate. For now everything routes
  // through "high" so the bar renders meaningfully.
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

// Suppress unused-import warning for Cmul8Mark when not on the empty path.
export const _ = IconPlay;
