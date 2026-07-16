import { useEffect, useMemo, useState } from "react";
import {
  cleanupSweeps,
  deleteSweep,
  getFindings,
  listSweeps,
  type Finding,
  type SweepSummary,
} from "../lib/api";
import { AreaChart } from "./AreaChart";
import { Cmul8Mark } from "./Cmul8Mark";
import { IconCheck, IconPlay } from "./Icons";

/**
 * Board — the primary landing view. Codex/Devin aesthetic (cleanui1.png):
 *   * a compact row of category pills (Total · Verified · Open · Failed)
 *   * a big area chart hero (findings over time)
 *   * clean sortable table below (Scans)
 *
 * Deliberately no severity donut, no dashboard-chrome. High signal only.
 */
export function Board({
  onOpen,
  onStart,
  onSelect,
  selected,
  refreshSignal,
}: {
  onOpen: (id: string) => void;
  onStart: () => void;
  onSelect: (row: SweepSummary | null) => void;
  selected: string | null;
  refreshSignal: number;
}) {
  const [rows, setRows] = useState<SweepSummary[] | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [findingsByThought, setFindingsByThought] = useState<Record<string, Finding[]>>({});

  useEffect(() => {
    listSweeps()
      .then((d) => setRows(Array.isArray(d) ? d : []))
      .catch(() => setRows([]));
  }, [refreshSignal]);

  useEffect(() => {
    if (!rows) return;
    const finished = rows.filter((r) => r.status === "finished" && r.findings_count > 0);
    Promise.all(
      finished.slice(0, 20).map(async (r) => [r.sweep_id, await getFindings(r.sweep_id)] as const)
    ).then((entries) => {
      const map: Record<string, Finding[]> = {};
      for (const [id, fs] of entries) map[id] = fs;
      setFindingsByThought(map);
    });
  }, [rows]);

  const rollup = useMemo(() => summarize(rows ?? [], findingsByThought), [rows, findingsByThought]);
  const chartPoints = useMemo(() => buildDailyPoints(rows ?? []), [rows]);

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

  async function onCleanupAll() {
    if (!confirm(`Delete ALL sweeps? This cannot be undone.`)) return;
    await cleanupSweeps("finished");
    await cleanupSweeps("failed");
    await cleanupSweeps("running");
    const fresh = await listSweeps();
    setRows(Array.isArray(fresh) ? fresh : []);
  }

  const nothingYet = rows !== null && rows.length === 0;

  return (
    <section className="flex-1 min-w-0 overflow-y-auto bg-paper-50">
      {/* Top: category pills — Total · Verified · Open · Failed */}
      <div className="px-10 pt-8 pb-4 flex items-center gap-8">
        <StatPill label="Total" value={rollup.total} tone="neutral" />
        <StatPill
          label="Verified"
          value={rollup.verified}
          pct={rollup.total ? (rollup.verified / rollup.total) * 100 : 0}
          tone="accent"
        />
        <StatPill
          label="Open"
          value={rollup.open}
          pct={rollup.total ? (rollup.open / rollup.total) * 100 : 0}
          tone="amber"
        />
        <StatPill
          label="Failed"
          value={rollup.failed}
          pct={rollup.total ? (rollup.failed / rollup.total) * 100 : 0}
          tone="red"
        />
        <div className="ml-auto flex items-center gap-2 text-2xs mono text-paper-500">
          {rollup.total > 0 && (
            <button
              onClick={onCleanupAll}
              className="uppercase tracking-wider border border-paper-300 hover:border-sev-critical/40 hover:text-sev-critical rounded px-2 py-1 transition-colors"
            >
              Clear all
            </button>
          )}
        </div>
      </div>

      {/* Big chart hero — findings over time */}
      <div className="px-10 pb-4">
        <div className="flex items-center gap-3 mb-2">
          <div className="text-sm text-paper-900 font-medium">
            Findings <span className="text-accent">↗ {rollup.totalFindings}</span>
          </div>
          <div className="ml-auto flex items-center gap-1 text-2xs mono uppercase tracking-wider text-paper-500">
            <span className="h-1.5 w-1.5 rounded-full bg-accent" />
            Total
          </div>
        </div>
        <div className="border border-paper-300 rounded-xl bg-white shadow-card p-4">
          <AreaChart
            points={chartPoints}
            color="#5b8def"
            height={240}
            emptyMessage={nothingYet ? "Start a sweep to see activity" : "No findings yet"}
          />
        </div>
      </div>

      {/* Scans/Profiles tabs + Start scan */}
      <div className="px-10 pt-2 pb-2 flex items-center gap-6 border-b border-paper-300">
        <TabPill label="Scans" count={rows?.length ?? 0} active />
        <TabPill label="Profiles" count={4} />
        <div className="ml-auto flex items-center gap-2">
          <button
            onClick={onStart}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-accent text-white text-xs uppercase tracking-wider mono hover:brightness-95 shadow-card"
          >
            <IconPlay size={12} />
            Start scan
          </button>
        </div>
      </div>

      {/* Scans table — cleanui1-style */}
      <div className="px-10 py-4">
        {rows === null && <SkeletonRows />}
        {nothingYet && <EmptyState onStart={onStart} />}
        {rows !== null && rows.length > 0 && (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-2xs mono uppercase tracking-wider text-paper-500">
                <th className="text-left px-3 py-2 font-medium">Created by you</th>
                <th className="text-right px-3 py-2 font-medium">Total</th>
                <th className="text-right px-3 py-2 font-medium">Critical</th>
                <th className="text-right px-3 py-2 font-medium">High</th>
                <th className="text-right px-3 py-2 font-medium">Med</th>
                <th className="text-right px-3 py-2 font-medium">Last Scan</th>
                <th className="px-2"></th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => {
                const findings = findingsByThought[r.sweep_id] ?? [];
                const sev = countSeverities(findings);
                const active = selected === r.sweep_id;
                return (
                  <tr
                    key={r.sweep_id}
                    onClick={() => onSelect(r)}
                    onDoubleClick={() => onOpen(r.sweep_id)}
                    className={`border-t border-paper-200 group cursor-pointer transition-colors ${
                      active ? "bg-white shadow-card" : "hover:bg-paper-100/50"
                    }`}
                  >
                    <td className="px-3 py-3">
                      <div className="flex items-center gap-2 min-w-0">
                        <StatusDot status={r.status} />
                        <span className="text-paper-900 font-medium truncate">{r.repo_name}</span>
                        <span className="mono text-2xs text-paper-500 tabular-nums">
                          {r.sweep_id.slice(0, 10)}
                        </span>
                      </div>
                    </td>
                    <TdNum n={r.findings_count} />
                    <TdNum n={sev.critical} colorClass={sev.critical > 0 ? "text-sev-critical" : ""} />
                    <TdNum n={sev.high} colorClass={sev.high > 0 ? "text-sev-high" : ""} />
                    <TdNum n={sev.medium} colorClass={sev.medium > 0 ? "text-sev-medium" : ""} />
                    <td className="px-3 py-3 text-right mono text-2xs text-paper-500 tabular-nums">
                      {r.started_at ? relativeTime(r.started_at) : "—"}
                    </td>
                    <td className="px-2 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onDelete(r.sweep_id);
                        }}
                        disabled={busy === r.sweep_id}
                        className="opacity-0 group-hover:opacity-100 text-2xs mono uppercase text-paper-400 hover:text-sev-critical px-1 py-0.5 rounded transition-all"
                      >
                        {busy === r.sweep_id ? "…" : "×"}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </section>
  );
}

function StatPill({
  label,
  value,
  pct,
  tone,
}: {
  label: string;
  value: number;
  pct?: number;
  tone: "neutral" | "accent" | "amber" | "red";
}) {
  const color =
    tone === "accent"
      ? "text-accent"
      : tone === "amber"
      ? "text-sev-medium"
      : tone === "red"
      ? "text-sev-critical"
      : "text-paper-700";
  const dot =
    tone === "accent"
      ? "bg-accent"
      : tone === "amber"
      ? "bg-sev-medium"
      : tone === "red"
      ? "bg-sev-critical"
      : "bg-paper-500";
  return (
    <div className="flex items-baseline gap-2">
      <span className="flex items-center gap-1.5 text-2xs mono uppercase tracking-wider text-paper-500">
        <span className={`h-1.5 w-1.5 rounded-full ${dot}`} />
        {label}
      </span>
      <span className={`text-lg font-semibold tabular-nums ${color}`}>{value}</span>
      {pct !== undefined && value > 0 && (
        <span className="text-2xs mono tabular-nums text-paper-500">
          {pct.toFixed(1)}%
        </span>
      )}
    </div>
  );
}

function TabPill({ label, count, active }: { label: string; count: number; active?: boolean }) {
  return (
    <div
      className={`flex items-baseline gap-1.5 py-2 ${
        active ? "text-paper-900 border-b-2 border-paper-900" : "text-paper-500"
      }`}
    >
      <span className="text-sm font-medium">{label}</span>
      <span className="mono text-2xs tabular-nums text-paper-500">{count}</span>
    </div>
  );
}

function StatusDot({ status }: { status: string }) {
  const color =
    status === "finished"
      ? "bg-accent"
      : status === "running"
      ? "bg-sev-medium animate-pulse"
      : status === "failed"
      ? "bg-sev-critical"
      : "bg-paper-400";
  return <span className={`h-1.5 w-1.5 rounded-full shrink-0 ${color}`} />;
}

function TdNum({ n, colorClass }: { n: number; colorClass?: string }) {
  return (
    <td
      className={`px-3 py-3 text-right mono tabular-nums text-sm ${
        n === 0 ? "text-paper-400" : colorClass || "text-paper-900 font-medium"
      }`}
    >
      {n === 0 ? "0" : n}
    </td>
  );
}

function SkeletonRows() {
  return (
    <div className="space-y-1">
      {[0, 1, 2].map((i) => (
        <div key={i} className="flex items-center gap-3 py-3 border-t border-paper-200">
          <div className="skeleton h-3 w-64" />
          <div className="skeleton h-3 w-10 ml-auto" />
          <div className="skeleton h-3 w-10" />
        </div>
      ))}
    </div>
  );
}

function EmptyState({ onStart }: { onStart: () => void }) {
  return (
    <div className="py-16 text-center">
      <div className="mx-auto mb-4 opacity-40 grid place-items-center">
        <Cmul8Mark size={48} />
      </div>
      <div className="text-paper-800 text-base font-medium">No scans yet.</div>
      <div className="text-paper-500 text-sm mt-1 max-w-md mx-auto">
        Pick a target from the top bar or paste a{" "}
        <span className="mono">.git</span> URL. Spotlight clones, sweeps, patches, and
        independently verifies — all in a hardened Modal sandbox.
      </div>
      <button
        onClick={onStart}
        className="mt-6 inline-flex items-center gap-2 px-4 py-2 rounded bg-accent text-white text-sm uppercase tracking-wider mono hover:brightness-95 shadow-card"
      >
        <IconPlay />
        Start scan
      </button>
    </div>
  );
}

function summarize(rows: SweepSummary[], findingsMap: Record<string, Finding[]>) {
  const total = rows.length;
  const finished = rows.filter((r) => r.status === "finished");
  const open = rows.filter((r) => r.status === "running").length;
  const failed = rows.filter((r) => r.status === "failed").length;
  let verified = 0;
  let totalFindings = 0;
  for (const r of finished) {
    const findings = findingsMap[r.sweep_id] ?? [];
    totalFindings += findings.length;
    if (findings.some((f) => f.tier === "verified")) verified += 1;
  }
  return { total, verified, open, failed, totalFindings };
}

function countSeverities(findings: Finding[]) {
  const out = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    if (f.severity === "critical") out.critical += 1;
    else if (f.severity === "high") out.high += 1;
    else if (f.severity === "medium") out.medium += 1;
    else if (f.severity === "low") out.low += 1;
  }
  return out;
}

function buildDailyPoints(rows: SweepSummary[]) {
  if (rows.length === 0) return [];
  // Bucket findings_count by day over the last 30 days.
  const days = 30;
  const now = new Date();
  now.setHours(0, 0, 0, 0);
  const buckets: Record<string, number> = {};
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(now);
    d.setDate(d.getDate() - i);
    buckets[d.toISOString().slice(0, 10)] = 0;
  }
  for (const r of rows) {
    if (!r.started_at) continue;
    const key = new Date(r.started_at).toISOString().slice(0, 10);
    if (buckets[key] !== undefined) {
      buckets[key] += r.findings_count || 0;
    }
  }
  return Object.entries(buckets).map(([iso, v]) => {
    const [_, m, day] = iso.split("-");
    return { label: `${monthLabel(+m - 1)} ${+day}`, value: v };
  });
}

function monthLabel(monthIdx: number): string {
  return ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][
    monthIdx
  ];
}

function relativeTime(iso: string): string {
  const then = new Date(iso).getTime();
  const now = Date.now();
  const s = Math.max(0, Math.round((now - then) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}
