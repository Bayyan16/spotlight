import { Fragment, useEffect, useMemo, useState } from "react";
import {
  cleanupSweeps,
  deleteSweep,
  listProfiles,
  listSweeps,
  type Finding,
  type Profile,
  type SweepSummary,
} from "../lib/api";
import { invalidateWorkspaceFindings, useWorkspaceData } from "../hooks/useWorkspaceData";
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
  const { sweeps: allRows, findingsBySweep, refresh } = useWorkspaceData(refreshSignal);
  const [busy, setBusy] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [repoFilter, setRepoFilter] = useState<string>("all");
  const [activeTab, setActiveTab] = useState<"sweeps" | "profiles">("sweeps");
  const [profiles, setProfiles] = useState<Profile[] | null>(null);

  useEffect(() => {
    listProfiles()
      .then((p) => setProfiles(Array.isArray(p) ? p : []))
      .catch(() => setProfiles([]));
  }, []);

  // Repo filter — a workspace with 5 acme-bank sweeps and 2 juice-shop
  // sweeps is confusing when you're focused on one repo's history. Filter
  // ONCE at the top; the KPI pills, chart, and table all read the filtered
  // view so nothing can drift.
  const repos = useMemo(() => {
    const names = new Set<string>();
    for (const r of allRows ?? []) names.add(r.repo_name);
    return [...names].sort();
  }, [allRows]);

  const rows = useMemo(() => {
    if (repoFilter === "all") return allRows;
    return (allRows ?? []).filter((r) => r.repo_name === repoFilter);
  }, [allRows, repoFilter]);

  const counts = useMemo(() => {
    const list = rows ?? [];
    const running = list.filter((r) => r.status === "running").length;
    const failed = list.filter((r) => r.status === "failed").length;
    let totalFindings = 0;
    let verifiedSweeps = 0;
    for (const r of list) {
      const findings = findingsBySweep[r.sweep_id] ?? [];
      totalFindings += findings.length;
      if (findings.some((f) => f.tier === "verified")) verifiedSweeps += 1;
    }
    return {
      total: list.length,
      running,
      failed,
      totalFindings,
      verifiedSweeps,
    };
  }, [rows, findingsBySweep]);

  function toggleExpanded(id: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  // Single-source-of-truth rollup — no longer computed twice by two callers.
  const rollup = useMemo(
    () => ({
      total: counts.total,
      open: counts.running,
      failed: counts.failed,
      verified: counts.verifiedSweeps,
      totalFindings: counts.totalFindings,
    }),
    [counts]
  );

  // Chart hotness — when the largest bucket exceeds this many findings the
  // chart turns red. Signals "this workspace / repo has real problems" at a
  // glance without needing to read the numbers.
  const HOT_BUCKET_THRESHOLD = 20;
  const [granularity, setGranularity] = useState<"day" | "hour">("day");
  const chartPoints = useMemo(
    () =>
      granularity === "day"
        ? buildDailyPoints(rows ?? [], findingsBySweep)
        : buildHourlyPoints(rows ?? [], findingsBySweep),
    [rows, granularity, findingsBySweep]
  );

  // Chart runs red when any bucket exceeds the hot-threshold. Signals
  // "real problems here" at a glance without having to read the numbers.
  const chartIsHot = useMemo(
    () => chartPoints.some((p) => p.value >= HOT_BUCKET_THRESHOLD),
    [chartPoints]
  );

  async function onDelete(id: string) {
    if (!confirm(`Delete sweep ${id}?`)) return;
    setBusy(id);
    try {
      await deleteSweep(id);
      invalidateWorkspaceFindings(id);
      refresh();
    } finally {
      setBusy(null);
    }
  }

  async function onCleanupAll() {
    if (!confirm(`Delete ALL sweeps? This cannot be undone.`)) return;
    await cleanupSweeps("finished");
    await cleanupSweeps("failed");
    await cleanupSweeps("running");
    invalidateWorkspaceFindings();
    refresh();
  }

  const nothingYet = rows !== null && rows.length === 0;

  return (
    <section className="flex-1 min-w-0 overflow-y-auto bg-paper-50">
      {/* Top: category pills — Total · Verified · Open · Failed. NO card, no border. */}
      <div className="px-12 pt-10 pb-6 flex items-center gap-10">
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
        {rollup.total > 0 && (
          <button
            onClick={onCleanupAll}
            className="ml-auto text-2xs mono uppercase tracking-wider text-paper-400 hover:text-sev-critical transition-colors"
          >
            Clear all
          </button>
        )}
      </div>

      {/* Repo filter — chip strip. `all` shows the aggregate workspace view;
          picking a repo scopes chart + table + KPIs to that repo. */}
      {repos.length > 1 && (
        <div className="px-12 pb-2 flex items-center gap-2 flex-wrap">
          <span className="text-2xs mono uppercase tracking-wider text-paper-500 mr-1">
            Filter by repo
          </span>
          <button
            onClick={() => setRepoFilter("all")}
            aria-pressed={repoFilter === "all"}
            className={`text-2xs mono uppercase tracking-wider rounded-full px-2 py-0.5 border ${
              repoFilter === "all"
                ? "bg-accent text-white border-accent"
                : "bg-white border-paper-300 text-paper-700 hover:bg-paper-100"
            }`}
          >
            all ({allRows?.length ?? 0})
          </button>
          {repos.map((r) => {
            const n = (allRows ?? []).filter((s) => s.repo_name === r).length;
            return (
              <button
                key={r}
                onClick={() => setRepoFilter(r)}
                aria-pressed={repoFilter === r}
                className={`text-2xs mono rounded-full px-2 py-0.5 border ${
                  repoFilter === r
                    ? "bg-accent text-white border-accent"
                    : "bg-white border-paper-300 text-paper-700 hover:bg-paper-100"
                }`}
              >
                {r} <span className="tabular-nums opacity-70">({n})</span>
              </button>
            );
          })}
        </div>
      )}

      {/* Chart floats on the paper background — NO wrapping card, NO border. */}
      <div className="px-12 pb-8">
        <div className="flex items-center gap-3 mb-1">
          <div className="text-sm text-paper-900 font-medium">
            Findings{" "}
            <span className={chartIsHot ? "text-sev-critical" : "text-accent"}>
              ↗ {rollup.totalFindings}
            </span>
            {repoFilter !== "all" && (
              <span className="ml-2 text-2xs mono uppercase tracking-wider text-paper-500">
                · {repoFilter}
              </span>
            )}
          </div>
          <div className="ml-auto flex items-center gap-3 text-2xs mono uppercase tracking-wider text-paper-500">
            <div className="inline-flex items-center gap-0 rounded border border-paper-300 overflow-hidden">
              <button
                onClick={() => setGranularity("day")}
                aria-pressed={granularity === "day"}
                className={`px-2 py-0.5 ${
                  granularity === "day"
                    ? "bg-paper-200 text-paper-900"
                    : "text-paper-500 hover:bg-paper-100"
                }`}
              >
                Day
              </button>
              <button
                onClick={() => setGranularity("hour")}
                aria-pressed={granularity === "hour"}
                className={`px-2 py-0.5 border-l border-paper-300 ${
                  granularity === "hour"
                    ? "bg-paper-200 text-paper-900"
                    : "text-paper-500 hover:bg-paper-100"
                }`}
              >
                Hour
              </button>
            </div>
            <span className="inline-flex items-center gap-1">
              <span className="h-1.5 w-1.5 rounded-full bg-accent" />
              Total
            </span>
          </div>
        </div>
        <AreaChart
          points={chartPoints}
          color={chartIsHot ? "#d94a3a" : "#5b8def"}
          height={260}
          emptyMessage={nothingYet ? "Start a sweep to see activity" : "No findings yet"}
        />
      </div>

      {/* Tabs — Sweeps / Profiles. Devin-style underline, no pill background.
          Uses our internal term ("Sweeps") consistently across the workspace. */}
      <div className="px-12 pt-3 flex items-center gap-8 border-b border-paper-300">
        <TabPill
          label="Sweeps"
          count={rows?.length ?? 0}
          active={activeTab === "sweeps"}
          onClick={() => setActiveTab("sweeps")}
        />
        <TabPill
          label="Profiles"
          count={profiles?.length ?? 0}
          active={activeTab === "profiles"}
          onClick={() => setActiveTab("profiles")}
        />
        <div className="ml-auto flex items-center gap-3 pb-2">
          <button
            onClick={onStart}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-accent text-white text-xs uppercase tracking-wider mono hover:brightness-95"
          >
            <IconPlay size={12} />
            New sweep
          </button>
        </div>
      </div>

      {/* PROFILES tab — clean list of the workspace's Profile presets. */}
      {activeTab === "profiles" && (
        <div className="px-12 py-6">
          <ProfilesTab profiles={profiles} />
        </div>
      )}

      {/* SWEEPS table — no card, no vertical dividers, just row lines */}
      {activeTab === "sweeps" && (
      <div className="px-12 py-4">
        {rows === null && <SkeletonRows />}
        {nothingYet && <EmptyState onStart={onStart} />}
        {rows !== null && rows.length > 0 && (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-2xs mono uppercase tracking-wider text-paper-500 border-b border-paper-200">
                <th className="w-6"></th>
                <th className="text-left px-3 py-3 font-normal">Target</th>
                <th className="text-left px-3 py-3 font-normal">Commit</th>
                <th className="text-right px-3 py-3 font-normal">Total</th>
                <th className="text-right px-3 py-3 font-normal">Crit</th>
                <th className="text-right px-3 py-3 font-normal">High</th>
                <th className="text-right px-3 py-3 font-normal">Med</th>
                <th className="text-right px-3 py-3 font-normal">Last Scan</th>
                <th className="px-2"></th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => {
                const findings = findingsBySweep[r.sweep_id] ?? [];
                const sev = countSeverities(findings);
                const active = selected === r.sweep_id;
                const isOpen = expanded.has(r.sweep_id);
                return (
                  <Fragment key={r.sweep_id}>
                    <tr
                      onClick={() => onSelect(r)}
                      onDoubleClick={() => onOpen(r.sweep_id)}
                      className={`border-b border-paper-200/60 last:border-none group cursor-pointer transition-colors ${
                        active ? "bg-paper-100/60" : "hover:bg-paper-100/40"
                      }`}
                    >
                      <td className="pl-3">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            toggleExpanded(r.sweep_id);
                          }}
                          className="w-5 h-5 grid place-items-center text-paper-400 hover:text-paper-800 rounded"
                          aria-label={isOpen ? "Collapse" : "Expand"}
                          aria-expanded={isOpen}
                        >
                          <span
                            className={`transition-transform inline-block ${isOpen ? "rotate-90" : ""}`}
                          >
                            ▸
                          </span>
                        </button>
                      </td>
                      <td className="px-3 py-3.5">
                        <div className="flex items-center gap-2 min-w-0">
                          <StatusDot status={r.status} />
                          <span className="text-paper-900 font-medium truncate">
                            {r.org ? (
                              <span>
                                <span className="text-paper-500">{r.org}/</span>
                                {r.repo_name}
                              </span>
                            ) : (
                              r.repo_name
                            )}
                          </span>
                          <span className="mono text-2xs text-paper-400 tabular-nums" title={r.sweep_id}>
                            {r.sweep_id.slice(0, 10)}
                          </span>
                          {r.interactive && (
                            <span
                              className="text-2xs mono uppercase tracking-wider bg-accent-soft text-accent border border-accent/30 rounded-full px-1.5 py-0.5"
                              title="Interactive-mode sweep"
                            >
                              interactive
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="px-3 py-3.5 mono text-2xs text-paper-600">
                        <CommitCell
                          sha={r.commit_sha ?? null}
                          branch={r.commit_branch ?? null}
                          source={r.source}
                        />
                      </td>
                      <TdNum n={r.findings_count} />
                      <TdNum n={sev.critical} colorClass={sev.critical > 0 ? "text-sev-critical" : ""} />
                      <TdNum n={sev.high} colorClass={sev.high > 0 ? "text-sev-high" : ""} />
                      <TdNum n={sev.medium} colorClass={sev.medium > 0 ? "text-sev-medium" : ""} />
                      <td className="px-3 py-3.5 text-right mono text-2xs text-paper-500 tabular-nums">
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
                    {isOpen && (
                      <tr className="bg-paper-50 border-b border-paper-200/60">
                        <td></td>
                        <td colSpan={8} className="px-3 py-3">
                          <SweepFindingsPreview
                            findings={findings}
                            onOpen={() => onOpen(r.sweep_id)}
                          />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
      )}
    </section>
  );
}

function ProfilesTab({ profiles }: { profiles: Profile[] | null }) {
  if (profiles === null) {
    return (
      <div className="text-paper-500 text-sm italic">Loading profiles…</div>
    );
  }
  if (profiles.length === 0) {
    return (
      <div className="text-paper-500 text-sm italic">
        No profiles configured.
      </div>
    );
  }
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
      {profiles.map((p) => (
        <div
          key={p.id}
          className="border border-paper-300 rounded-xl bg-white p-4 shadow-card hover:shadow-md transition-shadow"
        >
          <div className="flex items-center gap-2 mb-1.5">
            <span className="text-base text-paper-900 font-semibold tracking-tight">
              {p.name}
            </span>
            <span className="ml-auto mono text-2xs text-paper-500">{p.id}</span>
          </div>
          <p className="text-2xs text-paper-600 leading-relaxed mb-3">
            {p.description}
          </p>
          <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-2xs mono">
            <div>
              <div className="uppercase tracking-wider text-paper-500">Surfaces</div>
              <div className="text-paper-800 truncate" title={p.surfaces.join(", ")}>
                {p.surfaces.join(", ")}
              </div>
            </div>
            <div>
              <div className="uppercase tracking-wider text-paper-500">Classes</div>
              <div className="text-paper-800 tabular-nums">{p.classes.length}</div>
            </div>
            <div>
              <div className="uppercase tracking-wider text-paper-500">Max agents</div>
              <div className="text-paper-800 tabular-nums">{p.max_agents}</div>
            </div>
            <div>
              <div className="uppercase tracking-wider text-paper-500">Budget</div>
              <div className="text-paper-800 tabular-nums">
                {(p.budget_tokens / 1000).toFixed(0)}k tokens
              </div>
            </div>
            <div>
              <div className="uppercase tracking-wider text-paper-500">Languages</div>
              <div className="text-paper-800 truncate">
                {p.languages.join(", ")}
              </div>
            </div>
            <div>
              <div className="uppercase tracking-wider text-paper-500">Model</div>
              <div className="text-paper-800 truncate">{p.model}</div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

function CommitCell({
  sha,
  branch,
  source,
}: {
  sha: string | null;
  branch: string | null;
  source: string;
}) {
  if (!sha) {
    // Fixture targets have no git ancestry. Show the source kind so the
    // table cell isn't a bald "—".
    if (source === "fixture") {
      return (
        <span className="text-2xs mono uppercase tracking-wider text-paper-400">
          fixture
        </span>
      );
    }
    return <span className="text-paper-400">—</span>;
  }
  return (
    <div className="flex flex-col leading-tight">
      <span className="mono text-paper-800 tabular-nums" title={sha}>
        {sha.slice(0, 8)}
      </span>
      {branch && (
        <span
          className="mono text-[10px] uppercase tracking-wider text-paper-500 truncate max-w-[10ch]"
          title={branch}
        >
          {branch}
        </span>
      )}
    </div>
  );
}

/**
 * Row-expansion preview — chip strip + one big affordance to open the
 * canonical Findings inbox for this sweep. Deliberately NOT a mini-inbox:
 * that path lives in the Findings view, filtered to the sweep via
 * openHistoricalSweep in App.tsx. Two views would drift; one is the truth.
 */
function SweepFindingsPreview({
  findings,
  onOpen,
}: {
  findings: Finding[];
  onOpen: () => void;
}) {
  if (findings.length === 0) {
    return (
      <div className="text-2xs mono uppercase tracking-wider text-paper-400 py-2">
        no findings landed yet
      </div>
    );
  }
  // Class → count map. Sorted by count desc so the biggest offenders are
  // visually first, matching how the Findings inbox groups by severity
  // rank when opened.
  const byClass = new Map<string, Finding[]>();
  for (const f of findings) {
    const arr = byClass.get(f.class) ?? [];
    arr.push(f);
    byClass.set(f.class, arr);
  }
  const sortedClasses = [...byClass.entries()].sort(
    (a, b) => b[1].length - a[1].length
  );
  const verifiedCount = findings.filter((f) => f.tier === "verified").length;

  return (
    <div className="flex items-center gap-3 flex-wrap">
      <div className="flex items-center gap-1.5 flex-wrap flex-1 min-w-0">
        {sortedClasses.map(([cls, list]) => {
          const worst = list.reduce((acc, f) => {
            const rank = SEV_RANK[f.severity] ?? 0;
            return rank > (SEV_RANK[acc.severity] ?? 0) ? f : acc;
          }, list[0]);
          return (
            <span
              key={cls}
              className="inline-flex items-center gap-1 mono text-2xs bg-white border border-paper-300 rounded-full pl-2 pr-1.5 py-0.5"
              title={`${list.length}× ${cls} (worst: ${worst.severity})`}
            >
              <span className="text-paper-800">{cls}</span>
              <span className="tabular-nums text-paper-500">×{list.length}</span>
              <MiniSevChip sev={worst.severity} />
            </span>
          );
        })}
      </div>
      {verifiedCount > 0 && (
        <span className="text-2xs mono uppercase tracking-wider text-accent">
          {verifiedCount} verified
        </span>
      )}
      <button
        onClick={onOpen}
        className="text-2xs mono uppercase tracking-wider text-white bg-accent hover:brightness-95 rounded-full px-3 py-1"
      >
        Open in Findings →
      </button>
    </div>
  );
}

const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

function MiniSevChip({ sev }: { sev: string }) {
  const map: Record<string, string> = {
    critical: "bg-sev-critical text-white",
    high: "bg-sev-high text-white",
    medium: "bg-sev-medium text-white",
    low: "bg-sev-low text-white",
  };
  return (
    <span
      className={`text-[9px] mono uppercase tracking-wider px-1 py-0.5 rounded ${map[sev] ?? "bg-paper-400 text-white"}`}
    >
      {sev}
    </span>
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

function TabPill({
  label,
  count,
  active,
  onClick,
}: {
  label: string;
  count: number;
  active?: boolean;
  onClick?: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={`relative flex items-baseline gap-1.5 py-2 focus:outline-none ${
        active
          ? "text-paper-900"
          : "text-paper-500 hover:text-paper-800 transition-colors"
      }`}
      aria-pressed={active}
    >
      <span className="text-sm font-medium">{label}</span>
      <span className="mono text-2xs tabular-nums text-paper-500">{count}</span>
      {active && (
        <span className="absolute left-0 right-0 -bottom-[2px] h-[2px] bg-paper-900" />
      )}
    </button>
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
        New sweep
      </button>
    </div>
  );
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

type BucketAgg = {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  sweeps: number;
};

function _emptyBucket(): BucketAgg {
  return { total: 0, critical: 0, high: 0, medium: 0, low: 0, sweeps: 0 };
}

function _foldSweepInto(
  bucket: BucketAgg,
  row: SweepSummary,
  findings: Finding[] | undefined
): void {
  bucket.sweeps += 1;
  if (findings && findings.length) {
    for (const f of findings) {
      bucket.total += 1;
      const key = f.severity as keyof BucketAgg;
      if (key === "critical" || key === "high" || key === "medium" || key === "low") {
        bucket[key] += 1;
      }
    }
  } else {
    // Fall back to the row-level `findings_count` when the per-finding
    // list isn't loaded yet (chart still shows something useful).
    bucket.total += row.findings_count || 0;
  }
}

function _finalizeBucket(
  iso: string,
  label: string,
  bucket: BucketAgg,
  isLive: boolean
) {
  return {
    label,
    value: bucket.total,
    critical: bucket.critical,
    high: bucket.high,
    medium: bucket.medium,
    low: bucket.low,
    sweeps: bucket.sweeps,
    live: isLive,
  };
}

function buildDailyPoints(
  rows: SweepSummary[],
  findingsBySweep: Record<string, Finding[]>
) {
  const days = 30;
  const now = new Date();
  now.setHours(0, 0, 0, 0);
  const todayKey = now.toISOString().slice(0, 10);
  const buckets: Record<string, BucketAgg> = {};
  const order: string[] = [];
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(now);
    d.setDate(d.getDate() - i);
    const key = d.toISOString().slice(0, 10);
    order.push(key);
    buckets[key] = _emptyBucket();
  }
  for (const r of rows) {
    if (!r.started_at) continue;
    const key = new Date(r.started_at).toISOString().slice(0, 10);
    if (buckets[key] !== undefined) {
      _foldSweepInto(buckets[key], r, findingsBySweep[r.sweep_id]);
    }
  }
  return order.map((iso) => {
    const [_, m, day] = iso.split("-");
    return _finalizeBucket(
      iso,
      `${monthLabel(+m - 1)} ${+day}`,
      buckets[iso],
      iso === todayKey && buckets[iso].sweeps > 0
    );
  });
}

function buildHourlyPoints(
  rows: SweepSummary[],
  findingsBySweep: Record<string, Finding[]>
) {
  const hours = 48;
  const now = new Date();
  now.setMinutes(0, 0, 0);
  const nowKey = now.toISOString().slice(0, 13);
  const buckets: Record<string, BucketAgg> = {};
  const keyOrder: string[] = [];
  for (let i = hours - 1; i >= 0; i--) {
    const d = new Date(now);
    d.setHours(d.getHours() - i);
    const key = d.toISOString().slice(0, 13);
    keyOrder.push(key);
    buckets[key] = _emptyBucket();
  }
  for (const r of rows) {
    if (!r.started_at) continue;
    const key = new Date(r.started_at).toISOString().slice(0, 13);
    if (buckets[key] !== undefined) {
      _foldSweepInto(buckets[key], r, findingsBySweep[r.sweep_id]);
    }
  }
  return keyOrder.map((iso) => {
    const hh = iso.slice(11, 13);
    const day = iso.slice(8, 10);
    return _finalizeBucket(
      iso,
      `${day} · ${hh}:00`,
      buckets[iso],
      iso === nowKey && buckets[iso].sweeps > 0
    );
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
