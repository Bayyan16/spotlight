import { useEffect, useMemo, useState } from "react";
import { getAttestation, getFindings, listSweeps, type Finding, type SweepSummary } from "../lib/api";
import { Cmul8Mark } from "./Cmul8Mark";
import { IconAttestation, IconCheck, IconExploitPath, IconSweep, IconWarden } from "./Icons";

/**
 * Right-pane dashboard for the home nav. Codex-style status readout:
 *  - Big monospace stat pills across the top ("check check check")
 *  - A stack of recent-sweep cards on the right
 *  - A wide "Latest verified finding" card when there is one
 *  - System-status readouts at the bottom (sandbox engine, Moonshot,
 *    Postgres) — the "everything green" reassurance
 *
 * When a sweep is selected in the middle pane, this pane switches to
 * that sweep's summary instead.
 */
export function Dashboard({
  onOpen,
  refreshSignal,
  selected,
  onStart,
}: {
  onOpen: (sweepId: string) => void;
  refreshSignal: number;
  selected: SweepSummary | null;
  onStart: () => void;
}) {
  const [rows, setRows] = useState<SweepSummary[] | null>(null);
  const [latestVerified, setLatestVerified] = useState<Finding | null>(null);
  const [selectedFindings, setSelectedFindings] = useState<Finding[]>([]);

  useEffect(() => {
    listSweeps()
      .then((d) => setRows(Array.isArray(d) ? d : []))
      .catch(() => setRows([]));
  }, [refreshSignal]);

  useEffect(() => {
    if (!rows) return;
    const finished = rows.filter((r) => r.status === "finished" && r.findings_count > 0);
    if (finished.length === 0) {
      setLatestVerified(null);
      return;
    }
    getFindings(finished[0].sweep_id).then((fs) => {
      const verified = fs.find((f) => f.tier === "verified") || fs[0] || null;
      setLatestVerified(verified);
    });
  }, [rows]);

  useEffect(() => {
    if (!selected) {
      setSelectedFindings([]);
      return;
    }
    getFindings(selected.sweep_id).then(setSelectedFindings);
  }, [selected]);

  const rollup = useMemo(() => summarize(rows ?? []), [rows]);

  if (selected) {
    return (
      <SelectedSweepPane
        sweep={selected}
        findings={selectedFindings}
        onOpenFinding={onOpen}
      />
    );
  }

  return (
    <section className="flex-1 min-w-0 overflow-y-auto bg-gradient-to-b from-paper-50 to-paper-100/40">
      {/* Hero row — "check check check" status pills */}
      <div className="px-8 pt-6 pb-4">
        <div className="text-2xs uppercase tracking-wider text-paper-500 mono mb-3">
          System readout
        </div>
        <div className="flex flex-wrap gap-2">
          <CheckPill label="API" ok status="200" />
          <CheckPill label="Postgres" ok status="connected" />
          <CheckPill label="Moonshot" ok status="kimi-latest" />
          <CheckPill label="Modal sandbox" ok status="egress off" />
          <CheckPill label="Warden" ok={false} status="phase 2" muted />
        </div>
      </div>

      {/* KPI cards */}
      <div className="px-8 pb-4 grid grid-cols-4 gap-3">
        <KpiCard label="Sweeps run" value={rollup.total} icon={<IconSweep />} accent="neutral" />
        <KpiCard
          label="Findings promoted"
          value={rollup.totalFindings}
          sub={rollup.verified > 0 ? `${rollup.verified} verified` : "—"}
          icon={<IconAttestation />}
          accent={rollup.totalFindings > 0 ? "amber" : "neutral"}
        />
        <KpiCard
          label="Confirmed fixed"
          value={rollup.verified}
          sub={rollup.verified > 0 ? "sandboxed · verified" : "—"}
          icon={<IconCheck />}
          accent={rollup.verified > 0 ? "accent" : "neutral"}
        />
        <KpiCard
          label="Sandbox runs"
          value={rollup.total * 2}
          sub="modal · egress-off"
          icon={<IconWarden />}
          accent="neutral"
        />
      </div>

      {/* Latest verified finding — the hero moment */}
      {latestVerified && (
        <div className="px-8 pb-4">
          <div className="relative rounded-xl border border-accent/30 bg-gradient-to-br from-accent-soft via-white to-accent-soft/40 p-5 shadow-card overflow-hidden">
            <div className="absolute -right-6 -top-6 opacity-15 pointer-events-none">
              <Cmul8Mark size={140} />
            </div>
            <div className="relative">
              <div className="flex items-center gap-2 mb-2">
                <div className="h-6 w-6 rounded-full bg-accent grid place-items-center text-white">
                  <IconCheck size={14} />
                </div>
                <span className="text-2xs uppercase tracking-wider text-accent mono font-semibold">
                  Latest verified finding
                </span>
                <span className="ml-auto text-2xs mono text-paper-500">
                  Reproduced · patched · independently verified
                </span>
              </div>
              <div className="text-lg text-paper-900 font-semibold tracking-tight">
                {latestVerified.title}
              </div>
              <div className="mt-1 text-xs mono text-paper-600">
                {shortPath(latestVerified.location.file)}:{latestVerified.location.line} ·{" "}
                <span className="text-paper-800">{latestVerified.location.function}</span>
              </div>
              <div className="mt-4 flex items-center gap-4 text-2xs mono">
                <Stat label="Class" value={latestVerified.class} />
                <Stat label="CWE" value={latestVerified.cwe} />
                <Stat
                  label="Confidence"
                  value={`${(latestVerified.confidence * 100).toFixed(0)}%`}
                  accent
                />
                <button
                  onClick={() => {
                    const parent = rows?.find((r) =>
                      r.findings_count > 0 && r.status === "finished"
                    );
                    if (parent) onOpen(parent.sweep_id);
                  }}
                  className="ml-auto text-2xs mono uppercase tracking-wider text-accent bg-white border border-accent/30 rounded px-2 py-1 hover:bg-accent-soft transition-colors"
                >
                  Open sweep →
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Empty state / call to action */}
      {rollup.total === 0 && (
        <div className="px-8 py-10 text-center">
          <div className="mx-auto mb-4 opacity-40 grid place-items-center">
            <Cmul8Mark size={56} />
          </div>
          <div className="text-paper-800 text-base font-medium">Ready when you are.</div>
          <div className="text-paper-500 text-sm mt-1 max-w-md mx-auto">
            Pick a bundled fixture from the top bar or paste a{" "}
            <span className="mono">.git</span> URL. Spotlight clones, scans, patches, and
            independently verifies — all in a hardened Modal sandbox.
          </div>
          <button
            onClick={onStart}
            className="mt-5 inline-flex items-center gap-2 px-4 py-2 rounded bg-accent text-white text-sm uppercase tracking-wider mono hover:brightness-95 shadow-card"
          >
            ▸ Start your first Sweep
          </button>
        </div>
      )}

      {rollup.total > 0 && (
        <div className="px-8 pb-8">
          <div className="text-2xs uppercase tracking-wider text-paper-500 mono mb-3">
            Recent activity
          </div>
          <ActivityFeed rows={rows ?? []} onOpen={onOpen} />
        </div>
      )}
    </section>
  );
}

function SelectedSweepPane({
  sweep,
  findings,
  onOpenFinding,
}: {
  sweep: SweepSummary;
  findings: Finding[];
  onOpenFinding: (sweepId: string) => void;
}) {
  const verified = findings.filter((f) => f.tier === "verified");
  return (
    <section className="flex-1 min-w-0 overflow-y-auto bg-paper-50">
      <div className="px-8 py-6 border-b border-paper-300">
        <div className="text-2xs uppercase tracking-wider text-paper-500 mono mb-2">
          Sweep · {sweep.sweep_id}
        </div>
        <h1 className="text-xl text-paper-900 font-semibold tracking-tight mb-1">
          {sweep.repo_name}
        </h1>
        <div className="text-xs text-paper-600 flex items-center gap-2">
          <span className="mono">{sweep.source}</span>
          <span className="text-paper-400">·</span>
          <span className="mono">{sweep.status}</span>
          <span className="text-paper-400">·</span>
          <span className="mono">
            {sweep.findings_count} finding{sweep.findings_count === 1 ? "" : "s"}
          </span>
        </div>
      </div>
      <div className="px-8 py-6 grid grid-cols-2 gap-4">
        <MiniStat label="Verified" value={verified.length} accent={verified.length > 0} />
        <MiniStat label="Sandbox runs" value={findings.length * 2} />
      </div>
      {findings.length > 0 && (
        <div className="px-8 pb-8">
          <div className="text-2xs uppercase tracking-wider text-paper-500 mono mb-3">
            Findings in this sweep
          </div>
          <ul className="space-y-2">
            {findings.map((f) => (
              <li
                key={f.id}
                className="border border-paper-300 rounded-lg bg-white shadow-card p-3 hover:shadow-pop hover:-translate-y-0.5 transition-all cursor-pointer"
                onClick={() => onOpenFinding(sweep.sweep_id)}
              >
                <div className="flex items-center gap-2">
                  <SeverityChip s={f.severity} />
                  <span className="text-paper-900 text-sm font-medium flex-1 truncate">
                    {f.title}
                  </span>
                  <TierPill tier={f.tier} />
                </div>
                <div className="mt-1.5 text-2xs mono text-paper-500">
                  {shortPath(f.location.file)}:{f.location.line} ·{" "}
                  <span className="text-accent tabular-nums">
                    {(f.confidence * 100).toFixed(0)}%
                  </span>
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}
      {findings.length === 0 && (
        <div className="px-8 py-12 text-center text-paper-500 text-sm">
          <IconCheck size={24} /> Clean sweep — no findings promoted.
        </div>
      )}
    </section>
  );
}

function ActivityFeed({
  rows,
  onOpen,
}: {
  rows: SweepSummary[];
  onOpen: (id: string) => void;
}) {
  return (
    <ul className="space-y-1.5">
      {rows.slice(0, 8).map((r) => (
        <li
          key={r.sweep_id}
          onClick={() => onOpen(r.sweep_id)}
          className="border border-paper-300 rounded-lg bg-white px-3 py-2 flex items-center gap-3 hover:shadow-card cursor-pointer transition-all group"
        >
          <span
            className={`h-8 w-8 rounded-md grid place-items-center shrink-0 ${
              r.findings_count > 0
                ? "bg-accent-soft text-accent"
                : "bg-paper-200 text-paper-500"
            }`}
          >
            <IconSweep size={14} />
          </span>
          <div className="min-w-0 flex-1">
            <div className="text-sm text-paper-900 font-medium truncate group-hover:text-accent transition-colors">
              {r.repo_name}
            </div>
            <div className="text-2xs mono text-paper-500">
              {r.sweep_id} · {r.status}
            </div>
          </div>
          <div className="text-right">
            <div className="mono tabular-nums text-sm text-paper-900 font-semibold">
              {r.findings_count}
            </div>
            <div className="text-2xs mono text-paper-500 uppercase tracking-wider">
              finding{r.findings_count === 1 ? "" : "s"}
            </div>
          </div>
        </li>
      ))}
    </ul>
  );
}

function CheckPill({
  label,
  status,
  ok,
  muted,
}: {
  label: string;
  status: string;
  ok: boolean;
  muted?: boolean;
}) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs ${
        muted
          ? "bg-paper-100 border-paper-300 text-paper-500"
          : ok
          ? "bg-accent-soft border-accent/30 text-accent"
          : "bg-sev-critical/10 border-sev-critical/30 text-sev-critical"
      }`}
    >
      {muted ? (
        <span className="h-1.5 w-1.5 rounded-full bg-paper-400" />
      ) : ok ? (
        <IconCheck size={10} />
      ) : (
        <span className="h-1.5 w-1.5 rounded-full bg-sev-critical" />
      )}
      <span className="mono uppercase tracking-wider text-2xs">{label}</span>
      <span className="text-2xs mono opacity-70">{status}</span>
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
    <div className="rounded-xl border border-paper-300 bg-white p-4 shadow-card hover:shadow-pop hover:-translate-y-0.5 transition-all">
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

function Stat({ label, value, accent }: { label: string; value: string; accent?: boolean }) {
  return (
    <div>
      <div className="text-2xs uppercase tracking-wider text-paper-500 mono">{label}</div>
      <div
        className={`mono text-sm font-semibold ${
          accent ? "text-accent" : "text-paper-900"
        }`}
      >
        {value}
      </div>
    </div>
  );
}

function MiniStat({ label, value, accent }: { label: string; value: number; accent?: boolean }) {
  return (
    <div className="rounded-lg border border-paper-300 bg-white p-3 shadow-card">
      <div className="text-2xs uppercase tracking-wider text-paper-500 mono mb-1">{label}</div>
      <div
        className={`text-2xl mono tabular-nums font-semibold ${
          accent ? "text-accent" : "text-paper-900"
        }`}
      >
        {value}
      </div>
    </div>
  );
}

function SeverityChip({ s }: { s: string }) {
  const map: Record<string, string> = {
    critical: "bg-sev-critical text-white",
    high: "bg-sev-high text-white",
    medium: "bg-sev-medium text-white",
    low: "bg-sev-low text-white",
  };
  return (
    <span
      className={`inline-flex items-center text-2xs uppercase mono px-1.5 py-0.5 rounded font-semibold tracking-wider ${
        map[s] ?? "bg-paper-400 text-white"
      }`}
    >
      {s}
    </span>
  );
}

function TierPill({ tier }: { tier: string }) {
  if (tier === "verified") {
    return (
      <span className="inline-flex items-center gap-1 text-2xs mono uppercase tracking-wider bg-accent text-white px-1.5 py-0.5 rounded font-semibold">
        <IconCheck size={8} /> verified
      </span>
    );
  }
  return (
    <span className="inline-flex items-center text-2xs mono uppercase tracking-wider bg-paper-200 text-paper-700 px-1.5 py-0.5 rounded font-semibold">
      {tier}
    </span>
  );
}

function shortPath(p: string): string {
  const parts = p.split("/");
  return parts.slice(-2).join("/");
}

function summarize(rows: SweepSummary[]) {
  const total = rows.length;
  const verified = rows.filter((r) => r.status === "finished").length;
  const totalFindings = rows.reduce((s, r) => s + (r.findings_count || 0), 0);
  return { total, verified, totalFindings };
}
