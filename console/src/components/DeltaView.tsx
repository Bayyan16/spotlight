import { useEffect, useMemo, useState } from "react";

import {
  getSweepDelta,
  listSweeps,
  type DeltaFinding,
  type SweepDelta,
  type SweepSummary,
} from "../lib/api";

/**
 * C6 · Delta View — compare two sweeps.
 *
 * Three columns:
 *   NEW         findings introduced since `since`
 *   RESOLVED    findings gone since `since`
 *   STILL OPEN  findings in both, not analyst-suppressed
 *
 * The "still open" column is the recurring-value story — you get a shorter
 * inbox every sweep, and the delta explains what changed.
 */
export function DeltaView() {
  const [sweeps, setSweeps] = useState<SweepSummary[] | null>(null);
  const [currId, setCurrId] = useState<string>("");
  const [sinceId, setSinceId] = useState<string>("");
  const [delta, setDelta] = useState<SweepDelta | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    listSweeps().then((rows) => {
      const list = Array.isArray(rows) ? rows : [];
      setSweeps(list);
      // Default: latest two sweeps on the same repo. Falls back to global
      // latest+previous when only one repo has ≥ 2 sweeps.
      const byRepo = new Map<string, SweepSummary[]>();
      for (const s of list) {
        const arr = byRepo.get(s.repo_name) ?? [];
        arr.push(s);
        byRepo.set(s.repo_name, arr);
      }
      for (const arr of byRepo.values()) {
        if (arr.length >= 2) {
          arr.sort((a, b) => (b.started_at ?? "").localeCompare(a.started_at ?? ""));
          setCurrId(arr[0].sweep_id);
          setSinceId(arr[1].sweep_id);
          return;
        }
      }
      if (list.length >= 2) {
        const sorted = [...list].sort((a, b) =>
          (b.started_at ?? "").localeCompare(a.started_at ?? "")
        );
        setCurrId(sorted[0].sweep_id);
        setSinceId(sorted[1].sweep_id);
      }
    });
  }, []);

  useEffect(() => {
    if (!currId || !sinceId) return;
    setLoading(true);
    setErr(null);
    getSweepDelta(currId, sinceId)
      .then((d) => {
        if (!d) {
          setErr("delta not available — check both sweep ids exist");
          setDelta(null);
        } else {
          setDelta(d);
        }
      })
      .finally(() => setLoading(false));
  }, [currId, sinceId]);

  const options = useMemo(
    () =>
      (sweeps ?? []).map((s) => ({
        value: s.sweep_id,
        label: `${s.repo_name} · ${s.sweep_id.slice(0, 14)} · ${s.findings_count}f`,
      })),
    [sweeps]
  );

  return (
    <section className="flex-1 min-w-0 overflow-y-auto bg-paper-50">
      <header className="border-b border-paper-300 px-8 py-5 sticky top-0 bg-paper-50/95 backdrop-blur z-10">
        <div className="flex items-baseline gap-3">
          <h1 className="text-xl text-paper-900 font-semibold tracking-tight">Delta</h1>
          <span className="text-xs text-paper-500">
            What changed between two sweeps — new / resolved / still open.
          </span>
        </div>
        <div className="mt-4 flex items-center gap-3 text-xs text-paper-700">
          <label className="flex items-center gap-2">
            <span className="mono text-2xs uppercase tracking-wider text-paper-500">Since</span>
            <select
              value={sinceId}
              onChange={(e) => setSinceId(e.target.value)}
              className="border border-paper-300 rounded px-2 py-1 text-xs"
            >
              <option value="">— pick previous sweep —</option>
              {options.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </label>
          <span className="text-paper-400">→</span>
          <label className="flex items-center gap-2">
            <span className="mono text-2xs uppercase tracking-wider text-paper-500">Current</span>
            <select
              value={currId}
              onChange={(e) => setCurrId(e.target.value)}
              className="border border-paper-300 rounded px-2 py-1 text-xs"
            >
              <option value="">— pick current sweep —</option>
              {options.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </label>
        </div>
        {delta && (
          <div className="mt-3 flex items-center gap-6 text-2xs mono uppercase tracking-wider">
            <span>
              New{" "}
              <span className="tabular-nums text-sev-critical font-semibold">
                {delta.counts.new}
              </span>
            </span>
            <span>
              Resolved{" "}
              <span className="tabular-nums text-accent font-semibold">
                {delta.counts.resolved}
              </span>
            </span>
            <span>
              Still open{" "}
              <span className="tabular-nums text-paper-900 font-semibold">
                {delta.counts.still_open}
              </span>
            </span>
          </div>
        )}
      </header>

      <div className="px-8 py-6">
        {loading && <div className="text-paper-500 text-sm italic">Loading…</div>}
        {err && <div className="text-sm text-sev-high">{err}</div>}
        {delta && !loading && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <Column label="New" tone="critical" rows={delta.new} />
            <Column label="Resolved" tone="ok" rows={delta.resolved} />
            <Column label="Still open" tone="neutral" rows={delta.still_open} />
          </div>
        )}
        {!delta && !loading && !err && (
          <div className="text-paper-500 text-sm italic mt-4">
            Pick two sweeps above to see the diff.
          </div>
        )}
      </div>
    </section>
  );
}

function Column({
  label,
  tone,
  rows,
}: {
  label: string;
  tone: "critical" | "ok" | "neutral";
  rows: DeltaFinding[];
}) {
  const toneCls =
    tone === "critical"
      ? "border-sev-critical/30 bg-red-50/40"
      : tone === "ok"
        ? "border-accent/30 bg-accent-soft/40"
        : "border-paper-300 bg-white";
  return (
    <div className={`border rounded-xl ${toneCls}`}>
      <div className="px-4 py-3 border-b border-paper-200 flex items-center justify-between">
        <span className="mono text-2xs uppercase tracking-wider text-paper-700">{label}</span>
        <span className="tabular-nums text-sm text-paper-900 font-semibold">{rows.length}</span>
      </div>
      {rows.length === 0 ? (
        <div className="px-4 py-6 text-2xs mono uppercase tracking-wider text-paper-400">none</div>
      ) : (
        <ul className="divide-y divide-paper-200">
          {rows.map((r) => (
            <li key={r.id} className="px-4 py-2 text-xs">
              <div className="flex items-center gap-2">
                <span className="mono text-2xs text-paper-500">{r.id}</span>
                <span className="mono text-2xs uppercase tracking-wider text-paper-700">
                  {r.class}
                </span>
                <SevChip s={r.severity} />
                {r.review_state && (
                  <span className="text-2xs mono uppercase tracking-wider text-paper-500 border border-paper-300 rounded-full px-1.5">
                    {r.review_state}
                  </span>
                )}
              </div>
              <div className="mt-1 text-2xs mono text-paper-500 truncate">
                {r.file}:{r.line} · {r.function}
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function SevChip({ s }: { s: string }) {
  const map: Record<string, string> = {
    critical: "bg-sev-critical text-white",
    high: "bg-sev-high text-white",
    medium: "bg-sev-medium text-white",
    low: "bg-sev-low text-white",
  };
  return (
    <span
      className={`text-2xs uppercase mono px-1.5 py-0.5 rounded font-semibold tracking-wider ${
        map[s] ?? "bg-paper-400 text-white"
      }`}
    >
      {s}
    </span>
  );
}
