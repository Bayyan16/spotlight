import { useEffect, useState } from "react";
import { cleanupSweeps, deleteSweep, listSweeps, type SweepSummary } from "../lib/api";
import { IconAlert, IconCheck, IconSweep } from "./Icons";

/**
 * Compact sweep list for the middle pane. Header + scrollable list of
 * clickable rows with a colored left-rail per row (accent when the sweep
 * has findings, muted when clean). Selected row gets a subtle shadow.
 */
export function SweepsList({
  onOpen,
  onSelect,
  selected,
  refreshSignal,
}: {
  onOpen: (id: string) => void;
  onSelect: (row: SweepSummary | null) => void;
  selected: string | null;
  refreshSignal: number;
}) {
  const [rows, setRows] = useState<SweepSummary[] | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  useEffect(() => {
    listSweeps()
      .then((d) => setRows(Array.isArray(d) ? d : []))
      .catch(() => setRows([]));
  }, [refreshSignal]);

  useEffect(() => {
    if (rows && rows.length > 0 && !selected) onSelect(rows[0]);
  }, [rows, selected, onSelect]);

  const failed = (rows ?? []).filter((r) => r.status === "failed").length;

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

  return (
    <section className="w-[360px] shrink-0 border-r border-paper-300 bg-paper-100/40 flex flex-col overflow-hidden">
      <div className="h-11 shrink-0 border-b border-paper-300 px-3 flex items-center gap-2 bg-paper-50/70 backdrop-blur">
        <IconSweep size={14} />
        <span className="text-2xs uppercase tracking-wider text-paper-700 mono font-semibold">
          Sweeps
        </span>
        <span className="ml-auto text-2xs mono text-paper-500 tabular-nums">
          {rows === null ? "…" : rows.length}
        </span>
        {failed > 0 && (
          <button
            onClick={async () => {
              if (!confirm(`Clear ${failed} failed sweep${failed === 1 ? "" : "s"}?`)) return;
              await cleanupSweeps("failed");
              const fresh = await listSweeps();
              setRows(Array.isArray(fresh) ? fresh : []);
            }}
            className="text-2xs mono uppercase text-sev-critical/70 hover:text-sev-critical px-1.5 py-0.5 rounded border border-sev-critical/20 hover:border-sev-critical/40"
            title="Clear stuck/failed sweeps"
          >
            {failed} failed
          </button>
        )}
      </div>

      <div className="overflow-y-auto flex-1">
        {rows === null && (
          <ul>
            {[0, 1, 2].map((i) => (
              <li key={i} className="px-3 py-3 border-b border-paper-200">
                <div className="skeleton h-3 w-3/4 mb-2" />
                <div className="skeleton h-2 w-1/2" />
              </li>
            ))}
          </ul>
        )}
        {rows !== null && rows.length === 0 && (
          <div className="text-center py-10 px-4 text-paper-500 text-xs">
            No sweeps yet. Kick one off from the top bar.
          </div>
        )}
        {rows !== null && rows.length > 0 && (
          <ul>
            {rows.map((r) => (
              <SweepRow
                key={r.sweep_id}
                row={r}
                active={selected === r.sweep_id}
                busy={busy === r.sweep_id}
                onClick={() => {
                  onSelect(r);
                }}
                onOpen={() => onOpen(r.sweep_id)}
                onDelete={() => onDelete(r.sweep_id)}
              />
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}

function SweepRow({
  row,
  active,
  busy,
  onClick,
  onOpen,
  onDelete,
}: {
  row: SweepSummary;
  active: boolean;
  busy: boolean;
  onClick: () => void;
  onOpen: () => void;
  onDelete: () => void;
}) {
  const hasFindings = row.findings_count > 0;
  const railColor = hasFindings
    ? "bg-accent"
    : row.status === "failed"
    ? "bg-sev-critical"
    : row.status === "running"
    ? "bg-sev-medium"
    : "bg-paper-300";
  return (
    <li className="relative group">
      <span
        className={`absolute left-0 top-0 bottom-0 w-[3px] ${railColor} ${
          active ? "opacity-100" : "opacity-60"
        }`}
        aria-hidden
      />
      <button
        onClick={onClick}
        onDoubleClick={onOpen}
        className={`w-full text-left pl-3.5 pr-3 py-2.5 border-b border-paper-200 transition-colors ${
          active ? "bg-white shadow-card" : "hover:bg-paper-100"
        }`}
      >
        <div className="flex items-center gap-2 mb-1">
          <span className="text-sm text-paper-900 font-medium truncate">{row.repo_name}</span>
          <span className="ml-auto flex items-center gap-1">
            {hasFindings ? (
              <span className="mono text-xs tabular-nums text-accent font-semibold">
                {row.findings_count}
              </span>
            ) : (
              <IconCheck size={12} />
            )}
          </span>
        </div>
        <div className="flex items-center gap-1.5 text-2xs mono text-paper-500">
          <StatusDot status={row.status} />
          <span className="uppercase tracking-wider">{row.status}</span>
          <span className="text-paper-400">·</span>
          <span>{row.source}</span>
          <span className="text-paper-400 ml-auto">
            {row.started_at ? relativeTime(row.started_at) : "—"}
          </span>
        </div>
      </button>
      <button
        onClick={onDelete}
        disabled={busy}
        title="Delete"
        className="absolute right-2 top-2 opacity-0 group-hover:opacity-100 text-2xs mono uppercase text-paper-400 hover:text-sev-critical px-1 py-0.5 rounded transition-all"
      >
        {busy ? "…" : "×"}
      </button>
    </li>
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
  return <span className={`h-1.5 w-1.5 rounded-full ${color}`} />;
}

function relativeTime(iso: string): string {
  const then = new Date(iso).getTime();
  const now = Date.now();
  const s = Math.max(0, Math.round((now - then) / 1000));
  if (s < 60) return `${s}s`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h`;
  return `${Math.round(h / 24)}d`;
}
