import { useEffect, useState } from "react";
import { deleteSweep, listSweeps, type SweepSummary } from "../lib/api";
import { IconAlert } from "./Icons";

export function SweepsHistory({
  onOpen,
  refreshSignal,
}: {
  onOpen: (sweepId: string) => void;
  refreshSignal: number;
}) {
  const [rows, setRows] = useState<SweepSummary[]>([]);
  const [busy, setBusy] = useState<string | null>(null);

  useEffect(() => {
    listSweeps().then(setRows);
  }, [refreshSignal]);

  async function onDelete(id: string) {
    if (!confirm(`Delete sweep ${id}?`)) return;
    setBusy(id);
    try {
      await deleteSweep(id);
      setRows((prev) => prev.filter((r) => r.sweep_id !== id));
    } finally {
      setBusy(null);
    }
  }

  return (
    <section className="flex-1 min-w-0 overflow-y-auto bg-paper-50">
      <header className="border-b border-paper-300 px-6 py-4 sticky top-0 bg-paper-50/90 backdrop-blur">
        <h1 className="text-lg text-paper-900 font-semibold tracking-tight">Sweeps</h1>
        <p className="text-xs text-paper-600">
          Every sweep this workspace has run, persisted. Click a row to open its findings.
        </p>
      </header>

      <div className="px-6 py-4">
        {rows.length === 0 && (
          <div className="text-center py-16 text-paper-500 text-sm">
            <IconAlert size={16} />
            <div className="mt-2">No sweeps yet. Kick one off from the top bar.</div>
          </div>
        )}
        {rows.length > 0 && (
          <div className="border border-paper-300 rounded-md bg-white shadow-card overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-paper-100 border-b border-paper-300 text-2xs uppercase tracking-wider text-paper-500 mono">
                <tr>
                  <th className="text-left px-4 py-2">Sweep</th>
                  <th className="text-left px-4 py-2">Target</th>
                  <th className="text-left px-4 py-2">Source</th>
                  <th className="text-left px-4 py-2">Status</th>
                  <th className="text-right px-4 py-2">Findings</th>
                  <th className="text-left px-4 py-2">Started</th>
                  <th className="px-4 py-2"></th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr
                    key={r.sweep_id}
                    className="border-b border-paper-200 last:border-none hover:bg-paper-100/60 cursor-pointer"
                    onClick={() => onOpen(r.sweep_id)}
                  >
                    <td className="px-4 py-2.5 mono text-xs text-paper-700">{r.sweep_id}</td>
                    <td className="px-4 py-2.5 text-paper-900">{r.repo_name}</td>
                    <td className="px-4 py-2.5 mono text-2xs text-paper-500 uppercase">
                      {r.source}
                    </td>
                    <td className="px-4 py-2.5">
                      <StatusPill status={r.status} />
                    </td>
                    <td className="px-4 py-2.5 mono text-right text-paper-800">
                      {r.findings_count}
                    </td>
                    <td className="px-4 py-2.5 mono text-2xs text-paper-500">
                      {r.started_at ? new Date(r.started_at).toLocaleString() : "—"}
                    </td>
                    <td className="px-2 py-2.5 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onDelete(r.sweep_id);
                        }}
                        disabled={busy === r.sweep_id}
                        className="text-2xs mono uppercase text-paper-500 hover:text-sev-critical px-2 py-1 rounded"
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

function StatusPill({ status }: { status: string }) {
  const map: Record<string, string> = {
    finished: "bg-accent-soft text-accent border-accent/30",
    running: "bg-amber-50 text-sev-medium border-sev-medium/30 animate-pulse",
    failed: "bg-sev-critical/15 text-sev-critical border-sev-critical/30",
  };
  return (
    <span className={`text-2xs mono uppercase px-1.5 py-0.5 rounded border ${map[status] ?? ""}`}>
      {status}
    </span>
  );
}
