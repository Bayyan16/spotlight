import { IconChevron, IconPlay } from "./Icons";
import type { Target } from "../lib/api";

export function TopBar({
  running,
  onStart,
  target,
  onTarget,
  targets,
  sweepId,
}: {
  running: boolean;
  onStart: () => void;
  target: string;
  onTarget: (t: string) => void;
  targets: Target[];
  sweepId: string | null;
}) {
  return (
    <header className="h-12 shrink-0 border-b border-paper-300 bg-paper-50 px-4 flex items-center gap-2 text-sm">
      <div className="flex items-center gap-1.5 text-paper-600">
        <span className="text-paper-800 font-medium">CMUL8</span>
        <IconChevron />
        <span className="mono text-paper-700">{target}</span>
        {sweepId && (
          <>
            <IconChevron />
            <span className="mono text-paper-500 text-xs">{sweepId}</span>
          </>
        )}
      </div>

      <div className="ml-auto flex items-center gap-2">
        <select
          className="bg-paper-100 border border-paper-300 hover:border-paper-400 text-paper-800 text-xs rounded px-2 py-1 mono"
          value={target}
          onChange={(e) => onTarget(e.target.value)}
          disabled={running}
        >
          {targets.map((t) => (
            <option key={t.name} value={t.name}>
              {t.name}
            </option>
          ))}
        </select>
        <button
          onClick={onStart}
          disabled={running}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs uppercase tracking-wider mono transition-colors ${
            running
              ? "bg-paper-200 text-paper-500 cursor-not-allowed"
              : "bg-accent text-white hover:brightness-95"
          }`}
        >
          <IconPlay />
          {running ? "Sweeping…" : "Start Sweep"}
        </button>
      </div>
    </header>
  );
}
