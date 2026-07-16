import type { SweepEvent } from "../lib/api";

const PHASES = [
  "recon",
  "investigate",
  "reduce",
  "reproduce",
  "remediate",
  "verify",
  "attest",
] as const;

type Phase = (typeof PHASES)[number];

export function PhaseTracker({ events }: { events: SweepEvent[] }) {
  const current = currentPhase(events);
  const finished = events.some((e) => e.type === "sweep.finished");
  return (
    <div className="border border-ink-800 rounded-md p-4 bg-ink-900">
      <div className="text-xs uppercase tracking-wider text-ink-400 mb-3 mono">Sweep Phases</div>
      <ol className="flex gap-2 flex-wrap">
        {PHASES.map((p) => {
          const state = phaseState(p, current, finished);
          return (
            <li
              key={p}
              className={`px-3 py-1.5 rounded border mono text-xs transition-colors
                ${state === "done" ? "border-spot-green/40 text-spot-green bg-spot-green/5" : ""}
                ${state === "active" ? "border-spot-green text-spot-green bg-spot-green/10 animate-pulse" : ""}
                ${state === "pending" ? "border-ink-700 text-ink-500" : ""}`}
            >
              {state === "done" ? "✓ " : state === "active" ? "▸ " : ""}
              {p}
            </li>
          );
        })}
      </ol>
    </div>
  );
}

function currentPhase(events: SweepEvent[]): Phase | null {
  for (let i = events.length - 1; i >= 0; i--) {
    const e = events[i];
    if (e.type === "sweep.phase.changed") {
      const p = (e.payload as { phase?: string }).phase;
      if (p && (PHASES as readonly string[]).includes(p)) return p as Phase;
    }
  }
  return null;
}

function phaseState(p: Phase, current: Phase | null, finished: boolean): "done" | "active" | "pending" {
  if (finished) return "done";
  if (!current) return "pending";
  const currentIdx = PHASES.indexOf(current);
  const idx = PHASES.indexOf(p);
  if (idx < currentIdx) return "done";
  if (idx === currentIdx) return "active";
  return "pending";
}
