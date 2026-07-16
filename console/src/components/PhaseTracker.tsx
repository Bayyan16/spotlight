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
    <div className="rounded-md border border-paper-300 bg-white shadow-card p-4">
      <div className="text-2xs uppercase tracking-wider text-paper-500 mono mb-3">Sweep phases</div>
      <ol className="flex items-center flex-wrap gap-1.5">
        {PHASES.map((p, i) => {
          const state = phaseState(p, current, finished);
          return (
            <li key={p} className="flex items-center gap-1.5">
              <span
                className={`px-2.5 py-1 rounded-full border text-2xs mono uppercase tracking-wider transition-colors ${
                  state === "done"
                    ? "border-accent/40 text-accent bg-accent-soft"
                    : state === "active"
                    ? "border-sev-medium/60 text-sev-medium bg-amber-50 animate-pulse"
                    : "border-paper-300 text-paper-500 bg-paper-100"
                }`}
              >
                {state === "done" ? "✓ " : state === "active" ? "▸ " : ""}
                {p}
              </span>
              {i < PHASES.length - 1 && <span className="text-paper-400">·</span>}
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

function phaseState(
  p: Phase,
  current: Phase | null,
  finished: boolean
): "done" | "active" | "pending" {
  if (finished) return "done";
  if (!current) return "pending";
  const currentIdx = PHASES.indexOf(current);
  const idx = PHASES.indexOf(p);
  if (idx < currentIdx) return "done";
  if (idx === currentIdx) return "active";
  return "pending";
}
