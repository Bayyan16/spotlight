import type { SweepEvent } from "../lib/api";
import { PhaseTracker } from "./PhaseTracker";
import { SwarmGrid } from "./SwarmGrid";
import { EventLog } from "./EventLog";

export function LiveSweepPanel({ events }: { events: SweepEvent[] }) {
  const finished = events.some((e) => e.type === "sweep.finished");
  return (
    <section className="flex-1 min-w-0 overflow-y-auto bg-paper-50">
      <div className="px-6 py-4 border-b border-paper-300">
        <div className="flex items-center gap-2 mb-1">
          <span
            className={`h-2 w-2 rounded-full ${
              finished ? "bg-accent" : "bg-sev-medium animate-pulse"
            }`}
          />
          <h1 className="text-lg text-paper-900 font-semibold tracking-tight">
            {finished ? "Sweep complete" : "Sweep in progress"}
          </h1>
        </div>
        <p className="text-xs text-paper-600">
          Reasoning over the code graph, corroborating candidates, reproducing where feasible,
          patching, and independently verifying — live.
        </p>
      </div>

      <div className="p-6 space-y-4">
        <PhaseTracker events={events} />
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <SwarmGrid events={events} />
          <EventLog events={events} />
        </div>
      </div>
    </section>
  );
}
