import type { SweepEvent } from "../lib/api";
import { PhaseTracker } from "./PhaseTracker";
import { SwarmGrid } from "./SwarmGrid";
import { EventLog } from "./EventLog";
import { Cmul8Mark } from "./Cmul8Mark";

export function LiveSweepPanel({ events, running }: { events: SweepEvent[]; running?: boolean }) {
  const finished = events.some((e) => e.type === "sweep.finished");
  const active = running && !finished;
  return (
    <section className="flex-1 min-w-0 overflow-y-auto bg-paper-50">
      <div className="px-6 py-4 border-b border-paper-300 flex items-center gap-3">
        <div className={active ? "" : "opacity-70"}>
          <Cmul8Mark size={22} active={active} />
        </div>
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <h1 className="text-lg text-paper-900 font-semibold tracking-tight">
              {finished ? "Sweep complete" : "Sweep in progress"}
            </h1>
            {active && (
              <span className="text-2xs mono uppercase tracking-wider text-accent bg-accent-soft border border-accent/30 rounded px-1.5 py-0.5 animate-pulse">
                Live
              </span>
            )}
          </div>
          <p className="text-xs text-paper-600">
            {active
              ? "Reasoning over the code graph, corroborating, reproducing, patching, verifying."
              : "Sweep finished. Findings promoted by the Consensus Kernel are in the list."}
          </p>
        </div>
        <div className="ml-auto flex items-center gap-3 text-2xs mono text-paper-500">
          <span>
            <span className="uppercase tracking-wider">events</span>{" "}
            <span className="text-paper-900 tabular-nums font-semibold">{events.length}</span>
          </span>
        </div>
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
