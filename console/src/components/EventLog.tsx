import type { SweepEvent } from "../lib/api";

export function EventLog({ events }: { events: SweepEvent[] }) {
  return (
    <div className="border border-ink-800 rounded-md p-4 bg-ink-900 max-h-[400px] overflow-y-auto">
      <div className="text-xs uppercase tracking-wider text-ink-400 mb-3 mono">Event stream</div>
      <ul className="space-y-1 mono text-[11px]">
        {events.map((e) => (
          <li key={e.seq} className="flex gap-3">
            <span className="text-ink-500 w-8 text-right">{e.seq}</span>
            <span className={typeColor(e.type)}>{e.type}</span>
            <span className="text-ink-500">·</span>
            <span className="text-ink-400">{e.actor}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function typeColor(t: string) {
  if (t.startsWith("warden.")) return "text-spot-amber";
  if (t.startsWith("finding.") || t.startsWith("candidate.")) return "text-spot-green";
  if (t.startsWith("sweep.failed")) return "text-spot-red";
  return "text-ink-300";
}
