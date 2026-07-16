import type { SweepEvent } from "../lib/api";

export function EventLog({ events }: { events: SweepEvent[] }) {
  return (
    <div className="rounded-md border border-paper-300 bg-white shadow-card">
      <div className="px-4 py-2.5 border-b border-paper-200 text-2xs uppercase tracking-wider text-paper-500 mono">
        Event stream
      </div>
      <div className="max-h-[340px] overflow-y-auto">
        <ul className="mono text-2xs">
          {events.map((e) => (
            <li
              key={e.seq}
              className="px-4 py-1 flex items-center gap-3 border-b border-paper-200 last:border-none"
            >
              <span className="text-paper-500 w-8 text-right">{e.seq}</span>
              <span className={typeColor(e.type) + " w-56 shrink-0"}>{e.type}</span>
              <span className="text-paper-500">·</span>
              <span className="text-paper-700 truncate">{e.actor}</span>
            </li>
          ))}
          {events.length === 0 && (
            <li className="px-4 py-6 text-paper-500 italic">Events will appear here as the sweep runs.</li>
          )}
        </ul>
      </div>
    </div>
  );
}

function typeColor(t: string) {
  if (t.startsWith("warden.")) return "text-sev-medium";
  if (t.startsWith("finding.") || t.startsWith("candidate.")) return "text-accent";
  if (t.startsWith("sweep.failed")) return "text-sev-critical";
  if (t.startsWith("verify.")) return "text-paper-900";
  return "text-paper-700";
}
