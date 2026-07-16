import type { SweepEvent } from "../lib/api";

type Agent = { role: string; status: string; last: string };

export function SwarmGrid({ events }: { events: SweepEvent[] }) {
  const agents = buildAgents(events);
  return (
    <div className="border border-ink-800 rounded-md p-4 bg-ink-900">
      <div className="text-xs uppercase tracking-wider text-ink-400 mb-3 mono">Swarm</div>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
        {agents.map((a, i) => (
          <AgentCard key={`${a.role}-${i}`} agent={a} />
        ))}
        {agents.length === 0 && (
          <div className="text-ink-500 text-sm italic col-span-full">No agents spawned yet.</div>
        )}
      </div>
    </div>
  );
}

function AgentCard({ agent }: { agent: Agent }) {
  const dotColor =
    agent.status === "finished"
      ? "bg-spot-green"
      : agent.status === "failed"
      ? "bg-spot-red"
      : "bg-spot-amber animate-pulse";
  return (
    <div className="border border-ink-700 rounded p-3 bg-ink-800">
      <div className="flex items-center gap-2 mb-1">
        <span className={`h-2 w-2 rounded-full ${dotColor}`} />
        <span className="mono text-xs uppercase text-ink-300">{agent.role}</span>
      </div>
      <div className="text-xs text-ink-500 truncate" title={agent.last}>
        {agent.last}
      </div>
    </div>
  );
}

function buildAgents(events: SweepEvent[]): Agent[] {
  const roles: Agent[] = [];
  for (const e of events) {
    if (e.type === "agent.spawned") {
      const role = (e.payload as { role?: string }).role ?? "?";
      roles.push({ role, status: "running", last: e.actor });
    }
    if (e.type === "agent.finished") {
      const last = roles.reverse().find((a) => a.role === e.actor);
      roles.reverse();
      if (last) last.status = "finished";
    }
    if (e.type === "candidate.raised" || e.type === "repro.result" || e.type === "verify.result") {
      const target = e.actor;
      const last = [...roles].reverse().find((a) => a.role === target);
      if (last) last.last = `${e.type} ${JSON.stringify(e.payload).slice(0, 80)}`;
    }
  }
  return roles;
}
