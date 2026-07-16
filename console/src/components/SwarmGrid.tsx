import type { SweepEvent } from "../lib/api";

type Agent = { role: string; status: string; last: string };

export function SwarmGrid({ events }: { events: SweepEvent[] }) {
  const agents = buildAgents(events);
  return (
    <div className="rounded-md border border-paper-300 bg-white shadow-card">
      <div className="px-4 py-2.5 border-b border-paper-200 text-2xs uppercase tracking-wider text-paper-500 mono">
        Swarm
      </div>
      <div className="p-3 grid grid-cols-1 sm:grid-cols-2 gap-2">
        {agents.map((a, i) => (
          <AgentCard key={`${a.role}-${i}`} agent={a} />
        ))}
        {agents.length === 0 && (
          <div className="col-span-full text-xs italic text-paper-500 p-4">No agents spawned yet.</div>
        )}
      </div>
    </div>
  );
}

function AgentCard({ agent }: { agent: Agent }) {
  const color =
    agent.status === "finished"
      ? "bg-accent"
      : agent.status === "failed"
      ? "bg-sev-critical"
      : "bg-sev-medium animate-pulse";
  return (
    <div className="border border-paper-200 rounded p-2.5 bg-paper-100/50">
      <div className="flex items-center gap-2 mb-1">
        <span className={`h-2 w-2 rounded-full ${color}`} />
        <span className="mono text-2xs uppercase tracking-wider text-paper-700 font-semibold">
          {agent.role}
        </span>
        <span className="ml-auto mono text-2xs text-paper-500">{agent.status}</span>
      </div>
      <div className="mono text-2xs text-paper-500 truncate" title={agent.last}>
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
      const last = [...roles].reverse().find((a) => a.role === e.actor);
      if (last) last.status = "finished";
    }
    if (e.type === "candidate.raised" || e.type === "repro.result" || e.type === "verify.result") {
      const target = e.actor;
      const last = [...roles].reverse().find((a) => a.role === target);
      if (last) last.last = `${e.type} ${JSON.stringify(e.payload).slice(0, 60)}`;
    }
  }
  return roles;
}
