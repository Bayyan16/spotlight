import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
export function SwarmGrid({ events }) {
    const agents = buildAgents(events);
    return (_jsxs("div", { className: "border border-ink-800 rounded-md p-4 bg-ink-900", children: [_jsx("div", { className: "text-xs uppercase tracking-wider text-ink-400 mb-3 mono", children: "Swarm" }), _jsxs("div", { className: "grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3", children: [agents.map((a, i) => (_jsx(AgentCard, { agent: a }, `${a.role}-${i}`))), agents.length === 0 && (_jsx("div", { className: "text-ink-500 text-sm italic col-span-full", children: "No agents spawned yet." }))] })] }));
}
function AgentCard({ agent }) {
    const dotColor = agent.status === "finished"
        ? "bg-spot-green"
        : agent.status === "failed"
            ? "bg-spot-red"
            : "bg-spot-amber animate-pulse";
    return (_jsxs("div", { className: "border border-ink-700 rounded p-3 bg-ink-800", children: [_jsxs("div", { className: "flex items-center gap-2 mb-1", children: [_jsx("span", { className: `h-2 w-2 rounded-full ${dotColor}` }), _jsx("span", { className: "mono text-xs uppercase text-ink-300", children: agent.role })] }), _jsx("div", { className: "text-xs text-ink-500 truncate", title: agent.last, children: agent.last })] }));
}
function buildAgents(events) {
    const roles = [];
    for (const e of events) {
        if (e.type === "agent.spawned") {
            const role = e.payload.role ?? "?";
            roles.push({ role, status: "running", last: e.actor });
        }
        if (e.type === "agent.finished") {
            const last = roles.reverse().find((a) => a.role === e.actor);
            roles.reverse();
            if (last)
                last.status = "finished";
        }
        if (e.type === "candidate.raised" || e.type === "repro.result" || e.type === "verify.result") {
            const target = e.actor;
            const last = [...roles].reverse().find((a) => a.role === target);
            if (last)
                last.last = `${e.type} ${JSON.stringify(e.payload).slice(0, 80)}`;
        }
    }
    return roles;
}
