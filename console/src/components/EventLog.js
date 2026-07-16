import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
export function EventLog({ events }) {
    return (_jsxs("div", { className: "border border-ink-800 rounded-md p-4 bg-ink-900 max-h-[400px] overflow-y-auto", children: [_jsx("div", { className: "text-xs uppercase tracking-wider text-ink-400 mb-3 mono", children: "Event stream" }), _jsx("ul", { className: "space-y-1 mono text-[11px]", children: events.map((e) => (_jsxs("li", { className: "flex gap-3", children: [_jsx("span", { className: "text-ink-500 w-8 text-right", children: e.seq }), _jsx("span", { className: typeColor(e.type), children: e.type }), _jsx("span", { className: "text-ink-500", children: "\u00B7" }), _jsx("span", { className: "text-ink-400", children: e.actor })] }, e.seq))) })] }));
}
function typeColor(t) {
    if (t.startsWith("warden."))
        return "text-spot-amber";
    if (t.startsWith("finding.") || t.startsWith("candidate."))
        return "text-spot-green";
    if (t.startsWith("sweep.failed"))
        return "text-spot-red";
    return "text-ink-300";
}
