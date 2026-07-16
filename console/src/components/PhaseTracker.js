import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
const PHASES = [
    "recon",
    "investigate",
    "reduce",
    "reproduce",
    "remediate",
    "verify",
    "attest",
];
export function PhaseTracker({ events }) {
    const current = currentPhase(events);
    const finished = events.some((e) => e.type === "sweep.finished");
    return (_jsxs("div", { className: "border border-ink-800 rounded-md p-4 bg-ink-900", children: [_jsx("div", { className: "text-xs uppercase tracking-wider text-ink-400 mb-3 mono", children: "Sweep Phases" }), _jsx("ol", { className: "flex gap-2 flex-wrap", children: PHASES.map((p) => {
                    const state = phaseState(p, current, finished);
                    return (_jsxs("li", { className: `px-3 py-1.5 rounded border mono text-xs transition-colors
                ${state === "done" ? "border-spot-green/40 text-spot-green bg-spot-green/5" : ""}
                ${state === "active" ? "border-spot-green text-spot-green bg-spot-green/10 animate-pulse" : ""}
                ${state === "pending" ? "border-ink-700 text-ink-500" : ""}`, children: [state === "done" ? "✓ " : state === "active" ? "▸ " : "", p] }, p));
                }) })] }));
}
function currentPhase(events) {
    for (let i = events.length - 1; i >= 0; i--) {
        const e = events[i];
        if (e.type === "sweep.phase.changed") {
            const p = e.payload.phase;
            if (p && PHASES.includes(p))
                return p;
        }
    }
    return null;
}
function phaseState(p, current, finished) {
    if (finished)
        return "done";
    if (!current)
        return "pending";
    const currentIdx = PHASES.indexOf(current);
    const idx = PHASES.indexOf(p);
    if (idx < currentIdx)
        return "done";
    if (idx === currentIdx)
        return "active";
    return "pending";
}
