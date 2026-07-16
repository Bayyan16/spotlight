import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import { useEffect, useState } from "react";
import { PhaseTracker } from "./components/PhaseTracker";
import { SwarmGrid } from "./components/SwarmGrid";
import { EventLog } from "./components/EventLog";
import { FindingDetail } from "./components/FindingDetail";
import { getFindings, listTargets, openSweepStream, startSweep, } from "./lib/api";
export default function App() {
    const [targets, setTargets] = useState([]);
    const [selected, setSelected] = useState("vuln-bank-api");
    const [sweepId, setSweepId] = useState(null);
    const [events, setEvents] = useState([]);
    const [findings, setFindings] = useState([]);
    const [running, setRunning] = useState(false);
    const [detail, setDetail] = useState(null);
    useEffect(() => {
        listTargets().then(setTargets).catch(() => setTargets([]));
    }, []);
    useEffect(() => {
        if (!sweepId)
            return;
        const ws = openSweepStream(sweepId, (e) => {
            setEvents((prev) => [...prev, e]);
            if (e.type === "sweep.finished") {
                setRunning(false);
                getFindings(sweepId).then(setFindings);
            }
        });
        return () => ws.close();
    }, [sweepId]);
    async function onStart() {
        setEvents([]);
        setFindings([]);
        setDetail(null);
        setRunning(true);
        try {
            const { sweep_id } = await startSweep(selected);
            setSweepId(sweep_id);
        }
        catch (err) {
            setRunning(false);
            alert(`Failed to start sweep: ${err}`);
        }
    }
    return (_jsxs("div", { className: "min-h-screen bg-ink-950", children: [_jsx(TopBar, { running: running, onStart: onStart, target: selected, onTarget: setSelected, targets: targets }), _jsxs("main", { className: "max-w-7xl mx-auto p-6 space-y-4", children: [!sweepId && _jsx(EmptyState, { onStart: onStart }), sweepId && (_jsxs(_Fragment, { children: [_jsxs("div", { className: "text-xs text-ink-500 mono", children: ["sweep_id ", _jsx("span", { className: "text-ink-300", children: sweepId }), " \u00B7 target", " ", _jsx("span", { className: "text-ink-300", children: selected })] }), _jsx(PhaseTracker, { events: events }), _jsxs("div", { className: "grid grid-cols-1 lg:grid-cols-2 gap-4", children: [_jsx(SwarmGrid, { events: events }), _jsx(EventLog, { events: events })] }), _jsx(FindingsSection, { findings: findings, onOpen: setDetail }), detail && _jsx(FindingDetail, { finding: detail })] }))] })] }));
}
function TopBar({ running, onStart, target, onTarget, targets, }) {
    return (_jsx("div", { className: "border-b border-ink-800 bg-ink-900/60 backdrop-blur", children: _jsxs("div", { className: "max-w-7xl mx-auto px-6 py-3 flex items-center gap-4", children: [_jsxs("div", { className: "flex items-center gap-2", children: [_jsx("span", { className: "h-2.5 w-2.5 rounded-full bg-spot-green" }), _jsx("span", { className: "text-ink-100 font-semibold tracking-tight", children: "Spotlight" }), _jsx("span", { className: "text-ink-500 text-xs mono", children: "by CMUL8" })] }), _jsxs("div", { className: "ml-auto flex items-center gap-3", children: [_jsx("select", { className: "bg-ink-800 border border-ink-700 text-ink-200 text-sm rounded px-2 py-1.5 mono", value: target, onChange: (e) => onTarget(e.target.value), disabled: running, children: targets.map((t) => (_jsx("option", { value: t.name, children: t.name }, t.name))) }), _jsx("button", { className: `px-4 py-1.5 rounded text-sm mono uppercase tracking-wider transition-colors ${running
                                ? "bg-ink-800 text-ink-500 cursor-not-allowed"
                                : "bg-spot-green/20 text-spot-green border border-spot-green/40 hover:bg-spot-green/30"}`, onClick: onStart, disabled: running, children: running ? "Sweeping…" : "▸ Start Sweep" })] })] }) }));
}
function EmptyState({ onStart }) {
    return (_jsxs("div", { className: "text-center py-24", children: [_jsx("h1", { className: "text-2xl text-ink-100 font-semibold tracking-tight mb-2", children: "The AI security engineer" }), _jsx("p", { className: "text-ink-400 max-w-lg mx-auto text-sm", children: "Point Spotlight at a target repo. It classifies the stack, reasons over a code graph, corroborates every candidate, reproduces where feasible, patches, and gets independently verified \u2014 all before you see a finding." }), _jsx("button", { onClick: onStart, className: "mt-6 px-5 py-2 rounded mono uppercase tracking-wider text-sm bg-spot-green/20 text-spot-green border border-spot-green/40 hover:bg-spot-green/30", children: "\u25B8 Start your first Sweep" })] }));
}
function FindingsSection({ findings, onOpen, }) {
    return (_jsxs("div", { className: "border border-ink-800 rounded-md bg-ink-900", children: [_jsx("div", { className: "p-4 border-b border-ink-800", children: _jsxs("div", { className: "text-xs uppercase tracking-wider text-ink-400 mono", children: ["Findings (", findings.length, ")"] }) }), findings.length === 0 && (_jsx("div", { className: "p-6 text-ink-500 text-sm italic", children: "None promoted yet. When the Consensus Kernel promotes a candidate it appears here." })), _jsx("ul", { className: "divide-y divide-ink-800", children: findings.map((f) => (_jsx("li", { children: _jsxs("button", { className: "w-full flex items-center gap-3 p-3 hover:bg-ink-800 text-left", onClick: () => onOpen(f), children: [_jsx("span", { className: "mono text-xs text-ink-400", children: f.id }), _jsx("span", { className: "text-ink-100 text-sm", children: f.title }), _jsx("span", { className: "mono text-[10px] uppercase px-1.5 py-0.5 rounded border border-spot-green/40 text-spot-green", children: f.tier }), _jsxs("span", { className: "mono text-xs text-ink-500 ml-auto", children: [f.location.file, ":", f.location.line] }), _jsxs("span", { className: "mono text-xs text-spot-green", children: [(f.confidence * 100).toFixed(0), "%"] })] }) }, f.id))) })] }));
}
