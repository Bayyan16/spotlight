import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
export function FindingDetail({ finding }) {
    return (_jsxs("div", { className: "border border-ink-800 rounded-md bg-ink-900 divide-y divide-ink-800", children: [_jsxs("header", { className: "p-4 flex items-start justify-between gap-4", children: [_jsxs("div", { children: [_jsxs("div", { className: "flex items-center gap-2 mb-1", children: [_jsx(SeverityChip, { s: finding.severity }), _jsx("span", { className: "mono text-xs text-ink-400", children: finding.id }), _jsx("span", { className: "mono text-xs text-ink-500", children: finding.cwe }), _jsx(TierBadge, { tier: finding.tier })] }), _jsx("h2", { className: "text-lg text-ink-100", children: finding.title }), _jsxs("div", { className: "mono text-xs text-ink-500 mt-1", children: [finding.location.file, ":", finding.location.line, " \u00B7 ", finding.location.function] })] }), _jsxs("div", { className: "text-right", children: [_jsx("div", { className: "text-xs uppercase text-ink-500 mono", children: "Confidence" }), _jsxs("div", { className: "mono text-2xl text-spot-green", children: [(finding.confidence * 100).toFixed(0), "%"] }), _jsx("div", { className: "mono text-xs text-ink-400 mt-1", children: finding.state })] })] }), _jsxs("section", { className: "p-4", children: [_jsx("div", { className: "text-xs uppercase tracking-wider text-ink-400 mono mb-2", children: "Why you can trust this" }), _jsx("div", { className: "text-sm text-ink-200 mb-3", children: finding.evidence.root_cause }), _jsxs("ul", { className: "space-y-1 text-sm", children: [finding.evidence.corroboration.map((c, i) => (_jsxs("li", { className: "flex items-start gap-2", children: [_jsx("span", { className: "text-spot-green mono", children: "\u2713" }), _jsx("span", { className: "mono text-xs text-ink-400 uppercase", children: c.type }), _jsx("span", { className: "text-ink-300 text-xs", children: c.result ?? (Array.isArray(c.detail) ? c.detail.join(" · ") : String(c.detail ?? "")) })] }, i))), _jsxs("li", { className: "flex items-start gap-2", children: [_jsx("span", { className: "text-spot-green mono", children: "\u2713" }), _jsx("span", { className: "mono text-xs text-ink-400 uppercase", children: "consensus" }), _jsxs("span", { className: "text-ink-300 text-xs", children: [finding.consensus.rationale, " (", finding.consensus.independent_corroborators, " independent corroborators)"] })] })] })] }), _jsxs("section", { className: "p-4", children: [_jsx("div", { className: "text-xs uppercase tracking-wider text-ink-400 mono mb-2", children: "Fix" }), _jsx("div", { className: "text-sm text-ink-300", children: finding.evidence.fix.approach }), _jsxs("div", { className: "mt-2 flex gap-3 text-xs mono", children: [_jsx(StatChip, { label: "Verifier", value: finding.evidence.verification.result, good: finding.evidence.verification.result === "repro-now-blocked" }), _jsx(StatChip, { label: "Backdoor check", value: finding.evidence.verification.backdoor_check, good: finding.evidence.verification.backdoor_check === "pass" }), _jsx(StatChip, { label: "Independent", value: String(finding.evidence.verification.independent_verifier), good: !!finding.evidence.verification.independent_verifier })] })] })] }));
}
function SeverityChip({ s }) {
    const color = s === "critical" || s === "high"
        ? "bg-spot-red/20 text-spot-red border-spot-red/40"
        : s === "medium"
            ? "bg-spot-amber/20 text-spot-amber border-spot-amber/40"
            : "bg-ink-700 text-ink-300 border-ink-600";
    return _jsx("span", { className: `mono text-[10px] uppercase px-1.5 py-0.5 rounded border ${color}`, children: s });
}
function TierBadge({ tier }) {
    const map = {
        verified: "border-spot-green/50 text-spot-green bg-spot-green/10",
        "high-confidence": "border-spot-amber/50 text-spot-amber bg-spot-amber/10",
        "needs-review": "border-ink-600 text-ink-300 bg-ink-800",
        held: "border-ink-700 text-ink-500 bg-ink-900",
    };
    return (_jsx("span", { className: `mono text-[10px] uppercase px-1.5 py-0.5 rounded border ${map[tier] ?? ""}`, children: tier }));
}
function StatChip({ label, value, good }) {
    return (_jsxs("div", { className: `px-2 py-1 rounded border ${good ? "border-spot-green/40 text-spot-green" : "border-ink-600 text-ink-400"}`, children: [_jsx("span", { className: "text-ink-500 uppercase text-[10px] mr-1", children: label }), good ? "✓ " : "", value] }));
}
