import { jsx as _jsx } from "react/jsx-runtime";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import App from "./App";
const mockFindings = [
    {
        id: "SPOT-0001",
        surface: "code",
        title: "SQLI in get_account",
        severity: "high",
        class: "sqli",
        cwe: "CWE-89",
        location: { file: "app.py", line: 24, function: "get_account" },
        state: "confirmed-fixed",
        tier: "verified",
        confidence: 0.93,
        evidence: {
            detected_by: ["investigator-1", "codegraph:source->sink reachable"],
            corroboration: [
                { type: "static-fact", detail: ["reachable"] },
                { type: "reproduction", result: "confirmed" },
            ],
            root_cause: "Untrusted `username` flows into cursor.execute via concat.",
            fix: { diff: "SPOT-0001.diff", approach: "parameterized query" },
            verification: {
                result: "repro-now-blocked",
                backdoor_check: "pass",
                independent_verifier: true,
            },
        },
        consensus: {
            tier: "verified",
            independent_corroborators: 2,
            decision: "promote",
            rationale: "reproduction + static-analysis fact",
        },
        audit: {},
    },
];
beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn((url, init) => {
        if (url.endsWith("/targets")) {
            return Promise.resolve({
                ok: true,
                json: () => Promise.resolve([{ name: "vuln-bank-api", path: "/tmp/vuln", has_ground_truth: true }]),
            });
        }
        if (url.endsWith("/sweeps") && init?.method === "POST") {
            return Promise.resolve({ ok: true, json: () => Promise.resolve({ sweep_id: "sw_test" }) });
        }
        if (url.includes("/findings")) {
            return Promise.resolve({ ok: true, json: () => Promise.resolve(mockFindings) });
        }
        return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
    }));
    // Mock WebSocket so useEffect doesn't blow up.
    class MockWS {
        url;
        onmessage = null;
        onopen = null;
        close = vi.fn();
        constructor(url) {
            this.url = url;
        }
    }
    vi.stubGlobal("WebSocket", MockWS);
});
describe("App", () => {
    it("renders the empty state with the CTA", async () => {
        render(_jsx(App, {}));
        expect(screen.getByText(/The AI security engineer/i)).toBeInTheDocument();
        expect(screen.getAllByText(/Start your first Sweep|Start Sweep/i).length).toBeGreaterThan(0);
    });
    it("loads targets into the selector", async () => {
        render(_jsx(App, {}));
        await waitFor(() => {
            expect(screen.getByRole("combobox")).toBeInTheDocument();
        });
        expect(screen.getByRole("option", { name: "vuln-bank-api" })).toBeInTheDocument();
    });
});
describe("FindingDetail", () => {
    it("renders the 'Why you can trust this' evidence block", async () => {
        const { FindingDetail } = await import("./components/FindingDetail");
        render(_jsx(FindingDetail, { finding: mockFindings[0] }));
        expect(screen.getByText(/Why you can trust this/i)).toBeInTheDocument();
        expect(screen.getByText(/parameterized query/i)).toBeInTheDocument();
        expect(screen.getByText(/repro-now-blocked/)).toBeInTheDocument();
        // Confidence percentage rendered.
        expect(screen.getByText(/93%/)).toBeInTheDocument();
    });
});
describe("PhaseTracker", () => {
    it("advances phases as events arrive", async () => {
        const { PhaseTracker } = await import("./components/PhaseTracker");
        const events = [
            { sweep_id: "s", seq: 0, ts: 1, type: "sweep.started", actor: "o", payload: {} },
            {
                sweep_id: "s",
                seq: 1,
                ts: 2,
                type: "sweep.phase.changed",
                actor: "o",
                payload: { phase: "reproduce" },
            },
        ];
        render(_jsx(PhaseTracker, { events: events }));
        // recon, investigate, reduce should be done; reproduce active; the rest pending.
        expect(screen.getByText(/reproduce/)).toBeInTheDocument();
    });
});
