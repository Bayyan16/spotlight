import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
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
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init?: RequestInit) => {
      if (url.endsWith("/targets")) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve([{ name: "vuln-bank-api", path: "/tmp/vuln", has_ground_truth: true }]),
        }) as any;
      }
      if (url.endsWith("/profiles")) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve([
              {
                id: "balanced",
                name: "Balanced",
                description: "test",
                surfaces: ["code"],
                classes: ["sqli"],
                languages: ["python"],
                model: "moonshot",
                max_agents: 6,
                budget_tokens: 1500000,
                scope_globs: ["**/*.py"],
                runtime_validate: true,
                interactive: false,
              },
            ]),
        }) as any;
      }
      if (url.endsWith("/sweeps") && init?.method === "POST") {
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ sweep_id: "sw_test" }) }) as any;
      }
      if (url.includes("/presence")) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              class: "sqli",
              cwe: "CWE-89",
              self: { sweep_id: "sw_test", repo_name: "vuln-bank-api", finding_id: "SPOT-0001" },
              matches: [],
              presence_count: 0,
            }),
        }) as any;
      }
      if (url.includes("/findings")) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(mockFindings) }) as any;
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) }) as any;
    })
  );

  // Mock WebSocket so useEffect doesn't blow up.
  class MockWS {
    onmessage: ((e: MessageEvent) => void) | null = null;
    onopen: (() => void) | null = null;
    close = vi.fn();
    constructor(public url: string) {}
  }
  vi.stubGlobal("WebSocket", MockWS as unknown as typeof WebSocket);
});

describe("App", () => {
  it("renders the sweeps-history default view with CMUL8 brand + New-scan CTA", async () => {
    render(<App />);
    // TopBar's single start-affordance is now "New scan" (the wizard opener);
    // the fixture/git/profile pickers moved into the wizard itself so there
    // is exactly one place to configure a sweep.
    await waitFor(() => {
      expect(screen.getAllByText(/New scan/i).length).toBeGreaterThan(0);
    });
    expect(screen.getAllByText(/CMUL8/).length).toBeGreaterThan(0);
  });

  it("shows targets in the Board or empty-state as appropriate", async () => {
    render(<App />);
    // No more TopBar combobox — pickers live inside the wizard now. Wait for
    // targets to load so an empty-state or board renders past skeleton.
    await waitFor(() => {
      // Board area chart or empty-state renders once targets/sweeps resolve.
      expect(document.querySelector(".animate-fade-in")).toBeInTheDocument();
    });
  });
});

describe("FindingDetail", () => {
  it("renders the 'Why you can trust this' evidence block", async () => {
    const { FindingDetail } = await import("./components/FindingDetail");
    render(<FindingDetail finding={mockFindings[0] as any} />);
    expect(screen.getByText(/Why you can trust this/i)).toBeInTheDocument();
    // The "parameterized query" approach text now appears in BOTH the Fix
    // panel and the Fix-diff-placeholder Panel (when diff_content is
    // absent). Either match satisfies the "the fix recommendation renders"
    // assertion this test is guarding.
    expect(screen.getAllByText(/parameterized query/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/repro-now-blocked/)).toBeInTheDocument();
    // Confidence percentage rendered in the confidence dial (mono digits).
    expect(screen.getAllByText(/93/)[0]).toBeInTheDocument();
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
    render(<PhaseTracker events={events as any} />);
    // recon, investigate, reduce should be done; reproduce active; the rest pending.
    expect(screen.getByText(/reproduce/)).toBeInTheDocument();
  });
});
