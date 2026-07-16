import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { PresencePanel } from "./PresencePanel";

/**
 * PresencePanel tests exercise the actual state-machine the user sees:
 * loading -> loaded (with matches), loading -> loaded (empty), loading ->
 * error (null from a 404). Each stubs fetch with a controllable promise
 * so we can assert the skeleton renders before resolution.
 *
 * This is the exact failure mode the "features ship with tests" rule was
 * written for: verify the interactive path, not just the API contract.
 */

const MATCH_PAYLOAD = {
  class: "sqli",
  cwe: "CWE-89",
  self: {
    sweep_id: "sw_self",
    repo_name: "vuln-bank-api",
    finding_id: "SPOT-0001",
  },
  matches: [
    {
      sweep_id: "sw_other",
      repo_name: "payments-api",
      finding_id: "SPOT-0007",
      file: "src/db.py",
      line: 42,
      tier: "verified",
      state: "detected",
      sweep_started_at: new Date(Date.now() - 3600 * 1000).toISOString(),
    },
  ],
  presence_count: 1,
};

const EMPTY_PAYLOAD = {
  class: "sqli",
  cwe: "CWE-89",
  self: {
    sweep_id: "sw_self",
    repo_name: "vuln-bank-api",
    finding_id: "SPOT-0001",
  },
  matches: [],
  presence_count: 0,
};

beforeEach(() => {
  vi.useFakeTimers({ shouldAdvanceTime: true, now: new Date("2026-07-16T12:00:00Z") });
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

function stubFetch(response: { ok: boolean; status?: number; json?: unknown }) {
  vi.stubGlobal(
    "fetch",
    vi.fn(() =>
      Promise.resolve({
        ok: response.ok,
        status: response.status ?? (response.ok ? 200 : 500),
        json: () => Promise.resolve(response.json ?? {}),
      })
    ) as unknown as typeof fetch
  );
}

describe("PresencePanel", () => {
  it("renders skeletons while fetching", () => {
    // Never-resolving fetch so we can catch the loading UI.
    vi.stubGlobal(
      "fetch",
      vi.fn(() => new Promise(() => {})) as unknown as typeof fetch
    );
    const { container } = render(<PresencePanel findingId="SPOT-0001" />);
    expect(screen.getByText(/Cross-surface presence/i)).toBeInTheDocument();
    expect(container.querySelectorAll(".skeleton").length).toBe(3);
  });

  it("renders match rows when presence_count > 0", async () => {
    stubFetch({ ok: true, json: MATCH_PAYLOAD });
    render(<PresencePanel findingId="SPOT-0001" />);
    await waitFor(() =>
      expect(screen.getByText(/other repo/i)).toBeInTheDocument()
    );
    // The class chip.
    expect(screen.getByText("sqli")).toBeInTheDocument();
    // The presence count.
    expect(screen.getByText("1")).toBeInTheDocument();
    // The matching repo name (bold).
    expect(screen.getByText("payments-api")).toBeInTheDocument();
    // sweep_id in monospace.
    expect(screen.getByText("sw_other")).toBeInTheDocument();
    // file:line.
    expect(screen.getByText("src/db.py:42")).toBeInTheDocument();
    // tier chip.
    expect(screen.getByText(/verified/i)).toBeInTheDocument();
    // relative time — 1h ago.
    expect(screen.getByText(/ago/)).toBeInTheDocument();
  });

  it("renders the muted 'Not present' state when presence_count == 0", async () => {
    stubFetch({ ok: true, json: EMPTY_PAYLOAD });
    render(<PresencePanel findingId="SPOT-0001" />);
    await waitFor(() =>
      expect(screen.getByText(/Not present elsewhere/i)).toBeInTheDocument()
    );
  });

  it("gracefully handles a 404 (finding gone) as 'unavailable'", async () => {
    stubFetch({ ok: false, status: 404 });
    render(<PresencePanel findingId="SPOT-nope" />);
    await waitFor(() =>
      expect(screen.getByText(/Presence lookup unavailable/i)).toBeInTheDocument()
    );
  });
});
