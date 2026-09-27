import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { CortexView } from "./CortexView";

/**
 * CortexView tests cover the three states an operator actually meets:
 * memory switched off, a learned policy in effect, and a proposal the Cortex
 * withheld from itself pending a human. The last one is the important one —
 * the approve button must not appear without a name, because an unattributed
 * activation is exactly the audit gap this whole subsystem exists to close.
 */

const HEALTHY_AUDIT = {
  rows_replayed: 12,
  labeled_rows: 7,
  tp_demoted: 0,
  fp_demoted: 6,
  tp_boosted: 0,
  fp_boosted: 0,
  tp_confidence_loss: 0,
  fp_confidence_loss: 0.9,
  unchanged: 5,
  demoted_true_positive_keys: [],
  beneficial_effects: 7,
  raises_anything: false,
};

const STATUS = {
  active_policy_audit: HEALTHY_AUDIT,
  root: "/var/lib/spotlight/cortex",
  autonomy: true,
  policy: {
    policy_id: "a".repeat(32),
    version: 1,
    ledger_head: "b".repeat(64),
    min_support: 5,
    directives: {
      "ssti|independent_agent": {
        cohort: "ssti|independent_agent",
        action: "route-to-review",
        target_confidence: 0.14,
        n_labeled: 6,
        tp: 0,
        fp: 6,
        human_tp: 0,
        precision_mean: 0.071,
        precision_lower: 0.0,
        rationale: "6/6 labelled findings in this evidence shape were false positives",
      },
    },
    created_at: "2026-09-01T00:00:00.000000Z",
    derived_from: "",
    notes: "",
    is_identity: false,
  },
  pin: {},
  ledger: { records: 12, distinct_findings: 12, labeled: 7, unlabeled: 5, head: "b".repeat(64) },
  cohorts: { total: 3, actionable: 1 },
  lessons: { served: 2, quarantined: 1 },
  governance_entries: 4,
};

const HISTORY = {
  active_policy_id: "a".repeat(32),
  policies: [
    { ...STATUS.policy, version: 0, policy_id: "0".repeat(32), directives: {}, is_identity: true, is_active: false },
    { ...STATUS.policy, is_active: true },
  ],
};

const LESSONS = {
  served: [],
  quarantined: [
    {
      lesson_id: "l1",
      scope: "finding",
      key: "ssti@app/templates",
      class_: "ssti",
      path_hint: "app/templates",
      observations: 2,
      text: "withheld",
      quarantined: true,
      quarantine_kinds: ["ignore_instructions"],
    },
  ],
};

const GOVERNANCE = {
  total: 2,
  entries: [
    { ts: "2026-09-01T00:00:00.000000Z", action: "policy.proposed", actor: "cortex", payload: {} },
    {
      ts: "2026-09-01T00:00:01.000000Z",
      action: "policy.activated",
      actor: "cortex-autonomous",
      payload: { policy_id: "a".repeat(32) },
    },
  ],
};

const VERIFY = {
  ok: true,
  records: 12,
  head: "b".repeat(64),
  chain_ok: true,
  signatures_ok: true,
  signatures_checked: 12,
  broken_at: null,
  reason: "chain intact",
};

const WITHHELD_PROPOSAL = {
  proposal: {
    policy: { ...STATUS.policy, version: 2, policy_id: "c".repeat(32) },
    shadow: {
      rows_replayed: 12,
      labeled_rows: 7,
      tp_demoted: 0,
      fp_demoted: 6,
      tp_boosted: 1,
      fp_boosted: 0,
      tp_confidence_loss: 0,
      fp_confidence_loss: 0.9,
      unchanged: 5,
      demoted_true_positive_keys: [],
      beneficial_effects: 7,
      raises_anything: true,
    },
    invariant_violations: [],
    gate_failures: [],
    admissible: true,
    requires_human: true,
    auto_activatable: false,
  },
  activation: {
    activated: false,
    reason: "policy raises confidence or is non-conservative; a named human approver is required",
    policy_id: "c".repeat(32),
    version: 2,
    approver: "",
  },
  lessons_refreshed: 2,
  lessons_quarantined: 1,
};

function jsonResponse(body: unknown, status = 200) {
  return Promise.resolve({
    ok: status < 400,
    status,
    json: () => Promise.resolve(body),
  } as Response);
}

function route(url: string) {
  if (url.includes("/cortex/status")) return jsonResponse(STATUS);
  if (url.includes("/cortex/policy/history")) return jsonResponse(HISTORY);
  if (url.includes("/cortex/lessons")) return jsonResponse(LESSONS);
  if (url.includes("/cortex/governance")) return jsonResponse(GOVERNANCE);
  if (url.includes("/cortex/ledger/verify")) return jsonResponse(VERIFY);
  if (url.includes("/cortex/evolve")) return jsonResponse(WITHHELD_PROPOSAL);
  return jsonResponse({ detail: "not found" }, 404);
}

describe("CortexView", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => route(String(input))),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("tells the operator how to switch memory on when it is off", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() => jsonResponse({ detail: "Cortex is not enabled" }, 404)),
    );
    render(<CortexView />);
    await waitFor(() =>
      expect(screen.getByText(/Cortex is off for this workspace/i)).toBeInTheDocument(),
    );
    expect(screen.getByText(/SPOTLIGHT_CORTEX_DIR/)).toBeInTheDocument();
    // The promise it makes must be stated wherever it is offered.
    expect(screen.getByText(/never promote one and never suppress one/i)).toBeInTheDocument();
  });

  it("shows each directive with the counts that justify it", async () => {
    render(<CortexView />);
    await waitFor(() => expect(screen.getByText("route to review")).toBeInTheDocument());
    expect(screen.getByText("ssti|independent_agent")).toBeInTheDocument();
    expect(screen.getByText("0 / 6")).toBeInTheDocument();
    expect(
      screen.getByText(/6\/6 labelled findings in this evidence shape were false positives/),
    ).toBeInTheDocument();
  });

  it("surfaces a quarantined lesson as a poisoning attempt", async () => {
    render(<CortexView />);
    await waitFor(() => expect(screen.getByText("Quarantined lessons")).toBeInTheDocument());
    expect(screen.getByText(/ignore_instructions/)).toBeInTheDocument();
    expect(screen.getByText(/never served to a model/i)).toBeInTheDocument();
  });

  it("reports ledger integrity", async () => {
    render(<CortexView />);
    await waitFor(() => expect(screen.getByText("verified")).toBeInTheDocument());
    expect(screen.getByText("chain intact")).toBeInTheDocument();
  });

  it("marks an autonomous activation as an agent action in the log", async () => {
    render(<CortexView />);
    await waitFor(() => expect(screen.getByText("policy.activated")).toBeInTheDocument());
    expect(screen.getByText("cortex-autonomous")).toBeInTheDocument();
    expect(screen.getByText("agent")).toBeInTheDocument();
  });

  it("warns when the policy in force has gone stale against new evidence", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/cortex/status")) {
          return jsonResponse({
            ...STATUS,
            active_policy_audit: { ...HEALTHY_AUDIT, tp_demoted: 2 },
          });
        }
        return route(url);
      }),
    );
    render(<CortexView />);
    await waitFor(() =>
      expect(
        screen.getByText(/demotes 2 confirmed true\s+positive\(s\)/),
      ).toBeInTheDocument(),
    );
  });

  it("does not warn while the policy in force is still healthy", async () => {
    render(<CortexView />);
    await waitFor(() => expect(screen.getByText("route to review")).toBeInTheDocument());
    expect(screen.queryByText(/confirmed true positive\(s\) against the current/)).toBeNull();
  });

  it("refuses to activate a withheld proposal without a named approver", async () => {
    render(<CortexView />);
    await waitFor(() => expect(screen.getByText("route to review")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: /run evolution cycle/i }));
    await waitFor(() => expect(screen.getByText("withheld")).toBeInTheDocument());
    expect(screen.getByText(/named human approver is required/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /approve as human/i }));
    await waitFor(() =>
      expect(screen.getByText(/an activation with nobody attached to it/i)).toBeInTheDocument(),
    );
    // Nothing was sent: the activation route was never called.
    const calls = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls.map((c) => String(c[0]));
    expect(calls.some((u) => u.includes("/cortex/policy/activate"))).toBe(false);
  });

  it("sends the approver when one is typed", async () => {
    render(<CortexView />);
    await waitFor(() => expect(screen.getByText("route to review")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: /run evolution cycle/i }));
    await waitFor(() => expect(screen.getByText("withheld")).toBeInTheDocument());

    fireEvent.change(screen.getByPlaceholderText("you@example.com"), {
      target: { value: "ciso@bank.example" },
    });
    fireEvent.click(screen.getByRole("button", { name: /approve as human/i }));

    await waitFor(() => {
      const call = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls.find((c) =>
        String(c[0]).includes("/cortex/policy/activate"),
      );
      expect(call).toBeTruthy();
      expect(String((call?.[1] as RequestInit)?.body)).toContain("ciso@bank.example");
    });
  });

  it("shows the shadow replay so a human can see what the policy would have done", async () => {
    render(<CortexView />);
    await waitFor(() => expect(screen.getByText("route to review")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: /run evolution cycle/i }));
    await waitFor(() =>
      expect(screen.getByText("True positives demoted")).toBeInTheDocument(),
    );
    expect(screen.getByText("False positives demoted")).toBeInTheDocument();
    expect(screen.getByText("False positives boosted")).toBeInTheDocument();
  });
});
