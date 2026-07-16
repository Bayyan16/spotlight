import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { ThreatModelPanel } from "./ThreatModelPanel";
import type { SweepEvent } from "../lib/api";

function makeEvent(partial: Partial<SweepEvent>): SweepEvent {
  return {
    sweep_id: "sw_test",
    seq: 0,
    ts: 1,
    type: "recon.threat_model",
    actor: "recon",
    payload: {},
    ...partial,
  };
}

describe("ThreatModelPanel", () => {
  it("renders the empty 'Recon in progress' state before any event", () => {
    render(<ThreatModelPanel events={[]} />);
    expect(screen.getByText(/Threat model/i)).toBeInTheDocument();
    expect(screen.getByText(/Recon in progress/i)).toBeInTheDocument();
  });

  it("renders stack + surfaces + untrusted sources + sinks from a recon.threat_model event", () => {
    const events: SweepEvent[] = [
      makeEvent({
        seq: 0,
        type: "sweep.started",
        actor: "orchestrator",
        payload: {},
      }),
      makeEvent({
        seq: 1,
        type: "recon.threat_model",
        actor: "recon",
        payload: {
          threat_model: {
            stack: { language: "python", framework: "flask" },
            surfaces: ["code"],
            threat_model: {
              untrusted_sources: ["req.body", "param:username"],
              high_impact_sinks: ["cursor.execute", "eval"],
            },
          },
          stack: { language: "python", framework: "flask" },
          signals_count: 3,
          surfaces: ["code"],
        },
      }),
    ];

    render(<ThreatModelPanel events={events} />);

    // Stack label rendered as "Python · Flask".
    expect(screen.getByText(/Python\s*·\s*Flask/i)).toBeInTheDocument();

    // Signals count exposed.
    expect(screen.getByText("3")).toBeInTheDocument();

    // At least one untrusted-source chip renders.
    expect(screen.getByText("req.body")).toBeInTheDocument();
    expect(screen.getByText("param:username")).toBeInTheDocument();

    // At least one high-impact sink chip renders.
    expect(screen.getByText("cursor.execute")).toBeInTheDocument();
    expect(screen.getByText("eval")).toBeInTheDocument();

    // Surface chip rendered too.
    expect(screen.getAllByText(/code/i).length).toBeGreaterThan(0);
  });

  it("uses the last recon.threat_model event when multiple appear", () => {
    const events: SweepEvent[] = [
      makeEvent({
        seq: 0,
        type: "recon.threat_model",
        actor: "recon",
        payload: {
          threat_model: {
            stack: { language: "javascript", framework: "express" },
            threat_model: { untrusted_sources: ["stale.source"] },
          },
          stack: { language: "javascript", framework: "express" },
          signals_count: 1,
          surfaces: ["code"],
        },
      }),
      makeEvent({
        seq: 1,
        type: "recon.threat_model",
        actor: "recon",
        payload: {
          threat_model: {
            stack: { language: "python", framework: "flask" },
            threat_model: { untrusted_sources: ["fresh.source"] },
          },
          stack: { language: "python", framework: "flask" },
          signals_count: 7,
          surfaces: ["code"],
        },
      }),
    ];

    render(<ThreatModelPanel events={events} />);
    expect(screen.getByText(/Python\s*·\s*Flask/i)).toBeInTheDocument();
    expect(screen.getByText("fresh.source")).toBeInTheDocument();
    expect(screen.queryByText("stale.source")).not.toBeInTheDocument();
    expect(screen.getByText("7")).toBeInTheDocument();
  });
});
