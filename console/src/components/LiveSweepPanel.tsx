import { useState } from "react";

import type { SweepEvent } from "../lib/api";
import { resumeSweep } from "../lib/api";
import { Cmul8Mark } from "./Cmul8Mark";
import { EventLog } from "./EventLog";
import { PhaseTracker } from "./PhaseTracker";
import { SwarmGrid } from "./SwarmGrid";
import { ThreatModelPanel } from "./ThreatModelPanel";

function SandboxBadge({ events }: { events: SweepEvent[] }) {
  const spawn = events.find((e) => e.type === "sandbox.spawned");
  if (!spawn) return null;
  const engine = String((spawn.payload as { engine?: string }).engine ?? "");
  const denied = events.some((e) => e.type === "sandbox.egress.denied");
  const modal = engine === "modal";
  return (
    <span
      className={`inline-flex items-center gap-1 mono uppercase tracking-wider px-1.5 py-0.5 rounded border ${
        modal
          ? "border-accent/40 bg-accent-soft text-accent"
          : "border-paper-300 bg-paper-100 text-paper-600"
      }`}
      title={
        modal
          ? "Reproducer + Verifier ran in an ephemeral Modal container with egress off"
          : "Local subprocess fallback — Modal not configured in this environment"
      }
    >
      <span className={`h-1.5 w-1.5 rounded-full ${modal ? "bg-accent" : "bg-paper-400"}`} />
      {modal ? "sandboxed · modal" : `sandboxed · ${engine}`}
      {denied && <span className="ml-1 text-sev-medium">· egress denied</span>}
    </span>
  );
}

/**
 * C2 · InteractivePausePanel — surfaces when a sweep pauses after Recon.
 *
 * Shows the auto-generated threat model and lets the analyst edit its JSON
 * before resuming. Edits shallow-merge into recon_out.threat_model on the
 * backend and a signed audit entry lands on the chain of custody.
 *
 * Intentionally minimal — a proper structured editor (add source, mark sink
 * intentional, tighten scope) is a Phase-3 polish item. This is enough to
 * prove the plumbing and unlock the demo.
 */
function InteractivePausePanel({
  sweepId,
  threatModel,
}: {
  sweepId: string;
  threatModel: Record<string, unknown> | null;
}) {
  const [editing, setEditing] = useState(false);
  const [editsText, setEditsText] = useState<string>(
    JSON.stringify(threatModel ?? {}, null, 2)
  );
  const [submitting, setSubmitting] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function resumeWith(edits: Record<string, unknown> | undefined) {
    setSubmitting(true);
    setErr(null);
    try {
      await resumeSweep(sweepId, edits);
      setEditing(false);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "resume failed");
    } finally {
      setSubmitting(false);
    }
  }

  async function onResumeUnedited() {
    await resumeWith(undefined);
  }

  async function onResumeEdited() {
    let parsed: Record<string, unknown> = {};
    try {
      parsed = JSON.parse(editsText);
    } catch (e) {
      setErr("Invalid JSON — please fix before resuming.");
      return;
    }
    await resumeWith(parsed);
  }

  return (
    <div className="border-l-2 border-accent bg-accent-soft/30 rounded-r-lg px-4 py-3">
      <div className="flex items-center gap-2 mb-2">
        <span className="mono text-2xs uppercase tracking-wider bg-accent text-white px-2 py-0.5 rounded-full">
          paused · interactive mode
        </span>
        <span className="text-sm text-paper-800">
          Recon finished. Review the threat model, edit if needed, then continue.
        </span>
      </div>
      {editing ? (
        <div className="space-y-2">
          <textarea
            value={editsText}
            onChange={(e) => setEditsText(e.target.value)}
            rows={12}
            className="w-full font-mono text-xs border border-paper-300 rounded p-2 bg-white focus:outline-none focus:border-accent"
          />
          {err && <div className="text-2xs text-sev-high">{err}</div>}
          <div className="flex items-center gap-2">
            <button
              disabled={submitting}
              onClick={onResumeEdited}
              className="px-3 py-1 rounded bg-accent text-white text-xs uppercase mono tracking-wider disabled:opacity-50"
            >
              {submitting ? "Signing…" : "Sign & continue"}
            </button>
            <button
              disabled={submitting}
              onClick={() => {
                setEditing(false);
                setErr(null);
              }}
              className="px-3 py-1 rounded border border-paper-300 text-xs uppercase mono tracking-wider text-paper-700"
            >
              Cancel edits
            </button>
          </div>
        </div>
      ) : (
        <div className="flex items-center gap-2">
          <button
            onClick={onResumeUnedited}
            disabled={submitting}
            className="px-3 py-1 rounded bg-accent text-white text-xs uppercase mono tracking-wider disabled:opacity-50"
          >
            {submitting ? "Resuming…" : "Continue as-is"}
          </button>
          <button
            onClick={() => setEditing(true)}
            className="px-3 py-1 rounded border border-paper-300 text-xs uppercase mono tracking-wider text-paper-700 hover:bg-white"
          >
            Edit threat model
          </button>
          {err && <span className="text-2xs text-sev-high ml-2">{err}</span>}
        </div>
      )}
    </div>
  );
}

export function LiveSweepPanel({ events, running }: { events: SweepEvent[]; running?: boolean }) {
  const finished = events.some((e) => e.type === "sweep.finished");
  const active = running && !finished;
  const pausedEvt = events.find((e) => e.type === "sweep.paused.for-review");
  const resumedEvt = events.find((e) => e.type === "sweep.resumed");
  const paused = !!pausedEvt && !resumedEvt;
  const sweepId = pausedEvt?.sweep_id ?? null;
  return (
    <section className="flex-1 min-w-0 overflow-y-auto bg-paper-50">
      <div className="px-6 py-4 border-b border-paper-300 flex items-center gap-3">
        <div className={active ? "" : "opacity-70"}>
          <Cmul8Mark size={22} active={active} />
        </div>
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <h1 className="text-lg text-paper-900 font-semibold tracking-tight">
              {finished ? "Sweep complete" : "Sweep in progress"}
            </h1>
            {active && (
              <span className="text-2xs mono uppercase tracking-wider text-accent bg-accent-soft border border-accent/30 rounded px-1.5 py-0.5 animate-pulse">
                Live
              </span>
            )}
          </div>
          <p className="text-xs text-paper-600">
            {active
              ? "Reasoning over the code graph, corroborating, reproducing, patching, verifying."
              : "Sweep finished. Findings promoted by the Consensus Kernel are in the list."}
          </p>
        </div>
        <div className="ml-auto flex items-center gap-3 text-2xs mono text-paper-500">
          <SandboxBadge events={events} />
          <span>
            <span className="uppercase tracking-wider">events</span>{" "}
            <span className="text-paper-900 tabular-nums font-semibold">{events.length}</span>
          </span>
        </div>
      </div>

      <div className="p-6 space-y-4">
        <PhaseTracker events={events} />
        {paused && sweepId && (
          <InteractivePausePanel
            sweepId={sweepId}
            threatModel={(pausedEvt?.payload as { threat_model?: Record<string, unknown> })?.threat_model ?? null}
          />
        )}
        <ThreatModelPanel events={events} />
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <SwarmGrid events={events} />
          <EventLog events={events} />
        </div>
      </div>
    </section>
  );
}
