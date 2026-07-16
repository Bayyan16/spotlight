import type { SweepEvent } from "../lib/api";
import { Cmul8Mark } from "./Cmul8Mark";

/**
 * ThreatModelPanel — surfaces the Recon agent's structured threat model
 * live during a sweep, driven off `recon.threat_model` events emitted by
 * the orchestrator immediately after Recon completes.
 *
 * Empty state: shows a muted "Recon in progress…" skeleton with the
 * spinning CMUL8 mark until the first `recon.threat_model` event lands.
 */

type ThreatModel = {
  stack?: { language?: string; framework?: string };
  surfaces?: string[];
  untrusted_sources?: string[];
  high_impact_sinks?: string[];
  threat_model?: {
    untrusted_sources?: string[];
    high_impact_sinks?: string[];
  };
};

type ReconPayload = {
  threat_model?: ThreatModel;
  stack?: { language?: string; framework?: string };
  signals_count?: number;
  surfaces?: string[];
};

function extractLastReconPayload(events: SweepEvent[]): ReconPayload | null {
  for (let i = events.length - 1; i >= 0; i--) {
    if (events[i].type === "recon.threat_model") {
      return events[i].payload as ReconPayload;
    }
  }
  return null;
}

function formatStack(stack?: { language?: string; framework?: string }): string | null {
  if (!stack) return null;
  const lang = stack.language ? cap(stack.language) : null;
  const fw = stack.framework ? cap(stack.framework) : null;
  if (lang && fw) return `${lang} \u00b7 ${fw}`;
  return lang || fw || null;
}

function cap(s: string): string {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
}

function InboundArrow() {
  return (
    <svg
      width="10"
      height="10"
      viewBox="0 0 12 12"
      aria-hidden
      className="shrink-0"
    >
      <path
        d="M1 6 H9 M6 3 L9 6 L6 9"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function OutboundArrow() {
  return (
    <svg
      width="10"
      height="10"
      viewBox="0 0 12 12"
      aria-hidden
      className="shrink-0"
    >
      <path
        d="M3 6 H11 M8 3 L11 6 L8 9"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export function ThreatModelPanel({ events }: { events: SweepEvent[] }) {
  const payload = extractLastReconPayload(events);

  if (!payload) {
    return (
      <div className="rounded-md border border-paper-300 bg-white shadow-card">
        <div className="px-4 py-2.5 border-b border-paper-200 text-2xs uppercase tracking-wider text-paper-500 mono">
          Threat model
        </div>
        <div className="p-4 flex items-center gap-3 text-xs text-paper-500 italic">
          <Cmul8Mark size={18} mode="spin" />
          <span>Recon in progress&hellip;</span>
        </div>
      </div>
    );
  }

  const tm = payload.threat_model || {};
  const stack = payload.stack || tm.stack || {};
  const surfaces = payload.surfaces || tm.surfaces || [];
  const signalsCount = payload.signals_count ?? 0;
  // Recon output nests the source/sink lists one level deeper as
  // `threat_model.threat_model.{untrusted_sources,high_impact_sinks}`;
  // the top-level dict may also carry them directly. Read both.
  const untrusted =
    tm.untrusted_sources ||
    tm.threat_model?.untrusted_sources ||
    [];
  const sinks =
    tm.high_impact_sinks ||
    tm.threat_model?.high_impact_sinks ||
    [];

  const stackLabel = formatStack(stack);

  return (
    <div className="rounded-md border border-paper-300 bg-white shadow-card">
      <div className="px-4 py-2.5 border-b border-paper-200 text-2xs uppercase tracking-wider text-paper-500 mono flex items-center gap-2">
        <span>Threat model</span>
        <span className="text-paper-400">·</span>
        <span className="text-paper-600 normal-case tracking-normal">
          derived by Recon
        </span>
      </div>

      <div className="px-4 py-3 border-b border-paper-200 flex flex-wrap items-center gap-3 text-xs">
        {stackLabel && (
          <span className="mono text-paper-900 font-semibold">{stackLabel}</span>
        )}
        {surfaces.length > 0 && (
          <div className="flex items-center gap-1.5">
            <span className="text-2xs uppercase tracking-wider text-paper-500 mono">
              surfaces
            </span>
            <div className="flex flex-wrap gap-1">
              {surfaces.map((s) => (
                <span
                  key={s}
                  className="mono text-2xs px-1.5 py-0.5 rounded border border-paper-300 bg-paper-100 text-paper-700 uppercase tracking-wider"
                >
                  {s}
                </span>
              ))}
            </div>
          </div>
        )}
        <span className="ml-auto text-2xs mono text-paper-500">
          <span className="uppercase tracking-wider">signals</span>{" "}
          <span className="text-paper-900 tabular-nums font-semibold">
            {signalsCount}
          </span>
        </span>
      </div>

      <div className="p-4 grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <div className="text-2xs uppercase tracking-wider text-paper-500 mono mb-2">
            Untrusted sources
          </div>
          {untrusted.length === 0 ? (
            <div className="text-2xs italic text-paper-500">
              None reported.
            </div>
          ) : (
            <div className="flex flex-wrap gap-1.5">
              {untrusted.map((src) => (
                <span
                  key={src}
                  className="inline-flex items-center gap-1 mono text-2xs px-1.5 py-0.5 rounded border border-sev-medium/40 bg-amber-50 text-sev-medium"
                >
                  <InboundArrow />
                  {src}
                </span>
              ))}
            </div>
          )}
        </div>
        <div>
          <div className="text-2xs uppercase tracking-wider text-paper-500 mono mb-2">
            High-impact sinks
          </div>
          {sinks.length === 0 ? (
            <div className="text-2xs italic text-paper-500">
              None reported.
            </div>
          ) : (
            <div className="flex flex-wrap gap-1.5">
              {sinks.map((sink) => (
                <span
                  key={sink}
                  className="inline-flex items-center gap-1 mono text-2xs px-1.5 py-0.5 rounded border border-sev-critical/40 bg-red-50 text-sev-critical"
                >
                  <OutboundArrow />
                  {sink}
                </span>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
