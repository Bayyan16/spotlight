import { useEffect, useState } from "react";
import { getPresence, type PresenceResult } from "../lib/api";
import { IconCheck } from "./Icons";

/**
 * PresencePanel — cross-surface presence (Tranche B7).
 *
 * Answers the wedge question from the bank-security review
 * (docs/BANK_FEEDBACK_2026-07-16.md): every scanner tells you what it
 * found in *this* repo; nobody tells you whether the same class is also
 * reachable in your *other* repos. This panel fetches the /findings/
 * {id}/presence endpoint and renders one row per matching sweep.
 */

type Props = {
  findingId: string;
};

export function PresencePanel({ findingId }: Props) {
  const [state, setState] = useState<
    { kind: "loading" } | { kind: "loaded"; data: PresenceResult } | { kind: "error" }
  >({ kind: "loading" });

  useEffect(() => {
    let cancelled = false;
    setState({ kind: "loading" });
    getPresence(findingId)
      .then((data) => {
        if (cancelled) return;
        if (data === null) {
          setState({ kind: "error" });
        } else {
          setState({ kind: "loaded", data });
        }
      })
      .catch(() => {
        if (!cancelled) setState({ kind: "error" });
      });
    return () => {
      cancelled = true;
    };
  }, [findingId]);

  return (
    <div className="border border-paper-300 rounded-md bg-white shadow-card">
      <div className="px-4 py-2.5 border-b border-paper-200 text-2xs uppercase tracking-wider text-paper-500 mono">
        Cross-surface presence
      </div>
      <div className="px-4 py-3">
        {state.kind === "loading" && <PresenceSkeleton />}
        {state.kind === "error" && (
          <div className="text-xs text-paper-500 italic">
            Presence lookup unavailable.
          </div>
        )}
        {state.kind === "loaded" && <PresenceBody data={state.data} />}
      </div>
    </div>
  );
}

function PresenceSkeleton() {
  return (
    <div className="space-y-2">
      <div className="skeleton h-3 w-2/3" />
      <div className="skeleton h-3 w-2/3" />
      <div className="skeleton h-3 w-2/3" />
    </div>
  );
}

function PresenceBody({ data }: { data: PresenceResult }) {
  if (data.presence_count === 0) {
    return (
      <div className="flex items-center gap-2 text-xs text-paper-600">
        <span className="text-accent">
          <IconCheck size={12} />
        </span>
        <span>Not present elsewhere in this workspace.</span>
      </div>
    );
  }
  return (
    <>
      <p className="text-sm text-paper-800 leading-relaxed mb-3">
        This{" "}
        <span className="mono text-2xs uppercase tracking-wider bg-accent-soft text-accent border border-accent/30 rounded px-1.5 py-0.5 mx-0.5">
          {data.class}
        </span>{" "}
        class is reachable in{" "}
        <span className="mono tabular-nums font-semibold text-paper-900">
          {data.presence_count}
        </span>{" "}
        other repo{data.presence_count === 1 ? "" : "s"} in your workspace.
      </p>
      <ul className="space-y-2">
        {data.matches.map((m) => (
          <li
            key={m.finding_id}
            className="flex items-center gap-3 border border-paper-200 rounded px-3 py-2 bg-paper-50"
          >
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-sm font-semibold text-paper-900 truncate">
                  {m.repo_name}
                </span>
                <span className="text-2xs mono text-paper-500 truncate">
                  {m.sweep_id}
                </span>
              </div>
              <div className="mt-1 text-2xs mono text-paper-600 truncate">
                {m.file}:{m.line}
              </div>
            </div>
            <TierChip tier={m.tier} />
            <span className="text-2xs mono uppercase tracking-wider text-paper-500 shrink-0 w-16 text-right">
              {relativeTime(m.sweep_started_at)}
            </span>
          </li>
        ))}
      </ul>
    </>
  );
}

function TierChip({ tier }: { tier: string }) {
  if (tier === "verified") {
    return (
      <span className="inline-flex items-center gap-1 text-2xs uppercase mono px-1.5 py-0.5 rounded font-semibold tracking-wider bg-accent text-white shrink-0">
        <IconCheck size={9} /> verified
      </span>
    );
  }
  const map: Record<string, string> = {
    "high-confidence": "bg-amber-100 text-sev-medium border border-sev-medium/40",
    "needs-review": "bg-paper-200 text-paper-700 border border-paper-400",
    held: "bg-paper-100 text-paper-500 border border-paper-300",
  };
  return (
    <span
      className={`inline-flex items-center text-2xs uppercase mono px-1.5 py-0.5 rounded font-semibold tracking-wider shrink-0 ${
        map[tier] ?? ""
      }`}
    >
      {tier}
    </span>
  );
}

function relativeTime(iso: string | null): string {
  if (!iso) return "—";
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return "—";
  const diffS = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (diffS < 60) return `${diffS}s ago`;
  const diffM = Math.round(diffS / 60);
  if (diffM < 60) return `${diffM}m ago`;
  const diffH = Math.round(diffM / 60);
  if (diffH < 24) return `${diffH}h ago`;
  const diffD = Math.round(diffH / 24);
  return `${diffD}d ago`;
}
