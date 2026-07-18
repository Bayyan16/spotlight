import { useState } from "react";

import type { Finding, ReviewAction } from "../lib/api";
import { attestationUrl, reviewFinding } from "../lib/api";
import { IconAttestation, IconCheck } from "./Icons";
import { PresencePanel } from "./PresencePanel";

export function FindingDetail({
  finding,
  sweepId,
  onFindingUpdated,
}: {
  finding: Finding;
  sweepId?: string | null;
  onFindingUpdated?: (updated: Finding) => void;
}) {
  const verified = finding.tier === "verified";
  const fixed = finding.state === "confirmed-fixed";
  return (
    <section className="flex-1 min-w-0 overflow-y-auto bg-paper-50">
      <header className="border-b border-paper-300 bg-paper-50/95 backdrop-blur px-8 py-5 sticky top-0 z-10">
        <div className="flex items-center gap-2 mb-2 text-2xs mono text-paper-500 uppercase tracking-wider">
          <span className="text-paper-700 font-semibold">{finding.id}</span>
          <span className="text-paper-400">·</span>
          <span>{finding.cwe}</span>
          <span className="text-paper-400">·</span>
          <span>surface {finding.surface}</span>
        </div>
        <div className="flex items-start gap-4">
          <div className="min-w-0 flex-1">
            <h1 className="text-2xl text-paper-900 font-semibold tracking-tight leading-tight">
              {finding.title}
            </h1>
            <div className="mt-1.5 text-xs mono text-paper-600">
              {finding.location.file}:{finding.location.line} ·{" "}
              <span className="text-paper-800">{finding.location.function}</span>
            </div>
          </div>
          <ConfidenceDial confidence={finding.confidence} verified={verified} />
        </div>
        <div className="mt-4 flex items-center gap-2 flex-wrap">
          <BigSevChip s={finding.severity} />
          <BigTierChip tier={finding.tier} />
          <BigStateChip state={finding.state} fixed={fixed} />
          <span className="ml-auto text-2xs mono uppercase tracking-wider text-paper-500">
            <span className="mono tabular-nums text-paper-800 font-semibold">
              {finding.consensus.independent_corroborators}
            </span>{" "}
            corroborators
          </span>
        </div>
        {sweepId && (
          <div className="mt-3 flex items-center gap-1.5">
            <span className="text-2xs mono uppercase tracking-wider text-paper-500 mr-2">
              Export Attestation
            </span>
            <AttestationBtn href={attestationUrl(sweepId, "pdf")} label="PDF" />
            <AttestationBtn href={attestationUrl(sweepId, "markdown")} label="Markdown" />
            <AttestationBtn href={attestationUrl(sweepId, "json")} label="JSON" />
          </div>
        )}
      </header>

      <div className="px-6 py-5 space-y-6">
        {finding.plain_language && (finding.plain_language.one_liner ||
          finding.plain_language.blast_radius ||
          finding.plain_language.urgency) && (
          <Panel title="Why this matters (plain-language)">
            {finding.plain_language.one_liner && (
              <p className="text-base text-paper-900 font-medium leading-relaxed">
                {finding.plain_language.one_liner}
              </p>
            )}
            {finding.plain_language.blast_radius && (
              <p className="mt-3 text-sm text-paper-800 leading-relaxed">
                <span className="mono text-2xs uppercase tracking-wider text-paper-500 mr-2">
                  Blast radius
                </span>
                {finding.plain_language.blast_radius}
              </p>
            )}
            {finding.plain_language.urgency && (
              <p className="mt-3 text-sm text-paper-800 leading-relaxed">
                <span className="mono text-2xs uppercase tracking-wider text-paper-500 mr-2">
                  Urgency
                </span>
                {finding.plain_language.urgency}
              </p>
            )}
          </Panel>
        )}

        <Panel title="Why you can trust this">
          <p className="text-sm text-paper-800 leading-relaxed mb-3">{finding.evidence.root_cause}</p>
          <ul className="space-y-1.5">
            {finding.evidence.corroboration.map((c, i) => (
              <li key={i} className="flex items-start gap-2 text-sm">
                <span className="text-accent mt-0.5">
                  <IconCheck />
                </span>
                <span className="mono text-2xs uppercase tracking-wider text-paper-500 pt-0.5 w-24 shrink-0">
                  {c.type}
                </span>
                <span className="text-paper-800 text-xs">
                  {c.result ??
                    (Array.isArray(c.detail) ? c.detail.join(" · ") : String(c.detail ?? ""))}
                </span>
              </li>
            ))}
            <li className="flex items-start gap-2 text-sm">
              <span className="text-accent mt-0.5">
                <IconCheck />
              </span>
              <span className="mono text-2xs uppercase tracking-wider text-paper-500 pt-0.5 w-24 shrink-0">
                consensus
              </span>
              <span className="text-paper-800 text-xs">{finding.consensus.rationale}</span>
            </li>
          </ul>
        </Panel>

        <Panel title="Fix">
          <p className="text-sm text-paper-800 mb-3">{finding.evidence.fix.approach}</p>
          <div className="flex flex-wrap gap-2 text-xs">
            <StatChip
              label="Verifier"
              value={String(finding.evidence.verification.result ?? "")}
              good={finding.evidence.verification.result === "repro-now-blocked"}
            />
            <StatChip
              label="Backdoor scan"
              value={String(finding.evidence.verification.backdoor_check ?? "")}
              good={finding.evidence.verification.backdoor_check === "pass"}
            />
            <StatChip
              label="Independence"
              value={String(finding.evidence.verification.independent_verifier ?? "")}
              good={!!finding.evidence.verification.independent_verifier}
            />
          </div>
        </Panel>

        <DiffPanel finding={finding} />

        <ReviewPanel finding={finding} onUpdated={onFindingUpdated} />

        {finding.evidence.sandbox && (
          <Panel title="Sandbox (hostile-input containment)">
            <div className="text-xs text-paper-700 mb-3">
              Reproduction and verification ran in an isolated container with{" "}
              <span className="mono text-2xs uppercase tracking-wider bg-accent-soft text-accent border border-accent/30 rounded px-1.5 py-0.5">
                egress off
              </span>{" "}
              — the target code cannot phone home from Spotlight's sandbox.
            </div>
            <div className="grid grid-cols-2 gap-4">
              <SandboxCard label="Reproducer" data={finding.evidence.sandbox.reproducer} />
              <SandboxCard label="Verifier" data={finding.evidence.sandbox.verifier} />
            </div>
          </Panel>
        )}

        {finding.evidence.threat_model && (
          <Panel title="Threat model in effect">
            <div className="mb-3 text-xs text-paper-700 leading-relaxed">
              Judged under the{" "}
              <span className="mono uppercase tracking-wider text-2xs text-accent bg-accent-soft border border-accent/30 rounded px-1.5 py-0.5">
                {finding.evidence.threat_model.profile}
              </span>{" "}
              profile. The threat model below was authored by{" "}
              <span className="mono">{finding.evidence.threat_model.author}</span> at Recon time —
              it describes *what could go wrong at this repo*.
              {finding.evidence.threat_model.stack?.language && (
                <>
                  {" "}Stack detected:{" "}
                  <span className="mono text-paper-800">
                    {finding.evidence.threat_model.stack.language}
                    {finding.evidence.threat_model.stack.framework
                      ? ` · ${finding.evidence.threat_model.stack.framework}`
                      : ""}
                  </span>
                  .
                </>
              )}
            </div>
            <div className="grid grid-cols-2 gap-4 text-xs">
              <div>
                <div className="text-2xs uppercase tracking-wider text-paper-500 mono mb-1.5">
                  Untrusted sources
                </div>
                <ul className="space-y-1">
                  {(finding.evidence.threat_model.untrusted_sources ?? []).map((s) => (
                    <li key={s} className="mono text-paper-800 text-2xs bg-paper-100 border border-paper-200 rounded px-2 py-0.5 inline-block mr-1 mb-1">
                      {s}
                    </li>
                  ))}
                  {(finding.evidence.threat_model.untrusted_sources ?? []).length === 0 && (
                    <li className="text-paper-500 text-2xs italic">none</li>
                  )}
                </ul>
              </div>
              <div>
                <div className="text-2xs uppercase tracking-wider text-paper-500 mono mb-1.5">
                  High-impact sinks
                </div>
                <ul className="space-y-1">
                  {(finding.evidence.threat_model.high_impact_sinks ?? []).map((s) => (
                    <li key={s} className="mono text-paper-800 text-2xs bg-paper-100 border border-paper-200 rounded px-2 py-0.5 inline-block mr-1 mb-1">
                      {s}
                    </li>
                  ))}
                  {(finding.evidence.threat_model.high_impact_sinks ?? []).length === 0 && (
                    <li className="text-paper-500 text-2xs italic">none</li>
                  )}
                </ul>
              </div>
            </div>
          </Panel>
        )}

        <PresencePanel findingId={finding.id} />

        <Panel title="Audit">
          <dl className="grid grid-cols-2 gap-x-6 gap-y-1.5 text-xs mono">
            {Object.entries(finding.audit ?? {}).map(([k, v]) => (
              <div key={k} className="contents">
                <dt className="text-paper-500 uppercase text-2xs tracking-wider">{k}</dt>
                <dd className="text-paper-800 truncate">{String(v ?? "—")}</dd>
              </div>
            ))}
          </dl>
        </Panel>
      </div>
    </section>
  );
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center gap-3">
      <span className="text-2xs uppercase tracking-wider text-paper-500 mono w-24 shrink-0">
        {label}
      </span>
      {value}
    </div>
  );
}

function ConfidenceDial({ confidence, verified }: { confidence: number; verified: boolean }) {
  const pct = Math.round(confidence * 100);
  const circumference = 2 * Math.PI * 26;
  const dashOffset = circumference * (1 - confidence);
  const stroke = verified ? "#3c8f5c" : confidence >= 0.7 ? "#c99a1e" : "#8a8578";
  return (
    <div className="relative shrink-0">
      <svg width="72" height="72" viewBox="0 0 72 72" className="rotate-[-90deg]">
        <circle cx="36" cy="36" r="26" stroke="#e6e2d9" strokeWidth="5" fill="none" />
        <circle
          cx="36"
          cy="36"
          r="26"
          stroke={stroke}
          strokeWidth="5"
          strokeLinecap="round"
          fill="none"
          strokeDasharray={circumference}
          strokeDashoffset={dashOffset}
          style={{ transition: "stroke-dashoffset 500ms ease" }}
        />
      </svg>
      <div className="absolute inset-0 grid place-items-center">
        <div className="text-center">
          <div className="mono tabular-nums text-sm font-semibold text-paper-900">{pct}</div>
          <div className="text-[8px] uppercase tracking-wider text-paper-500 mono">conf</div>
        </div>
      </div>
    </div>
  );
}

function AttestationBtn({ href, label }: { href: string; label: string }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noreferrer"
      className="inline-flex items-center gap-1 text-2xs mono uppercase tracking-wider text-paper-700 border border-paper-300 hover:border-accent hover:text-accent bg-white rounded px-2 py-1 transition-colors"
    >
      <IconAttestation size={10} />
      {label}
    </a>
  );
}

function BigSevChip({ s }: { s: string }) {
  const map: Record<string, string> = {
    critical: "bg-sev-critical text-white",
    high: "bg-sev-high text-white",
    medium: "bg-sev-medium text-white",
    low: "bg-sev-low text-white",
  };
  return (
    <span
      className={`inline-flex items-center text-2xs uppercase mono px-2 py-1 rounded font-semibold tracking-wider ${
        map[s] ?? "bg-paper-400 text-white"
      }`}
    >
      {s}
    </span>
  );
}

function BigTierChip({ tier }: { tier: string }) {
  if (tier === "verified") {
    return (
      <span className="inline-flex items-center gap-1 text-2xs uppercase mono px-2 py-1 rounded font-semibold tracking-wider bg-accent text-white">
        <IconCheck size={10} /> verified
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
      className={`inline-flex items-center text-2xs uppercase mono px-2 py-1 rounded font-semibold tracking-wider ${
        map[tier] ?? ""
      }`}
    >
      {tier}
    </span>
  );
}

function BigStateChip({ state, fixed }: { state: string; fixed: boolean }) {
  if (fixed) {
    return (
      <span className="inline-flex items-center gap-1 text-2xs uppercase mono px-2 py-1 rounded font-semibold tracking-wider bg-accent-soft text-accent border border-accent/40">
        <IconCheck size={10} /> {state}
      </span>
    );
  }
  return (
    <span className="inline-flex items-center text-2xs uppercase mono px-2 py-1 rounded font-semibold tracking-wider bg-paper-200 text-paper-700 border border-paper-300">
      {state}
    </span>
  );
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="border border-paper-300 rounded-md bg-white shadow-card">
      <div className="px-4 py-2.5 border-b border-paper-200 text-2xs uppercase tracking-wider text-paper-500 mono">
        {title}
      </div>
      <div className="px-4 py-3">{children}</div>
    </div>
  );
}

function SeverityPill({ s }: { s: string }) {
  const map: Record<string, string> = {
    critical: "bg-sev-critical/15 text-sev-critical border-sev-critical/30",
    high: "bg-sev-high/15 text-sev-high border-sev-high/30",
    medium: "bg-sev-medium/15 text-sev-medium border-sev-medium/30",
    low: "bg-sev-low/15 text-sev-low border-sev-low/30",
  };
  return (
    <span className={`text-2xs uppercase mono px-1.5 py-0.5 rounded border ${map[s] ?? ""}`}>
      {s}
    </span>
  );
}

function SandboxCard({
  label,
  data,
}: {
  label: string;
  data:
    | {
        engine?: string;
        duration_s?: number;
        egress_attempts?: number;
        egress_denied_hosts?: string[];
        exit_code?: number;
        capability_token?: Record<string, unknown>;
      }
    | undefined;
}) {
  if (!data || !data.engine) {
    return (
      <div className="border border-paper-200 rounded p-3 bg-paper-50 text-2xs italic text-paper-500">
        {label}: no run
      </div>
    );
  }
  const modal = data.engine === "modal";
  const cap = data.capability_token as {
    egress_allowed?: boolean;
    timeout_s?: number;
    memory_mb?: number;
    cpu?: number;
    ro_paths?: string[];
  } | undefined;
  return (
    <div className="border border-paper-200 rounded p-3 bg-white">
      <div className="flex items-center gap-2 mb-2">
        <span className="text-2xs uppercase tracking-wider text-paper-500 mono">{label}</span>
        <span
          className={`text-2xs mono uppercase tracking-wider px-1.5 py-0.5 rounded border ${
            modal
              ? "border-accent/40 bg-accent-soft text-accent"
              : "border-paper-400 text-paper-600"
          }`}
        >
          {modal ? "modal · isolated" : data.engine}
        </span>
      </div>
      <dl className="grid grid-cols-2 gap-x-3 gap-y-1 text-2xs mono">
        <dt className="text-paper-500 uppercase">Duration</dt>
        <dd className="text-paper-800 tabular-nums">
          {data.duration_s != null ? `${data.duration_s.toFixed(2)}s` : "—"}
        </dd>
        <dt className="text-paper-500 uppercase">Exit</dt>
        <dd className="text-paper-800 tabular-nums">{data.exit_code ?? "—"}</dd>
        {cap && (
          <>
            <dt className="text-paper-500 uppercase">Egress</dt>
            <dd className={cap.egress_allowed ? "text-sev-medium" : "text-accent"}>
              {cap.egress_allowed ? "allowed" : "denied"}
            </dd>
            <dt className="text-paper-500 uppercase">Timeout</dt>
            <dd className="text-paper-800 tabular-nums">{cap.timeout_s}s</dd>
            <dt className="text-paper-500 uppercase">Memory</dt>
            <dd className="text-paper-800 tabular-nums">{cap.memory_mb}MB</dd>
          </>
        )}
        {(data.egress_attempts ?? 0) > 0 && (
          <>
            <dt className="text-paper-500 uppercase col-span-2 mt-1">
              Egress attempts denied
            </dt>
            <dd className="col-span-2 text-sev-medium">
              {(data.egress_denied_hosts ?? []).join(", ")}
            </dd>
          </>
        )}
      </dl>
    </div>
  );
}


/**
 * DiffPanel — C5 · unified diff + Warden backdoor-check verdict.
 *
 * Renders the Remediator's proposed patch with `+` / `-` line highlighting,
 * then a Warden panel below showing what the backdoor-check found. If the
 * backdoor check FAILED, the panel banner turns red — even a repro-blocked
 * fix cannot be trusted when the diff removed a control instead of adding
 * one. That's what the Verifier is protecting against.
 */
function DiffPanel({ finding }: { finding: Finding }) {
  const diff = finding.evidence.fix.diff_content;
  const verification = finding.evidence.verification as {
    result?: string;
    backdoor_check?: string;
    backdoor_findings?: string[];
  };
  const backdoor = verification.backdoor_check ?? "unknown";
  const backdoorFindings = Array.isArray(verification.backdoor_findings)
    ? verification.backdoor_findings
    : [];
  const backdoorFailed = backdoor === "fail";

  if (!diff) return null;

  const lines = diff.split("\n");
  return (
    <Panel title="Fix diff · Warden self-defense">
      <div className="mb-3 flex items-center gap-2 text-2xs">
        <span
          className={`mono uppercase tracking-wider px-2 py-0.5 rounded-full border ${
            backdoorFailed
              ? "bg-red-50 text-sev-critical border-sev-critical/40"
              : "bg-accent-soft text-accent border-accent/30"
          }`}
        >
          Warden backdoor scan: {backdoor}
        </span>
        {finding.evidence.fix.pr_url && (
          <a
            href={finding.evidence.fix.pr_url}
            target="_blank"
            rel="noreferrer"
            className="mono uppercase tracking-wider text-accent hover:underline"
          >
            Open PR ↗
          </a>
        )}
        {finding.evidence.fix.branch && (
          <span className="mono text-paper-500">
            branch <span className="text-paper-700">{finding.evidence.fix.branch}</span>
          </span>
        )}
      </div>

      <pre className="text-2xs mono leading-tight border border-paper-300 rounded overflow-x-auto bg-paper-50">
        {lines.map((line, i) => (
          <div key={i} className={diffLineClass(line)}>
            <span className="tabular-nums text-paper-400 pr-2 select-none inline-block w-8 text-right">
              {i + 1}
            </span>
            <span>{line || " "}</span>
          </div>
        ))}
      </pre>

      {backdoorFailed && (
        <div className="mt-3 border-l-2 border-sev-critical bg-red-50/60 px-3 py-2 text-xs">
          <div className="mono uppercase tracking-wider text-2xs text-sev-critical mb-1">
            Warden REJECTED this fix
          </div>
          <div className="text-paper-800">
            The Remediator produced a diff that removes a security control
            rather than adding one. This finding stays open regardless of
            the Reproducer's outcome — a "not exploited" PoC on a stripped
            control is not a valid fix.
          </div>
          {backdoorFindings.length > 0 && (
            <ul className="mt-2 space-y-0.5 mono text-2xs text-paper-700">
              {backdoorFindings.map((k, i) => (
                <li key={i}>· {k}</li>
              ))}
            </ul>
          )}
        </div>
      )}

      {!backdoorFailed && backdoorFindings.length === 0 && (
        <div className="mt-3 text-2xs text-paper-500 italic">
          Warden reviewed the diff; no control-removal patterns detected.
        </div>
      )}
    </Panel>
  );
}

function diffLineClass(line: string): string {
  if (line.startsWith("+++") || line.startsWith("---")) {
    return "px-2 py-0.5 text-paper-500 bg-paper-100";
  }
  if (line.startsWith("+")) {
    return "px-2 py-0.5 bg-accent-soft/60 text-accent";
  }
  if (line.startsWith("-")) {
    return "px-2 py-0.5 bg-red-50 text-sev-critical";
  }
  if (line.startsWith("@@")) {
    return "px-2 py-0.5 bg-paper-200 text-paper-600 mono";
  }
  return "px-2 py-0.5 text-paper-700";
}


function StatChip({ label, value, good }: { label: string; value: string; good: boolean }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-1 rounded border mono ${
        good ? "border-accent/40 bg-accent-soft text-accent" : "border-paper-400 text-paper-600"
      }`}
    >
      <span className="text-2xs uppercase text-paper-500">{label}</span>
      {good && <IconCheck size={10} />}
      <span>{value}</span>
    </span>
  );
}


/**
 * ReviewPanel — C4 · analyst verdict + signed audit thread.
 *
 * Three verdicts:
 *   accept              — real, ship the fix
 *   false-positive      — Spotlight was wrong, skip
 *   risk-accept-until   — real, but accepted-until an ISO date
 *
 * Every click POSTs to /findings/{id}/review, which signs the verdict into
 * the finding's chain of custody. The panel shows previously-signed reviews
 * inline so an auditor sees the full analyst history without leaving the
 * finding. Terminal reviews aren't reversed — a new review appends a new
 * signed entry that supersedes the old visible state.
 */
function ReviewPanel({
  finding,
  onUpdated,
}: {
  finding: Finding;
  onUpdated?: (updated: Finding) => void;
}) {
  const [action, setAction] = useState<ReviewAction | null>(null);
  const [reason, setReason] = useState("");
  const [until, setUntil] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const review = finding.review;
  const cocEntries =
    ((finding.audit as { chain_of_custody?: Array<Record<string, unknown>> } | undefined)
      ?.chain_of_custody ?? []) as Array<{
      actor_kind: string;
      actor_id: string;
      action: string;
      ts: string;
      key_fingerprint?: string;
    }>;
  const reviewEntries = cocEntries.filter(
    (e) => e.actor_kind === "human" && e.action?.startsWith("review.")
  );

  async function submit() {
    if (!action || !reason.trim()) {
      setErr("Reason is required.");
      return;
    }
    if (action === "risk-accept-until" && !until) {
      setErr("Until date is required for risk-accept-until.");
      return;
    }
    setSubmitting(true);
    setErr(null);
    try {
      const updated = await reviewFinding(finding.id, {
        action,
        reason: reason.trim(),
        until: action === "risk-accept-until" ? until : undefined,
      });
      onUpdated?.(updated);
      setAction(null);
      setReason("");
      setUntil("");
    } catch (e) {
      setErr(e instanceof Error ? e.message : "review failed");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Panel title="Analyst review">
      {review ? (
        <div className="mb-3 flex items-center gap-2 text-xs">
          <ReviewStateChip state={review.state} />
          <span className="text-paper-700">
            by <span className="mono">{review.reviewer}</span>
          </span>
          {review.until && (
            <span className="text-paper-500 mono text-2xs uppercase tracking-wider">
              until {review.until}
            </span>
          )}
          <span className="text-2xs mono text-paper-400">
            {new Date(review.ts).toLocaleString()}
          </span>
        </div>
      ) : (
        <div className="mb-3 text-xs text-paper-600">
          No review yet. An analyst verdict lands as a signed entry on the
          chain of custody — bank auditors see human decisions in the same
          log as agent actions.
        </div>
      )}

      {review?.reason && (
        <div className="mb-3 text-sm text-paper-800 border-l-2 border-paper-300 pl-3 italic">
          {review.reason}
        </div>
      )}

      {action === null ? (
        <div className="flex flex-wrap gap-2">
          <ReviewBtn label="Accept" onClick={() => setAction("accept")} tone="ok" />
          <ReviewBtn
            label="False positive"
            onClick={() => setAction("false-positive")}
            tone="neutral"
          />
          <ReviewBtn
            label="Risk-accept until…"
            onClick={() => setAction("risk-accept-until")}
            tone="warn"
          />
        </div>
      ) : (
        <div className="space-y-2 border border-paper-300 rounded-md p-3 bg-white">
          <div className="text-2xs mono uppercase tracking-wider text-paper-500">
            Verdict: {action}
          </div>
          <textarea
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Reason (required) — one or two sentences"
            rows={2}
            className="w-full text-sm border border-paper-300 rounded px-2 py-1 focus:outline-none focus:border-accent"
          />
          {action === "risk-accept-until" && (
            <input
              type="date"
              value={until}
              onChange={(e) => setUntil(e.target.value)}
              className="text-sm border border-paper-300 rounded px-2 py-1 focus:outline-none focus:border-accent"
            />
          )}
          {err && <div className="text-2xs text-sev-high">{err}</div>}
          <div className="flex items-center gap-2">
            <button
              disabled={submitting}
              onClick={submit}
              className="px-3 py-1 rounded bg-accent text-white text-xs uppercase mono tracking-wider disabled:opacity-50"
            >
              {submitting ? "Signing…" : "Sign & submit"}
            </button>
            <button
              disabled={submitting}
              onClick={() => {
                setAction(null);
                setReason("");
                setUntil("");
                setErr(null);
              }}
              className="px-3 py-1 rounded border border-paper-300 text-xs uppercase mono tracking-wider text-paper-700"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {reviewEntries.length > 0 && (
        <div className="mt-4">
          <div className="text-2xs mono uppercase tracking-wider text-paper-500 mb-2">
            Signed review history
          </div>
          <ul className="space-y-1 text-2xs">
            {reviewEntries.map((e, i) => (
              <li key={i} className="flex items-center gap-2 text-paper-600">
                <span className="mono text-paper-800">{e.action.replace("review.", "")}</span>
                <span className="text-paper-500">·</span>
                <span className="mono">{e.actor_id}</span>
                <span className="text-paper-500">·</span>
                <span className="mono">{new Date(e.ts).toLocaleString()}</span>
                {e.key_fingerprint && (
                  <span
                    className="mono text-paper-400 truncate"
                    title={`key fingerprint ${e.key_fingerprint}`}
                  >
                    · fp {e.key_fingerprint.slice(0, 12)}
                  </span>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
    </Panel>
  );
}

function ReviewStateChip({ state }: { state: string }) {
  const map: Record<string, string> = {
    accepted: "bg-accent-soft text-accent border-accent/40",
    "false-positive": "bg-paper-200 text-paper-700 border-paper-400",
    "risk-accepted": "bg-yellow-50 text-yellow-800 border-yellow-300",
  };
  return (
    <span
      className={`text-2xs mono uppercase tracking-wider px-2 py-0.5 rounded-full border ${map[state] ?? "bg-paper-200 text-paper-700 border-paper-400"}`}
    >
      {state}
    </span>
  );
}

function ReviewBtn({
  label,
  onClick,
  tone,
}: {
  label: string;
  onClick: () => void;
  tone: "ok" | "warn" | "neutral";
}) {
  const cls =
    tone === "ok"
      ? "border-accent/40 bg-accent-soft text-accent hover:brightness-95"
      : tone === "warn"
        ? "border-yellow-300 bg-yellow-50 text-yellow-800 hover:brightness-95"
        : "border-paper-300 bg-white text-paper-700 hover:bg-paper-100";
  return (
    <button
      onClick={onClick}
      className={`text-xs uppercase mono tracking-wider px-3 py-1.5 rounded border ${cls}`}
    >
      {label}
    </button>
  );
}
