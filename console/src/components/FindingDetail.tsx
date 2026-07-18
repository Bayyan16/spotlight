import { useMemo, useState } from "react";

import type { Finding, ReviewAction, SweepSummary } from "../lib/api";
import { attestationUrl, repoFileUrl, reviewFinding } from "../lib/api";
import { IconAttestation, IconCheck } from "./Icons";
import { PresencePanel } from "./PresencePanel";

export function FindingDetail({
  finding,
  sweepId,
  sweep,
  onFindingUpdated,
}: {
  finding: Finding;
  sweepId?: string | null;
  /** Active sweep row — used to build linkable file URLs from clone_url +
   *  commit_sha. Optional so callers that don't have it degrade to plain
   *  path display. */
  sweep?: SweepSummary | null;
  onFindingUpdated?: (updated: Finding) => void;
}) {
  const verified = finding.tier === "verified";
  const fixed = finding.state === "confirmed-fixed";

  // Prefer the repo-relative path so we never leak the ephemeral tmpdir
  // clone directory into the UI. Fall back to the raw `file` field only
  // for pre-migration findings that don't carry `repo_relative_path`.
  const relPath =
    finding.location.repo_relative_path ??
    finding.location.file.replace(/^\/tmp\/spotlight-clone-[^/]+\/src\//, "");

  const fileUrl = useMemo(
    () =>
      repoFileUrl(
        sweep?.clone_url ?? null,
        sweep?.commit_sha ?? null,
        relPath,
        finding.location.line
      ),
    [sweep?.clone_url, sweep?.commit_sha, relPath, finding.location.line]
  );

  return (
    <section className="flex-1 min-w-0 overflow-y-auto bg-paper-50">
      <header className="border-b border-paper-300 bg-paper-50/95 backdrop-blur px-8 py-5 sticky top-0 z-10">
        <div className="flex items-center gap-2 mb-2 text-2xs mono text-paper-500 uppercase tracking-wider">
          <span className="text-paper-700 font-semibold">{finding.id}</span>
          <span className="text-paper-400">·</span>
          <span>{finding.cwe}</span>
          <span className="text-paper-400">·</span>
          <span>surface {finding.surface}</span>
          {sweep?.org && sweep?.repo_name && (
            <>
              <span className="text-paper-400">·</span>
              <span className="text-paper-700">
                {sweep.org}/{sweep.repo_name}
              </span>
            </>
          )}
          {sweep?.commit_sha && (
            <>
              <span className="text-paper-400">·</span>
              <span
                className="text-paper-700 bg-paper-100 border border-paper-300 rounded px-1.5"
                title={sweep.commit_sha}
              >
                {sweep.commit_sha.slice(0, 8)}
              </span>
            </>
          )}
        </div>
        <div className="flex items-start gap-4">
          <div className="min-w-0 flex-1">
            <h1 className="text-[26px] text-paper-900 font-display leading-tight">
              {finding.title}
            </h1>
            <div className="mt-1.5 text-xs mono text-paper-600 flex items-center gap-1 flex-wrap">
              {fileUrl ? (
                <a
                  href={fileUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="text-accent hover:underline"
                >
                  {relPath}:{finding.location.line} ↗
                </a>
              ) : (
                <span>
                  {relPath}:{finding.location.line}
                </span>
              )}
              <span className="text-paper-400">·</span>
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

        <CodePreviewPanel finding={finding} fileUrl={fileUrl} />

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

        <SandboxOrStaticFactPanel finding={finding} />

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

        <PipelineTimelinePanel finding={finding} />
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
 * PipelineTimelinePanel — signed chain of custody + audit metadata as a
 * proper vertical timeline. Lives at the bottom of the finding detail
 * because it's reference material, not what an analyst reads first.
 * Collapsed by default so the reading flow lands on the high-signal
 * panels (plain language, code preview, evidence, fix, review) without
 * scrolling past a wall of hashes and timestamps.
 *
 * The old "Audit" key-value dump is replaced by:
 *   * a mini-grid of audit metadata (model, profile, deployment tier,
 *     tokens used, wall seconds, workspace signing-key fingerprint), and
 *   * a stage-by-stage timeline of every signed action, with human-
 *     readable labels + descriptions per stage.
 */
function PipelineTimelinePanel({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  const audit = (finding.audit ?? {}) as Record<string, unknown>;
  const coc = (audit.chain_of_custody ?? []) as Array<{
    actor_kind: string;
    actor_id: string;
    action: string;
    ts: string;
    payload_hash: string;
    signature: string;
    key_fingerprint: string;
  }>;

  const metaCandidates: Array<[string, unknown]> = [
    ["Model", audit.model],
    ["Deployment tier", audit.deployment_tier],
    ["Profile", audit.profile_name ?? audit.profile],
    ["Tokens used", audit.tokens_used],
    ["Wall seconds", audit.wall_seconds],
    ["Signing key fp", coc[0]?.key_fingerprint],
  ];
  const metaFields = metaCandidates.filter(
    ([, v]) => v !== undefined && v !== null && v !== ""
  );

  const stageCount = coc.length;
  const t0 = coc[0]?.ts;
  const tLast = coc[coc.length - 1]?.ts;

  return (
    <div className="border border-paper-300 rounded-md bg-white shadow-card">
      <button
        onClick={() => setOpen((s) => !s)}
        aria-expanded={open}
        className="w-full flex items-center gap-3 px-4 py-2.5 border-b border-paper-200"
      >
        <span
          className={`text-paper-400 text-xs transition-transform inline-block ${
            open ? "rotate-90" : ""
          }`}
        >
          ▸
        </span>
        <span className="text-2xs uppercase tracking-wider text-paper-500 mono">
          Pipeline timeline
        </span>
        <span className="text-2xs mono text-paper-500">
          {stageCount} signed stage{stageCount === 1 ? "" : "s"}
        </span>
        {t0 && tLast && (
          <span className="text-2xs mono text-paper-400 ml-auto">
            {new Date(t0).toLocaleString()} → {new Date(tLast).toLocaleString()}
          </span>
        )}
      </button>
      {open && (
        <div className="p-4 space-y-4">
          {metaFields.length > 0 && (
            <dl className="grid grid-cols-2 md:grid-cols-3 gap-x-6 gap-y-1.5 text-xs mono">
              {metaFields.map(([k, v]) => (
                <div key={k} className="min-w-0">
                  <dt className="text-paper-500 uppercase text-2xs tracking-wider">
                    {k}
                  </dt>
                  <dd className="text-paper-800 truncate" title={String(v)}>
                    {String(v)}
                  </dd>
                </div>
              ))}
            </dl>
          )}
          {stageCount === 0 ? (
            <div className="text-2xs mono uppercase tracking-wider text-paper-400 py-2">
              chain-of-custody empty — workspace signer unavailable at sweep time
            </div>
          ) : (
            <ol className="relative border-l border-paper-300 ml-2 space-y-3">
              {coc.map((e, i) => {
                const meta = describeStage(e.action, e.actor_kind, e.actor_id);
                return (
                  <li key={i} className="ml-4 relative">
                    <span
                      className={`absolute -left-[22px] top-1 h-3 w-3 rounded-full border-2 ${
                        e.actor_kind === "human"
                          ? "border-accent bg-accent"
                          : "border-paper-400 bg-white"
                      }`}
                    />
                    <div className="flex items-center gap-2 flex-wrap">
                      <span
                        className={`mono text-2xs uppercase tracking-wider px-1.5 py-0.5 rounded ${
                          e.actor_kind === "human"
                            ? "bg-accent-soft text-accent border border-accent/30"
                            : "bg-paper-100 text-paper-700 border border-paper-300"
                        }`}
                      >
                        {meta.label}
                      </span>
                      <span className="text-2xs mono text-paper-500">
                        {new Date(e.ts).toLocaleString()}
                      </span>
                    </div>
                    <div className="mt-1 text-xs text-paper-700 leading-relaxed">
                      {meta.description}
                    </div>
                    <div className="mt-1 text-[10px] mono text-paper-400 truncate">
                      hash {e.payload_hash.slice(0, 24)}… ·
                      sig {e.signature.slice(0, 16)}… · fp {e.key_fingerprint}
                    </div>
                  </li>
                );
              })}
            </ol>
          )}
        </div>
      )}
    </div>
  );
}

/**
 * Map raw action strings to a human-readable label + description. Anything
 * we don't recognise falls back to the raw action + a generic "signed
 * action" description so future stages don't silently regress the UX.
 */
function describeStage(
  action: string,
  actorKind: string,
  actorId: string
): { label: string; description: string } {
  switch (action) {
    case "candidate-raised":
      return {
        label: "Investigator · candidate raised",
        description:
          "The Investigator agent judged the data-flow slice sg-core produced and returned verdict=candidate. Bounded role — sees only this one slice, not the whole repo.",
      };
    case "reproduction-attempted":
      return {
        label: "Reproducer · PoC fired",
        description:
          "The Reproducer booted the target in a Modal sandbox with block_network=True, fired the class-appropriate PoC, and recorded the outcome plus egress-attempts count on the capability token.",
      };
    case "patch-generated":
      return {
        label: "Remediator · patch generated",
        description:
          "The Remediator produced a unified diff against the vulnerable file and wrote it to a .patched sibling. The original stays intact so the Verifier can compare before and after.",
      };
    case "reproduction-rechecked-after-patch":
      return {
        label: "Verifier · re-ran PoC",
        description:
          "The Verifier is a different agent with a fresh context and a distinct system prompt. It re-ran the PoC against the patched build and ran Warden's backdoor scan on the diff — repro-blocked ≠ fixed if the diff removed a control.",
      };
    case "tier-decided":
      return {
        label: "Consensus · tier decided",
        description:
          "Consensus counted the independent corroborators (deduped by modality × model_family × context_id), applied the tier rules, and set the finding's tier + confidence.",
      };
    case "review.accept":
      return {
        label: `Human · accept · ${actorId}`,
        description:
          "Analyst confirmed the finding is real and the fix should ship. Signed with the same workspace key as the agent stages — auditor sees human decisions in the same log as agent actions.",
      };
    case "review.false-positive":
      return {
        label: `Human · false-positive · ${actorId}`,
        description:
          "Analyst determined the finding is a false positive. Reason recorded in the signed payload; supersedes any prior verdict.",
      };
    case "review.risk-accept-until":
      return {
        label: `Human · risk-accepted · ${actorId}`,
        description:
          "Analyst accepted the risk until a specific date (in the payload). Bank / compliance path — the signed record is proof of a considered risk decision.",
      };
    case "review.threat-model-edit":
      return {
        label: `Human · edited threat model · ${actorId}`,
        description:
          "Analyst modified the auto-generated Recon threat model during an interactive-mode sweep. The merged model was signed into the audit trail so the finding's provenance shows the human touch.",
      };
    default:
      return {
        label: `${actorKind} · ${action}`,
        description: "Signed action on this finding's chain of custody.",
      };
  }
}


/**
 * CodePreviewPanel — the vulnerable code lines in context.
 *
 * ±6 lines around the sink, with the vulnerable line highlighted and line
 * numbers rendered. Language is best-guessed from the file extension so we
 * can drop in real syntax highlighting later (Prism / Shiki) without
 * changing the data shape. When `fileUrl` is available (GitHub-hosted
 * clone), the header offers a direct "open on GitHub ↗" affordance so an
 * analyst who wants full context is one click away.
 */
function CodePreviewPanel({
  finding,
  fileUrl,
}: {
  finding: Finding;
  fileUrl: string | null;
}) {
  const preview = finding.code_preview;
  if (!preview || !preview.content) return null;
  const lines = preview.content.split("\n");
  const startLine = preview.start_line;
  const highlight = preview.highlight_line;
  return (
    <Panel title="Where the danger lives">
      <div className="mb-2 flex items-center gap-2 text-2xs">
        <span className="mono uppercase tracking-wider bg-paper-200 text-paper-700 rounded px-1.5 py-0.5">
          {preview.language}
        </span>
        <span className="mono text-paper-500">
          lines {startLine}–{preview.end_line}
        </span>
        <span className="ml-auto flex items-center gap-2">
          {fileUrl && (
            <a
              href={fileUrl}
              target="_blank"
              rel="noreferrer"
              className="mono uppercase tracking-wider text-accent hover:underline"
            >
              open on github ↗
            </a>
          )}
        </span>
      </div>
      <pre
        className="text-xs mono leading-snug rounded-md border border-paper-300 bg-[#fdfcf9] overflow-x-auto"
        aria-label={`${preview.language} source preview lines ${startLine} to ${preview.end_line}`}
      >
        {lines.map((line, i) => {
          const num = startLine + i;
          const isHit = num === highlight;
          return (
            <div
              key={i}
              className={`flex items-start ${
                isHit
                  ? "bg-red-50/70 border-l-2 border-sev-critical"
                  : "border-l-2 border-transparent"
              }`}
            >
              <span
                className={`tabular-nums select-none px-3 py-0.5 min-w-[3.2rem] text-right ${
                  isHit ? "text-sev-critical font-semibold" : "text-paper-400"
                }`}
              >
                {num}
              </span>
              <span
                className={`whitespace-pre px-2 py-0.5 flex-1 ${
                  isHit ? "text-paper-900" : "text-paper-700"
                }`}
              >
                {line || " "}
              </span>
              {isHit && (
                <span className="text-2xs mono uppercase tracking-wider text-sev-critical pr-3 py-0.5 select-none">
                  ← sink
                </span>
              )}
            </div>
          );
        })}
      </pre>
    </Panel>
  );
}


const STATIC_FACT_CLASSES = new Set(["secrets", "hardcoded-secret"]);

/**
 * SandboxOrStaticFactPanel — different framing per finding class.
 *
 * For static-fact classes (secrets, hardcoded-secret) the Consensus
 * Kernel intentionally short-circuits sandbox reproduction — the finding
 * IS the static evidence, there's nothing to "run". Showing an empty
 * Reproducer / Verifier grid is confusing and makes the pipeline look
 * broken. Instead we surface a purpose-built callout that:
 *
 *   1. names the class shape ("static fact") and explains why no PoC
 *      is needed, and
 *   2. gives specific remediation guidance for the credential-leak case
 *      (rotate + purge from git history, not just from the current
 *      commit).
 *
 * For everything else, the existing sandbox card grid renders as before.
 */
function SandboxOrStaticFactPanel({ finding }: { finding: Finding }) {
  const sandbox = finding.evidence.sandbox;
  const isStaticFact = STATIC_FACT_CLASSES.has(finding.class);

  if (isStaticFact) {
    return (
      <Panel title="Reproduction — not applicable">
        <div className="rounded-lg border border-accent/30 bg-accent-soft/40 p-4">
          <div className="flex items-start gap-3">
            <span className="mt-0.5 h-5 w-5 rounded-full bg-accent text-white grid place-items-center text-2xs mono font-semibold shrink-0">
              i
            </span>
            <div className="min-w-0">
              <div className="text-sm text-paper-900 font-medium leading-snug">
                Static-fact class · no sandbox PoC needed.
              </div>
              <p className="mt-1 text-xs text-paper-700 leading-relaxed">
                A hardcoded credential is its own evidence — no attacker
                input is required to "trigger" it, so the Consensus
                Kernel promotes to <span className="mono">verified</span>{" "}
                on static evidence alone (see PRD §8.2). Firing a sandbox
                would be theatre; the leak exists the moment the string
                is committed.
              </p>
              <div className="mt-3 text-2xs mono uppercase tracking-wider text-paper-500 mb-1">
                Remediation
              </div>
              <ol className="text-xs text-paper-800 leading-relaxed space-y-1.5 list-decimal ml-4">
                <li>
                  <span className="font-medium">Rotate the credential first.</span>{" "}
                  Deleting a line from source does nothing — assume the key
                  is compromised the moment it landed in git.
                </li>
                <li>
                  <span className="font-medium">
                    Purge the value from git history
                  </span>{" "}
                  (<span className="mono">git filter-repo</span> or the
                  BFG cleaner). A commit-level delete leaves the secret in
                  every branch, tag, and fork's reflog.
                </li>
                <li>
                  <span className="font-medium">
                    Replace with a secrets-manager reference
                  </span>{" "}
                  — AWS Secrets Manager, Vault, or the platform-native
                  equivalent. Never re-check-in.
                </li>
                <li>
                  Mark this finding{" "}
                  <span className="mono bg-white border border-paper-300 rounded px-1">
                    accept
                  </span>{" "}
                  once (1) and (2) are done. The signed review entry
                  lands on the chain of custody so the auditor sees the
                  rotation was performed.
                </li>
              </ol>
            </div>
          </div>
        </div>
      </Panel>
    );
  }

  if (!sandbox) return null;

  return (
    <Panel title="Sandbox — hostile-input containment">
      <div className="text-xs text-paper-700 mb-3 leading-relaxed">
        Reproduction and verification ran in an isolated container with{" "}
        <span className="mono text-2xs uppercase tracking-wider bg-accent-soft text-accent border border-accent/30 rounded px-1.5 py-0.5">
          egress off
        </span>{" "}
        — the target code cannot phone home from Spotlight's sandbox. The
        capability token below is the signed grant.
      </div>
      <div className="grid grid-cols-2 gap-4">
        <SandboxCard label="Reproducer" data={sandbox.reproducer} />
        <SandboxCard label="Verifier" data={sandbox.verifier} />
      </div>
    </Panel>
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

  // When no diff was produced (Remediator has no template for this class
  // yet — e.g., eval, cmdi, ssrf, deserialization, path-traversal beyond
  // sqli), show a Fix panel PLACEHOLDER instead of hiding. Static-fact
  // classes get their own richer callout in the Reproduction panel
  // above; here we just no-op so we're not showing the same
  // "patch pending" copy twice.
  if (!diff) {
    if (STATIC_FACT_CLASSES.has(finding.class)) return null;
    return (
      <Panel title="Fix">
        <div className="text-sm text-paper-800 leading-relaxed mb-3">
          {finding.evidence.fix.approach ||
            "See the root cause and evidence panels for recommended remediation."}
        </div>
        <div className="rounded-lg border border-dashed border-paper-400 bg-paper-50 p-4">
          <div className="mono text-2xs uppercase tracking-wider text-paper-500 mb-1">
            Patch generation — pending
          </div>
          <div className="text-2xs text-paper-600 leading-relaxed">
            Spotlight ships a hand-authored patch template only for a subset
            of classes today. Automatic per-class patch generation lands
            with Phase 4 D7 (a fine-tuned TemplateWriter over{" "}
            <span className="mono">(finding, verified-fix, PoC)</span>{" "}
            triples). Until then, the analyst applies the fix using the
            recommendation above and marks the finding{" "}
            <span className="mono">accept</span> once the change is
            deployed. The signed review lands on the chain of custody.
          </div>
        </div>
      </Panel>
    );
  }

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
