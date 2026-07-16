import type { Finding } from "../lib/api";
import { IconCheck } from "./Icons";
import { PresencePanel } from "./PresencePanel";

export function FindingDetail({ finding }: { finding: Finding }) {
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
      </header>

      <div className="px-6 py-5 space-y-6">
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
            <div className="mb-3 text-xs text-paper-700">
              This finding was judged under the threat model{" "}
              <span className="mono uppercase tracking-wider text-2xs text-accent bg-accent-soft border border-accent/30 rounded px-1.5 py-0.5 mx-0.5">
                {finding.evidence.threat_model.profile}
              </span>{" "}
              (author:{" "}
              <span className="mono">{finding.evidence.threat_model.author}</span>).
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
