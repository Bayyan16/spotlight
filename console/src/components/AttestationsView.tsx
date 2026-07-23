import { useEffect, useState } from "react";

import { apiFetch, attestationUrl } from "../lib/api";
import { useWorkspaceData } from "../hooks/useWorkspaceData";
import { IconAttestation } from "./Icons";

/**
 * AttestationsView — one row per completed sweep with big download buttons.
 *
 * Attestation is the load-bearing artifact for the bank-audit story. This
 * view is where a compliance officer actually pulls a PDF / Markdown /
 * signed JSON to hand off. Also shows the sweep's identity (org, commit,
 * branch) so the auditor can prove which code was scanned.
 */
type VerifyKey = {
  algorithm: string;
  public_key_b64: string;
  fingerprint: string;
  signing_input_template: string;
};

export function AttestationsView({
  onOpenSweep,
  refreshSignal,
}: {
  onOpenSweep: (sweepId: string) => void;
  refreshSignal: number;
}) {
  const { sweeps } = useWorkspaceData(refreshSignal);
  const [verifyKey, setVerifyKey] = useState<VerifyKey | null>(null);
  const [keyErr, setKeyErr] = useState(false);

  useEffect(() => {
    apiFetch("/verify-key")
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then((k) => setVerifyKey(k as VerifyKey))
      .catch(() => setKeyErr(true));
  }, []);

  const completed = (sweeps ?? []).filter(
    (s) => s.status === "finished" || s.status === "failed"
  );

  return (
    <section className="flex-1 min-w-0 overflow-y-auto bg-paper-50">
      <header className="border-b border-paper-300 px-8 py-5 sticky top-0 bg-paper-50/95 backdrop-blur z-10">
        <div className="flex items-baseline gap-3">
          <h1 className="text-xl text-paper-900 font-semibold tracking-tight">
            Attestations
          </h1>
          <span className="text-xs text-paper-500">
            Signed, offline-verifiable evidence bundles per sweep.
          </span>
        </div>
        <VerifyKeyBanner verifyKey={verifyKey} keyErr={keyErr} />
      </header>

      <div className="px-8 py-6">
        {completed.length === 0 ? (
          <div className="text-paper-500 text-sm italic py-16 text-center">
            No completed sweeps yet. Attestations appear here after a sweep
            finishes.
          </div>
        ) : (
          <ul className="space-y-3">
            {completed.map((s) => (
              <li
                key={s.sweep_id}
                className="border border-paper-300 rounded-xl bg-white p-4 flex items-center gap-4"
              >
                <span className="h-10 w-10 rounded-md grid place-items-center bg-accent-soft text-accent shrink-0">
                  <IconAttestation size={16} />
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-sm font-semibold text-paper-900 truncate">
                      {s.org ? `${s.org}/${s.repo_name}` : s.repo_name}
                    </span>
                    <span className="mono text-2xs text-paper-500">
                      {s.sweep_id.slice(0, 14)}
                    </span>
                    {s.commit_sha && (
                      <span
                        className="mono text-2xs text-paper-700 bg-paper-100 border border-paper-300 rounded px-1.5"
                        title={s.commit_sha}
                      >
                        {s.commit_sha.slice(0, 8)}
                      </span>
                    )}
                    {s.commit_branch && (
                      <span className="text-2xs mono uppercase tracking-wider text-paper-500">
                        {s.commit_branch}
                      </span>
                    )}
                    <span
                      className={`text-2xs mono uppercase tracking-wider px-1.5 py-0.5 rounded-full border ${
                        s.status === "finished"
                          ? "bg-accent-soft text-accent border-accent/30"
                          : "bg-red-50 text-sev-critical border-sev-critical/30"
                      }`}
                    >
                      {s.status}
                    </span>
                  </div>
                  <div className="mt-1 text-2xs mono text-paper-500">
                    {s.findings_count} finding{s.findings_count === 1 ? "" : "s"}
                    {s.finished_at && (
                      <> · {new Date(s.finished_at).toLocaleString()}</>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-1.5 shrink-0">
                  <DownloadBtn
                    href={attestationUrl(s.sweep_id, "pdf")}
                    label="PDF"
                  />
                  <DownloadBtn
                    href={attestationUrl(s.sweep_id, "markdown")}
                    label="MD"
                  />
                  <DownloadBtn
                    href={attestationUrl(s.sweep_id, "json")}
                    label="JSON"
                  />
                  <button
                    onClick={() => onOpenSweep(s.sweep_id)}
                    className="text-2xs mono uppercase tracking-wider text-accent hover:underline px-2"
                  >
                    Open →
                  </button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}

function VerifyKeyBanner({
  verifyKey,
  keyErr,
}: {
  verifyKey: VerifyKey | null;
  keyErr: boolean;
}) {
  if (keyErr) {
    return (
      <div className="mt-3 text-2xs mono text-sev-critical">
        /verify-key unavailable — external verification cannot be
        completed. Contact ops.
      </div>
    );
  }
  if (!verifyKey) return null;
  return (
    <div className="mt-3 flex items-center gap-3 text-2xs mono">
      <span className="uppercase tracking-wider text-paper-500">
        Workspace verify key
      </span>
      <span
        className="text-paper-700 bg-paper-100 border border-paper-300 rounded px-2 py-0.5"
        title={verifyKey.public_key_b64}
      >
        {verifyKey.algorithm} · fp {verifyKey.fingerprint}
      </span>
      <a
        href="/verify-key"
        target="_blank"
        rel="noreferrer"
        className="text-accent hover:underline uppercase tracking-wider"
      >
        raw pubkey ↗
      </a>
      <span className="text-paper-400 truncate">
        template: {verifyKey.signing_input_template}
      </span>
    </div>
  );
}

function DownloadBtn({ href, label }: { href: string; label: string }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noreferrer"
      className="text-2xs mono uppercase tracking-wider bg-paper-100 border border-paper-300 hover:bg-white rounded px-2 py-1 text-paper-700"
    >
      {label}
    </a>
  );
}
