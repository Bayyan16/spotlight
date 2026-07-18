const BASE = (import.meta as unknown as { env?: Record<string, string> }).env?.VITE_API ?? "";

export type Target = { name: string; path: string; has_ground_truth: boolean };

export type SweepEvent = {
  sweep_id: string;
  seq: number;
  ts: number;
  type: string;
  actor: string;
  payload: Record<string, unknown>;
};

export type Profile = {
  id: string;
  name: string;
  description: string;
  surfaces: string[];
  classes: string[];
  languages: string[];
  model: string;
  max_agents: number;
  budget_tokens: number;
  scope_globs: string[];
  runtime_validate: boolean;
  interactive: boolean;
};

export async function listProfiles(): Promise<Profile[]> {
  const r = await fetch(`${BASE}/profiles`);
  return r.ok ? r.json() : [];
}

export type Finding = {
  id: string;
  surface: string;
  title: string;
  severity: string;
  class: string;
  cwe: string;
  location: { file: string; line: number; function: string };
  state: string;
  tier: string;
  confidence: number;
  evidence: {
    detected_by: string[];
    corroboration: Array<{ type: string; detail?: unknown; result?: string; path?: string }>;
    root_cause: string;
    fix: {
      diff: string | null;
      // C5 · unified diff text, inlined so the Console can render without
      // an extra RTT. Empty string when no patch was applied.
      diff_content?: string | null;
      approach: string;
      pr_url?: string | null;
      branch?: string | null;
      commit_sha?: string | null;
    };
    verification: Record<string, unknown>;
    threat_model?: {
      author: string;
      profile: string;
      surfaces: string[];
      untrusted_sources: string[];
      high_impact_sinks: string[];
      stack?: { language?: string; framework?: string };
    };
    sandbox?: {
      reproducer?: {
        engine?: string;
        duration_s?: number;
        egress_attempts?: number;
        egress_denied_hosts?: string[];
        exit_code?: number;
        capability_token?: Record<string, unknown>;
      };
      verifier?: {
        engine?: string;
        duration_s?: number;
        exit_code?: number;
        capability_token?: Record<string, unknown>;
      };
    };
  };
  consensus: { tier: string; independent_corroborators: number; decision: string; rationale: string };
  audit: Record<string, unknown>;
  // C3 — plain-language "why this matters". Three short paragraphs, no
  // jargon, targeted at engineers who don't work security day-to-day.
  plain_language?: {
    one_liner?: string;
    blast_radius?: string;
    urgency?: string;
  };
  // C4 — analyst review state. Absent until first review; each review is
  // ALSO appended as a signed entry on `audit.chain_of_custody` so external
  // verifiers see human decisions in the same auditable log as agent actions.
  review?: {
    state: "accepted" | "false-positive" | "risk-accepted";
    reason: string;
    reviewer: string;
    ts: string;
    until?: string;
  };
};

export type ReviewAction = "accept" | "false-positive" | "risk-accept-until";

export async function reviewFinding(
  findingId: string,
  body: { action: ReviewAction; reason: string; until?: string; reviewer?: string }
): Promise<Finding> {
  const r = await fetch(`${BASE}/findings/${findingId}/review`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error((await r.text()) || `HTTP ${r.status}`);
  return r.json();
}

export type SweepSummary = {
  sweep_id: string;
  repo_name: string;
  source: string;
  status: string;
  findings_count: number;
  started_at: string | null;
  finished_at: string | null;
};

export async function listTargets(): Promise<Target[]> {
  const r = await fetch(`${BASE}/targets`);
  return r.json();
}

export async function listSweeps(): Promise<SweepSummary[]> {
  const r = await fetch(`${BASE}/sweeps`);
  if (!r.ok) return [];
  return r.json();
}

export type SweepEvents = Array<{
  sweep_id: string;
  seq: number;
  ts: number;
  type: string;
  actor: string;
  payload: Record<string, unknown>;
}>;

export async function getSweepEvents(id: string): Promise<SweepEvents> {
  const r = await fetch(`${BASE}/sweeps/${id}/events`);
  if (!r.ok) return [];
  return r.json();
}

export type VulnClass = {
  id: string;
  name: string;
  cwe: string;
  owasp?: string;
  owasp_llm?: string;
  surface: string;
  detection: string;
  default_severity: string;
  description: string;
};

export type Taxonomy = {
  total: number;
  counts_by_surface: Record<string, number>;
  classes: VulnClass[];
};

export async function getTaxonomy(): Promise<Taxonomy> {
  const r = await fetch(`${BASE}/taxonomy`);
  if (!r.ok) return { total: 0, counts_by_surface: {}, classes: [] };
  return r.json();
}

export async function startSweep(
  repo: string,
  profileId?: string,
  opts?: { interactive?: boolean }
): Promise<{ sweep_id: string }> {
  const r = await fetch(`${BASE}/sweeps`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      repo,
      profile_id: profileId,
      surfaces: ["code"],
      interactive: opts?.interactive ?? false,
    }),
  });
  if (!r.ok) {
    const err = await r.text();
    throw new Error(`start_sweep failed: ${r.status} ${err.slice(0, 200)}`);
  }
  return r.json();
}

// Server-persisted preferences — replace localStorage. Every read has a
// cheap AbortController-safe fetch; every write is fire-and-forget so the
// UI stays responsive. Callers that need reliability should await.
export async function getWorkspacePref<T = unknown>(key: string): Promise<T | null> {
  const r = await fetch(`${BASE}/prefs/workspace/${encodeURIComponent(key)}`);
  if (!r.ok) return null;
  const body = (await r.json()) as { value: T | null };
  return body.value;
}

export async function setWorkspacePref<T = unknown>(key: string, value: T): Promise<void> {
  await fetch(`${BASE}/prefs/workspace/${encodeURIComponent(key)}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ value }),
  });
}

export async function getFindingsFilterPref<T = unknown>(
  profileId: string,
  name: string = "current"
): Promise<T | null> {
  const url = `${BASE}/prefs/findings-filter/${encodeURIComponent(profileId)}?name=${encodeURIComponent(name)}`;
  const r = await fetch(url);
  if (!r.ok) return null;
  const body = (await r.json()) as { value: T | null };
  return body.value;
}

export async function setFindingsFilterPref<T = unknown>(
  profileId: string,
  value: T,
  name: string = "current"
): Promise<void> {
  const url = `${BASE}/prefs/findings-filter/${encodeURIComponent(profileId)}?name=${encodeURIComponent(name)}`;
  await fetch(url, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ value }),
  });
}

export async function resumeSweep(
  sweepId: string,
  edits?: Record<string, unknown>,
  reviewer?: string
): Promise<{ sweep_id: string; resumed: boolean }> {
  const r = await fetch(`${BASE}/sweeps/${encodeURIComponent(sweepId)}/resume`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      threat_model_edits: edits ?? null,
      reviewer: reviewer ?? "analyst",
    }),
  });
  if (!r.ok) {
    const err = await r.text();
    throw new Error(`resume failed: ${r.status} ${err.slice(0, 200)}`);
  }
  return r.json();
}

export async function deleteSweep(id: string): Promise<void> {
  await fetch(`${BASE}/sweeps/${id}`, { method: "DELETE" });
}

export async function cleanupSweeps(
  status: "failed" | "running" | "finished" = "failed"
): Promise<{ deleted: number }> {
  const r = await fetch(`${BASE}/sweeps/cleanup?status=${status}`, { method: "POST" });
  return r.ok ? r.json() : { deleted: 0 };
}

export async function getSweep(id: string): Promise<{ status: string; findings_count?: number }> {
  const r = await fetch(`${BASE}/sweeps/${id}`);
  return r.json();
}

export async function getFindings(id: string): Promise<Finding[]> {
  const r = await fetch(`${BASE}/sweeps/${id}/findings`);
  if (!r.ok) return [];
  return r.json();
}

export async function getAttestation(id: string): Promise<unknown> {
  const r = await fetch(`${BASE}/attestations/${id}`);
  return r.json();
}

// Cross-surface presence (Tranche B7). Answers "is this same class also
// reachable in my other repos?" — the bank-feedback wedge.
export type PresenceMatch = {
  sweep_id: string;
  repo_name: string;
  finding_id: string;
  file: string;
  line: number;
  tier: string;
  state: string;
  sweep_started_at: string | null;
};

export type PresenceResult = {
  class: string;
  cwe: string;
  self: { sweep_id: string; repo_name: string; finding_id: string };
  matches: PresenceMatch[];
  presence_count: number;
};

export async function getPresence(findingId: string): Promise<PresenceResult | null> {
  const r = await fetch(`${BASE}/findings/${findingId}/presence`);
  if (r.status === 404) return null;
  if (!r.ok) return null;
  return r.json();
}

// Exploit Paths (Tranche B4) — the cross-surface money-shot.
export type ExploitPathStep = {
  order: number;
  finding_id: string;
  surface: string;
  class: string;
  cwe: string;
  file: string;
  line: number;
  edge: string;
};

export type ExploitPath = {
  id: string;
  title: string;
  severity: string;
  cross_surface: boolean;
  steps: ExploitPathStep[];
  reproduced: boolean;
  rationale: string;
  // Tranche B5 — signed rule chains carry tier="verified" (default),
  // model proposals carry tier="hypothesis" and never enter the signed
  // attestation set.
  tier?: "verified" | "hypothesis";
  origin?: "chainer-rule" | "llm-proposal";
};

export async function getExploitPaths(sweepId: string): Promise<ExploitPath[]> {
  const r = await fetch(`${BASE}/paths/${sweepId}`);
  if (!r.ok) return [];
  return r.json();
}

// C6 — Delta between two sweeps.
export type DeltaFinding = {
  id: string;
  class: string;
  severity: string;
  tier: string;
  title: string;
  file: string;
  line: number;
  function: string;
  review_state: string | null;
};

export type SweepDelta = {
  sweep_id: string;
  since: string;
  new: DeltaFinding[];
  resolved: DeltaFinding[];
  still_open: DeltaFinding[];
  counts: { new: number; resolved: number; still_open: number };
};

export async function getSweepDelta(
  sweepId: string,
  sinceSweepId: string
): Promise<SweepDelta | null> {
  const r = await fetch(
    `${BASE}/sweeps/${encodeURIComponent(sweepId)}/delta?since=${encodeURIComponent(sinceSweepId)}`
  );
  if (!r.ok) return null;
  return r.json();
}

// Attestation download URL — used by the Export button on FindingDetail.
export function attestationUrl(sweepId: string, format: "json" | "markdown" | "pdf"): string {
  return `${BASE}/attestations/${sweepId}?format=${format}`;
}

export function openSweepStream(id: string, onEvent: (e: SweepEvent) => void): WebSocket {
  const scheme = window.location.protocol === "https:" ? "wss" : "ws";
  const host = window.location.host;
  const ws = new WebSocket(`${scheme}://${host}/ws/sweeps/${id}`);
  ws.onmessage = (msg) => {
    try {
      onEvent(JSON.parse(msg.data));
    } catch {
      /* ignore */
    }
  };
  return ws;
}
