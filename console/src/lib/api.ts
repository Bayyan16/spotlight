const BASE = (import.meta as unknown as { env?: Record<string, string> }).env?.VITE_API ?? "";

export async function apiFetch(input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
  const response = await fetch(input, { ...init, credentials: "same-origin" });
  if (response.status === 401 && typeof window !== "undefined") {
    window.dispatchEvent(new Event("spotlight:auth-required"));
  }
  return response;
}

export type AuthSession = {
  required: boolean;
  authenticated: boolean;
  subject: string | null;
};

export async function getAuthSession(): Promise<AuthSession> {
  const response = await fetch(`${BASE}/auth/session`, { credentials: "same-origin" });
  if (!response.ok) throw new Error(`session check failed: HTTP ${response.status}`);
  return response.json();
}

export async function loginWithApiKey(apiKey: string): Promise<void> {
  const response = await fetch(`${BASE}/auth/session`, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ api_key: apiKey }),
  });
  if (!response.ok) throw new Error("That workspace key was not accepted.");
}

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
  const r = await apiFetch(`${BASE}/profiles`);
  return r.ok ? r.json() : [];
}

export type Finding = {
  id: string;
  surface: string;
  title: string;
  severity: string;
  class: string;
  cwe: string;
  // Parent CWE family — advisories (GHSA/NVD) often tag at the parent
  // level (e.g., CWE-94) while our detector's more precise class-CWE
  // (CWE-95 for eval) is a child. Surfacing both means exact-advisory
  // matching works in either direction.
  cwe_family?: string;
  location: {
    file: string;
    line: number;
    function: string;
    // Repo-relative path — stripped of the ephemeral tmpdir clone prefix.
    // Console uses this to render "redshift_connector/foo.py" instead of
    // "/tmp/spotlight-clone-abc/src/redshift_connector/foo.py" AND to
    // build GitHub blob links via sweep.clone_url + sweep.commit_sha.
    repo_relative_path?: string;
  };
  code_preview?: {
    language: string;
    start_line: number;
    end_line: number;
    highlight_line: number;
    content: string;
  } | null;
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
  const r = await apiFetch(`${BASE}/findings/${findingId}/review`, {
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
  // Sweep identity — what code did this sweep see?
  org?: string | null;
  commit_sha?: string | null;
  commit_branch?: string | null;
  clone_url?: string | null;
  interactive?: boolean | null;
};

/**
 * Build a "view this file on GitHub" URL from a sweep + a repo-relative
 * path + a line number. Returns null when clone_url isn't a GitHub URL,
 * or when commit_sha / relative path are missing — the FindingDetail
 * falls back to a plain mono path in that case (no broken links).
 *
 * Handles both HTTPS and SSH clone URL forms:
 *   https://github.com/aws/redshift-python-driver.git → blob URL
 *   git@github.com:aws/redshift-python-driver.git      → blob URL
 * Non-GitHub hosts return null; a GitLab handler can drop in later.
 */
export function repoFileUrl(
  cloneUrl: string | null | undefined,
  commitSha: string | null | undefined,
  relativePath: string | null | undefined,
  line?: number | null
): string | null {
  if (!cloneUrl || !commitSha || !relativePath) return null;
  let url = cloneUrl.trim();
  if (url.endsWith(".git")) url = url.slice(0, -4);
  // git@github.com:org/repo → https://github.com/org/repo
  if (url.startsWith("git@")) {
    const [, host, path] = url.match(/^git@([^:]+):(.+)$/) ?? [];
    if (!host || !path) return null;
    url = `https://${host}/${path}`;
  }
  if (!/^https?:\/\/github\.com\//i.test(url)) return null;
  const relPath = relativePath.startsWith("/")
    ? relativePath.slice(1)
    : relativePath;
  const anchor = line && line > 0 ? `#L${line}` : "";
  return `${url}/blob/${commitSha}/${relPath}${anchor}`;
}

export async function listTargets(): Promise<Target[]> {
  const r = await apiFetch(`${BASE}/targets`);
  return r.json();
}

export async function listSweeps(): Promise<SweepSummary[]> {
  const r = await apiFetch(`${BASE}/sweeps`);
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
  const r = await apiFetch(`${BASE}/sweeps/${id}/events`);
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
  const r = await apiFetch(`${BASE}/taxonomy`);
  if (!r.ok) return { total: 0, counts_by_surface: {}, classes: [] };
  return r.json();
}

export async function startSweep(
  repo: string,
  profileId?: string,
  opts?: { interactive?: boolean }
): Promise<{ sweep_id: string }> {
  const r = await apiFetch(`${BASE}/sweeps`, {
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
  const r = await apiFetch(`${BASE}/prefs/workspace/${encodeURIComponent(key)}`);
  if (!r.ok) return null;
  const body = (await r.json()) as { value: T | null };
  return body.value;
}

export async function setWorkspacePref<T = unknown>(key: string, value: T): Promise<void> {
  await apiFetch(`${BASE}/prefs/workspace/${encodeURIComponent(key)}`, {
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
  const r = await apiFetch(url);
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
  await apiFetch(url, {
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
  const r = await apiFetch(`${BASE}/sweeps/${encodeURIComponent(sweepId)}/resume`, {
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
  await apiFetch(`${BASE}/sweeps/${id}`, { method: "DELETE" });
}

export async function cleanupSweeps(
  status: "failed" | "running" | "finished" = "failed"
): Promise<{ deleted: number }> {
  const r = await apiFetch(`${BASE}/sweeps/cleanup?status=${status}`, { method: "POST" });
  return r.ok ? r.json() : { deleted: 0 };
}

export async function getSweep(id: string): Promise<{ status: string; findings_count?: number }> {
  const r = await apiFetch(`${BASE}/sweeps/${id}`);
  return r.json();
}

export async function getFindings(id: string): Promise<Finding[]> {
  const r = await apiFetch(`${BASE}/sweeps/${id}/findings`);
  if (!r.ok) return [];
  return r.json();
}

export async function getAttestation(id: string): Promise<unknown> {
  const r = await apiFetch(`${BASE}/attestations/${id}`);
  return r.json();
}

// Cross-surface presence (Tranche B7). Answers "is this same class also
// reachable in my other repos?" — the bank-feedback wedge.
export type PresenceMatch = {
  sweep_id: string;
  repo_name: string;
  // Identity — a match at a DIFFERENT commit on the same repo is a
  // separate bucket, not a duplicate. `org` disambiguates same-name repos
  // across GitHub orgs. Both optional to stay compatible with pre-identity
  // sweep rows that lack this metadata.
  org?: string | null;
  commit_sha?: string | null;
  commit_branch?: string | null;
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
  const r = await apiFetch(`${BASE}/findings/${findingId}/presence`);
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
  const r = await apiFetch(`${BASE}/paths/${sweepId}`);
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
  const r = await apiFetch(
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

// ── Cortex — the self-improving layer (see docs/CORTEX.md) ──────────────
// Every route here is 404 on a workspace that has not set SPOTLIGHT_CORTEX_DIR,
// so callers treat "not configured" as a first-class state rather than an error.

export type CortexDirective = {
  cohort: string;
  action: "none" | "adjust-confidence" | "route-to-review";
  target_confidence: number;
  n_labeled: number;
  tp: number;
  fp: number;
  human_tp: number;
  precision_mean: number;
  precision_lower: number;
  rationale: string;
};

export type CortexPolicy = {
  policy_id: string;
  version: number;
  ledger_head: string;
  min_support: number;
  directives: Record<string, CortexDirective>;
  created_at: string;
  derived_from: string;
  notes: string;
  is_identity: boolean;
  is_active?: boolean;
};

export type CortexShadow = {
  rows_replayed: number;
  labeled_rows: number;
  tp_demoted: number;
  fp_demoted: number;
  tp_boosted: number;
  fp_boosted: number;
  tp_confidence_loss: number;
  fp_confidence_loss: number;
  unchanged: number;
  demoted_true_positive_keys: string[];
  beneficial_effects: number;
  raises_anything: boolean;
};

export type CortexStatus = {
  /** Standing replay of the policy in force against today's labels. */
  active_policy_audit: CortexShadow;
  root: string;
  autonomy: boolean;
  policy: CortexPolicy;
  pin: Record<string, unknown>;
  ledger: {
    records: number;
    distinct_findings: number;
    labeled: number;
    unlabeled: number;
    head: string;
  };
  cohorts: { total: number; actionable: number };
  lessons: { served: number; quarantined: number };
  governance_entries: number;
};

export type CortexEvolution = {
  proposal: {
    policy: CortexPolicy;
    shadow: CortexShadow;
    invariant_violations: string[];
    gate_failures: string[];
    admissible: boolean;
    requires_human: boolean;
    auto_activatable: boolean;
  };
  activation: {
    activated: boolean;
    reason: string;
    policy_id: string;
    version: number;
    approver: string;
  };
  lessons_refreshed: number;
  lessons_quarantined: number;
};

export type CortexLesson = {
  lesson_id: string;
  scope: string;
  key: string;
  class_: string;
  path_hint: string;
  observations: number;
  text: string;
  quarantined: boolean;
  quarantine_kinds: string[];
};

export type CortexGovernanceEntry = {
  ts: string;
  action: string;
  actor: string;
  payload: Record<string, unknown>;
};

/** null means "this workspace has no Cortex configured" — not an error. */
export async function getCortexStatus(): Promise<CortexStatus | null> {
  const r = await apiFetch(`${BASE}/cortex/status`);
  if (r.status === 404) return null;
  if (!r.ok) throw new Error(`cortex status failed: HTTP ${r.status}`);
  return r.json();
}

export async function getCortexPolicyHistory(): Promise<{
  active_policy_id: string;
  policies: CortexPolicy[];
}> {
  const r = await apiFetch(`${BASE}/cortex/policy/history`);
  if (!r.ok) throw new Error(`cortex history failed: HTTP ${r.status}`);
  return r.json();
}

export async function getCortexLessons(): Promise<{
  served: CortexLesson[];
  quarantined: CortexLesson[];
}> {
  const r = await apiFetch(`${BASE}/cortex/lessons`);
  if (!r.ok) throw new Error(`cortex lessons failed: HTTP ${r.status}`);
  return r.json();
}

export async function getCortexGovernance(limit = 50): Promise<{
  total: number;
  entries: CortexGovernanceEntry[];
}> {
  const r = await apiFetch(`${BASE}/cortex/governance?limit=${limit}`);
  if (!r.ok) throw new Error(`cortex governance failed: HTTP ${r.status}`);
  return r.json();
}

export async function verifyCortexLedger(): Promise<{
  ok: boolean;
  records: number;
  head: string;
  chain_ok: boolean;
  signatures_ok: boolean;
  signatures_checked: number;
  broken_at: number | null;
  reason: string;
}> {
  const r = await apiFetch(`${BASE}/cortex/ledger/verify`);
  if (!r.ok) throw new Error(`ledger verify failed: HTTP ${r.status}`);
  return r.json();
}

/** Propose + gate. Activates only a strictly conservative change. */
export async function evolveCortex(): Promise<CortexEvolution> {
  const r = await apiFetch(`${BASE}/cortex/evolve`, { method: "POST" });
  if (!r.ok) throw new Error(`cortex evolve failed: HTTP ${r.status}`);
  return r.json();
}

/** Human sign-off on a proposal the Cortex withheld from itself. */
export async function activateCortexPolicy(
  approver: string,
  policyId?: string,
): Promise<CortexEvolution> {
  const r = await apiFetch(`${BASE}/cortex/policy/activate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ approver, policy_id: policyId ?? null }),
  });
  if (!r.ok) {
    const detail = await r.json().catch(() => ({ detail: `HTTP ${r.status}` }));
    throw new Error(String(detail.detail ?? `HTTP ${r.status}`));
  }
  return r.json();
}

export async function rollbackCortexPolicy(
  policyId: string,
  approver: string,
): Promise<{ activated: boolean; reason: string; version: number; policy_id: string }> {
  const r = await apiFetch(`${BASE}/cortex/policy/rollback`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ policy_id: policyId, approver }),
  });
  if (!r.ok) {
    const detail = await r.json().catch(() => ({ detail: `HTTP ${r.status}` }));
    throw new Error(String(detail.detail ?? `HTTP ${r.status}`));
  }
  return r.json();
}
