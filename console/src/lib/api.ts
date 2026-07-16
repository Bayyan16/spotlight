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
    fix: { diff: string | null; approach: string };
    verification: Record<string, unknown>;
  };
  consensus: { tier: string; independent_corroborators: number; decision: string; rationale: string };
  audit: Record<string, unknown>;
};

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

export async function startSweep(repo: string): Promise<{ sweep_id: string }> {
  const r = await fetch(`${BASE}/sweeps`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ repo, surfaces: ["code"] }),
  });
  if (!r.ok) {
    const err = await r.text();
    throw new Error(`start_sweep failed: ${r.status} ${err.slice(0, 200)}`);
  }
  return r.json();
}

export async function deleteSweep(id: string): Promise<void> {
  await fetch(`${BASE}/sweeps/${id}`, { method: "DELETE" });
}

export async function cleanupSweeps(status: "failed" | "running" = "failed"): Promise<{ deleted: number }> {
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
