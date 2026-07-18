import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  getFindings,
  listSweeps,
  type Finding,
  type SweepSummary,
} from "../lib/api";

/**
 * useWorkspaceData — the ONE source of truth for the sweep list and
 * per-sweep findings.
 *
 * Before this hook, the Board owned its own `findingsByThought` state
 * fetched per-sweep in a useEffect, App owned a parallel `historyCount`
 * via a second listSweeps() call, and any component that needed a sweep
 * count derived it from whichever of those it happened to see. Two sweep
 * counts can disagree by a race window. Two findings-per-sweep maps can
 * differ if one refresh missed the other. This hook collapses those into
 * a single fetch pipeline every consumer subscribes to.
 *
 * Cache semantics:
 *   * sweeps refresh on mount + when `refreshSignal` changes
 *   * findings for each finished sweep are fetched at most once, cached
 *     until refresh. In-flight requests are deduped by sweep_id.
 *   * only the first N=20 finished sweeps are prefetched (matches the
 *     old Board behavior — the ones visible above the fold).
 */
const MAX_PREFETCH = 20;

// Module-level cache so multiple consumers (Board, EmptySweep,
// SweepsHistory) share one dataset without prop-drilling.
const _findingsCache = new Map<string, Finding[]>();
const _inFlight = new Map<string, Promise<Finding[]>>();

async function _fetchFindingsCached(sweepId: string): Promise<Finding[]> {
  const cached = _findingsCache.get(sweepId);
  if (cached) return cached;
  const pending = _inFlight.get(sweepId);
  if (pending) return pending;
  const p = getFindings(sweepId).then((fs) => {
    _findingsCache.set(sweepId, fs);
    _inFlight.delete(sweepId);
    return fs;
  });
  _inFlight.set(sweepId, p);
  return p;
}

/** Explicit cache invalidation — call after a mutation that changes a
 *  finding (e.g., accept, false-positive). */
export function invalidateWorkspaceFindings(sweepId?: string) {
  if (sweepId) {
    _findingsCache.delete(sweepId);
  } else {
    _findingsCache.clear();
  }
}

export type WorkspaceData = {
  sweeps: SweepSummary[] | null;
  findingsBySweep: Record<string, Finding[]>;
  counts: {
    total: number;
    running: number;
    finished: number;
    failed: number;
    totalFindings: number;
    verifiedSweeps: number;
  };
  refresh: () => void;
};

export function useWorkspaceData(refreshSignal: number): WorkspaceData {
  const [sweeps, setSweeps] = useState<SweepSummary[] | null>(null);
  const [findingsBySweep, setFindingsBySweep] = useState<Record<string, Finding[]>>({});
  const [localSignal, setLocalSignal] = useState(0);

  const refresh = useCallback(() => setLocalSignal((n) => n + 1), []);

  // Fetch sweeps.
  useEffect(() => {
    let cancelled = false;
    listSweeps()
      .then((d) => {
        if (cancelled) return;
        setSweeps(Array.isArray(d) ? d : []);
      })
      .catch(() => {
        if (!cancelled) setSweeps([]);
      });
    return () => {
      cancelled = true;
    };
  }, [refreshSignal, localSignal]);

  // Prefetch findings for the first N finished sweeps with findings > 0.
  // Consumers can also call ensureFindings(id) explicitly for lazy loads.
  const seenSignatureRef = useRef<string>("");
  useEffect(() => {
    if (!sweeps) return;
    const finished = sweeps
      .filter((r) => r.status === "finished" && r.findings_count > 0)
      .slice(0, MAX_PREFETCH);
    const signature = finished.map((r) => r.sweep_id).join(",");
    if (signature === seenSignatureRef.current) return;
    seenSignatureRef.current = signature;

    let cancelled = false;
    Promise.all(
      finished.map(async (r) => [r.sweep_id, await _fetchFindingsCached(r.sweep_id)] as const)
    ).then((entries) => {
      if (cancelled) return;
      setFindingsBySweep((prev) => {
        const next = { ...prev };
        for (const [id, fs] of entries) next[id] = fs;
        return next;
      });
    });
    return () => {
      cancelled = true;
    };
  }, [sweeps]);

  const counts = useMemo(() => {
    const rows = sweeps ?? [];
    const running = rows.filter((r) => r.status === "running").length;
    const failed = rows.filter((r) => r.status === "failed").length;
    const finished = rows.filter((r) => r.status === "finished").length;
    let totalFindings = 0;
    let verifiedSweeps = 0;
    for (const r of rows) {
      const list = findingsBySweep[r.sweep_id] ?? [];
      totalFindings += list.length;
      if (list.some((f) => f.tier === "verified")) verifiedSweeps += 1;
    }
    return {
      total: rows.length,
      running,
      finished,
      failed,
      totalFindings,
      verifiedSweeps,
    };
  }, [sweeps, findingsBySweep]);

  return { sweeps, findingsBySweep, counts, refresh };
}
