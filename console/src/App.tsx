import { useEffect, useMemo, useState } from "react";
import { NavRail, type NavKey } from "./components/NavRail";
import { TopBar } from "./components/TopBar";
import { FindingsList } from "./components/FindingsList";
import { FindingDetail } from "./components/FindingDetail";
import { LiveSweepPanel } from "./components/LiveSweepPanel";
import { Board } from "./components/Board";
import { Dashboard } from "./components/Dashboard";
import { CommandPalette } from "./components/CommandPalette";
import { AttestationsView } from "./components/AttestationsView";
import { DeltaView } from "./components/DeltaView";
import { ExploitPathsView } from "./components/ExploitPathsView";
import { FirstScanWizard } from "./components/FirstScanWizard";
import { WardenView } from "./components/WardenView";
import { CortexView } from "./components/CortexView";
import { Cmul8Mark } from "./components/Cmul8Mark";
import { IconPlay } from "./components/Icons";
import {
  getAuthSession,
  getFindings,
  getWorkspacePref,
  loginWithApiKey,
  listTargets,
  openSweepStream,
  startSweep,
  type Finding,
  type SweepEvent,
  type SweepSummary,
  type Target,
} from "./lib/api";
import { invalidateWorkspaceFindings, useWorkspaceData } from "./hooks/useWorkspaceData";

const NAV_ORDER: NavKey[] = [
  "home",
  "sweeps",
  "findings",
  "paths",
  "warden",
  "cortex",
  "delta",
  "attestations",
];

export default function App() {
  return (
    <AuthBoundary>
      <WorkspaceApp />
    </AuthBoundary>
  );
}

function AuthBoundary({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<"checking" | "authenticated" | "required" | "error">(
    "checking"
  );
  const [apiKey, setApiKey] = useState("");
  const [message, setMessage] = useState("");

  async function checkSession() {
    setState("checking");
    try {
      const session = await getAuthSession();
      setState(!session.required || session.authenticated ? "authenticated" : "required");
    } catch {
      setMessage("Spotlight could not reach the control plane.");
      setState("error");
    }
  }

  useEffect(() => {
    void checkSession();
    const requireAuth = () => setState("required");
    window.addEventListener("spotlight:auth-required", requireAuth);
    return () => window.removeEventListener("spotlight:auth-required", requireAuth);
  }, []);

  if (state === "authenticated") return <>{children}</>;

  return (
    <main className="h-screen w-screen grid place-items-center bg-paper-50 text-paper-900">
      <section className="w-full max-w-sm rounded-xl border border-paper-300 bg-white p-7 shadow-card">
        <div className="flex justify-center mb-5">
          <Cmul8Mark size={52} />
        </div>
        <h1 className="text-xl font-semibold text-center">Spotlight workspace</h1>
        {state === "checking" ? (
          <p className="mt-3 text-sm text-center text-paper-500">Checking secure session…</p>
        ) : state === "error" ? (
          <div className="mt-4 text-center">
            <p className="text-sm text-red-700">{message}</p>
            <button
              className="mt-4 px-3 py-2 rounded bg-accent text-white text-sm"
              onClick={() => void checkSession()}
            >
              Retry
            </button>
          </div>
        ) : (
          <form
            className="mt-5"
            onSubmit={async (event) => {
              event.preventDefault();
              setMessage("");
              try {
                await loginWithApiKey(apiKey);
                setApiKey("");
                setState("authenticated");
              } catch (error) {
                setMessage(error instanceof Error ? error.message : "Authentication failed.");
              }
            }}
          >
            <label
              className="block text-xs uppercase tracking-wider text-paper-600 mono"
              htmlFor="workspace-key"
            >
              Workspace API key
            </label>
            <input
              id="workspace-key"
              type="password"
              autoComplete="current-password"
              autoFocus
              required
              value={apiKey}
              onChange={(event) => setApiKey(event.target.value)}
              className="mt-2 w-full rounded border border-paper-300 bg-paper-50 px-3 py-2 text-sm focus:border-accent outline-none"
            />
            {message && <p className="mt-2 text-sm text-red-700">{message}</p>}
            <button
              type="submit"
              className="mt-4 w-full rounded bg-accent px-3 py-2 text-sm text-white hover:brightness-95"
            >
              Enter workspace
            </button>
            <p className="mt-3 text-xs leading-relaxed text-paper-500">
              The key is exchanged for an HttpOnly same-site session and is not stored in browser JavaScript.
            </p>
          </form>
        )}
      </section>
    </main>
  );
}

function WorkspaceApp() {
  const [nav, setNav] = useState<NavKey>("home");
  const [targets, setTargets] = useState<Target[]>([]);
  // No hardcoded fixture default — target gets set from the wizard when
  // the user picks one. Findings pane derives its label from the active
  // sweep's repo, not from a stale placeholder.
  const [selected, setSelected] = useState<string>("");
  const [sweepId, setSweepId] = useState<string | null>(null);
  const [events, setEvents] = useState<SweepEvent[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [running, setRunning] = useState(false);
  const [activeFinding, setActiveFinding] = useState<string | null>(null);
  const [historyRefresh, setHistoryRefresh] = useState(0);
  const [palette, setPalette] = useState(false);
  const [profileId, setProfileId] = useState<string>("balanced");
  const [selectedSweep, setSelectedSweep] = useState<SweepSummary | null>(null);
  const [wizardOpen, setWizardOpen] = useState(false);

  // Single source of truth for sweep list + per-sweep findings. Board reads
  // the same hook; `historyCount` (used by the empty-state) reads .total.
  const workspace = useWorkspaceData(historyRefresh);
  const historyCount = workspace.counts.total;

  useEffect(() => {
    listTargets().then(setTargets).catch(() => setTargets([]));
  }, []);

  useEffect(() => {
    // Auto-open the wizard once when the workspace is empty AND the user
    // hasn't dismissed it. Dismissal persists server-side.
    if (workspace.sweeps === null) return; // still loading
    if (workspace.sweeps.length === 0) {
      getWorkspacePref<boolean>("wizard-dismissed").then((dismissed) => {
        if (!dismissed) setWizardOpen(true);
      });
    }
  }, [workspace.sweeps]);

  useEffect(() => {
    if (!sweepId) return;
    const ws = openSweepStream(sweepId, (e) => {
      setEvents((prev) => [...prev, e]);
      if (e.type === "sweep.finished") {
        setRunning(false);
        // Fresh sweep landed — invalidate the shared cache so Board's count
        // + row expansions pick up the new findings on next render. Then
        // bump historyRefresh to trigger the hook's re-fetch.
        invalidateWorkspaceFindings(sweepId);
        setHistoryRefresh((n) => n + 1);
        getFindings(sweepId).then((fs) => {
          setFindings(fs);
          if (fs.length > 0) setActiveFinding(fs[0].id);
        });
      }
    });
    return () => ws.close();
  }, [sweepId]);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      const target = e.target as HTMLElement | null;
      const inField =
        target &&
        (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable);
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPalette((p) => !p);
        return;
      }
      if (inField) return;
      if (e.key >= "1" && e.key <= "7") {
        const idx = parseInt(e.key, 10) - 1;
        if (idx >= 0 && idx < NAV_ORDER.length) setNav(NAV_ORDER[idx]);
      }
      if ((e.metaKey || e.ctrlKey) && e.key === "Enter" && !running) {
        e.preventDefault();
        setWizardOpen(true);
      }
      if (e.key === "Escape") setPalette(false);
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [running]);

  async function onStart(customRepo?: string, opts?: { interactive?: boolean }) {
    setEvents([]);
    setFindings([]);
    setActiveFinding(null);
    setRunning(true);
    setNav("sweeps");
    try {
      const repo = customRepo ?? selected;
      const { sweep_id } = await startSweep(repo, profileId, opts);
      setSweepId(sweep_id);
    } catch (err) {
      setRunning(false);
      alert(`Failed to start sweep: ${err}`);
    }
  }

  function openHistoricalSweep(id: string) {
    setSweepId(id);
    setEvents([]);
    setActiveFinding(null);
    getFindings(id).then((fs) => {
      setFindings(fs);
      if (fs.length > 0) setActiveFinding(fs[0].id);
    });
    setNav("findings");
  }

  // Look up the active sweep's row so downstream views (FindingDetail's
  // "open on GitHub" link, TopBar breadcrumb, etc.) can read its identity
  // fields without a second fetch.
  const activeSweep = useMemo(() => {
    if (!sweepId) return null;
    return workspace.sweeps?.find((row) => row.sweep_id === sweepId) ?? null;
  }, [sweepId, workspace.sweeps]);

  // Derive the FindingsList header label from the active sweep — the
  // stale `selected` fallback showed hardcoded fixture names before the
  // user picked anything, which leaked into the UI as "vuln-bank-api"
  // even after real sweeps had landed.
  const activeTargetLabel = useMemo(() => {
    if (!sweepId) return selected || "no sweep selected";
    if (!activeSweep) return sweepId.slice(0, 14);
    return activeSweep.org
      ? `${activeSweep.org}/${activeSweep.repo_name}`
      : activeSweep.repo_name;
  }, [sweepId, selected, activeSweep]);

  const detail = useMemo(
    () => (activeFinding ? findings.find((f) => f.id === activeFinding) ?? null : null),
    [activeFinding, findings]
  );

  return (
    <div className="h-screen w-screen flex bg-paper-50 text-paper-900 overflow-hidden">
      <NavRail active={nav} onSelect={setNav} sweeping={running} />

      <div className="flex-1 min-w-0 flex flex-col">
        <TopBar
          running={running}
          onOpenWizard={() => setWizardOpen(true)}
          sweepId={sweepId}
          onOpenPalette={() => setPalette(true)}
        />

        <div key={nav} className="flex-1 min-h-0 flex overflow-hidden animate-fade-in">
          {/* HOME (Board) — full-width table + chart hero, cleanui1 aesthetic. */}
          {nav === "home" && !selectedSweep && (
            <Board
              onOpen={openHistoricalSweep}
              onStart={() => setWizardOpen(true)}
              onSelect={setSelectedSweep}
              selected={null}
              refreshSignal={historyRefresh}
            />
          )}
          {nav === "home" && selectedSweep && (
            <>
              <Board
                onOpen={openHistoricalSweep}
                onStart={() => setWizardOpen(true)}
                onSelect={setSelectedSweep}
                selected={selectedSweep.sweep_id}
                refreshSignal={historyRefresh}
              />
              <Dashboard
                onOpen={openHistoricalSweep}
                refreshSignal={historyRefresh}
                selected={selectedSweep}
                onStart={() => setWizardOpen(true)}
              />
            </>
          )}

          {/* LIVE — nav | findings list (if any) | Live Sweep panel */}
          {nav === "sweeps" && (
            <>
              {findings.length > 0 && (
                <FindingsList
                  findings={findings}
                  active={activeFinding}
                  onSelect={(id) => {
                    setActiveFinding(id);
                    setNav("findings");
                  }}
                  target={activeTargetLabel}
                  profileId={profileId}
                />
              )}
              {sweepId && <LiveSweepPanel events={events} running={running} />}
              {!sweepId && (
                <EmptySweep
                  onStart={() => setWizardOpen(true)}
                  onViewHistory={() => setNav("home")}
                  hasHistory={historyCount > 0}
                  historyCount={historyCount}
                />
              )}
            </>
          )}

          {/* FINDINGS — nav | findings list | finding detail */}
          {nav === "findings" && (
            <>
              <FindingsList
                findings={findings}
                active={activeFinding}
                onSelect={(id) => setActiveFinding(id)}
                target={activeTargetLabel}
                profileId={profileId}
              />
              {detail ? (
                <FindingDetail
                  finding={detail}
                  sweepId={sweepId}
                  sweep={activeSweep}
                  onFindingUpdated={(updated) => {
                    setFindings((prev) =>
                      prev.map((f) => (f.id === updated.id ? updated : f))
                    );
                    // Keep the shared workspace cache in sync so the Board's
                    // row expansion doesn't render a stale review_state.
                    if (sweepId) invalidateWorkspaceFindings(sweepId);
                  }}
                />
              ) : (
                <EmptyDetail />
              )}
            </>
          )}

          {nav === "paths" && <ExploitPathsView onOpenSweep={openHistoricalSweep} />}
          {nav === "warden" && <WardenView onOpenSweep={openHistoricalSweep} />}
          {nav === "cortex" && <CortexView />}
          {nav === "delta" && <DeltaView />}
          {nav === "attestations" && (
            <AttestationsView
              onOpenSweep={openHistoricalSweep}
              refreshSignal={historyRefresh}
            />
          )}
        </div>
      </div>

      <CommandPalette
        open={palette}
        onClose={() => setPalette(false)}
        onNavigate={setNav}
        onStartSweep={() => setWizardOpen(true)}
        onPickTarget={setSelected}
        targets={targets}
      />

      {wizardOpen && (
        <FirstScanWizard
          defaultProfileId={profileId}
          onClose={() => setWizardOpen(false)}
          onStart={async (repos, chosenProfile, opts) => {
            setProfileId(chosenProfile);
            for (const repo of repos) {
              setSelected(repo);
              // eslint-disable-next-line no-await-in-loop
              await onStart(repo, { interactive: opts.interactive });
            }
          }}
        />
      )}
    </div>
  );
}

function EmptyDetail() {
  return (
    <div className="flex-1 min-w-0 grid place-items-center bg-paper-50">
      <div className="text-center">
        <div className="opacity-40 mb-3 grid place-items-center">
          <Cmul8Mark size={44} />
        </div>
        <div className="text-paper-500 text-sm">Select a finding to see its evidence.</div>
      </div>
    </div>
  );
}

function EmptySweep({
  onStart,
  onViewHistory,
  hasHistory,
  historyCount,
}: {
  onStart: () => void;
  onViewHistory: () => void;
  hasHistory: boolean;
  historyCount: number;
}) {
  if (hasHistory) {
    return (
      <div className="flex-1 min-w-0 grid place-items-center bg-paper-50">
        <div className="text-center max-w-md px-6">
          <div className="mb-5 flex justify-center opacity-80">
            <Cmul8Mark size={40} />
          </div>
          <h1 className="text-lg text-paper-900 font-semibold tracking-tight">Ready for the next sweep</h1>
          <p className="text-sm text-paper-600 mt-1">
            Nothing running right now. Pick a target from the top bar or paste a git URL.
          </p>
          <div className="mt-5 flex items-center justify-center gap-2">
            <button
              onClick={onStart}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-accent text-white text-xs uppercase tracking-wider mono hover:brightness-95 hover:scale-[1.02] active:scale-[0.98] transition-transform shadow-card"
            >
              <IconPlay />
              New sweep
            </button>
            <button
              onClick={onViewHistory}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded border border-paper-300 text-paper-700 hover:text-paper-900 hover:border-paper-400 text-xs uppercase tracking-wider mono transition-colors"
            >
              History · {historyCount}
            </button>
          </div>
        </div>
      </div>
    );
  }
  return (
    <div className="flex-1 min-w-0 grid place-items-center bg-paper-50">
      <div className="text-center max-w-md px-6">
        <div className="mb-6 flex justify-center">
          <Cmul8Mark size={72} />
        </div>
        <h1 className="text-2xl text-paper-900 font-semibold tracking-tight mb-2">
          The AI security engineer
        </h1>
        <p className="text-sm text-paper-600 leading-relaxed">
          Point Spotlight at a target repo. It classifies the stack, reasons over a code graph,
          corroborates every candidate with independent evidence, reproduces in a hardened Modal
          sandbox, patches, and gets independently verified — all before you see a finding.
        </p>
        <button
          onClick={onStart}
          className="mt-6 inline-flex items-center gap-2 px-4 py-2 rounded bg-accent text-white text-sm uppercase tracking-wider mono hover:brightness-95"
        >
          <IconPlay />
          Start your first Sweep
        </button>
      </div>
    </div>
  );
}

function ComingSoonPane({ label }: { label: string }) {
  return (
    <div className="flex-1 min-w-0 grid place-items-center bg-paper-50">
      <div className="text-center">
        <div className="opacity-30 mb-3 grid place-items-center">
          <Cmul8Mark size={48} />
        </div>
        <div className="text-2xs uppercase tracking-wider text-paper-500 mono mb-1">{label}</div>
        <div className="text-paper-700 text-sm">Ships in Phase 2/3.</div>
      </div>
    </div>
  );
}
