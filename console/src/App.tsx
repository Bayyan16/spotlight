import { useEffect, useMemo, useState } from "react";
import { NavRail, type NavKey } from "./components/NavRail";
import { TopBar } from "./components/TopBar";
import { FindingsList } from "./components/FindingsList";
import { FindingDetail } from "./components/FindingDetail";
import { LiveSweepPanel } from "./components/LiveSweepPanel";
import { Board } from "./components/Board";
import { Dashboard } from "./components/Dashboard";
import { CommandPalette } from "./components/CommandPalette";
import { ExploitPathsView } from "./components/ExploitPathsView";
import { WardenView } from "./components/WardenView";
import { Cmul8Mark } from "./components/Cmul8Mark";
import { IconPlay } from "./components/Icons";
import {
  getFindings,
  listSweeps,
  listTargets,
  openSweepStream,
  startSweep,
  type Finding,
  type SweepEvent,
  type SweepSummary,
  type Target,
} from "./lib/api";

const NAV_ORDER: NavKey[] = ["home", "sweeps", "findings", "paths", "warden", "attestations"];

export default function App() {
  const [nav, setNav] = useState<NavKey>("home");
  const [targets, setTargets] = useState<Target[]>([]);
  const [selected, setSelected] = useState<string>("vuln-bank-api");
  const [sweepId, setSweepId] = useState<string | null>(null);
  const [events, setEvents] = useState<SweepEvent[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [running, setRunning] = useState(false);
  const [activeFinding, setActiveFinding] = useState<string | null>(null);
  const [historyRefresh, setHistoryRefresh] = useState(0);
  const [historyCount, setHistoryCount] = useState<number>(0);
  const [palette, setPalette] = useState(false);
  const [profileId, setProfileId] = useState<string>("balanced");
  const [selectedSweep, setSelectedSweep] = useState<SweepSummary | null>(null);

  useEffect(() => {
    listTargets().then(setTargets).catch(() => setTargets([]));
  }, []);

  useEffect(() => {
    listSweeps()
      .then((s) => setHistoryCount(Array.isArray(s) ? s.length : 0))
      .catch(() => setHistoryCount(0));
  }, [historyRefresh]);

  useEffect(() => {
    if (!sweepId) return;
    const ws = openSweepStream(sweepId, (e) => {
      setEvents((prev) => [...prev, e]);
      if (e.type === "sweep.finished") {
        setRunning(false);
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
      if (e.key >= "1" && e.key <= "6") {
        const idx = parseInt(e.key, 10) - 1;
        if (idx >= 0 && idx < NAV_ORDER.length) setNav(NAV_ORDER[idx]);
      }
      if ((e.metaKey || e.ctrlKey) && e.key === "Enter" && !running) {
        e.preventDefault();
        onStart();
      }
      if (e.key === "Escape") setPalette(false);
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [running]);

  async function onStart(customRepo?: string) {
    setEvents([]);
    setFindings([]);
    setActiveFinding(null);
    setRunning(true);
    setNav("sweeps");
    try {
      const repo = customRepo ?? selected;
      const { sweep_id } = await startSweep(repo, profileId);
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
          onStart={onStart}
          target={selected}
          onTarget={setSelected}
          targets={targets}
          sweepId={sweepId}
          onOpenPalette={() => setPalette(true)}
          profileId={profileId}
          onProfileChange={setProfileId}
        />

        <div key={nav} className="flex-1 min-h-0 flex overflow-hidden animate-fade-in">
          {/* HOME (Board) — full-width table + chart hero, cleanui1 aesthetic. */}
          {nav === "home" && !selectedSweep && (
            <Board
              onOpen={openHistoricalSweep}
              onStart={() => onStart()}
              onSelect={setSelectedSweep}
              selected={null}
              refreshSignal={historyRefresh}
            />
          )}
          {nav === "home" && selectedSweep && (
            <>
              <Board
                onOpen={openHistoricalSweep}
                onStart={() => onStart()}
                onSelect={setSelectedSweep}
                selected={selectedSweep.sweep_id}
                refreshSignal={historyRefresh}
              />
              <Dashboard
                onOpen={openHistoricalSweep}
                refreshSignal={historyRefresh}
                selected={selectedSweep}
                onStart={() => onStart()}
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
                  target={selected}
                />
              )}
              {sweepId && <LiveSweepPanel events={events} running={running} />}
              {!sweepId && (
                <EmptySweep
                  onStart={() => onStart()}
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
                target={selected}
              />
              {detail ? (
                <FindingDetail
                  finding={detail}
                  sweepId={sweepId}
                  onFindingUpdated={(updated) =>
                    setFindings((prev) =>
                      prev.map((f) => (f.id === updated.id ? updated : f))
                    )
                  }
                />
              ) : (
                <EmptyDetail />
              )}
            </>
          )}

          {nav === "paths" && <ExploitPathsView onOpenSweep={openHistoricalSweep} />}
          {nav === "warden" && <WardenView onOpenSweep={openHistoricalSweep} />}
          {nav === "attestations" && <ComingSoonPane label={nav} />}
        </div>
      </div>

      <CommandPalette
        open={palette}
        onClose={() => setPalette(false)}
        onNavigate={setNav}
        onStartSweep={() => onStart()}
        onPickTarget={setSelected}
        targets={targets}
      />
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
