import { useEffect, useMemo, useState } from "react";
import { NavRail, type NavKey } from "./components/NavRail";
import { TopBar } from "./components/TopBar";
import { FindingsList } from "./components/FindingsList";
import { FindingDetail } from "./components/FindingDetail";
import { LiveSweepPanel } from "./components/LiveSweepPanel";
import { SweepsHistory } from "./components/SweepsHistory";
import { CommandPalette } from "./components/CommandPalette";
import { Cmul8Mark } from "./components/Cmul8Mark";
import { IconPlay } from "./components/Icons";
import {
  getFindings,
  listTargets,
  openSweepStream,
  startSweep,
  type Finding,
  type SweepEvent,
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
  const [palette, setPalette] = useState(false);

  useEffect(() => {
    listTargets().then(setTargets).catch(() => setTargets([]));
  }, []);

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

  // Keyboard shortcuts — Codex/Linear-style
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      const target = e.target as HTMLElement | null;
      const inField =
        target &&
        (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable);

      // ⌘K / Ctrl+K → command palette
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPalette((p) => !p);
        return;
      }

      if (inField) return;

      // Number keys 1..6 → nav
      if (e.key >= "1" && e.key <= "6") {
        const idx = parseInt(e.key, 10) - 1;
        if (idx >= 0 && idx < NAV_ORDER.length) setNav(NAV_ORDER[idx]);
      }
      // ⌘Enter → start sweep
      if ((e.metaKey || e.ctrlKey) && e.key === "Enter" && !running) {
        e.preventDefault();
        onStart();
      }
      // Esc → close palette
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
      const { sweep_id } = await startSweep(repo);
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
        />

        <div key={nav} className="flex-1 min-h-0 flex overflow-hidden animate-fade-in">
          {nav === "home" && (
            <SweepsHistory onOpen={openHistoricalSweep} refreshSignal={historyRefresh} />
          )}

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
              {!sweepId && <EmptySweep onStart={() => onStart()} />}
            </>
          )}

          {nav === "findings" && (
            <>
              <FindingsList
                findings={findings}
                active={activeFinding}
                onSelect={(id) => setActiveFinding(id)}
                target={selected}
              />
              {detail ? <FindingDetail finding={detail} /> : <EmptyDetail />}
            </>
          )}

          {(nav === "paths" || nav === "warden" || nav === "attestations") && (
            <ComingSoonPane label={nav} />
          )}
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
        <div className="text-paper-400 text-2xs mono uppercase tracking-wider mt-1">
          j / k to navigate · enter to open
        </div>
      </div>
    </div>
  );
}

function EmptySweep({ onStart }: { onStart: () => void }) {
  return (
    <div className="flex-1 min-w-0 grid place-items-center bg-paper-50">
      <div className="text-center max-w-md px-6">
        <div className="mb-6 flex justify-center">
          <div className="relative">
            <Cmul8Mark size={72} />
            <div className="absolute -inset-6 rounded-full bg-accent/5 blur-2xl -z-10" />
          </div>
        </div>
        <h1 className="text-2xl text-paper-900 font-semibold tracking-tight mb-2">
          The AI security engineer
        </h1>
        <p className="text-sm text-paper-600 leading-relaxed">
          Point Spotlight at a target repo. It classifies the stack, reasons over a code graph,
          corroborates every candidate with independent evidence, reproduces where feasible, patches,
          and gets independently verified — all before you see a finding.
        </p>
        <button
          onClick={onStart}
          className="mt-6 inline-flex items-center gap-2 px-4 py-2 rounded bg-accent text-white text-sm uppercase tracking-wider mono hover:brightness-95 hover:scale-[1.02] active:scale-[0.98] transition-transform shadow-card"
        >
          <IconPlay />
          Start your first Sweep
        </button>
        <div className="mt-4 text-2xs mono uppercase tracking-wider text-paper-500">
          <kbd className="border border-paper-300 rounded px-1 py-0.5 bg-white mr-1">⌘</kbd>
          <kbd className="border border-paper-300 rounded px-1 py-0.5 bg-white">↵</kbd>{" "}
          <span className="ml-1">to start</span>
        </div>
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
