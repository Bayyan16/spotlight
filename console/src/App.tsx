import { useEffect, useState } from "react";
import { NavRail, type NavKey } from "./components/NavRail";
import { TopBar } from "./components/TopBar";
import { FindingsList } from "./components/FindingsList";
import { FindingDetail } from "./components/FindingDetail";
import { LiveSweepPanel } from "./components/LiveSweepPanel";
import { SweepsHistory } from "./components/SweepsHistory";
import {
  getFindings,
  listTargets,
  openSweepStream,
  startSweep,
  type Finding,
  type SweepEvent,
  type Target,
} from "./lib/api";

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

  const showFindings = nav === "findings" && findings.length > 0;
  const showLive = nav === "sweeps";
  const detail = activeFinding ? findings.find((f) => f.id === activeFinding) ?? null : null;

  return (
    <div className="h-screen w-screen flex bg-paper-50 text-paper-900 overflow-hidden">
      <NavRail active={nav} onSelect={setNav} />

      <div className="flex-1 min-w-0 flex flex-col">
        <TopBar
          running={running}
          onStart={onStart}
          target={selected}
          onTarget={setSelected}
          targets={targets}
          sweepId={sweepId}
        />

        <div className="flex-1 min-h-0 flex overflow-hidden">
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
              {sweepId && <LiveSweepPanel events={events} />}
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
    </div>
  );
}

function EmptyDetail() {
  return (
    <div className="flex-1 min-w-0 grid place-items-center bg-paper-50">
      <div className="text-paper-500 text-sm">Select a finding to see its evidence.</div>
    </div>
  );
}

function EmptySweep({ onStart }: { onStart: () => void }) {
  return (
    <div className="flex-1 min-w-0 grid place-items-center bg-paper-50">
      <div className="text-center max-w-md px-6">
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
          className="mt-6 inline-flex items-center gap-2 px-4 py-2 rounded bg-accent text-white text-sm uppercase tracking-wider mono hover:brightness-95"
        >
          ▸ Start your first Sweep
        </button>
      </div>
    </div>
  );
}

function ComingSoonPane({ label }: { label: string }) {
  return (
    <div className="flex-1 min-w-0 grid place-items-center bg-paper-50">
      <div className="text-center">
        <div className="text-2xs uppercase tracking-wider text-paper-500 mono mb-1">{label}</div>
        <div className="text-paper-700 text-sm">Ships in Phase 2/3.</div>
      </div>
    </div>
  );
}
