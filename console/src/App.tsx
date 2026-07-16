import { useEffect, useState } from "react";
import { PhaseTracker } from "./components/PhaseTracker";
import { SwarmGrid } from "./components/SwarmGrid";
import { EventLog } from "./components/EventLog";
import { FindingDetail } from "./components/FindingDetail";
import {
  getFindings,
  getSweep,
  listTargets,
  openSweepStream,
  startSweep,
  type Finding,
  type SweepEvent,
  type Target,
} from "./lib/api";

export default function App() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [selected, setSelected] = useState<string>("vuln-bank-api");
  const [sweepId, setSweepId] = useState<string | null>(null);
  const [events, setEvents] = useState<SweepEvent[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [running, setRunning] = useState(false);
  const [detail, setDetail] = useState<Finding | null>(null);

  useEffect(() => {
    listTargets().then(setTargets).catch(() => setTargets([]));
  }, []);

  useEffect(() => {
    if (!sweepId) return;
    const ws = openSweepStream(sweepId, (e) => {
      setEvents((prev) => [...prev, e]);
      if (e.type === "sweep.finished") {
        setRunning(false);
        getFindings(sweepId).then(setFindings);
      }
    });
    return () => ws.close();
  }, [sweepId]);

  async function onStart() {
    setEvents([]);
    setFindings([]);
    setDetail(null);
    setRunning(true);
    try {
      const { sweep_id } = await startSweep(selected);
      setSweepId(sweep_id);
    } catch (err) {
      setRunning(false);
      alert(`Failed to start sweep: ${err}`);
    }
  }

  return (
    <div className="min-h-screen bg-ink-950">
      <TopBar running={running} onStart={onStart} target={selected} onTarget={setSelected} targets={targets} />
      <main className="max-w-7xl mx-auto p-6 space-y-4">
        {!sweepId && <EmptyState onStart={onStart} />}
        {sweepId && (
          <>
            <div className="text-xs text-ink-500 mono">
              sweep_id <span className="text-ink-300">{sweepId}</span> · target{" "}
              <span className="text-ink-300">{selected}</span>
            </div>
            <PhaseTracker events={events} />
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <SwarmGrid events={events} />
              <EventLog events={events} />
            </div>
            <FindingsSection findings={findings} onOpen={setDetail} />
            {detail && <FindingDetail finding={detail} />}
          </>
        )}
      </main>
    </div>
  );
}

function TopBar({
  running,
  onStart,
  target,
  onTarget,
  targets,
}: {
  running: boolean;
  onStart: () => void;
  target: string;
  onTarget: (t: string) => void;
  targets: Target[];
}) {
  return (
    <div className="border-b border-ink-800 bg-ink-900/60 backdrop-blur">
      <div className="max-w-7xl mx-auto px-6 py-3 flex items-center gap-4">
        <div className="flex items-center gap-2">
          <span className="h-2.5 w-2.5 rounded-full bg-spot-green" />
          <span className="text-ink-100 font-semibold tracking-tight">Spotlight</span>
          <span className="text-ink-500 text-xs mono">by CMUL8</span>
        </div>
        <div className="ml-auto flex items-center gap-3">
          <select
            className="bg-ink-800 border border-ink-700 text-ink-200 text-sm rounded px-2 py-1.5 mono"
            value={target}
            onChange={(e) => onTarget(e.target.value)}
            disabled={running}
          >
            {targets.map((t) => (
              <option key={t.name} value={t.name}>
                {t.name}
              </option>
            ))}
          </select>
          <button
            className={`px-4 py-1.5 rounded text-sm mono uppercase tracking-wider transition-colors ${
              running
                ? "bg-ink-800 text-ink-500 cursor-not-allowed"
                : "bg-spot-green/20 text-spot-green border border-spot-green/40 hover:bg-spot-green/30"
            }`}
            onClick={onStart}
            disabled={running}
          >
            {running ? "Sweeping…" : "▸ Start Sweep"}
          </button>
        </div>
      </div>
    </div>
  );
}

function EmptyState({ onStart }: { onStart: () => void }) {
  return (
    <div className="text-center py-24">
      <h1 className="text-2xl text-ink-100 font-semibold tracking-tight mb-2">
        The AI security engineer
      </h1>
      <p className="text-ink-400 max-w-lg mx-auto text-sm">
        Point Spotlight at a target repo. It classifies the stack, reasons over a code graph, corroborates every
        candidate, reproduces where feasible, patches, and gets independently verified — all before you see a finding.
      </p>
      <button
        onClick={onStart}
        className="mt-6 px-5 py-2 rounded mono uppercase tracking-wider text-sm bg-spot-green/20 text-spot-green border border-spot-green/40 hover:bg-spot-green/30"
      >
        ▸ Start your first Sweep
      </button>
    </div>
  );
}

function FindingsSection({
  findings,
  onOpen,
}: {
  findings: Finding[];
  onOpen: (f: Finding) => void;
}) {
  return (
    <div className="border border-ink-800 rounded-md bg-ink-900">
      <div className="p-4 border-b border-ink-800">
        <div className="text-xs uppercase tracking-wider text-ink-400 mono">
          Findings ({findings.length})
        </div>
      </div>
      {findings.length === 0 && (
        <div className="p-6 text-ink-500 text-sm italic">
          None promoted yet. When the Consensus Kernel promotes a candidate it appears here.
        </div>
      )}
      <ul className="divide-y divide-ink-800">
        {findings.map((f) => (
          <li key={f.id}>
            <button
              className="w-full flex items-center gap-3 p-3 hover:bg-ink-800 text-left"
              onClick={() => onOpen(f)}
            >
              <span className="mono text-xs text-ink-400">{f.id}</span>
              <span className="text-ink-100 text-sm">{f.title}</span>
              <span className="mono text-[10px] uppercase px-1.5 py-0.5 rounded border border-spot-green/40 text-spot-green">
                {f.tier}
              </span>
              <span className="mono text-xs text-ink-500 ml-auto">
                {f.location.file}:{f.location.line}
              </span>
              <span className="mono text-xs text-spot-green">
                {(f.confidence * 100).toFixed(0)}%
              </span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
