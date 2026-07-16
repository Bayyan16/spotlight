import { useEffect, useMemo, useRef, useState } from "react";
import type { Target } from "../lib/api";
import type { NavKey } from "./NavRail";
import { Cmul8Mark } from "./Cmul8Mark";

type Cmd = {
  id: string;
  group: string;
  label: string;
  hint?: string;
  action: () => void;
};

export function CommandPalette({
  open,
  onClose,
  onNavigate,
  onStartSweep,
  onPickTarget,
  targets,
}: {
  open: boolean;
  onClose: () => void;
  onNavigate: (k: NavKey) => void;
  onStartSweep: () => void;
  onPickTarget: (name: string) => void;
  targets: Target[];
}) {
  const [q, setQ] = useState("");
  const [i, setI] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (open) {
      setQ("");
      setI(0);
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  const commands = useMemo<Cmd[]>(() => {
    const navCommands: Cmd[] = [
      { id: "nav-home", group: "Go to", label: "Sweeps history", hint: "1", action: () => onNavigate("home") },
      { id: "nav-live", group: "Go to", label: "Live sweep", hint: "2", action: () => onNavigate("sweeps") },
      { id: "nav-findings", group: "Go to", label: "Findings", hint: "3", action: () => onNavigate("findings") },
      { id: "nav-paths", group: "Go to", label: "Exploit paths", hint: "4", action: () => onNavigate("paths") },
      { id: "nav-warden", group: "Go to", label: "Warden", hint: "5", action: () => onNavigate("warden") },
      { id: "nav-atts", group: "Go to", label: "Attestations", hint: "6", action: () => onNavigate("attestations") },
    ];
    const actionCommands: Cmd[] = [
      { id: "act-start", group: "Actions", label: "Start Sweep", hint: "⌘↵", action: () => onStartSweep() },
    ];
    const targetCommands: Cmd[] = targets.map((t) => ({
      id: `tgt-${t.name}`,
      group: "Targets",
      label: `Use fixture · ${t.name}`,
      action: () => onPickTarget(t.name),
    }));
    return [...actionCommands, ...navCommands, ...targetCommands];
  }, [onNavigate, onStartSweep, onPickTarget, targets]);

  const filtered = useMemo(() => {
    const s = q.trim().toLowerCase();
    if (!s) return commands;
    return commands.filter((c) => (c.label + " " + c.group).toLowerCase().includes(s));
  }, [commands, q]);

  useEffect(() => {
    if (i >= filtered.length) setI(0);
  }, [filtered, i]);

  if (!open) return null;

  function invoke(c: Cmd) {
    c.action();
    onClose();
  }

  function onKey(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setI((n) => (n + 1) % Math.max(1, filtered.length));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setI((n) => (n - 1 + filtered.length) % Math.max(1, filtered.length));
    } else if (e.key === "Enter") {
      e.preventDefault();
      const c = filtered[i];
      if (c) invoke(c);
    } else if (e.key === "Escape") {
      onClose();
    }
  }

  // Group by group in display order.
  const groups: Record<string, Cmd[]> = {};
  filtered.forEach((c) => (groups[c.group] ??= []).push(c));

  return (
    <div
      className="fixed inset-0 z-50 bg-paper-900/25 backdrop-blur-sm animate-fade-in grid place-items-start pt-[15vh]"
      onClick={onClose}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="w-[560px] max-w-[90vw] bg-white rounded-lg border border-paper-300 shadow-pop overflow-hidden animate-pop"
      >
        <div className="flex items-center gap-3 px-4 py-3 border-b border-paper-200">
          <Cmul8Mark size={20} />
          <input
            ref={inputRef}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={onKey}
            placeholder="Search commands, targets, sweeps…"
            className="flex-1 bg-transparent outline-none text-sm text-paper-900 placeholder:text-paper-400"
          />
          <kbd className="text-2xs mono text-paper-400 border border-paper-300 rounded px-1.5 py-0.5">
            esc
          </kbd>
        </div>
        <div className="max-h-[50vh] overflow-y-auto py-1">
          {Object.entries(groups).map(([group, list]) => (
            <div key={group}>
              <div className="px-4 pt-2 pb-1 text-2xs mono uppercase tracking-wider text-paper-500">
                {group}
              </div>
              <ul>
                {list.map((c) => {
                  const idx = filtered.indexOf(c);
                  const active = idx === i;
                  return (
                    <li key={c.id}>
                      <button
                        onMouseEnter={() => setI(idx)}
                        onClick={() => invoke(c)}
                        className={`w-full flex items-center gap-3 px-4 py-2 text-sm text-left transition-colors ${
                          active ? "bg-accent-soft text-paper-900" : "text-paper-800 hover:bg-paper-100"
                        }`}
                      >
                        <span className="flex-1 truncate">{c.label}</span>
                        {c.hint && (
                          <kbd className="text-2xs mono text-paper-400 border border-paper-300 rounded px-1 bg-paper-50">
                            {c.hint}
                          </kbd>
                        )}
                      </button>
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}
          {filtered.length === 0 && (
            <div className="px-4 py-6 text-center text-paper-500 text-sm italic">
              No matches.
            </div>
          )}
        </div>
        <div className="border-t border-paper-200 px-4 py-2 flex items-center gap-3 text-2xs mono text-paper-500">
          <span className="flex items-center gap-1">
            <kbd className="border border-paper-300 rounded px-1 bg-paper-50">↑</kbd>
            <kbd className="border border-paper-300 rounded px-1 bg-paper-50">↓</kbd> navigate
          </span>
          <span className="flex items-center gap-1">
            <kbd className="border border-paper-300 rounded px-1 bg-paper-50">↵</kbd> select
          </span>
          <span className="ml-auto text-paper-400">CMUL8 Spotlight</span>
        </div>
      </div>
    </div>
  );
}
