import { useState } from "react";
import { IconChevron, IconPlay } from "./Icons";
import type { Target } from "../lib/api";

export function TopBar({
  running,
  onStart,
  target,
  onTarget,
  targets,
  sweepId,
}: {
  running: boolean;
  onStart: (customRepo?: string) => void;
  target: string;
  onTarget: (t: string) => void;
  targets: Target[];
  sweepId: string | null;
}) {
  const [mode, setMode] = useState<"fixture" | "git">("fixture");
  const [gitUrl, setGitUrl] = useState("");

  function handleStart() {
    if (mode === "git" && gitUrl.trim()) {
      onStart(gitUrl.trim());
    } else {
      onStart();
    }
  }

  return (
    <header className="shrink-0 border-b border-paper-300 bg-paper-50 px-4 py-2.5 flex items-center gap-3 text-sm">
      <div className="flex items-center gap-1.5 text-paper-600 mono text-xs">
        <span className="text-paper-900 font-semibold uppercase tracking-[0.14em]">CMUL8</span>
        <IconChevron />
        <span className="text-paper-700">Spotlight</span>
        <IconChevron />
        <span className="text-paper-700">{mode === "git" ? "git url" : target}</span>
        {sweepId && (
          <>
            <IconChevron />
            <span className="text-paper-500">{sweepId}</span>
          </>
        )}
      </div>

      <div className="ml-auto flex items-center gap-2">
        {/* Segmented control: fixture vs git URL */}
        <div className="flex border border-paper-300 rounded overflow-hidden bg-paper-100">
          <button
            className={`px-2.5 py-1 text-2xs uppercase mono tracking-wider ${
              mode === "fixture" ? "bg-white text-paper-900 shadow-inner" : "text-paper-500"
            }`}
            onClick={() => setMode("fixture")}
            disabled={running}
          >
            Fixture
          </button>
          <button
            className={`px-2.5 py-1 text-2xs uppercase mono tracking-wider ${
              mode === "git" ? "bg-white text-paper-900 shadow-inner" : "text-paper-500"
            }`}
            onClick={() => setMode("git")}
            disabled={running}
          >
            Git URL
          </button>
        </div>

        {mode === "fixture" ? (
          <select
            className="bg-paper-100 border border-paper-300 hover:border-paper-400 text-paper-800 text-xs rounded px-2 py-1 mono"
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
        ) : (
          <input
            type="text"
            placeholder="https://github.com/…/repo.git"
            value={gitUrl}
            onChange={(e) => setGitUrl(e.target.value)}
            disabled={running}
            className="w-[260px] bg-white border border-paper-300 text-paper-800 text-xs rounded px-2 py-1 mono placeholder:text-paper-400"
          />
        )}

        <button
          onClick={handleStart}
          disabled={running || (mode === "git" && !gitUrl.trim())}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs uppercase tracking-wider mono transition-colors ${
            running || (mode === "git" && !gitUrl.trim())
              ? "bg-paper-200 text-paper-500 cursor-not-allowed"
              : "bg-accent text-white hover:brightness-95"
          }`}
        >
          <IconPlay />
          {running ? "Sweeping…" : "Start Sweep"}
        </button>
      </div>
    </header>
  );
}
