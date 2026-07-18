import { useEffect, useState } from "react";

import type { Profile, Target } from "../lib/api";
import { listProfiles, listTargets } from "../lib/api";

/**
 * C1 · First-scan onboarding wizard.
 *
 * Two tabs:
 *   Single repo  — pick one target, one profile
 *   All repos    — sweep every bundled target sequentially with the same profile
 *
 * Plus two switches:
 *   Auto scan       — persist "run one on load" preference (localStorage)
 *   Interactive     — pause after Recon so the user can edit the threat model
 *
 * When the workspace has zero sweeps, the wizard auto-opens on mount. The
 * user can dismiss it via ESC or the "Not now" button; both paths persist a
 * flag so it doesn't re-open on every reload.
 *
 * Submit fires `onStart(repo, opts)` for each selected target — the App is
 * responsible for actually starting sweeps and switching to Live view.
 */
export type WizardOpts = {
  autoScan: boolean;
  interactive: boolean;
};

export function FirstScanWizard({
  onClose,
  onStart,
  defaultProfileId,
}: {
  onClose: () => void;
  onStart: (repos: string[], profileId: string, opts: WizardOpts) => void;
  defaultProfileId?: string;
}) {
  const [tab, setTab] = useState<"single" | "all">("single");
  const [targets, setTargets] = useState<Target[]>([]);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [profileId, setProfileId] = useState<string>(defaultProfileId ?? "balanced");
  const [selectedRepo, setSelectedRepo] = useState<string>("");
  const [autoScan, setAutoScan] = useState<boolean>(() => {
    try {
      return localStorage.getItem("spotlight.auto-scan") === "1";
    } catch {
      return false;
    }
  });
  const [interactive, setInteractive] = useState(false);

  useEffect(() => {
    listTargets()
      .then((rows) => {
        setTargets(rows);
        if (rows[0]?.name) setSelectedRepo(rows[0].name);
      })
      .catch(() => setTargets([]));
    listProfiles()
      .then((rows) => setProfiles(rows))
      .catch(() => setProfiles([]));
  }, []);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  function submit() {
    try {
      localStorage.setItem("spotlight.auto-scan", autoScan ? "1" : "0");
      localStorage.setItem("spotlight.wizard-dismissed", "1");
    } catch {
      /* private mode — ignore */
    }
    const repos =
      tab === "single"
        ? selectedRepo
          ? [selectedRepo]
          : []
        : targets.map((t) => t.name);
    if (repos.length === 0) return;
    onStart(repos, profileId, { autoScan, interactive });
    onClose();
  }

  return (
    <div
      className="fixed inset-0 z-50 grid place-items-center bg-paper-900/40 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
    >
      <div className="w-[560px] max-w-[calc(100vw-2rem)] bg-white border border-paper-300 rounded-xl shadow-2xl overflow-hidden">
        <header className="px-6 py-4 border-b border-paper-300">
          <div className="text-2xs mono uppercase tracking-wider text-paper-500 mb-1">
            First scan
          </div>
          <h2 className="text-lg text-paper-900 font-semibold tracking-tight">
            Point Spotlight at your first repo
          </h2>
          <p className="text-xs text-paper-600 mt-1">
            Pick a target and a profile. Spotlight will run the full pipeline
            — recon, investigate, reproduce, remediate, verify — and land
            findings with signed attestations.
          </p>
        </header>

        <div className="px-6 py-4">
          <div className="flex items-center gap-6 border-b border-paper-200 -mx-6 px-6">
            <TabBtn active={tab === "single"} onClick={() => setTab("single")}>
              Single repo
            </TabBtn>
            <TabBtn active={tab === "all"} onClick={() => setTab("all")}>
              All repos
              <span className="ml-1 text-paper-400 mono text-2xs">
                {targets.length}
              </span>
            </TabBtn>
          </div>

          {tab === "single" ? (
            <div className="pt-4">
              <label className="block text-2xs mono uppercase tracking-wider text-paper-500 mb-1">
                Target
              </label>
              <select
                value={selectedRepo}
                onChange={(e) => setSelectedRepo(e.target.value)}
                className="w-full border border-paper-300 rounded px-2 py-1.5 text-sm bg-white"
              >
                {targets.map((t) => (
                  <option key={t.name} value={t.name}>
                    {t.name}
                    {t.has_ground_truth ? "  ·  ground-truth" : ""}
                  </option>
                ))}
              </select>
            </div>
          ) : (
            <div className="pt-4 space-y-1">
              <div className="text-xs text-paper-700 mb-1">
                Sweeps every bundled target with the same profile,
                sequentially. Results land in the Board.
              </div>
              <ul className="text-xs mono text-paper-800 space-y-0.5 max-h-40 overflow-y-auto">
                {targets.map((t) => (
                  <li key={t.name}>· {t.name}</li>
                ))}
              </ul>
            </div>
          )}

          <div className="mt-5">
            <label className="block text-2xs mono uppercase tracking-wider text-paper-500 mb-1">
              Scan profile
            </label>
            <select
              value={profileId}
              onChange={(e) => setProfileId(e.target.value)}
              className="w-full border border-paper-300 rounded px-2 py-1.5 text-sm bg-white"
            >
              {profiles.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} — {p.description.slice(0, 70)}
                </option>
              ))}
            </select>
          </div>

          <div className="mt-5 space-y-2">
            <ToggleRow
              label="Auto scan on load"
              hint="Kick off a sweep automatically when the console opens next time."
              checked={autoScan}
              onChange={setAutoScan}
            />
            <ToggleRow
              label="Interactive mode"
              hint="Pause after Recon so you can edit the threat model before investigation."
              checked={interactive}
              onChange={setInteractive}
              disabled
              disabledReason="Coming in the next release"
            />
          </div>
        </div>

        <footer className="px-6 py-3 border-t border-paper-300 flex items-center gap-2 bg-paper-50">
          <button
            onClick={onClose}
            className="text-xs uppercase mono tracking-wider text-paper-600 hover:text-paper-900"
          >
            Not now
          </button>
          <button
            onClick={submit}
            className="ml-auto px-4 py-1.5 rounded bg-accent text-white text-xs uppercase mono tracking-wider hover:brightness-95"
          >
            Start scan
          </button>
        </footer>
      </div>
    </div>
  );
}

function TabBtn({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={`px-1 py-2 text-sm border-b-2 -mb-px transition-colors ${
        active
          ? "border-accent text-paper-900 font-medium"
          : "border-transparent text-paper-600 hover:text-paper-800"
      }`}
    >
      {children}
    </button>
  );
}

function ToggleRow({
  label,
  hint,
  checked,
  onChange,
  disabled,
  disabledReason,
}: {
  label: string;
  hint: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
  disabledReason?: string;
}) {
  return (
    <label
      className={`flex items-start gap-3 py-1 cursor-pointer ${disabled ? "opacity-60 cursor-not-allowed" : ""}`}
    >
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
        className="mt-1 h-4 w-4 accent-current"
      />
      <div className="min-w-0">
        <div className="text-sm text-paper-900">{label}</div>
        <div className="text-2xs text-paper-500">
          {disabled ? disabledReason || hint : hint}
        </div>
      </div>
    </label>
  );
}
