import { useEffect, useMemo, useRef, useState } from "react";

import type { Profile, Target } from "../lib/api";
import {
  getWorkspacePref,
  listProfiles,
  listTargets,
  setWorkspacePref,
} from "../lib/api";

/**
 * FirstScanWizard — Devin-style onboarding modal.
 *
 * Opens on:
 *   * first workspace load (when workspace has zero sweeps AND the
 *     dismissed flag isn't set server-side); and
 *   * every "New scan" click from the TopBar so the same considered
 *     start-flow applies to every sweep, not just the first.
 *
 * Design axes:
 *   * Single primary question up top ("Point Spotlight at a repo")
 *   * Big-list target picker with search (Devin's repo picker rhythm)
 *   * Segmented profile picker (pills, not dropdown)
 *   * Two toggles: Auto-scan · Interactive mode
 *   * One primary action button, big and unmistakable
 *
 * State persistence: last-choice (repo, profile, interactive) writes to
 * server-side workspace prefs so it survives redeploys, incognito, and
 * browser cache clears.
 */
export type WizardOpts = {
  autoScan: boolean;
  interactive: boolean;
};

const LAST_CHOICE_KEY = "wizard-last-choice";
const DISMISSED_KEY = "wizard-dismissed";

type LastChoice = {
  repo?: string;
  profile_id?: string;
  interactive?: boolean;
  auto_scan?: boolean;
};

export function FirstScanWizard({
  onClose,
  onStart,
  defaultProfileId,
  title,
}: {
  onClose: () => void;
  onStart: (repos: string[], profileId: string, opts: WizardOpts) => void;
  defaultProfileId?: string;
  title?: string;
}) {
  const [tab, setTab] = useState<"single" | "all">("single");
  const [targets, setTargets] = useState<Target[]>([]);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [profileId, setProfileId] = useState<string>(defaultProfileId ?? "balanced");
  const [selectedRepo, setSelectedRepo] = useState<string>("");
  const [query, setQuery] = useState("");
  const [autoScan, setAutoScan] = useState(false);
  const [interactive, setInteractive] = useState(false);
  const searchRef = useRef<HTMLInputElement>(null);

  // Load targets, profiles, and any previous choice (all server-side).
  useEffect(() => {
    listTargets()
      .then((rows) => {
        setTargets(rows);
        if (rows[0]?.name && !selectedRepo) setSelectedRepo(rows[0].name);
      })
      .catch(() => setTargets([]));
    listProfiles()
      .then(setProfiles)
      .catch(() => setProfiles([]));
    getWorkspacePref<LastChoice>(LAST_CHOICE_KEY).then((choice) => {
      if (!choice) return;
      if (choice.repo) setSelectedRepo(choice.repo);
      if (choice.profile_id) setProfileId(choice.profile_id);
      if (typeof choice.interactive === "boolean") setInteractive(choice.interactive);
      if (typeof choice.auto_scan === "boolean") setAutoScan(choice.auto_scan);
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    searchRef.current?.focus();
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const filteredTargets = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return targets;
    return targets.filter((t) => t.name.toLowerCase().includes(q));
  }, [targets, query]);

  const canStart =
    tab === "single" ? !!selectedRepo : filteredTargets.length > 0;

  function submit() {
    if (!canStart) return;
    const repos =
      tab === "single" ? [selectedRepo] : filteredTargets.map((t) => t.name);
    // Persist last-choice server-side so redeploys keep the user's context.
    void setWorkspacePref<LastChoice>(LAST_CHOICE_KEY, {
      repo: selectedRepo,
      profile_id: profileId,
      interactive,
      auto_scan: autoScan,
    });
    void setWorkspacePref<boolean>(DISMISSED_KEY, true);
    onStart(repos, profileId, { autoScan, interactive });
    onClose();
  }

  const activeProfile = profiles.find((p) => p.id === profileId);

  return (
    <div
      className="fixed inset-0 z-50 grid place-items-center bg-paper-900/50 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      onClick={onClose}
    >
      <div
        className="w-[640px] max-w-[calc(100vw-2rem)] max-h-[calc(100vh-2rem)] overflow-hidden bg-white border border-paper-300 rounded-2xl shadow-2xl flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header — single question, no visual noise */}
        <header className="px-8 pt-8 pb-3">
          <div className="text-2xs mono uppercase tracking-[0.14em] text-accent mb-2">
            {title ?? "New scan"}
          </div>
          <h2 className="text-2xl text-paper-900 font-semibold tracking-tight">
            Point Spotlight at a repo.
          </h2>
          <p className="mt-1.5 text-sm text-paper-600">
            Recon → Investigate → Reproduce → Remediate → Verify → Attest.
            Signed evidence at every step.
          </p>
        </header>

        <div className="px-8 flex items-center gap-6 border-b border-paper-200">
          <TabBtn active={tab === "single"} onClick={() => setTab("single")}>
            Single repo
          </TabBtn>
          <TabBtn active={tab === "all"} onClick={() => setTab("all")}>
            All repos
            <span className="ml-1.5 mono text-2xs text-paper-500">
              {targets.length}
            </span>
          </TabBtn>
        </div>

        {/* Body — scrollable when tall */}
        <div className="px-8 py-5 flex-1 overflow-y-auto space-y-6">
          {tab === "single" ? (
            <div>
              <div className="relative mb-2">
                <input
                  ref={searchRef}
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Search targets…"
                  className="w-full border border-paper-300 rounded-lg pl-10 pr-3 py-2 text-sm focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/20 bg-white"
                />
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-paper-400 mono text-xs">
                  ⌕
                </span>
              </div>
              <ul className="border border-paper-200 rounded-lg divide-y divide-paper-200 max-h-56 overflow-y-auto">
                {filteredTargets.length === 0 && (
                  <li className="px-3 py-6 text-center text-2xs mono uppercase tracking-wider text-paper-500">
                    no matches
                  </li>
                )}
                {filteredTargets.map((t) => (
                  <li key={t.name}>
                    <button
                      onClick={() => setSelectedRepo(t.name)}
                      className={`w-full text-left px-3 py-2.5 flex items-center gap-2 transition-colors ${
                        selectedRepo === t.name ? "bg-accent-soft" : "hover:bg-paper-50"
                      }`}
                    >
                      <span
                        className={`h-2 w-2 rounded-full ${
                          selectedRepo === t.name ? "bg-accent" : "bg-paper-300"
                        }`}
                      />
                      <span className="mono text-sm text-paper-900">{t.name}</span>
                      {t.has_ground_truth && (
                        <span className="ml-auto text-2xs mono uppercase tracking-wider text-paper-500">
                          ground-truth
                        </span>
                      )}
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            <div>
              <div className="text-sm text-paper-800">
                Sweeps every bundled target sequentially with the same
                profile. Results land in the Board.
              </div>
              <div className="mt-3 flex flex-wrap gap-1.5">
                {targets.map((t) => (
                  <span
                    key={t.name}
                    className="mono text-2xs uppercase tracking-wider bg-paper-100 border border-paper-300 text-paper-700 rounded-full px-2 py-0.5"
                  >
                    {t.name}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Scan profile — segmented pills */}
          <div>
            <div className="mono text-2xs uppercase tracking-wider text-paper-500 mb-2">
              Scan profile
            </div>
            <div className="flex flex-wrap gap-1.5">
              {profiles.map((p) => (
                <button
                  key={p.id}
                  onClick={() => setProfileId(p.id)}
                  aria-pressed={profileId === p.id}
                  className={`px-3 py-1.5 rounded-full text-sm border transition-colors ${
                    profileId === p.id
                      ? "bg-accent text-white border-accent"
                      : "bg-white text-paper-700 border-paper-300 hover:bg-paper-50"
                  }`}
                >
                  {p.name}
                </button>
              ))}
            </div>
            {activeProfile && (
              <div className="mt-2 text-2xs text-paper-500 leading-relaxed max-w-lg">
                {activeProfile.description}
              </div>
            )}
          </div>

          {/* Toggles */}
          <div className="space-y-1">
            <SwitchRow
              label="Interactive mode"
              hint="Pause after Recon so you can edit the threat model before the swarm goes deeper."
              checked={interactive}
              onChange={setInteractive}
            />
            <SwitchRow
              label="Auto-scan on load"
              hint="Kick off a scan automatically when the console opens next."
              checked={autoScan}
              onChange={setAutoScan}
            />
          </div>
        </div>

        {/* Footer — clear primary action */}
        <footer className="px-8 py-4 border-t border-paper-200 flex items-center gap-3 bg-paper-50">
          <button
            onClick={onClose}
            className="text-xs uppercase mono tracking-wider text-paper-600 hover:text-paper-900"
          >
            Not now
          </button>
          <div className="ml-auto flex items-center gap-3">
            {activeProfile && (
              <span className="text-2xs mono uppercase tracking-wider text-paper-500">
                {activeProfile.max_agents} agents · {(activeProfile.budget_tokens / 1000).toFixed(0)}k tokens
              </span>
            )}
            <button
              onClick={submit}
              disabled={!canStart}
              className={`px-5 py-2 rounded-full text-sm font-semibold uppercase tracking-wider mono transition-colors ${
                canStart
                  ? "bg-accent text-white hover:brightness-95"
                  : "bg-paper-300 text-paper-500 cursor-not-allowed"
              }`}
            >
              Start scan →
            </button>
          </div>
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
      className={`px-1 py-3 text-sm border-b-2 -mb-px transition-colors ${
        active
          ? "border-accent text-paper-900 font-medium"
          : "border-transparent text-paper-600 hover:text-paper-800"
      }`}
    >
      {children}
    </button>
  );
}

function SwitchRow({
  label,
  hint,
  checked,
  onChange,
}: {
  label: string;
  hint: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <label className="flex items-start gap-3 py-1.5 cursor-pointer">
      <button
        type="button"
        onClick={() => onChange(!checked)}
        aria-pressed={checked}
        className={`mt-0.5 h-5 w-9 rounded-full relative transition-colors ${
          checked ? "bg-accent" : "bg-paper-300"
        }`}
      >
        <span
          className={`absolute top-0.5 h-4 w-4 rounded-full bg-white transition-transform ${
            checked ? "translate-x-4" : "translate-x-0.5"
          }`}
        />
      </button>
      <div className="min-w-0 flex-1">
        <div className="text-sm text-paper-900 font-medium">{label}</div>
        <div className="text-2xs text-paper-500 leading-relaxed">{hint}</div>
      </div>
    </label>
  );
}
