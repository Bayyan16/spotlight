import { IconChevron, IconPlay } from "./Icons";

/**
 * TopBar — status header, NOT a control panel.
 *
 * The previous version tried to be a mini-launcher: fixture/git segmented
 * control, target dropdown, git URL text input, profile dropdown, big
 * "Start Sweep" button. All of that is now inside the FirstScanWizard,
 * which is the ONE canonical start-sweep surface. Duplicating the choice
 * here confused users and created two sources of truth for what
 * `selected` / `profileId` mean at any given moment.
 *
 * What's left up here:
 *   * workspace crumb (workspace › sweep_id if a sweep is live)
 *   * command palette shortcut
 *   * "+ New scan" pill that opens the wizard
 *   * running-sweep indicator when a sweep is live
 *
 * If the user needs to change target / profile mid-session, they open the
 * wizard. It's one click, always the same flow, no config-drift.
 */
export function TopBar({
  running,
  onOpenWizard,
  sweepId,
  onOpenPalette,
}: {
  running: boolean;
  onOpenWizard: () => void;
  sweepId: string | null;
  onOpenPalette: () => void;
}) {
  return (
    <header className="shrink-0 border-b border-paper-300 bg-paper-50 px-4 py-2.5 flex items-center gap-3 text-sm">
      <div className="flex items-center gap-1.5 text-paper-600 mono text-xs min-w-0">
        <span className="text-paper-900 font-semibold uppercase tracking-[0.14em]">CMUL8</span>
        <IconChevron />
        <span className="text-paper-700">Spotlight</span>
        {sweepId && (
          <>
            <IconChevron />
            <span
              className="text-paper-500 truncate max-w-[220px]"
              title={sweepId}
            >
              {sweepId}
            </span>
          </>
        )}
        {running && (
          <span className="ml-2 text-2xs mono uppercase tracking-wider text-accent bg-accent-soft border border-accent/30 rounded-full px-2 py-0.5 animate-pulse">
            live
          </span>
        )}
      </div>

      <div className="ml-auto flex items-center gap-2">
        <button
          onClick={onOpenPalette}
          className="flex items-center gap-2 px-2 py-1 rounded border border-paper-300 bg-paper-100 hover:bg-white text-2xs mono text-paper-500 hover:text-paper-800 transition-colors"
          title="Command palette (⌘K)"
        >
          <span>Search…</span>
          <kbd className="border border-paper-300 rounded px-1 bg-white">⌘K</kbd>
        </button>

        <button
          onClick={onOpenWizard}
          disabled={running}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs uppercase tracking-wider mono transition-colors ${
            running
              ? "bg-paper-200 text-paper-500 cursor-not-allowed"
              : "bg-accent text-white hover:brightness-95"
          }`}
        >
          <IconPlay size={12} />
          {running ? "Sweeping…" : "New scan"}
        </button>
      </div>
    </header>
  );
}
