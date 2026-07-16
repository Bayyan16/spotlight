import {
  IconAttestation,
  IconExploitPath,
  IconFindings,
  IconHome,
  IconSettings,
  IconSweep,
  IconWarden,
} from "./Icons";
import { Cmul8Mark } from "./Cmul8Mark";

type NavKey = "sweeps" | "findings" | "paths" | "warden" | "attestations" | "home";

export function NavRail({
  active,
  onSelect,
  sweeping,
}: {
  active: NavKey;
  onSelect: (k: NavKey) => void;
  sweeping: boolean;
}) {
  return (
    <aside className="w-[212px] shrink-0 bg-paper-100 border-r border-paper-300 flex flex-col">
      {/* Brand block — CMUL8 wordmark with animated mark */}
      <div className="px-4 pt-4 pb-2 select-none">
        <a
          href="#"
          onClick={(e) => {
            e.preventDefault();
            onSelect("home");
          }}
          className="group flex items-center gap-2.5 outline-none"
          aria-label="CMUL8"
        >
          <Cmul8Mark active={sweeping} size={18} />
          <span
            className="mono font-semibold tracking-[0.18em] text-paper-900 text-sm uppercase transition-opacity group-hover:opacity-80"
            title="CMUL8"
          >
            CMUL8
          </span>
        </a>
      </div>

      <div className="px-4 pb-1 pt-2 text-2xs uppercase tracking-wider text-paper-500 mono">Workspace</div>
      <nav className="px-2 space-y-0.5 text-sm">
        <NavItem k="home" active={active} onSelect={onSelect} icon={<IconHome />} label="Board" shortcut="1" />
        <NavItem
          k="sweeps"
          active={active}
          onSelect={onSelect}
          icon={<IconSweep />}
          label="Live sweep"
          shortcut="2"
          badge={sweeping ? "live" : undefined}
        />
        <NavItem
          k="findings"
          active={active}
          onSelect={onSelect}
          icon={<IconFindings />}
          label="Findings"
          shortcut="3"
        />
        <NavItem k="paths" active={active} onSelect={onSelect} icon={<IconExploitPath />} label="Exploit paths" shortcut="4" locked />
        <NavItem k="warden" active={active} onSelect={onSelect} icon={<IconWarden />} label="Warden" shortcut="5" locked />
        <NavItem
          k="attestations"
          active={active}
          onSelect={onSelect}
          icon={<IconAttestation />}
          label="Attestations"
          shortcut="6"
          locked
        />
      </nav>

      {/* Bottom section: user + spotlight version */}
      <div className="mt-auto">
        <div className="px-3 pt-3 pb-2 border-t border-paper-300 flex items-center gap-2">
          <div className="h-7 w-7 rounded-full bg-gradient-to-br from-paper-400/50 to-paper-500/50 grid place-items-center text-paper-800 text-xs font-semibold ring-1 ring-paper-300">
            AK
          </div>
          <div className="text-xs min-w-0">
            <div className="text-paper-800 truncate">Abhijeet Katte</div>
            <div className="text-paper-500 text-2xs truncate">CMUL8 Workspace</div>
          </div>
          <button
            className="ml-auto text-paper-500 hover:text-paper-800 hover:rotate-45 transition-transform duration-300"
            aria-label="Settings"
          >
            <IconSettings />
          </button>
        </div>

        {/* Spotlight brand pinned at the very bottom */}
        <div className="px-4 py-2 border-t border-paper-300 flex items-center gap-1.5 bg-paper-100/60">
          <span
            className={`h-1.5 w-1.5 rounded-full ${
              sweeping ? "bg-accent animate-pulse" : "bg-accent/70"
            }`}
          />
          <span className="text-2xs uppercase tracking-wider text-paper-500 mono">
            Spotlight
          </span>
          <span className="ml-auto text-2xs mono text-paper-400 tabular-nums">v0.1</span>
        </div>
      </div>
    </aside>
  );
}

function NavItem({
  k,
  active,
  onSelect,
  icon,
  label,
  badge,
  shortcut,
  locked,
}: {
  k: NavKey;
  active: NavKey;
  onSelect: (k: NavKey) => void;
  icon: React.ReactNode;
  label: string;
  badge?: string;
  shortcut?: string;
  locked?: boolean;
}) {
  const isActive = k === active;
  return (
    <button
      onClick={() => onSelect(k)}
      className={`group relative w-full flex items-center gap-2 px-2 py-1.5 rounded text-left transition-all duration-150 outline-none focus-visible:ring-2 focus-visible:ring-accent/60 focus-visible:ring-offset-1 focus-visible:ring-offset-paper-100 ${
        isActive
          ? "bg-white text-paper-900 shadow-card"
          : "text-paper-700 hover:bg-paper-200/70 hover:translate-x-0.5"
      }`}
    >
      {/* Active-state accent bar on the left */}
      <span
        className={`absolute left-0 top-1/2 -translate-y-1/2 w-[3px] rounded-r-full transition-all duration-200 ${
          isActive ? "h-5 bg-accent" : "h-0 bg-transparent"
        }`}
        aria-hidden
      />
      <span
        className={`transition-colors ${
          isActive ? "text-paper-900" : locked ? "text-paper-400" : "text-paper-500 group-hover:text-paper-800"
        }`}
      >
        {icon}
      </span>
      <span className={`truncate ${locked ? "text-paper-400" : ""}`}>{label}</span>
      {badge && (
        <span className="ml-auto text-2xs mono uppercase text-accent bg-accent-soft px-1.5 py-0.5 rounded ring-1 ring-accent/20 animate-pulse">
          {badge}
        </span>
      )}
      {!badge && locked && (
        <span className="ml-auto text-2xs mono uppercase text-paper-400 tracking-wider">soon</span>
      )}
      {!badge && !locked && shortcut && (
        <kbd className="ml-auto opacity-0 group-hover:opacity-100 transition-opacity text-2xs mono text-paper-400 border border-paper-300 rounded px-1 bg-paper-50">
          {shortcut}
        </kbd>
      )}
    </button>
  );
}

export type { NavKey };
