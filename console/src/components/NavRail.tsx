import {
  IconAttestation,
  IconExploitPath,
  IconFindings,
  IconHome,
  IconSettings,
  IconSweep,
  IconWarden,
} from "./Icons";

type NavKey = "sweeps" | "findings" | "paths" | "warden" | "attestations" | "home";

export function NavRail({
  active,
  onSelect,
}: {
  active: NavKey;
  onSelect: (k: NavKey) => void;
}) {
  return (
    <aside className="w-[200px] shrink-0 bg-paper-100 border-r border-paper-300 flex flex-col">
      <div className="px-4 pt-4 pb-2 flex items-center gap-2">
        <span className="h-2.5 w-2.5 rounded-full bg-accent inline-block" />
        <span className="text-paper-900 font-semibold tracking-tight">Spotlight</span>
        <span className="text-paper-500 text-2xs mono ml-auto">v0.1</span>
      </div>
      <div className="px-2 py-2 text-2xs uppercase tracking-wider text-paper-500">Workspace</div>
      <nav className="px-2 space-y-0.5 text-sm">
        <NavItem k="home" active={active} onSelect={onSelect} icon={<IconHome />} label="Dashboard" />
        <NavItem k="sweeps" active={active} onSelect={onSelect} icon={<IconSweep />} label="Sweeps" badge="live" />
        <NavItem
          k="findings"
          active={active}
          onSelect={onSelect}
          icon={<IconFindings />}
          label="Findings"
        />
        <NavItem k="paths" active={active} onSelect={onSelect} icon={<IconExploitPath />} label="Exploit Paths" />
        <NavItem k="warden" active={active} onSelect={onSelect} icon={<IconWarden />} label="Warden" />
        <NavItem
          k="attestations"
          active={active}
          onSelect={onSelect}
          icon={<IconAttestation />}
          label="Attestations"
        />
      </nav>

      <div className="mt-auto p-3 border-t border-paper-300 flex items-center gap-2">
        <div className="h-7 w-7 rounded-full bg-paper-400/40 grid place-items-center text-paper-800 text-xs font-semibold">
          AK
        </div>
        <div className="text-xs">
          <div className="text-paper-800">Abhijeet Katte</div>
          <div className="text-paper-500 text-2xs">CMUL8 Workspace</div>
        </div>
        <button className="ml-auto text-paper-500 hover:text-paper-800">
          <IconSettings />
        </button>
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
}: {
  k: NavKey;
  active: NavKey;
  onSelect: (k: NavKey) => void;
  icon: React.ReactNode;
  label: string;
  badge?: string;
}) {
  const isActive = k === active;
  return (
    <button
      onClick={() => onSelect(k)}
      className={`w-full flex items-center gap-2 px-2 py-1.5 rounded text-left transition-colors ${
        isActive
          ? "bg-paper-300/60 text-paper-900"
          : "text-paper-700 hover:bg-paper-200"
      }`}
    >
      <span className={isActive ? "text-paper-900" : "text-paper-500"}>{icon}</span>
      <span>{label}</span>
      {badge && (
        <span className="ml-auto text-2xs mono uppercase text-accent bg-accent-soft px-1.5 py-0.5 rounded">
          {badge}
        </span>
      )}
    </button>
  );
}

export type { NavKey };
