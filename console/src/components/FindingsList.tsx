import { useEffect, useMemo, useState } from "react";

import type { Finding } from "../lib/api";
import { getFindingsFilterPref, setFindingsFilterPref } from "../lib/api";

const GROUPS = [
  { key: "critical", label: "Critical" },
  { key: "high", label: "High" },
  { key: "medium", label: "Medium" },
  { key: "low", label: "Low" },
] as const;

type SortKey = "severity" | "tier" | "class" | "id";
type TierFilter = "all" | "verified" | "high-confidence" | "needs-review" | "held";
type ReviewFilter = "all" | "unreviewed" | "accepted" | "false-positive" | "risk-accepted";

const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
const TIER_RANK: Record<string, number> = {
  verified: 4,
  "high-confidence": 3,
  "needs-review": 2,
  held: 1,
};

// C8 · Saved-filter presets are persisted per Profile in the server-side
// findings_filter_prefs table — replaces the earlier localStorage
// implementation which was per-browser and lost on incognito / cache clear.
// The default preset (severity + all + all) is applied until the server
// returns a stored value for the active profile.
type Preset = { sort: SortKey; tier: TierFilter; review: ReviewFilter };
const DEFAULT_PRESET: Preset = { sort: "severity", tier: "all", review: "all" };

export function FindingsList({
  findings,
  active,
  onSelect,
  target,
  profileId = "default",
}: {
  findings: Finding[];
  active: string | null;
  onSelect: (id: string) => void;
  target: string;
  profileId?: string;
}) {
  const [preset, setPreset] = useState<Preset>(DEFAULT_PRESET);

  // Hydrate the saved preset from the server whenever the active profile
  // changes. A fresh profile with no stored preset stays on DEFAULT.
  useEffect(() => {
    let cancelled = false;
    getFindingsFilterPref<Preset>(profileId).then((stored) => {
      if (cancelled) return;
      setPreset(stored ? { ...DEFAULT_PRESET, ...stored } : DEFAULT_PRESET);
    });
    return () => {
      cancelled = true;
    };
  }, [profileId]);

  // Persist writes server-side. Fire-and-forget — the UI updates
  // optimistically, the server catches up.
  useEffect(() => {
    setFindingsFilterPref(profileId, preset);
  }, [profileId, preset]);

  const filtered = useMemo(
    () => applyFilters(findings, preset),
    [findings, preset]
  );
  const sorted = useMemo(() => applySort(filtered, preset.sort), [filtered, preset.sort]);

  const showGrouped = preset.sort === "severity";
  const grouped = useMemo(() => groupBySeverity(sorted), [sorted]);

  return (
    <section className="w-[380px] shrink-0 bg-paper-100/60 border-r border-paper-300 flex flex-col">
      <div className="h-11 shrink-0 border-b border-paper-300 px-3 flex items-center gap-2">
        <span className="text-2xs uppercase tracking-wider text-paper-500 mono">Findings</span>
        <span className="text-2xs text-paper-500">·</span>
        <span className="text-xs mono text-paper-700 truncate">{target}</span>
        <span className="ml-auto text-2xs mono text-paper-500">
          {sorted.length} of {findings.length}
        </span>
      </div>

      <Toolbar preset={preset} onChange={setPreset} />

      <div className="overflow-y-auto flex-1">
        {findings.length === 0 && (
          <div className="p-6 text-paper-500 text-sm">
            <div className="mb-1">Nothing promoted yet.</div>
            <div className="text-xs">Start a Sweep to populate this pane.</div>
          </div>
        )}
        {findings.length > 0 && sorted.length === 0 && (
          <div className="p-6 text-paper-500 text-xs">
            No findings match the current filters.
          </div>
        )}
        {showGrouped
          ? GROUPS.map(({ key, label }) => {
              const bucket = grouped[key] ?? [];
              if (bucket.length === 0) return null;
              return (
                <div key={key}>
                  <SeverityHeader label={label} sev={key} count={bucket.length} />
                  <ul>
                    {bucket.map((f) => (
                      <FindingRow
                        key={f.id}
                        f={f}
                        active={active === f.id}
                        onSelect={onSelect}
                      />
                    ))}
                  </ul>
                </div>
              );
            })
          : (
            <ul>
              {sorted.map((f) => (
                <FindingRow key={f.id} f={f} active={active === f.id} onSelect={onSelect} />
              ))}
            </ul>
          )}
      </div>
    </section>
  );
}

function Toolbar({
  preset,
  onChange,
}: {
  preset: Preset;
  onChange: (p: Preset) => void;
}) {
  return (
    <div className="border-b border-paper-300 px-3 py-2 space-y-1.5 bg-paper-50">
      <div className="flex items-center gap-1.5 text-2xs">
        <span className="mono uppercase tracking-wider text-paper-500">Sort</span>
        {(["severity", "tier", "class", "id"] as SortKey[]).map((k) => (
          <button
            key={k}
            onClick={() => onChange({ ...preset, sort: k })}
            aria-pressed={preset.sort === k}
            className={`mono uppercase tracking-wider px-1.5 py-0.5 rounded border ${
              preset.sort === k
                ? "border-accent/40 bg-accent-soft text-accent"
                : "border-paper-300 text-paper-600 hover:bg-paper-100"
            }`}
          >
            {k}
          </button>
        ))}
      </div>
      <div className="flex items-center gap-1.5 text-2xs">
        <span className="mono uppercase tracking-wider text-paper-500">Tier</span>
        <FilterSelect
          value={preset.tier}
          onChange={(v) => onChange({ ...preset, tier: v as TierFilter })}
          options={[
            ["all", "any"],
            ["verified", "verified"],
            ["high-confidence", "high-conf"],
            ["needs-review", "review"],
            ["held", "held"],
          ]}
        />
        <span className="mono uppercase tracking-wider text-paper-500 ml-1">Review</span>
        <FilterSelect
          value={preset.review}
          onChange={(v) => onChange({ ...preset, review: v as ReviewFilter })}
          options={[
            ["all", "any"],
            ["unreviewed", "open"],
            ["accepted", "accepted"],
            ["false-positive", "false-pos"],
            ["risk-accepted", "risk-acc"],
          ]}
        />
        <button
          onClick={() => onChange(DEFAULT_PRESET)}
          className="ml-auto mono uppercase tracking-wider px-1.5 py-0.5 rounded text-paper-500 hover:text-paper-800"
          title="Reset to default preset"
        >
          reset
        </button>
      </div>
    </div>
  );
}

function FilterSelect({
  value,
  onChange,
  options,
}: {
  value: string;
  onChange: (v: string) => void;
  options: Array<[string, string]>;
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="mono uppercase tracking-wider px-1.5 py-0.5 rounded border border-paper-300 bg-white text-paper-700"
    >
      {options.map(([v, label]) => (
        <option key={v} value={v}>
          {label}
        </option>
      ))}
    </select>
  );
}

function applyFilters(findings: Finding[], preset: Preset): Finding[] {
  return findings.filter((f) => {
    if (preset.tier !== "all" && f.tier !== preset.tier) return false;
    const reviewState = f.review?.state ?? null;
    if (preset.review === "unreviewed" && reviewState !== null) return false;
    if (preset.review !== "all" && preset.review !== "unreviewed" && reviewState !== preset.review)
      return false;
    return true;
  });
}

function applySort(findings: Finding[], key: SortKey): Finding[] {
  const arr = [...findings];
  arr.sort((a, b) => {
    switch (key) {
      case "severity":
        return (SEV_RANK[b.severity] ?? 0) - (SEV_RANK[a.severity] ?? 0);
      case "tier":
        return (TIER_RANK[b.tier] ?? 0) - (TIER_RANK[a.tier] ?? 0);
      case "class":
        return a.class.localeCompare(b.class);
      case "id":
        return a.id.localeCompare(b.id);
    }
  });
  return arr;
}

function SeverityHeader({ label, sev, count }: { label: string; sev: string; count: number }) {
  const map: Record<string, { text: string; bg: string; ring: string }> = {
    critical: { text: "text-sev-critical", bg: "bg-sev-critical/8", ring: "ring-sev-critical/30" },
    high: { text: "text-sev-high", bg: "bg-sev-high/8", ring: "ring-sev-high/30" },
    medium: { text: "text-sev-medium", bg: "bg-sev-medium/8", ring: "ring-sev-medium/30" },
    low: { text: "text-sev-low", bg: "bg-sev-low/8", ring: "ring-sev-low/30" },
  };
  const c = map[sev] ?? map.low;
  return (
    <div className={`sticky top-0 z-10 flex items-center gap-2 px-3 py-2 ${c.bg} border-b border-paper-300`}>
      <span className={`h-1.5 w-1.5 rounded-full ${sev === "critical" ? "bg-sev-critical" : sev === "high" ? "bg-sev-high" : sev === "medium" ? "bg-sev-medium" : "bg-sev-low"}`} />
      <span className={`text-2xs uppercase tracking-wider font-semibold ${c.text} mono`}>{label}</span>
      <span className={`ml-auto text-2xs mono tabular-nums px-1.5 py-0.5 rounded-full bg-white ring-1 ${c.ring} ${c.text}`}>
        {count}
      </span>
    </div>
  );
}

function FindingRow({
  f,
  active,
  onSelect,
}: {
  f: Finding;
  active: boolean;
  onSelect: (id: string) => void;
}) {
  const sevBar =
    f.severity === "critical"
      ? "bg-sev-critical"
      : f.severity === "high"
      ? "bg-sev-high"
      : f.severity === "medium"
      ? "bg-sev-medium"
      : "bg-sev-low";
  return (
    <li className="relative">
      {/* Colored left rail = severity, thicker when active */}
      <span
        className={`absolute left-0 top-0 bottom-0 w-1 ${sevBar} ${
          active ? "opacity-100" : "opacity-60"
        }`}
        aria-hidden
      />
      <button
        onClick={() => onSelect(f.id)}
        className={`w-full text-left pl-4 pr-3 py-3 border-b border-paper-200 transition-colors ${
          active ? "bg-white shadow-card" : "hover:bg-paper-100"
        }`}
      >
        <div className="text-sm text-paper-900 leading-snug mb-1.5 line-clamp-2">
          {f.title}
        </div>
        <div className="flex items-center gap-1.5 mb-1.5">
          <TierBadge tier={f.tier} />
          <StateBadge state={f.state} />
          <span className="ml-auto text-2xs mono tabular-nums text-accent font-semibold">
            {(f.confidence * 100).toFixed(0)}%
          </span>
        </div>
        <div className="flex items-center gap-1.5 text-2xs mono text-paper-500">
          <span className="text-paper-700">{f.id}</span>
          <span className="text-paper-400">·</span>
          <span>{f.cwe}</span>
          <span className="text-paper-400">·</span>
          <span className="truncate">
            {short(f.location.file)}:{f.location.line}
          </span>
        </div>
      </button>
    </li>
  );
}

function TierBadge({ tier }: { tier: string }) {
  const map: Record<string, string> = {
    verified: "bg-accent-soft text-accent border-accent/30",
    "high-confidence": "bg-amber-50 text-sev-medium border-sev-medium/30",
    "needs-review": "bg-paper-200 text-paper-700 border-paper-400",
    held: "bg-paper-200 text-paper-500 border-paper-300",
  };
  return (
    <span className={`text-2xs mono uppercase px-1.5 py-0.5 rounded border ${map[tier] ?? ""}`}>
      {tier}
    </span>
  );
}

function StateBadge({ state }: { state: string }) {
  const good = state === "confirmed-fixed";
  return (
    <span
      className={`text-2xs mono uppercase px-1.5 py-0.5 rounded border ${
        good ? "border-accent/40 text-accent" : "border-paper-400 text-paper-600"
      }`}
    >
      {state}
    </span>
  );
}

function short(path: string) {
  const parts = path.split("/");
  return parts.slice(-2).join("/");
}

function dotColor(sev: string) {
  switch (sev) {
    case "critical":
      return "bg-sev-critical";
    case "high":
      return "bg-sev-high";
    case "medium":
      return "bg-sev-medium";
    default:
      return "bg-sev-low";
  }
}

function groupBySeverity(findings: Finding[]): Record<string, Finding[]> {
  const out: Record<string, Finding[]> = {};
  for (const f of findings) {
    (out[f.severity] ??= []).push(f);
  }
  return out;
}
