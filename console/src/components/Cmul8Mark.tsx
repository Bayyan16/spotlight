/**
 * CMUL8 animated brand mark — two orbiting rings intersected by a scan line.
 * When `active`, the scan line sweeps continuously. When idle, it holds still
 * with just the rings.
 *
 * This is the CMUL8 identity used across all micro-interactions:
 *  - nav rail brand (idle -> sweeping animation)
 *  - loading spinner (spinning mode)
 *  - loading/attestation stamp (larger stroke)
 */
type Props = { active?: boolean; size?: number; className?: string; mode?: "static" | "spin" };

export function Cmul8Mark({ active = false, size = 20, className = "", mode = "static" }: Props) {
  const strokeColor = "#1a1a17";
  return (
    <svg
      width={size}
      height={(size * 16) / 28}
      viewBox="0 0 28 16"
      xmlns="http://www.w3.org/2000/svg"
      className={`${className} ${mode === "spin" ? "cmul8-spin" : ""}`}
      aria-hidden
    >
      {/* Left ring */}
      <circle cx="11.5" cy="8" r="4.5" fill="none" stroke={strokeColor} strokeWidth="1.5" />
      {/* Right ring */}
      <circle cx="16.5" cy="8" r="4.5" fill="none" stroke={strokeColor} strokeWidth="1.5" />

      {/* Scan line — dashed */}
      <line
        x1="1"
        y1="8"
        x2="27"
        y2="8"
        stroke={strokeColor}
        strokeWidth="1"
        strokeDasharray="2 2"
        className={active ? "cmul8-scan" : ""}
      />
      {/* Arrow head */}
      <polygon points="25,6 27,8 25,10" fill={strokeColor} />

      {/* Accent dot that pulses when active — the "beam" tracking across */}
      {active && (
        <circle cx="1" cy="8" r="1.2" fill="#3c8f5c" className="cmul8-beam" />
      )}

      <style>{`
        .cmul8-spin { animation: cmul8_spin 2.2s linear infinite; transform-origin: 14px 8px; }
        @keyframes cmul8_spin {
          from { transform: rotate(0deg); }
          to   { transform: rotate(360deg); }
        }
        .cmul8-scan { animation: cmul8_scan 1.6s ease-in-out infinite; }
        @keyframes cmul8_scan {
          0%, 100% { stroke-dashoffset: 0; opacity: 0.6; }
          50%      { stroke-dashoffset: 8; opacity: 1; }
        }
        .cmul8-beam { animation: cmul8_beam 1.6s ease-in-out infinite; }
        @keyframes cmul8_beam {
          0%   { cx: 1;  opacity: 0; }
          20%  { opacity: 1; }
          80%  { opacity: 1; }
          100% { cx: 27; opacity: 0; }
        }
      `}</style>
    </svg>
  );
}
