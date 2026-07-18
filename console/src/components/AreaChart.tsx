import { useMemo, useState } from "react";

/**
 * Activity chart — bar-per-bucket rendering with severity breakdown +
 * hover tooltip. Replaces the smoothed area (which flat-lined into a
 * plateau for sparse workspaces and hid the metadata the user was
 * asking for).
 *
 * Point shape can carry severity counts. When only `value` is set the
 * chart falls back to a single-colour bar per bucket. When any of
 * `critical/high/medium/low` is populated, bars stack the segments so
 * you see "3 critical, 12 high, …" at a glance without a legend.
 */
export type Point = {
  label: string;
  value: number;
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
  sweeps?: number;
  live?: boolean;
};

export function AreaChart({
  points,
  height = 240,
  color = "#5b8def",
  emptyMessage = "No activity yet",
}: {
  points: Point[];
  height?: number;
  color?: string;
  emptyMessage?: string;
}) {
  const padding = { top: 24, right: 24, bottom: 34, left: 44 };
  const width = 960;
  const chartW = width - padding.left - padding.right;
  const chartH = height - padding.top - padding.bottom;
  const [hover, setHover] = useState<number | null>(null);

  const hasSeverityBreakdown = useMemo(
    () =>
      points.some(
        (p) =>
          (p.critical ?? 0) +
            (p.high ?? 0) +
            (p.medium ?? 0) +
            (p.low ?? 0) >
          0
      ),
    [points]
  );

  const maxV = Math.max(1, ...points.map((p) => p.value));

  if (points.length === 0 || maxV === 0) {
    return (
      <div
        className="relative w-full grid place-items-center rounded-md border border-dashed border-paper-300 bg-paper-50/50"
        style={{ height }}
      >
        <div className="text-center max-w-md px-6">
          <div className="text-sm text-paper-800 font-medium mb-1">
            {emptyMessage}
          </div>
          <div className="text-2xs text-paper-500 leading-relaxed">
            Bars appear per day (or per hour in Hour mode). Each bar shows the
            findings landed in that bucket — critical, high, medium, low
            stacked. Hover a bar for the detail.
          </div>
        </div>
      </div>
    );
  }

  // Bar geometry — leave a little gap between bars.
  const barGap = points.length > 60 ? 1 : points.length > 30 ? 2 : 4;
  const rawBarW = chartW / points.length;
  const barW = Math.max(2, rawBarW - barGap);

  const yFor = (v: number) => padding.top + chartH - (v / maxV) * chartH;

  // Y-axis ticks: 4 lines
  const yTicks = 4;
  const ticks = Array.from({ length: yTicks + 1 }, (_, i) => {
    const v = Math.round((maxV / yTicks) * i);
    return { v, y: yFor(v) };
  });

  // X-axis labels: show only ~7 evenly spaced
  const labelStride = Math.max(1, Math.ceil(points.length / 7));

  // Stacked-severity palette (matches the CSS sev-* colours used elsewhere).
  const SEV_COLORS = {
    critical: "#d94a3a",
    high: "#e08b3a",
    medium: "#c99a1e",
    low: "#8ab064",
  } as const;

  return (
    <div className="w-full relative">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="w-full h-auto"
        preserveAspectRatio="none"
        onMouseLeave={() => setHover(null)}
      >
        <defs>
          <linearGradient id="areaGrad" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity="0.9" />
            <stop offset="100%" stopColor={color} stopOpacity="0.55" />
          </linearGradient>
        </defs>

        {/* Grid */}
        {ticks.map((t, i) => (
          <g key={i}>
            <line
              x1={padding.left}
              x2={width - padding.right}
              y1={t.y}
              y2={t.y}
              stroke="#e6e2d9"
              strokeWidth="1"
              strokeDasharray={i === 0 ? "" : "2 3"}
            />
            <text
              x={padding.left - 10}
              y={t.y + 3}
              textAnchor="end"
              fontSize="10"
              fill="#8a8578"
              fontFamily="JetBrains Mono, monospace"
            >
              {t.v}
            </text>
          </g>
        ))}

        {/* Bars — stacked severity if available, else single-colour */}
        {points.map((p, i) => {
          const x = padding.left + i * rawBarW + (rawBarW - barW) / 2;
          const totalV = p.value;
          const isHover = hover === i;
          const isLast = i === points.length - 1;
          const baselineY = padding.top + chartH;

          if (hasSeverityBreakdown) {
            const segments: Array<[keyof typeof SEV_COLORS, number]> = [
              ["low", p.low ?? 0],
              ["medium", p.medium ?? 0],
              ["high", p.high ?? 0],
              ["critical", p.critical ?? 0],
            ];
            let stackY = baselineY;
            return (
              <g
                key={i}
                onMouseEnter={() => setHover(i)}
                style={{ cursor: totalV > 0 ? "pointer" : "default" }}
              >
                {segments.map(([kind, v]) => {
                  const h = (v / maxV) * chartH;
                  if (h <= 0) return null;
                  stackY -= h;
                  return (
                    <rect
                      key={kind}
                      x={x}
                      y={stackY}
                      width={barW}
                      height={h}
                      fill={SEV_COLORS[kind]}
                      opacity={isHover ? 1 : 0.9}
                      rx={0}
                    />
                  );
                })}
                {isLast && p.live && (
                  <circle
                    cx={x + barW / 2}
                    cy={padding.top - 6}
                    r={4}
                    fill="#3c8f5c"
                    className="animate-pulse"
                  />
                )}
              </g>
            );
          }

          const h = (totalV / maxV) * chartH;
          return (
            <g
              key={i}
              onMouseEnter={() => setHover(i)}
              style={{ cursor: totalV > 0 ? "pointer" : "default" }}
            >
              <rect
                x={x}
                y={baselineY - h}
                width={barW}
                height={h}
                fill="url(#areaGrad)"
                opacity={isHover ? 1 : 0.85}
              />
              {isLast && p.live && (
                <circle
                  cx={x + barW / 2}
                  cy={padding.top - 6}
                  r={4}
                  fill="#3c8f5c"
                  className="animate-pulse"
                />
              )}
            </g>
          );
        })}

        {/* X labels */}
        {points.map(
          (p, i) =>
            i % labelStride === 0 && (
              <text
                key={`xl-${i}`}
                x={padding.left + i * rawBarW + rawBarW / 2}
                y={height - 10}
                textAnchor="middle"
                fontSize="10"
                fill="#8a8578"
                fontFamily="JetBrains Mono, monospace"
              >
                {p.label}
              </text>
            )
        )}
      </svg>

      {/* Hover tooltip */}
      {hover !== null && points[hover] && (
        <ChartTooltip
          point={points[hover]}
          hasSeverity={hasSeverityBreakdown}
          x={((hover + 0.5) / points.length) * 100}
        />
      )}
    </div>
  );
}

function ChartTooltip({
  point,
  hasSeverity,
  x,
}: {
  point: Point;
  hasSeverity: boolean;
  x: number;
}) {
  return (
    <div
      className="absolute z-10 pointer-events-none top-2 -translate-x-1/2 bg-paper-900/95 text-white text-2xs mono rounded-md px-2.5 py-1.5 shadow-lg"
      style={{ left: `${x}%` }}
    >
      <div className="font-semibold text-white/90 mb-0.5">{point.label}</div>
      <div className="flex items-center gap-2">
        <span className="tabular-nums">{point.value} findings</span>
        {point.sweeps !== undefined && (
          <>
            <span className="text-white/50">·</span>
            <span className="tabular-nums">
              {point.sweeps} sweep{point.sweeps === 1 ? "" : "s"}
            </span>
          </>
        )}
      </div>
      {hasSeverity && (
        <div className="mt-1 flex items-center gap-2 text-[10px]">
          {(point.critical ?? 0) > 0 && (
            <span className="text-sev-critical">
              ● <span className="tabular-nums">{point.critical}</span> crit
            </span>
          )}
          {(point.high ?? 0) > 0 && (
            <span className="text-sev-high">
              ● <span className="tabular-nums">{point.high}</span> high
            </span>
          )}
          {(point.medium ?? 0) > 0 && (
            <span className="text-sev-medium">
              ● <span className="tabular-nums">{point.medium}</span> med
            </span>
          )}
          {(point.low ?? 0) > 0 && (
            <span className="text-sev-low">
              ● <span className="tabular-nums">{point.low}</span> low
            </span>
          )}
        </div>
      )}
    </div>
  );
}
