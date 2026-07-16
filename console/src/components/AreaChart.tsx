/**
 * Minimal SVG area chart — no dependency, no legend clutter.
 * Renders a smoothed area with a soft gradient fill and a subtle grid.
 * Points are the daily count of findings; x-axis is date labels.
 *
 * Aesthetic reference: `UI inspo/cleanui1.png` — big blue area chart hero
 * with faint horizontal grid and light month/day ticks.
 */
type Point = { label: string; value: number };

export function AreaChart({
  points,
  height = 220,
  color = "#5b8def",
  emptyMessage = "No activity yet",
}: {
  points: Point[];
  height?: number;
  color?: string;
  emptyMessage?: string;
}) {
  const padding = { top: 20, right: 24, bottom: 28, left: 40 };
  const width = 900; // viewBox width — SVG scales to container
  const chartW = width - padding.left - padding.right;
  const chartH = height - padding.top - padding.bottom;

  if (points.length === 0) {
    return (
      <div
        className="relative w-full flex items-center justify-center text-paper-500 text-sm italic"
        style={{ height }}
      >
        {emptyMessage}
      </div>
    );
  }

  const maxV = Math.max(1, ...points.map((p) => p.value));
  const stepX = points.length > 1 ? chartW / (points.length - 1) : chartW;

  const coords = points.map((p, i) => ({
    x: padding.left + i * stepX,
    y: padding.top + chartH - (p.value / maxV) * chartH,
    v: p.value,
    label: p.label,
  }));

  // Build smooth path via cubic bezier
  const linePath = coords
    .map((c, i, arr) => {
      if (i === 0) return `M ${c.x} ${c.y}`;
      const prev = arr[i - 1];
      const cx = (prev.x + c.x) / 2;
      return `C ${cx} ${prev.y} ${cx} ${c.y} ${c.x} ${c.y}`;
    })
    .join(" ");

  const areaPath =
    linePath +
    ` L ${coords[coords.length - 1].x} ${padding.top + chartH}` +
    ` L ${coords[0].x} ${padding.top + chartH} Z`;

  // Y-axis ticks: 4 lines
  const yTicks = 4;
  const ticks = Array.from({ length: yTicks + 1 }, (_, i) => {
    const v = Math.round((maxV / yTicks) * i);
    const y = padding.top + chartH - (v / maxV) * chartH;
    return { v, y };
  });

  // X-axis labels: show only ~6 evenly spaced
  const labelStride = Math.max(1, Math.ceil(points.length / 6));

  return (
    <div className="w-full">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="w-full h-auto"
        preserveAspectRatio="none"
      >
        <defs>
          <linearGradient id="areaGrad" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity="0.28" />
            <stop offset="100%" stopColor={color} stopOpacity="0" />
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
              x={padding.left - 8}
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

        {/* Area */}
        <path d={areaPath} fill="url(#areaGrad)" />
        {/* Line */}
        <path d={linePath} fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" />

        {/* Point dots */}
        {coords.map((c, i) => (
          <circle key={i} cx={c.x} cy={c.y} r="2.5" fill={color} />
        ))}

        {/* X labels */}
        {coords.map(
          (c, i) =>
            i % labelStride === 0 && (
              <text
                key={`xl-${i}`}
                x={c.x}
                y={height - 8}
                textAnchor="middle"
                fontSize="10"
                fill="#8a8578"
                fontFamily="JetBrains Mono, monospace"
              >
                {c.label}
              </text>
            )
        )}
      </svg>
    </div>
  );
}
