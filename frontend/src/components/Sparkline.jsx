// Tiny trend line for stat cards. `values` is a list of numbers (oldest first); the
// tooltip (data-tip) states what the line shows. Decorative for screen readers.
export function Sparkline({ values, tip, color = "var(--ir-bar-to)" }) {
  if (!values || values.length < 2) return <div className="ir-spark" aria-hidden="true" />;
  const w = 100;
  const h = 28;
  const max = Math.max(...values);
  const min = Math.min(...values);
  const span = max - min || 1;
  const points = values.map((v, i) => [(i / (values.length - 1)) * w, h - 2 - ((v - min) / span) * (h - 4)]);
  const line = points.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" ");
  return (
    <div className="ir-spark" data-tip={tip}>
      <svg viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" aria-hidden="true" focusable="false">
        <polygon points={`0,${h} ${line} ${w},${h}`} fill={color} opacity="0.12" />
        <polyline points={line} fill="none" stroke={color} strokeWidth="1.6" vectorEffect="non-scaling-stroke" strokeLinejoin="round" />
      </svg>
    </div>
  );
}
