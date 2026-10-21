const LEVEL_STYLES = {
  Low: "bg-slate-800 text-slate-300",
  Medium: "bg-amber-900/60 text-amber-300",
  High: "bg-orange-900/60 text-orange-300",
  Critical: "bg-red-900/70 text-red-300",
};

export function RiskBadge({ level, score }) {
  return (
    <span
      className={`rounded px-2 py-0.5 text-xs font-medium ${
        LEVEL_STYLES[level] || "bg-slate-800 text-slate-300"
      }`}
    >
      {level} · {Math.round(score)}
    </span>
  );
}
