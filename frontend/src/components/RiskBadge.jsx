import { SevIcon, sevClass } from "./Severity";

export function RiskBadge({ level, score }) {
  return (
    <span className={`badge rounded px-2 py-0.5 text-xs font-medium ${sevClass(level)}`}>
      <SevIcon level={level} />
      {level} · {Math.round(score)}
    </span>
  );
}
