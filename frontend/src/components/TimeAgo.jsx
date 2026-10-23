import { useSyncExternalStore } from "react";

// "3 min ago" with the exact local time on hover (data-tip, see TooltipLayer).
// One shared 30s ticker re-renders every TimeAgo on screen.
const listeners = new Set();
let now = Date.now();
setInterval(() => {
  now = Date.now();
  listeners.forEach((fn) => fn());
}, 30_000);

function subscribe(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

const UNITS = [
  [60, "s", 1],
  [3600, "min", 60],
  [86400, "h", 3600],
  [86400 * 30, "d", 86400],
  [86400 * 365, "mo", 86400 * 30],
  [Infinity, "y", 86400 * 365],
];

export function relativeTime(ts, at = Date.now()) {
  const seconds = Math.round((at - new Date(ts).getTime()) / 1000);
  const abs = Math.abs(seconds);
  if (abs < 10) return "just now";
  const [, unit, size] = UNITS.find(([limit]) => abs < limit);
  const n = Math.floor(abs / size);
  return seconds >= 0 ? `${n} ${unit} ago` : `in ${n} ${unit}`;
}

export function TimeAgo({ ts, className = "" }) {
  const at = useSyncExternalStore(subscribe, () => now);
  if (!ts) return <span className={className}>—</span>;
  const exact = new Date(ts).toLocaleString();
  return (
    <time dateTime={new Date(ts).toISOString()} data-tip={exact} className={`whitespace-nowrap ${className}`}>
      {/* Never "in 20 s" for an event newer than the last tick. */}
      {relativeTime(ts, Math.max(at, new Date(ts).getTime()))}
    </time>
  );
}
