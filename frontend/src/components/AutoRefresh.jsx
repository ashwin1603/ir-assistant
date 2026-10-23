import { useEffect, useState } from "react";

// Returns [enabled, setEnabled, tick]; tick increments every `seconds` while enabled,
// so pages can add it to a useEffect dependency list to reload their data.
export function useAutoRefresh(seconds = 15) {
  const [enabled, setEnabled] = useState(false);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    if (!enabled) return undefined;
    const id = setInterval(() => setTick((t) => t + 1), seconds * 1000);
    return () => clearInterval(id);
  }, [enabled, seconds]);
  return [enabled, setEnabled, tick];
}

export function AutoRefreshToggle({ enabled, onChange, seconds = 15 }) {
  return (
    <label className="flex items-center gap-2 text-sm text-slate-400">
      <input type="checkbox" checked={enabled} onChange={(e) => onChange(e.target.checked)} />
      <span className={`live-dot${enabled ? "" : " off"}`} aria-hidden="true" />
      Auto-refresh ({seconds}s)
    </label>
  );
}
