import { useEffect, useState } from "react";
import { Switch } from "./Switch";
import { usePref } from "../lib/prefs";

// Returns [enabled, setEnabled, tick]; tick increments every `seconds` while enabled,
// so pages can add it to a useEffect dependency list to reload their data.
// The on/off choice is one app-wide preference (the command palette can toggle it).
export function useAutoRefresh(seconds = 15) {
  const [enabled, setEnabled] = usePref("autoRefresh", false);
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
    <div className="flex items-center gap-2 text-sm text-slate-400">
      <Switch checked={enabled} onChange={onChange}>
        Auto-refresh ({seconds}s)
      </Switch>
      <span className={`live-dot${enabled ? "" : " off"}`} aria-hidden="true" />
    </div>
  );
}
