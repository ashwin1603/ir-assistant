import { Switch } from "./Switch";
import { useLive } from "./LiveProvider";

const STATUS_TEXT = {
  live: "Live",
  connecting: "Connecting…",
  reconnecting: "Reconnecting…",
  fallback: "Polling every 15s",
  off: "Off",
};

// Returns [enabled, setEnabled, tick]; tick changes whenever live data changed (stream
// signal, or the 15s polling fallback), so pages add it to a useEffect dependency list to
// reload in place. The on/off choice is one app-wide preference (palette can toggle it).
export function useAutoRefresh() {
  const { enabled, setEnabled, version } = useLive();
  return [enabled, setEnabled, version];
}

export function AutoRefreshToggle({ enabled, onChange }) {
  const { status } = useLive();
  return (
    <div className="flex items-center gap-2 text-sm text-slate-400">
      <Switch checked={enabled} onChange={onChange}>
        Live updates <span className="text-xs text-slate-400">({STATUS_TEXT[status]})</span>
      </Switch>
      <span className={`live-dot ${liveDotClass(status)}`} aria-hidden="true" />
    </div>
  );
}

// live: pulsing green; polling or reconnecting: amber; off: grey.
export function liveDotClass(status) {
  if (status === "live") return "";
  if (status === "off") return "off";
  return "warn";
}

export { STATUS_TEXT };
