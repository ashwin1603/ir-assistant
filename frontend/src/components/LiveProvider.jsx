import { createContext, useContext, useEffect, useMemo, useRef, useState } from "react";
import { connectLive } from "../lib/live";
import { usePref } from "../lib/prefs";

// App-wide live updates. While "live updates" is on, one stream per tab reports changes;
// `version` goes up whenever the counts change, and pages reload when it does. If the
// stream keeps failing, `version` goes up every 15s instead (the old polling).
const POLL_SECONDS = 15;
const LiveContext = createContext({ enabled: false, setEnabled: () => {}, status: "off", version: 0, signal: null });

export function LiveProvider({ children }) {
  const [enabled, setEnabled] = usePref("autoRefresh", true);
  const [status, setStatus] = useState("off");
  const [version, setVersion] = useState(0);
  const [signal, setSignal] = useState(null);
  const last = useRef(null);

  useEffect(() => {
    if (!enabled) {
      setStatus("off");
      return undefined;
    }
    return connectLive({
      onStatus: setStatus,
      onSignal: (s) => {
        const text = JSON.stringify(s);
        // The first signal of each connection only sets the baseline.
        if (last.current !== null && last.current !== text) setVersion((v) => v + 1);
        last.current = text;
        setSignal(s);
      },
    });
  }, [enabled]);

  useEffect(() => {
    if (!enabled || status !== "fallback") return undefined;
    const id = setInterval(() => setVersion((v) => v + 1), POLL_SECONDS * 1000);
    return () => clearInterval(id);
  }, [enabled, status]);

  const value = useMemo(() => ({ enabled, setEnabled, status, version, signal }), [enabled, setEnabled, status, version, signal]);
  return <LiveContext.Provider value={value}>{children}</LiveContext.Provider>;
}

export function useLive() {
  return useContext(LiveContext);
}
