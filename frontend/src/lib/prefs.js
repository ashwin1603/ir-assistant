import { useCallback, useSyncExternalStore } from "react";

// Per-browser UI preferences (auto-refresh, demo mode, table layouts, saved filters...).
// Kept in localStorage as conveniences only: nothing security-relevant lives here, and the
// app works the same if storage is blocked (every access is wrapped in try/catch).
const PREFIX = "ir.";
const listeners = new Set();
const memory = new Map(); // fallback when localStorage is unavailable

function read(key, fallback) {
  try {
    const raw = localStorage.getItem(PREFIX + key);
    if (raw !== null) return JSON.parse(raw);
  } catch {
    if (memory.has(key)) return memory.get(key);
  }
  return memory.has(key) ? memory.get(key) : fallback;
}

// Snapshots must be stable between renders, so values are cached by their JSON text.
const snapshots = new Map();
function snapshot(key, fallback) {
  const value = read(key, fallback);
  const text = JSON.stringify(value);
  const cached = snapshots.get(key);
  if (cached && cached.text === text) return cached.value;
  snapshots.set(key, { text, value });
  return value;
}

export function setPref(key, value) {
  memory.set(key, value);
  try {
    localStorage.setItem(PREFIX + key, JSON.stringify(value));
  } catch {
    // storage blocked: the in-memory copy still works for this tab
  }
  listeners.forEach((fn) => fn());
}

export function getPref(key, fallback) {
  return read(key, fallback);
}

function subscribe(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

// const [value, setValue] = usePref("autoRefresh", false);
export function usePref(key, fallback) {
  const value = useSyncExternalStore(subscribe, () => snapshot(key, fallback));
  const set = useCallback(
    (next) => setPref(key, typeof next === "function" ? next(read(key, fallback)) : next),
    [key, fallback],
  );
  return [value, set];
}
