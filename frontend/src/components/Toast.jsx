import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";

// Small toast system: glass cards bottom-right, auto-dismiss after 4s, announced via aria-live.
// Usage: const toast = useToast(); toast.success("Saved");
const ToastContext = createContext(null);
const DURATION_MS = 4000;
const ICONS = { success: "✓", error: "!", info: "i" };

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);
  const nextId = useRef(0);

  const dismiss = useCallback((id) => setToasts((ts) => ts.filter((t) => t.id !== id)), []);

  const show = useCallback((kind, text) => {
    const id = ++nextId.current;
    setToasts((ts) => [...ts.slice(-3), { id, kind, text }]); // keep at most 4 on screen
    setTimeout(() => dismiss(id), DURATION_MS);
  }, [dismiss]);

  const api = useMemo(() => ({
    success: (text) => show("success", text),
    error: (text) => show("error", text),
    info: (text) => show("info", text),
  }), [show]);

  return (
    <ToastContext.Provider value={api}>
      {children}
      <div className="ir-toasts print:hidden" role="status" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`ir-toast ${t.kind}`}>
            <span className="ir-toast-icon" aria-hidden="true">{ICONS[t.kind]}</span>
            <span className="min-w-0 flex-1">{t.text}</span>
            <button type="button" onClick={() => dismiss(t.id)} aria-label="Dismiss" className="ir-toast-close">✕</button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  return useContext(ToastContext);
}

// Copies text and confirms with a toast.
export function useCopy() {
  const toast = useToast();
  return useCallback(async (text, label = "Copied to clipboard") => {
    try {
      await navigator.clipboard.writeText(text);
      toast.success(label);
    } catch {
      toast.error("Copy failed");
    }
  }, [toast]);
}

// Sets the browser tab title, e.g. "Detections · IR Assistant".
export function useDocumentTitle(title) {
  useEffect(() => {
    document.title = title ? `${title} · IR Assistant` : "IR Assistant";
  }, [title]);
}
