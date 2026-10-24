import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { usePref } from "../lib/prefs";

// First-login tour: a few tooltips pointing at the top-bar controls. Shown once per
// browser (the "tourDone" pref); Skip, Done or Escape dismiss it for good.
const STEPS = [
  { targets: ["nav", "menu"], title: "Navigation", text: "Every page lives here: logs, detections, incidents and recommendations." },
  { targets: ["palette"], title: "Search and commands", text: "Press Ctrl+K to jump to any page, incident or host." },
  { targets: ["bell"], title: "Notifications", text: "New high-risk incidents and pending approvals show up here." },
  { targets: ["live"], title: "Live status", text: "Green means the dashboard is receiving live updates from the server." },
];

// First target that is actually visible (the full nav is hidden on narrow screens).
function findTarget(names) {
  for (const name of names) {
    const el = document.querySelector(`[data-tour="${name}"]`);
    if (el && el.getClientRects().length > 0) return el;
  }
  return null;
}

export function FirstTour() {
  const [done, setDone] = usePref("tourDone", false);
  const [step, setStep] = useState(0);
  const [pos, setPos] = useState(null);
  const cardRef = useRef(null);
  const current = STEPS[step];

  // Place the card under the target, clamped inside the viewport.
  useLayoutEffect(() => {
    if (done) return;
    function place() {
      const el = findTarget(current.targets);
      if (!el) return setPos({ top: 80, left: 16 });
      const r = el.getBoundingClientRect();
      const width = 300;
      const left = Math.min(Math.max(16, r.left + r.width / 2 - width / 2), window.innerWidth - width - 16);
      setPos({ top: r.bottom + 12, left });
    }
    place();
    window.addEventListener("resize", place);
    return () => window.removeEventListener("resize", place);
  }, [done, current]);

  useEffect(() => {
    if (done) return;
    cardRef.current?.focus();
    const onKey = (e) => e.key === "Escape" && setDone(true);
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [done, step, setDone]);

  if (done || !pos) return null;
  const last = step === STEPS.length - 1;

  return (
    <div
      ref={cardRef}
      role="dialog"
      aria-labelledby="ir-tour-title"
      tabIndex={-1}
      className="ir-tour glass print:hidden"
      style={{ top: pos.top, left: pos.left }}
    >
      <p className="text-xs text-slate-400">
        Tip {step + 1} of {STEPS.length}
      </p>
      <h2 id="ir-tour-title" className="mt-1 text-sm">{current.title}</h2>
      <p className="mt-1 text-sm text-slate-300">{current.text}</p>
      <div className="mt-3 flex justify-end gap-2">
        <button type="button" onClick={() => setDone(true)} className="rounded-full border border-slate-700 px-3 py-1 text-xs text-slate-300">
          Skip tour
        </button>
        <button
          type="button"
          onClick={() => (last ? setDone(true) : setStep(step + 1))}
          className="rounded-full bg-sky-600 px-3 py-1 text-xs text-white"
        >
          {last ? "Done" : "Next"}
        </button>
      </div>
    </div>
  );
}
