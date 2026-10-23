import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { cached } from "../lib/api";
import { usePref } from "../lib/prefs";

// Demo mode (a per-browser preference, toggled in My account or the command palette):
// a "Demo / simulated data" ribbon, collector controls hidden, and a guided path
// Dashboard -> Incident -> Investigate -> Report as a small checklist.
// Display only: it changes nothing on the server.

export function useDemoMode() {
  return usePref("demoMode", false);
}

export function DemoRibbon() {
  const [demo] = useDemoMode();
  if (!demo) return null;
  return (
    <div className="ir-demo-ribbon print:hidden" role="status">
      Demo / simulated data
    </div>
  );
}

const STEPS = [
  { key: "dashboard", label: "Look at the Dashboard", match: (p) => p === "/dashboard" },
  { key: "incident", label: "Open the top incident", match: (p) => /^\/incidents\/[^/]+$/.test(p) },
  { key: "investigate", label: "Investigate it", match: (p, h) => /^\/incidents\/[^/]+$/.test(p) && h === "#investigate" },
  { key: "report", label: "Open the report", match: (p) => /^\/incidents\/[^/]+\/report$/.test(p) },
];

export function DemoChecklist() {
  const [demo] = useDemoMode();
  const [done, setDone] = usePref("demo.done", []);
  const [incidentId, setIncidentId] = usePref("demo.incident", null);
  const [collapsed, setCollapsed] = useState(false);
  const { pathname, hash } = useLocation();

  // Tick off steps as the presenter visits the pages.
  useEffect(() => {
    if (!demo) return;
    const visited = STEPS.filter((s) => s.match(pathname, hash)).map((s) => s.key);
    if (visited.some((k) => !done.includes(k))) setDone([...new Set([...done, ...visited])]);
    const id = pathname.match(/^\/incidents\/([^/]+)/)?.[1];
    if (id && id !== incidentId) setIncidentId(id);
  }, [demo, pathname, hash, done, setDone, incidentId, setIncidentId]);

  if (!demo) return null;

  // Prefer the incident already opened in this demo, else the highest-risk one loaded so far.
  const top = (cached("/incidents") || []).reduce((best, i) => (!best || i.risk_score > best.risk_score ? i : best), null);
  const id = incidentId || top?.id;
  const links = {
    dashboard: "/dashboard",
    incident: id ? `/incidents/${id}` : "/incidents",
    investigate: id ? `/incidents/${id}#investigate` : "/incidents",
    report: id ? `/incidents/${id}/report` : "/incidents",
  };
  const count = STEPS.filter((s) => done.includes(s.key)).length;

  return (
    <aside className="ir-demo-panel print:hidden" aria-label="Guided demo">
      <div className="flex items-center justify-between gap-2">
        <button type="button" className="text-left text-xs font-semibold uppercase tracking-wide text-slate-300"
          onClick={() => setCollapsed((c) => !c)} aria-expanded={!collapsed}>
          Guided demo · {count}/{STEPS.length} {collapsed ? "▸" : "▾"}
        </button>
        {!collapsed && (
          <button type="button" className="text-xs text-sky-400 hover:text-sky-300" onClick={() => { setDone([]); setIncidentId(null); }}>
            Reset
          </button>
        )}
      </div>
      {!collapsed && (
        <ol className="mt-2 space-y-1">
          {STEPS.map((s, i) => {
            const isDone = done.includes(s.key);
            return (
              <li key={s.key}>
                <Link to={links[s.key]} className={`ir-demo-step${isDone ? " done" : ""}`}>
                  <span className="ir-demo-check" aria-hidden="true">{isDone ? "✓" : i + 1}</span>
                  <span>{s.label}</span>
                  <span className="sr-only">{isDone ? "(done)" : "(to do)"}</span>
                </Link>
              </li>
            );
          })}
        </ol>
      )}
    </aside>
  );
}
