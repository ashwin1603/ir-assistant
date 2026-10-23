import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { get } from "../lib/api";
import { usePref } from "../lib/prefs";
import { RiskBadge } from "./RiskBadge";
import { TimeAgo } from "./TimeAgo";

const SHOWN = 15;
const READ_KEEP = 500; // remembered read ids (localStorage), oldest dropped first

// Bell in the top bar: Critical/High detections and (for analysts/admins) actions waiting
// for approval. Read state is per browser. `signal` changes when the live stream reports
// new data; the bell then reloads.
export function NotificationBell({ signal }) {
  const { can } = useAuth();
  const canDecide = can("decide_actions");
  const [items, setItems] = useState([]);
  const [read, setRead] = usePref("notifications.read", []);
  const [open, setOpen] = useState(false);
  const box = useRef(null);

  useEffect(() => {
    let cancelled = false;
    Promise.allSettled([get("/detections"), canDecide ? get("/actions") : Promise.resolve([])]).then(([dets, acts]) => {
      if (cancelled) return;
      const out = [];
      for (const d of dets.status === "fulfilled" ? dets.value : []) {
        if (d.risk_level !== "Critical" && d.risk_level !== "High") continue;
        out.push({
          id: `det:${d.id}`,
          kind: "detection",
          title: d.rule_name,
          sub: d.host,
          level: d.risk_level,
          score: d.risk_score,
          at: d.last_seen,
          to: d.incident_id ? `/incidents/${d.incident_id}` : "/detections",
        });
      }
      for (const a of acts.status === "fulfilled" ? acts.value : []) {
        if (a.status !== "pending") continue;
        out.push({ id: `act:${a.id}`, kind: "approval", title: a.action_text, sub: `Approval needed · ${a.incident_host}`, at: a.created_at, to: "/recommendations" });
      }
      out.sort((x, y) => new Date(y.at) - new Date(x.at));
      setItems(out);
    });
    return () => {
      cancelled = true;
    };
  }, [signal, canDecide]);

  useEffect(() => {
    if (!open) return undefined;
    const onDown = (e) => !box.current?.contains(e.target) && setOpen(false);
    const onKey = (e) => e.key === "Escape" && setOpen(false);
    document.addEventListener("pointerdown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("pointerdown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const unread = items.filter((i) => !read.includes(i.id));
  const markRead = (ids) => setRead([...read, ...ids.filter((id) => !read.includes(id))].slice(-READ_KEEP));

  return (
    <div ref={box} className="relative">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        aria-label={`Notifications, ${unread.length} unread`}
        className="ir-icon-btn relative"
      >
        <svg viewBox="0 0 20 20" width="15" height="15" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round">
          <path d="M5 8a5 5 0 0 1 10 0v3.5l1.5 2.5h-13L5 11.5z" />
          <path d="M8.2 16.5a2 2 0 0 0 3.6 0" />
        </svg>
        {unread.length > 0 && <span className="ir-badge-count">{unread.length > 99 ? "99+" : unread.length}</span>}
      </button>
      {open && (
        <div className="ir-popover ir-notify" role="region" aria-label="Notifications">
          <div className="mb-1 flex items-center justify-between px-2 py-1">
            <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">Notifications</span>
            {unread.length > 0 && (
              <button type="button" className="text-xs text-sky-400 hover:text-sky-300" onClick={() => markRead(items.map((i) => i.id))}>
                Mark all read
              </button>
            )}
          </div>
          {items.length === 0 && <p className="px-2 py-4 text-center text-sm text-slate-400">All quiet. No high-risk detections{canDecide ? " or pending approvals" : ""}.</p>}
          <ul className="space-y-0.5">
            {items.slice(0, SHOWN).map((n) => {
              const isUnread = !read.includes(n.id);
              return (
                <li key={n.id}>
                  <Link to={n.to} onClick={() => { markRead([n.id]); setOpen(false); }} className={`ir-notify-item${isUnread ? " unread" : ""}`}>
                    <span className="flex min-w-0 items-center gap-2">
                      {n.kind === "detection" ? <RiskBadge level={n.level} score={n.score} /> : <span className="badge rounded bg-amber-900/60 px-2 py-0.5 text-xs text-amber-300">Pending</span>}
                      <span className="truncate text-sm text-slate-100">{n.title}</span>
                    </span>
                    <span className="flex justify-between gap-2 text-xs text-slate-400">
                      <span className="truncate">{n.sub}</span>
                      <TimeAgo ts={n.at} />
                    </span>
                  </Link>
                </li>
              );
            })}
          </ul>
          {items.length > SHOWN && <p className="px-2 pt-1 text-xs text-slate-400">+{items.length - SHOWN} older</p>}
        </div>
      )}
    </div>
  );
}
