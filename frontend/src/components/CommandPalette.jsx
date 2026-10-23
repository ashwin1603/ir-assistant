import { useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { cached } from "../lib/api";
import { trapTab } from "../lib/a11y";
import { navItemsFor } from "../lib/nav";
import { usePref } from "../lib/prefs";

const MAX_PER_GROUP = 6;

// Ctrl+K / Cmd+K palette: jump to pages, search incidents and hosts that pages already
// loaded (no new requests), and a few quick actions. Arrow keys move, Enter runs, Esc closes.
export function CommandPalette({ open, onClose }) {
  const { can, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [autoRefresh, setAutoRefresh] = usePref("autoRefresh", false);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const panel = useRef(null);
  const list = useRef(null);

  const items = useMemo(() => {
    if (!open) return [];
    const go = (to) => () => navigate(to);
    const incidents = cached("/incidents") || [];
    const devices = cached("/devices") || [];
    const currentIncident = location.pathname.match(/^\/incidents\/([^/]+)$/)?.[1];
    const top = incidents.reduce((best, i) => (!best || i.risk_score > best.risk_score ? i : best), null);
    const reportId = currentIncident || top?.id;

    const actions = [
      { group: "Actions", label: `Turn auto-refresh ${autoRefresh ? "off" : "on"}`, run: () => setAutoRefresh(!autoRefresh) },
      reportId && {
        group: "Actions",
        label: "Open report",
        hint: currentIncident ? "this incident" : `highest-risk incident · ${top.host}`,
        run: go(`/incidents/${reportId}/report`),
      },
      { group: "Actions", label: "Log out", run: logout },
    ].filter(Boolean);
    const pages = navItemsFor(can).map((p) => ({ group: "Pages", label: p.label, hint: p.to, run: go(p.to) }));
    const incidentItems = [...incidents]
      .sort((a, b) => b.risk_score - a.risk_score)
      .map((i) => ({
        group: "Incidents",
        label: i.host,
        hint: `${i.risk_level} ${Math.round(i.risk_score)} · ${i.status} · ${new Date(i.started_at).toLocaleDateString()}`,
        run: go(`/incidents/${i.id}`),
      }));
    const hosts = [...new Set([...devices.map((d) => d.host), ...incidents.map((i) => i.host)])].map((h) => ({
      group: "Hosts",
      label: h,
      hint: "events on this host",
      run: go(`/events?host=${encodeURIComponent(h)}`),
    }));

    const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
    const matches = (item) => terms.every((t) => `${item.label} ${item.hint || ""}`.toLowerCase().includes(t));
    if (!terms.length) return [...actions, ...pages, ...incidentItems.slice(0, 3)];
    return [
      ...actions.filter(matches),
      ...pages.filter(matches),
      ...incidentItems.filter(matches).slice(0, MAX_PER_GROUP),
      ...hosts.filter(matches).slice(0, MAX_PER_GROUP),
    ];
  }, [open, query, can, logout, navigate, location.pathname, autoRefresh, setAutoRefresh]);

  useEffect(() => {
    if (!open) return undefined;
    const opener = document.activeElement;
    return () => opener?.focus?.({ preventScroll: true });
  }, [open]);

  useEffect(() => {
    list.current?.querySelector('[aria-selected="true"]')?.scrollIntoView({ block: "nearest" });
  }, [active]);

  if (!open) return null;

  function close() {
    setQuery("");
    setActive(0);
    onClose();
  }

  function run(item) {
    close();
    item.run();
  }

  function onKeyDown(e) {
    if (e.key === "Escape") {
      e.preventDefault();
      close();
    } else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      const step = e.key === "ArrowDown" ? 1 : -1;
      setActive((a) => (items.length ? (a + step + items.length) % items.length : 0));
    } else if (e.key === "Enter" && items[active]) {
      e.preventDefault();
      run(items[active]);
    } else {
      trapTab(e, panel.current);
    }
  }

  let lastGroup = null;
  return createPortal(
    <>
      <div className="ir-scrim" onClick={close} aria-hidden="true" />
      <div ref={panel} className="ir-palette" role="dialog" aria-modal="true" aria-label="Command palette" onKeyDown={onKeyDown}>
        <input
          autoFocus
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setActive(0);
          }}
          placeholder="Jump to a page, incident or host…"
          aria-label="Search commands"
          role="combobox"
          aria-expanded="true"
          aria-controls="ir-palette-list"
          aria-activedescendant={items[active] ? `ir-cmd-${active}` : undefined}
          className="ir-palette-input"
        />
        <ul ref={list} id="ir-palette-list" role="listbox" className="ir-palette-list">
          {items.length === 0 && <li className="px-4 py-6 text-center text-sm text-slate-400">No matches. Try a host name or page.</li>}
          {items.map((item, i) => {
            const header = item.group !== lastGroup;
            lastGroup = item.group;
            return (
              <li key={`${item.group}|${item.label}|${item.hint}`} role="presentation">
                {header && <div className="ir-palette-group">{item.group}</div>}
                <div
                  id={`ir-cmd-${i}`}
                  role="option"
                  aria-selected={i === active}
                  className="ir-palette-item"
                  onMouseMove={() => setActive(i)}
                  onClick={() => run(item)}
                >
                  <span className="truncate text-slate-100">{item.label}</span>
                  {item.hint && <span className="truncate text-xs text-slate-400">{item.hint}</span>}
                </div>
              </li>
            );
          })}
        </ul>
        <div className="ir-palette-foot">
          <span><kbd>↑</kbd><kbd>↓</kbd> move</span>
          <span><kbd>Enter</kbd> open</span>
          <span><kbd>Esc</kbd> close</span>
        </div>
      </div>
    </>,
    document.body,
  );
}
