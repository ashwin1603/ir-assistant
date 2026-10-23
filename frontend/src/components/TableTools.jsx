import { useEffect, useRef, useState } from "react";
import { download } from "../lib/api";
import { usePref } from "../lib/prefs";
import { Segmented } from "./Segmented";
import { useToast } from "./Toast";

// Table toolbar: column show/hide, density, saved filters and CSV export.
// Layout choices and saved filters are per-browser conveniences (lib/prefs.js, localStorage).

const DENSITY = [
  { value: "compact", label: "Compact" },
  { value: "comfortable", label: "Comfortable" },
];

// columns: [{ key, label }]. Returns the visible columns plus the controls' state.
export function useTableView(table, columns) {
  const [hidden, setHidden] = usePref(`table.${table}.hidden`, []);
  const [density, setDensity] = usePref(`table.${table}.density`, "comfortable");
  const visible = columns.filter((c) => !hidden.includes(c.key));
  function toggle(key) {
    if (hidden.includes(key)) setHidden(hidden.filter((k) => k !== key));
    else if (visible.length > 1) setHidden([...hidden, key]); // keep at least one column
  }
  return { visible, hidden, toggle, density, setDensity };
}

// CSV export of the current view: the server applies the same filters, role redaction
// and the 5,000-row cap, and audit-logs the export.
export function useCsvExport() {
  const toast = useToast();
  const [exporting, setExporting] = useState(false);
  async function run(path, filename) {
    setExporting(true);
    try {
      const { rows, truncated } = await download(path, filename);
      toast.success(truncated ? `Exported ${rows} rows (capped at 5,000)` : `Exported ${rows} row${rows === 1 ? "" : "s"}`);
    } catch (err) {
      toast.error(err.message || "Export failed");
    } finally {
      setExporting(false);
    }
  }
  return [exporting, run];
}

// Small glass popover anchored under its button; Esc or an outside click closes it.
function Popover({ label, children }) {
  const [open, setOpen] = useState(false);
  const box = useRef(null);
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
  return (
    <div ref={box} className="relative">
      <button type="button" className="ir-btn sm" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
        {label} <span aria-hidden="true">▾</span>
      </button>
      {open && <div className="ir-popover">{children}</div>}
    </div>
  );
}

function SavedFilters({ table, filters, onApply }) {
  const [saved, setSaved] = usePref(`table.${table}.saved`, []);
  const [name, setName] = useState("");
  const active = Object.values(filters).some(Boolean);
  function save(e) {
    e.preventDefault();
    const n = name.trim();
    if (!n) return;
    setSaved([...saved.filter((s) => s.name !== n), { name: n, filters }]);
    setName("");
  }
  return (
    <Popover label="Saved filters">
      {saved.length === 0 && <p className="px-2 py-1 text-xs text-slate-400">No saved filters yet.</p>}
      <ul className="mb-2 space-y-0.5">
        {saved.map((s) => (
          <li key={s.name} className="flex items-center gap-1">
            <button type="button" className="ir-popover-item flex-1 truncate" onClick={() => onApply(s.filters)}>
              {s.name}
            </button>
            <button type="button" className="ir-popover-item text-slate-400" aria-label={`Delete saved filter ${s.name}`}
              onClick={() => setSaved(saved.filter((x) => x.name !== s.name))}>
              ✕
            </button>
          </li>
        ))}
      </ul>
      <form onSubmit={save} className="flex gap-1.5 border-t border-white/10 pt-2">
        <input value={name} onChange={(e) => setName(e.target.value)} maxLength={40} placeholder={active ? "Name this filter" : "Set filters first"}
          disabled={!active} aria-label="Saved filter name" className="min-w-0 flex-1 px-2 py-1 text-xs" />
        <button type="submit" className="ir-btn sm" disabled={!active || !name.trim()}>Save</button>
      </form>
    </Popover>
  );
}

export function TableToolbar({ table, columns, view, filters, onApplyFilters, onExport, exporting }) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <SavedFilters table={table} filters={filters} onApply={onApplyFilters} />
      <Popover label="Columns">
        <ul className="space-y-0.5">
          {columns.map((c) => (
            <li key={c.key}>
              <label className="ir-popover-item flex cursor-pointer items-center gap-2">
                <input type="checkbox" checked={!view.hidden.includes(c.key)} onChange={() => view.toggle(c.key)} />
                {c.label}
              </label>
            </li>
          ))}
        </ul>
      </Popover>
      <Segmented label="Row density" options={DENSITY} value={view.density} onChange={view.setDensity} />
      {onExport && (
        <button type="button" className="ir-btn sm" onClick={onExport} disabled={exporting} title="Download the current view as CSV (max 5,000 rows)">
          {exporting ? "Exporting…" : "Export CSV"}
        </button>
      )}
    </div>
  );
}
