import { useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { get } from "../lib/api";
import { rowOpenProps } from "../lib/a11y";
import { DetectionDrawer } from "../components/DetailDrawers";
import { RiskBadge } from "../components/RiskBadge";
import { TIBadge } from "../components/TIBadge";
import { TimeAgo } from "../components/TimeAgo";
import { ErrorBanner, EmptyRow, SkeletonRows } from "../components/States";
import { TableToolbar, useCsvExport, useTableView } from "../components/TableTools";
import { useAutoRefresh } from "../components/AutoRefresh";
import { useNewIds } from "../components/useNewIds";

// Table columns. `exports` = the server's CSV columns for it (GET /detections/export).
const COLUMNS = [
  {
    key: "rule",
    label: "Rule",
    exports: ["rule_name", "summary"],
    className: "text-slate-200",
    cell: (d) => (
      <div className="flex flex-wrap items-center gap-2">
        {d.rule_name}
        <TIBadge matches={d.ti_matches} />
      </div>
    ),
  },
  {
    key: "attack",
    label: "ATT&CK",
    exports: ["technique_ids", "tactics"],
    cell: (d) => (
      <div className="flex flex-wrap gap-1">
        {d.technique_ids.map((id) => (
          <span key={id} className="rounded bg-indigo-900/50 px-1.5 py-0.5 text-xs text-indigo-300">
            {id}
          </span>
        ))}
      </div>
    ),
  },
  { key: "host", label: "Host", exports: ["host"], cell: (d) => d.host, className: "text-slate-300" },
  { key: "events", label: "Events", exports: ["event_count"], cell: (d) => d.event_count, className: "text-slate-300" },
  { key: "severity", label: "Severity", exports: ["severity"], cell: (d) => `${d.severity}/10`, className: "text-slate-300" },
  { key: "confidence", label: "Confidence", exports: ["confidence"], cell: (d) => `${Math.round(d.confidence * 100)}%`, className: "text-slate-300" },
  { key: "risk", label: "Risk", exports: ["risk_level", "risk_score"], cell: (d) => <RiskBadge level={d.risk_level} score={d.risk_score} /> },
  { key: "last_seen", label: "Last seen", exports: ["last_seen"], cell: (d) => <TimeAgo ts={d.last_seen} />, className: "whitespace-nowrap text-slate-400" },
];

export default function Detections() {
  const [params] = useSearchParams();
  const [host, setHost] = useState(params.get("host") || "");
  const [techniqueId, setTechniqueId] = useState(params.get("technique") || "");
  const [selectedId, setSelectedId] = useState(null);
  const [detections, setDetections] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [reload, setReload] = useState(0); // bumped by Retry
  const view = useTableView("detections", COLUMNS);
  const [exporting, runExport] = useCsvExport();
  const [, , tick] = useAutoRefresh(); // live signal: reload in place
  const lastQuery = useRef(null);
  const fresh = useNewIds(loading ? [] : detections); // a filter change flashes nothing

  const filterParams = useMemo(() => {
    const p = new URLSearchParams();
    if (host) p.set("host", host);
    if (techniqueId) p.set("technique_id", techniqueId);
    return p.toString();
  }, [host, techniqueId]);

  useEffect(() => {
    // Skeleton only when the query changed; a live refresh updates rows in place.
    const query = `${filterParams}|${reload}`;
    if (lastQuery.current !== query) setLoading(true);
    lastQuery.current = query;
    setError("");
    get(`/detections?${filterParams}`)
      .then(setDetections)
      .catch((err) => setError(err.message || "Failed to load detections"))
      .finally(() => setLoading(false));
  }, [filterParams, reload, tick]);

  function applyFilters(f) {
    setHost(f.host || "");
    setTechniqueId(f.techniqueId || "");
  }

  function exportCsv() {
    const columns = ["id", ...view.visible.flatMap((c) => c.exports)].join(",");
    runExport(`/detections/export?${filterParams}${filterParams ? "&" : ""}columns=${columns}`, "detections.csv");
  }

  return (
    <div>
      <h1 className="mb-4 text-xl font-semibold text-slate-100">Detections</h1>

      <div className="ir-filterbar">
        <div className="flex flex-wrap gap-3">
          <input
            placeholder="Host"
            aria-label="Host"
            value={host}
            onChange={(e) => setHost(e.target.value)}
            className="w-40 rounded border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-100 outline-none focus:border-sky-600"
          />
          <input
            placeholder="ATT&CK ID (e.g. T1110)"
            aria-label="ATT&CK technique ID"
            value={techniqueId}
            onChange={(e) => setTechniqueId(e.target.value)}
            className="w-48 rounded border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-100 outline-none focus:border-sky-600"
          />
        </div>
        <TableToolbar
          table="detections"
          columns={COLUMNS}
          view={view}
          filters={{ host, techniqueId }}
          onApplyFilters={applyFilters}
          onExport={exportCsv}
          exporting={exporting}
        />
      </div>

      <ErrorBanner message={error} onRetry={() => setReload((n) => n + 1)} />

      <div className={`overflow-x-auto rounded border border-slate-800 ir-density-${view.density}`}>
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900 text-slate-400">
            <tr>
              {view.visible.map((c) => (
                <th key={c.key} className="px-3 py-2">{c.label}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading && <SkeletonRows cols={view.visible.length} />}
            {!loading && !error && detections.length === 0 && (
              <EmptyRow colSpan={view.visible.length} title="No detections match"
                hint="Detections appear when rules match collected events. Clear the filters, or generate activity with the collector or simulate_attacks.ps1."
                action={host || techniqueId ? { onClick: () => applyFilters({}), label: "Clear filters" } : { to: "/events", label: "Open Log Explorer" }} />
            )}
            {!loading &&
              detections.map((d) => (
                <tr key={d.id} className={`border-t border-slate-800 hover:bg-slate-900/60${fresh.has(d.id) ? " row-flash" : ""}`}
                  {...rowOpenProps(() => setSelectedId(d.id), d.id === selectedId)}>
                  {view.visible.map((c) => (
                    <td key={c.key} className={`px-3 py-2 ${c.className || ""}`}>{c.cell(d)}</td>
                  ))}
                </tr>
              ))}
          </tbody>
        </table>
      </div>
      <DetectionDrawer detection={detections.find((d) => d.id === selectedId)} onClose={() => setSelectedId(null)} />
    </div>
  );
}
