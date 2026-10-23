import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { get } from "../lib/api";
import { AutoRefreshToggle, useAutoRefresh } from "../components/AutoRefresh";
import { RiskBadge } from "../components/RiskBadge";
import { StatusBadge, INCIDENT_STATUSES } from "../components/StatusBadge";
import { Segmented } from "../components/Segmented";
import { useNewIds } from "../components/useNewIds";
import { TimeAgo } from "../components/TimeAgo";
import { ErrorBanner, EmptyRow, SkeletonRows } from "../components/States";

export default function Incidents() {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [reload, setReload] = useState(0); // bumped by Retry
  const [statusFilter, setStatusFilter] = useState("");
  const [autoRefresh, setAutoRefresh, tick] = useAutoRefresh(15);
  const freshRows = useNewIds(loading ? [] : incidents);

  // Show "Loading..." only when the filter changes, not on every auto-refresh.
  useEffect(() => {
    setLoading(true);
  }, [statusFilter]);

  useEffect(() => {
    get(statusFilter ? `/incidents?status=${statusFilter}` : "/incidents")
      .then((data) => {
        setIncidents(data);
        setError("");
      })
      .catch((err) => setError(err.message || "Failed to load incidents"))
      .finally(() => setLoading(false));
  }, [statusFilter, tick, reload]);

  return (
    <div>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-xl font-semibold text-slate-100">Incidents</h1>
        <div className="flex flex-wrap items-center gap-4">
          <AutoRefreshToggle enabled={autoRefresh} onChange={setAutoRefresh} />
          <Segmented
            label="Filter by status"
            value={statusFilter}
            onChange={setStatusFilter}
            options={[{ value: "", label: "All" }, ...INCIDENT_STATUSES.map((s) => ({ value: s, label: s }))]}
          />
        </div>
      </div>

      <ErrorBanner message={error} onRetry={() => setReload((n) => n + 1)} />

      <div className="overflow-x-auto rounded border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900 text-slate-400">
            <tr>
              <th className="px-3 py-2">Host</th>
              <th className="px-3 py-2">Started</th>
              <th className="px-3 py-2">Ended</th>
              <th className="px-3 py-2">Detections</th>
              <th className="px-3 py-2">Risk</th>
              <th className="px-3 py-2">Status</th>
              <th className="px-3 py-2" />
            </tr>
          </thead>
          <tbody>
            {loading && <SkeletonRows cols={7} />}
            {!loading && !error && incidents.length === 0 && <EmptyRow colSpan={7} title="No incidents" hint="Incidents group related detections on one host. Try another status filter, or look at Detections for new activity." action={{ to: "/detections", label: "View detections" }} />}
            {!loading &&
              incidents.map((inc) => (
                <tr key={inc.id} className={`border-t border-slate-800 hover:bg-slate-900/60 ${freshRows.has(inc.id) ? "row-flash" : ""}`}>
                  <td className="px-3 py-2 text-slate-200">{inc.host}</td>
                  <td className="whitespace-nowrap px-3 py-2 text-slate-400">
                    <TimeAgo ts={inc.started_at} />
                  </td>
                  <td className="whitespace-nowrap px-3 py-2 text-slate-400">
                    <TimeAgo ts={inc.ended_at} />
                  </td>
                  <td className="px-3 py-2 text-slate-300">{inc.detection_count}</td>
                  <td className="px-3 py-2">
                    <RiskBadge level={inc.risk_level} score={inc.risk_score} />
                  </td>
                  <td className="px-3 py-2">
                    <StatusBadge status={inc.status} />
                  </td>
                  <td className="px-3 py-2 text-right">
                    <Link to={`/incidents/${inc.id}`} className="text-sky-400 hover:text-sky-300">
                      View &rarr;
                    </Link>
                  </td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
