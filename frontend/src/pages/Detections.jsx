import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { get } from "../lib/api";
import { rowOpenProps } from "../lib/a11y";
import { DetectionDrawer } from "../components/DetailDrawers";
import { TIBadge } from "../components/TIBadge";
import { TimeAgo } from "../components/TimeAgo";
import { ErrorBanner, EmptyRow, SkeletonRows } from "../components/States";

const LEVEL_STYLES = {
  Low: "bg-slate-800 text-slate-300",
  Medium: "bg-amber-900/60 text-amber-300",
  High: "bg-orange-900/60 text-orange-300",
  Critical: "bg-red-900/70 text-red-300",
};

export default function Detections() {
  const [params] = useSearchParams();
  const [host, setHost] = useState(params.get("host") || "");
  const [techniqueId, setTechniqueId] = useState(params.get("technique") || "");
  const [selectedId, setSelectedId] = useState(null);
  const [detections, setDetections] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [reload, setReload] = useState(0); // bumped by Retry

  useEffect(() => {
    const params = new URLSearchParams();
    if (host) params.set("host", host);
    if (techniqueId) params.set("technique_id", techniqueId);

    setLoading(true);
    setError("");
    get(`/detections?${params.toString()}`)
      .then(setDetections)
      .catch((err) => setError(err.message || "Failed to load detections"))
      .finally(() => setLoading(false));
  }, [host, techniqueId, reload]);

  return (
    <div>
      <h1 className="mb-4 text-xl font-semibold text-slate-100">Detections</h1>

      <div className="mb-4 flex flex-wrap gap-3">
        <input
          placeholder="Host"
          value={host}
          onChange={(e) => setHost(e.target.value)}
          className="w-40 rounded border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-100 outline-none focus:border-sky-600"
        />
        <input
          placeholder="ATT&CK ID (e.g. T1110)"
          value={techniqueId}
          onChange={(e) => setTechniqueId(e.target.value)}
          className="w-48 rounded border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-100 outline-none focus:border-sky-600"
        />
      </div>

      <ErrorBanner message={error} onRetry={() => setReload((n) => n + 1)} />

      <div className="overflow-x-auto rounded border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900 text-slate-400">
            <tr>
              <th className="px-3 py-2">Rule</th>
              <th className="px-3 py-2">ATT&CK</th>
              <th className="px-3 py-2">Host</th>
              <th className="px-3 py-2">Events</th>
              <th className="px-3 py-2">Severity</th>
              <th className="px-3 py-2">Confidence</th>
              <th className="px-3 py-2">Risk</th>
              <th className="px-3 py-2">Last seen</th>
            </tr>
          </thead>
          <tbody>
            {loading && <SkeletonRows cols={8} />}
            {!loading && !error && detections.length === 0 && <EmptyRow colSpan={8} title="No detections match" hint="Detections appear when rules match collected events. Clear the filters, or generate activity with the collector or simulate_attacks.ps1." action={{ to: "/events", label: "Open Log Explorer" }} />}
            {!loading &&
              detections.map((d) => (
                <tr key={d.id} className="border-t border-slate-800 hover:bg-slate-900/60" {...rowOpenProps(() => setSelectedId(d.id), d.id === selectedId)}>
                  <td className="px-3 py-2 text-slate-200">
                    <div className="flex flex-wrap items-center gap-2">
                      {d.rule_name}
                      <TIBadge matches={d.ti_matches} />
                    </div>
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex flex-wrap gap-1">
                      {d.technique_ids.map((id) => (
                        <span
                          key={id}
                          className="rounded bg-indigo-900/50 px-1.5 py-0.5 text-xs text-indigo-300"
                        >
                          {id}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="px-3 py-2 text-slate-300">{d.host}</td>
                  <td className="px-3 py-2 text-slate-300">{d.event_count}</td>
                  <td className="px-3 py-2 text-slate-300">{d.severity}/10</td>
                  <td className="px-3 py-2 text-slate-300">{Math.round(d.confidence * 100)}%</td>
                  <td className="px-3 py-2">
                    <span
                      className={`rounded px-2 py-0.5 text-xs font-medium ${
                        LEVEL_STYLES[d.risk_level] || "bg-slate-800 text-slate-300"
                      }`}
                    >
                      {d.risk_level} · {Math.round(d.risk_score)}
                    </span>
                  </td>
                  <td className="whitespace-nowrap px-3 py-2 text-slate-400">
                    <TimeAgo ts={d.last_seen} />
                  </td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>
      <DetectionDrawer detection={detections.find((d) => d.id === selectedId)} onClose={() => setSelectedId(null)} />
    </div>
  );
}
