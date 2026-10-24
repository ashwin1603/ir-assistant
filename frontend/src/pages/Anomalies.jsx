import { useEffect, useState } from "react";
import { get } from "../lib/api";
import { rowOpenProps } from "../lib/a11y";
import { AnomalyDrawer } from "../components/DetailDrawers";
import { TimeAgo } from "../components/TimeAgo";
import { ErrorBanner, EmptyRow, SkeletonRows } from "../components/States";

const CMD_PREVIEW = 160;

// Long command lines are cut to CMD_PREVIEW chars with a toggle to see the rest.
function CommandLine({ text }) {
  const [open, setOpen] = useState(false);
  if (!text) return null;
  const long = text.length > CMD_PREVIEW;
  return (
    <div className="break-all font-mono text-xs text-slate-400">
      {open || !long ? text : text.slice(0, CMD_PREVIEW) + "…"}
      {long && (
        <button onClick={() => setOpen(!open)} className="ml-1 font-sans text-sky-400 hover:underline">
          {open ? "show less" : "show more"}
        </button>
      )}
    </div>
  );
}

export default function Anomalies() {
  const [data, setData] = useState(null);
  const [limit, setLimit] = useState(50);
  const [selectedId, setSelectedId] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [reload, setReload] = useState(0); // bumped by Retry

  useEffect(() => {
    setLoading(true);
    setError("");
    get(`/anomalies?limit=${limit}`)
      .then(setData)
      .catch((err) => setError(err.message || "Failed to load anomalies"))
      .finally(() => setLoading(false));
  }, [limit, reload]);

  const items = data?.items || [];

  return (
    <div>
      <h1 className="mb-1 text-xl font-semibold text-slate-100">Anomalies</h1>
      <p className="mb-4 text-sm text-slate-400">
        Isolation Forest over process-creation (4688) events, trained on real host events only. These are
        unusual-looking events, not detections: they are not mapped to ATT&CK and are never merged into incidents.
      </p>

      {data && (
        <div className="mb-4 flex flex-wrap gap-4 text-sm text-slate-300">
          <span>Trained on: {data.trained_on}</span>
          <span>Scored: {data.scored}</span>
          <span>Threshold: {data.threshold}</span>
          <span>Anomaly rate (real): {(data.anomaly_rate_real * 100).toFixed(1)}%</span>
          <select
            value={limit}
            onChange={(e) => setLimit(Number(e.target.value))}
            className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-sm text-slate-100"
          >
            {[25, 50, 100, 200].map((n) => (
              <option key={n} value={n}>
                Top {n}
              </option>
            ))}
          </select>
        </div>
      )}

      <ErrorBanner message={error} onRetry={() => setReload((n) => n + 1)} />

      <div className="overflow-x-auto rounded border border-slate-800">
        <table className="w-full table-fixed text-left text-sm">
          <colgroup>
            <col className="w-8" />
            <col className="w-16" />
            <col className="w-24" />
            <col />
            <col className="w-52" />
            <col className="w-14" />
            <col className="w-24" />
            <col className="w-24" />
          </colgroup>
          <thead className="bg-slate-900 text-xs text-slate-400">
            <tr>
              <th className="px-2 py-2">#</th>
              <th className="px-2 py-2">Score</th>
              <th className="px-2 py-2">Label</th>
              <th className="px-2 py-2">Process / command line</th>
              <th className="px-2 py-2">Top features</th>
              <th className="px-2 py-2">Rule?</th>
              <th className="px-2 py-2">Host</th>
              <th className="px-2 py-2">Time</th>
            </tr>
          </thead>
          <tbody>
            {loading && <SkeletonRows cols={8} />}
            {!loading && !error && items.length === 0 && <EmptyRow colSpan={8} title="Not enough data to train yet" hint="The model needs at least 10 real process-creation (4688) events. Keep the collector running with process auditing on." action={{ to: "/devices", label: "Check devices" }} />}
            {!loading &&
              items.map((a) => (
                <tr key={a.event_id} className="border-t border-slate-800 align-top hover:bg-slate-900/60"
                  {...rowOpenProps(() => setSelectedId(a.event_id), a.event_id === selectedId)}>
                  <td className="px-2 py-1.5 text-slate-400">{a.rank}</td>
                  <td className="px-2 py-1.5">
                    <span
                      className={`rounded px-1.5 py-0.5 text-xs font-medium ${
                        a.is_anomaly ? "bg-slate-700 text-slate-100 ring-1 ring-slate-500" : "bg-slate-800 text-slate-300"
                      }`}
                    >
                      {a.score.toFixed(3)}
                    </span>
                  </td>
                  <td className="break-words px-2 py-1.5 text-xs text-violet-300">{a.label}</td>
                  <td className="px-2 py-1.5">
                    <div className="truncate text-slate-200" title={a.process}>{a.process || "-"}</div>
                    <CommandLine text={a.command_line} />
                    {a.source === "simulated" && <span className="text-xs text-amber-400">simulated</span>}
                  </td>
                  <td className="px-2 py-1.5 text-xs text-slate-300">
                    {a.top_features.map((f) => (
                      <div key={f.name} className="break-words">
                        {f.name}: {f.value} <span className="text-slate-500">(typical {f.typical})</span>
                      </div>
                    ))}
                  </td>
                  <td className="px-2 py-1.5 text-xs text-slate-300">{a.also_matched_rule ? "yes" : "no"}</td>
                  <td className="truncate px-2 py-1.5 text-xs text-slate-300" title={a.host}>{a.host}</td>
                  <td className="px-2 py-1.5 text-xs text-slate-400">
                    <TimeAgo ts={a.timestamp} />
                  </td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>
      <AnomalyDrawer anomaly={items.find((a) => a.event_id === selectedId)} onClose={() => setSelectedId(null)} />
    </div>
  );
}
