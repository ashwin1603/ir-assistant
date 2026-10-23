import { useEffect, useState } from "react";
import { get } from "../lib/api";
import { AutoRefreshToggle, useAutoRefresh } from "../components/AutoRefresh";

const STATUS_STYLES = {
  online: "bg-emerald-900/60 text-emerald-300",
  stale: "bg-amber-900/60 text-amber-300",
  offline: "bg-slate-800 text-slate-400",
};

export default function Devices() {
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [autoRefresh, setAutoRefresh, tick] = useAutoRefresh(15);

  useEffect(() => {
    get("/devices")
      .then((data) => {
        setDevices(data);
        setError("");
      })
      .catch((err) => setError(err.message || "Failed to load devices"))
      .finally(() => setLoading(false));
  }, [tick]);

  return (
    <div>
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-xl font-semibold text-slate-100">Devices</h1>
        <AutoRefreshToggle enabled={autoRefresh} onChange={setAutoRefresh} />
      </div>
      <p className="mb-3 text-xs text-slate-500">
        Online: heartbeat in the last 60s. Stale: within 5 min. Offline: older. Run{" "}
        <code>scripts/collector.py --watch</code> to keep a host online.
      </p>

      {error && <p className="mb-3 text-sm text-red-400">{error}</p>}

      <div className="overflow-x-auto rounded border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900 text-slate-400">
            <tr>
              <th className="px-3 py-2">Host</th>
              <th className="px-3 py-2">Source</th>
              <th className="px-3 py-2">Status</th>
              <th className="px-3 py-2">Last seen</th>
              <th className="px-3 py-2">Total events</th>
              <th className="px-3 py-2">Last 5 min</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td colSpan={6} className="px-3 py-6 text-center text-slate-500">
                  Loading...
                </td>
              </tr>
            )}
            {!loading && devices.length === 0 && (
              <tr>
                <td colSpan={6} className="px-3 py-6 text-center text-slate-500">
                  No devices have checked in yet.
                </td>
              </tr>
            )}
            {!loading &&
              devices.map((d) => (
                <tr key={`${d.host}|${d.source}`} className="border-t border-slate-800">
                  <td className="px-3 py-2 text-slate-200">
                    {d.host}
                    {d.simulated && (
                      <span className="ml-2 rounded bg-violet-900/60 px-1.5 py-0.5 text-xs text-violet-300">simulated</span>
                    )}
                  </td>
                  <td className="px-3 py-2 text-slate-400">{d.source}</td>
                  <td className="px-3 py-2">
                    <span className={`rounded px-2 py-0.5 text-xs ${STATUS_STYLES[d.status]}`}>{d.status}</span>
                  </td>
                  <td className="whitespace-nowrap px-3 py-2 text-slate-400">
                    {d.last_seen ? new Date(d.last_seen).toLocaleString() : "-"}
                  </td>
                  <td className="px-3 py-2 text-slate-300">{d.total_events}</td>
                  <td className="px-3 py-2 text-slate-300">{d.events_last_5m}</td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
