import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { get } from "../lib/api";
import { RiskBadge } from "../components/RiskBadge";

const BAR_COLOR = "#818cf8";

function formatBytes(n) {
  if (n >= 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${n} B`;
}

// One horizontal bar chart card; rows are {label, value}.
function TopChart({ title, rows, format = (v) => v }) {
  return (
    <div className="rounded border border-slate-800 bg-slate-900/40 p-4">
      <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">{title}</h2>
      {rows.length === 0 ? (
        <p className="text-sm text-slate-500">No data.</p>
      ) : (
        <ResponsiveContainer width="100%" height={Math.max(120, rows.length * 28)}>
          <BarChart data={rows} layout="vertical" margin={{ left: 8, right: 16, top: 4, bottom: 4 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#33302b" horizontal={false} />
            <XAxis type="number" stroke="#827b71" fontSize={12} tickLine={false} tickFormatter={format} allowDecimals={false} />
            <YAxis type="category" dataKey="label" stroke="#827b71" fontSize={12} tickLine={false} width={130} />
            <Tooltip
              cursor={{ fill: "#33302b" }}
              contentStyle={{ background: "#1a1c24", border: "1px solid #3a3d4a", fontSize: 12 }}
              formatter={(v) => [format(v), title]}
            />
            <Bar dataKey="value" fill={BAR_COLOR} radius={[0, 4, 4, 0]} maxBarSize={18} />
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}

export default function Network() {
  const [data, setData] = useState(null);
  const [host, setHost] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    setLoading(true);
    setError("");
    const params = host ? `?host=${encodeURIComponent(host)}` : "";
    get(`/network/summary${params}`)
      .then(setData)
      .catch((err) => setError(err.message || "Failed to load network data"))
      .finally(() => setLoading(false));
  }, [host]);

  return (
    <div>
      <h1 className="mb-1 text-xl font-semibold text-slate-100">Network</h1>
      <p className="mb-4 text-sm text-slate-400">
        Connections and DNS lookups from the network collector, flow-CSV uploads and the simulator, plus what the
        network rules (port scan, beaconing, large upload, uncommon port, DNS tunnelling) found.
      </p>

      <div className="mb-4 flex items-center gap-2 text-sm text-slate-300">
        <label htmlFor="host">Host</label>
        <select id="host" value={host} onChange={(e) => setHost(e.target.value)}
          className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-sm text-slate-100">
          <option value="">All hosts</option>
          {(data?.hosts || []).map((h) => <option key={h} value={h}>{h}</option>)}
        </select>
        {loading && <span className="skeleton inline-block" style={{ width: "6rem" }} />}
      </div>

      {error && <p className="mb-3 text-sm text-red-400">{error}</p>}

      {data && (
        <>
          <div className="mb-6 grid gap-4 md:grid-cols-3">
            <TopChart title="Top destinations" rows={data.top_destinations.map((d) => ({ label: d.dst_ip, value: d.count }))} />
            <TopChart title="Top processes" rows={data.top_processes.map((p) => ({ label: p.process, value: p.count }))} />
            <TopChart title="Bytes out per destination" format={formatBytes}
              rows={data.bytes_by_destination.map((d) => ({ label: d.dst_ip, value: d.bytes_out }))} />
          </div>

          <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-400">Network detections</h2>
          <div className="overflow-x-auto rounded border border-slate-800">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-900 text-xs uppercase text-slate-400">
                <tr>
                  <th className="px-3 py-2">First seen</th>
                  <th className="px-3 py-2">Host</th>
                  <th className="px-3 py-2">Rule</th>
                  <th className="px-3 py-2">ATT&amp;CK</th>
                  <th className="px-3 py-2">Risk</th>
                  <th className="px-3 py-2">Incident</th>
                </tr>
              </thead>
              <tbody>
                {data.detections.length === 0 && (
                  <tr><td colSpan={6} className="px-3 py-4 text-center text-slate-500">No network detections.</td></tr>
                )}
                {data.detections.map((d) => (
                  <tr key={d.id} className="border-t border-slate-800 align-top">
                    <td className="whitespace-nowrap px-3 py-2 text-slate-400">{new Date(d.first_seen).toLocaleString()}</td>
                    <td className="px-3 py-2 text-slate-300">{d.host}</td>
                    <td className="px-3 py-2 text-slate-200">
                      {d.rule_name}
                      {d.summary && <p className="mt-1 text-xs text-slate-400">{d.summary}</p>}
                    </td>
                    <td className="px-3 py-2 text-slate-400">{d.technique_ids.join(", ")}</td>
                    <td className="px-3 py-2"><RiskBadge level={d.risk_level} score={d.risk_score} /></td>
                    <td className="px-3 py-2">
                      {d.incident_id && <Link to={`/incidents/${d.incident_id}`} className="text-sky-400 hover:underline">Open</Link>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
