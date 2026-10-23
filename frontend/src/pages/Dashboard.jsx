import { useEffect, useState } from "react";
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { get } from "../lib/api";
import { AutoRefreshToggle, useAutoRefresh } from "../components/AutoRefresh";
import { PageSkeleton } from "../components/Skeleton";
import { CountUp } from "../components/CountUp";

const LEVEL_ORDER = ["Low", "Medium", "High", "Critical"];

// Matches RiskBadge's existing color language so the dashboard reads as one system with the rest of the app.
const LEVEL_COLORS = {
  Low: "#64748b",
  Medium: "#d79b1f",
  High: "#e07a2e",
  Critical: "#dc4c4c",
};

const TECHNIQUE_COLOR = "#818cf8";

function StatTile({ label, value }) {
  return (
    <div className="rounded border border-slate-800 bg-slate-900/40 p-4">
      <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">{label}</p>
      <p className="mt-1 text-2xl font-semibold tabular-nums text-slate-100"><CountUp value={value} /></p>
    </div>
  );
}

function ChartTooltip({ active, payload }) {
  if (!active || !payload?.length) return null;
  const { name, count } = payload[0].payload;
  return (
    <div className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-xs text-slate-200">
      {name}: {count}
    </div>
  );
}

export default function Dashboard() {
  const [incidents, setIncidents] = useState([]);
  const [detections, setDetections] = useState([]);
  const [eventTotal, setEventTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [autoRefresh, setAutoRefresh, tick] = useAutoRefresh(15);

  useEffect(() => {
    // loading starts true; refreshes update in place without a "Loading..." flash.
    Promise.all([get("/incidents"), get("/detections"), get("/events?page=1&page_size=1")])
      .then(([incidentData, detectionData, eventPage]) => {
        setIncidents(incidentData);
        setDetections(detectionData);
        setEventTotal(eventPage.total);
        setError("");
      })
      .catch((err) => setError(err.message || "Failed to load dashboard"))
      .finally(() => setLoading(false));
  }, [tick]);

  if (loading) return <PageSkeleton />;
  if (error) return <p className="text-red-400">{error}</p>;

  const severityData = LEVEL_ORDER.map((level) => ({
    name: level,
    count: detections.filter((d) => d.risk_level === level).length,
  }));

  const techniqueCounts = {};
  for (const d of detections) {
    for (const tid of d.technique_ids) {
      techniqueCounts[tid] = (techniqueCounts[tid] || 0) + 1;
    }
  }
  const techniqueData = Object.entries(techniqueCounts)
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);

  return (
    <div>
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-xl font-semibold text-slate-100">Dashboard</h1>
        <AutoRefreshToggle enabled={autoRefresh} onChange={setAutoRefresh} />
      </div>

      <div className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatTile label="Incidents" value={incidents.length} />
        <StatTile label="Detections" value={detections.length} />
        <StatTile label="Events collected" value={eventTotal} />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="rounded border border-slate-800 bg-slate-900/40 p-4">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">
            Detections by severity
          </h2>
          {detections.length === 0 ? (
            <p className="text-sm text-slate-500">No detections yet.</p>
          ) : (
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={severityData} margin={{ left: 0, right: 8, top: 4, bottom: 4 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#33302b" vertical={false} />
                <XAxis dataKey="name" stroke="#827b71" fontSize={12} tickLine={false} axisLine={{ stroke: "#33302b" }} />
                <YAxis stroke="#827b71" fontSize={12} tickLine={false} axisLine={false} allowDecimals={false} width={28} />
                <Tooltip content={<ChartTooltip />} cursor={{ fill: "#33302b" }} />
                <Bar dataKey="count" radius={[4, 4, 0, 0]} maxBarSize={56}>
                  {severityData.map((entry) => (
                    <Cell key={entry.name} fill={LEVEL_COLORS[entry.name]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="rounded border border-slate-800 bg-slate-900/40 p-4">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">
            Top ATT&amp;CK techniques
          </h2>
          {techniqueData.length === 0 ? (
            <p className="text-sm text-slate-500">No detections yet.</p>
          ) : (
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={techniqueData} layout="vertical" margin={{ left: 8, right: 16, top: 4, bottom: 4 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#33302b" horizontal={false} />
                <XAxis type="number" stroke="#827b71" fontSize={12} tickLine={false} axisLine={false} allowDecimals={false} />
                <YAxis
                  type="category"
                  dataKey="name"
                  stroke="#827b71"
                  fontSize={12}
                  tickLine={false}
                  axisLine={false}
                  width={72}
                />
                <Tooltip content={<ChartTooltip />} cursor={{ fill: "#33302b" }} />
                <Bar dataKey="count" fill={TECHNIQUE_COLOR} radius={[0, 4, 4, 0]} maxBarSize={18} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>
    </div>
  );
}
