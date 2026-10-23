import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { get } from "../lib/api";
import { useAuth } from "../auth/AuthContext";
import { AutoRefreshToggle, useAutoRefresh } from "../components/AutoRefresh";
import { Skeleton } from "../components/Skeleton";
import { CountUp } from "../components/CountUp";
import { RiskBadge } from "../components/RiskBadge";
import { StatusBadge } from "../components/StatusBadge";
import { useNewIds } from "../components/useNewIds";

const LEVEL_ORDER = ["Low", "Medium", "High", "Critical"];

// Matches RiskBadge's existing color language so the dashboard reads as one system with the rest of the app.
const LEVEL_COLORS = {
  Low: "#64748b",
  Medium: "#d79b1f",
  High: "#e07a2e",
  Critical: "#dc4c4c",
};

const TECHNIQUE_COLOR = "#818cf8";
const DEVICE_COLORS = { online: "#3fb950", stale: "#d79b1f", offline: "#5e5850" };
const FEED_SIZE = 8;

// Each widget loads independently: one failing endpoint does not blank the whole dashboard.
// The values are null until the first load finishes (skeletons show meanwhile).
const SOURCES = {
  incidents: "/incidents",
  detections: "/detections",
  events: `/events?page=1&page_size=${FEED_SIZE}`,
  devices: "/devices",
  matrix: "/attack/matrix",
};

const fmtTime = (ts) => new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const basename = (path) => (path ? path.split(/[\\/]/).pop() : "—");

function Panel({ title, span, action, children }) {
  return (
    <section className={`glass dash-panel rounded border p-4 ${span}`}>
      <div className="mb-3 flex items-center justify-between gap-2">
        <h2 className="text-xs font-semibold uppercase tracking-wide text-slate-400">{title}</h2>
        {action}
      </div>
      <div className="dash-body">{children}</div>
    </section>
  );
}

function Empty({ children }) {
  return <p className="dash-empty">{children}</p>;
}

function StatTile({ label, value, children }) {
  return (
    <div className="glass rounded border p-4">
      <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">{label}</p>
      {value === null ? (
        <span className="skeleton mt-2" style={{ width: "4rem", height: "1.6rem" }} />
      ) : (
        <p className="mt-1 text-2xl font-semibold tabular-nums text-slate-100">{children ?? <CountUp value={value} />}</p>
      )}
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

function SeverityChart({ detections }) {
  if (!detections) return <Skeleton lines={5} />;
  if (detections.length === 0) return <Empty>No detections yet.</Empty>;
  const data = LEVEL_ORDER.map((level) => ({ name: level, count: detections.filter((d) => d.risk_level === level).length }));
  return (
    <ResponsiveContainer width="100%" height="100%">
      <BarChart data={data} margin={{ left: 0, right: 8, top: 4, bottom: 4 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#33302b" vertical={false} />
        <XAxis dataKey="name" stroke="#827b71" fontSize={12} tickLine={false} axisLine={{ stroke: "#33302b" }} />
        <YAxis stroke="#827b71" fontSize={12} tickLine={false} axisLine={false} allowDecimals={false} width={28} />
        <Tooltip content={<ChartTooltip />} cursor={{ fill: "#33302b" }} />
        <Bar dataKey="count" radius={[4, 4, 0, 0]} maxBarSize={56}>
          {data.map((entry) => <Cell key={entry.name} fill={LEVEL_COLORS[entry.name]} />)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

function TechniqueChart({ detections }) {
  if (!detections) return <Skeleton lines={5} />;
  const counts = {};
  for (const d of detections) {
    for (const tid of d.technique_ids) counts[tid] = (counts[tid] || 0) + 1;
  }
  const data = Object.entries(counts)
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);
  if (data.length === 0) return <Empty>No techniques observed yet.</Empty>;
  return (
    <ResponsiveContainer width="100%" height="100%">
      <BarChart data={data} layout="vertical" margin={{ left: 8, right: 16, top: 4, bottom: 4 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#33302b" horizontal={false} />
        <XAxis type="number" stroke="#827b71" fontSize={12} tickLine={false} axisLine={false} allowDecimals={false} />
        <YAxis type="category" dataKey="name" stroke="#827b71" fontSize={12} tickLine={false} axisLine={false} width={72} />
        <Tooltip content={<ChartTooltip />} cursor={{ fill: "#33302b" }} />
        <Bar dataKey="count" fill={TECHNIQUE_COLOR} radius={[0, 4, 4, 0]} maxBarSize={18} />
      </BarChart>
    </ResponsiveContainer>
  );
}

// Incidents per risk level as a donut, with the total in the middle.
function RiskDonut({ incidents }) {
  if (!incidents) return <Skeleton lines={5} />;
  if (incidents.length === 0) return <Empty>No incidents yet.</Empty>;
  const data = LEVEL_ORDER.map((level) => ({ name: level, count: incidents.filter((i) => i.risk_level === level).length }))
    .filter((d) => d.count > 0);
  return (
    <div className="flex h-full flex-col">
      <div className="relative min-h-0 flex-1">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie data={data} dataKey="count" nameKey="name" innerRadius="62%" outerRadius="88%" paddingAngle={2} stroke="none">
              {data.map((d) => <Cell key={d.name} fill={LEVEL_COLORS[d.name]} />)}
            </Pie>
            <Tooltip content={<ChartTooltip />} />
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-semibold tabular-nums text-slate-100">{incidents.length}</span>
          <span className="text-xs text-slate-500">incidents</span>
        </div>
      </div>
      <ul className="mt-2 flex flex-wrap justify-center gap-x-3 gap-y-1 text-xs text-slate-400">
        {data.map((d) => (
          <li key={d.name} className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full" style={{ background: LEVEL_COLORS[d.name] }} aria-hidden="true" />
            {d.name} {d.count}
          </li>
        ))}
      </ul>
    </div>
  );
}

function RecentIncidents({ incidents }) {
  if (!incidents) return <Skeleton lines={6} />;
  if (incidents.length === 0) return <Empty>No incidents yet.</Empty>;
  const recent = [...incidents].sort((a, b) => new Date(b.started_at) - new Date(a.started_at)).slice(0, 7);
  return (
    <table className="w-full text-left text-sm">
      <thead>
        <tr>
          <th className="px-2 py-1.5">Host</th>
          <th className="px-2 py-1.5">Risk</th>
          <th className="px-2 py-1.5">Status</th>
          <th className="px-2 py-1.5"><span className="sr-only">Open</span></th>
        </tr>
      </thead>
      <tbody>
        {recent.map((i) => (
          <tr key={i.id}>
            <td className="max-w-[14rem] truncate px-2 py-1.5 text-slate-200" title={i.host}>{i.host}</td>
            <td className="px-2 py-1.5"><RiskBadge level={i.risk_level} score={i.risk_score} /></td>
            <td className="px-2 py-1.5"><StatusBadge status={i.status} /></td>
            <td className="px-2 py-1.5 text-right">
              <Link to={`/incidents/${i.id}`} className="text-sky-400 hover:text-sky-300">Open &rarr;</Link>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// Latest events as returned by /events: the server already redacts fields the role may not see.
function EventFeed({ events }) {
  const items = events?.items ?? [];
  const fresh = useNewIds(items);
  if (!events) return <Skeleton lines={7} />;
  if (items.length === 0) return <Empty>No events collected yet.</Empty>;
  return (
    <ul className="dash-feed text-sm">
      {items.map((ev) => (
        <li key={ev.id} className={`dash-feed-row ${fresh.has(ev.id) ? "row-flash" : ""}`}>
          <span className="font-mono text-xs tabular-nums text-slate-500">{fmtTime(ev.timestamp)}</span>
          <span className="font-mono text-xs text-sky-300">{ev.event_id}</span>
          <span className="min-w-0 truncate text-slate-200" title={`${ev.host} · ${ev.channel}`}>
            {ev.host} <span className="text-slate-500">· {basename(ev.process) !== "—" ? basename(ev.process) : ev.channel}</span>
          </span>
          <span className="truncate text-right text-xs text-slate-400" title={ev.user || ""}>{ev.user || ""}</span>
        </li>
      ))}
    </ul>
  );
}

function DeviceTiles({ devices }) {
  if (!devices) return <Skeleton lines={4} />;
  if (devices.length === 0) return <Empty>No devices have checked in yet.</Empty>;
  return (
    <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
      {devices.map((d) => (
        <div key={`${d.host}|${d.source}`} className="dash-tile rounded border p-2.5">
          <div className="flex items-center gap-2">
            <span
              className={d.status === "online" ? "live-dot" : "inline-block h-2 w-2 rounded-full"}
              style={d.status === "online" ? undefined : { background: DEVICE_COLORS[d.status] }}
              aria-hidden="true"
            />
            <span className="min-w-0 truncate text-sm text-slate-200" title={d.host}>{d.host}</span>
          </div>
          <p className="mt-1 text-xs text-slate-500">
            {d.status}{d.simulated ? " · simulated" : ""} · {d.events_last_5m} in 5m
          </p>
        </div>
      ))}
    </div>
  );
}

// Hosts ranked by their highest incident risk; bar length = that score out of 100.
function TopHosts({ incidents }) {
  if (!incidents) return <Skeleton lines={5} />;
  const byHost = {};
  for (const i of incidents) {
    const h = byHost[i.host] || (byHost[i.host] = { host: i.host, score: 0, level: "Low", count: 0 });
    h.count += 1;
    if (i.risk_score > h.score) Object.assign(h, { score: i.risk_score, level: i.risk_level });
  }
  const hosts = Object.values(byHost).sort((a, b) => b.score - a.score).slice(0, 6);
  if (hosts.length === 0) return <Empty>No hosts with incidents.</Empty>;
  return (
    <ul className="space-y-2.5 text-sm">
      {hosts.map((h) => (
        <li key={h.host}>
          <div className="mb-1 flex justify-between gap-2">
            <span className="truncate text-slate-200" title={h.host}>{h.host}</span>
            <span className="shrink-0 tabular-nums text-slate-400">
              {Math.round(h.score)} · {h.count} incident{h.count === 1 ? "" : "s"}
            </span>
          </div>
          <div className="dash-bar">
            <span style={{ width: `${Math.min(100, h.score)}%`, background: LEVEL_COLORS[h.level] }} />
          </div>
        </li>
      ))}
    </ul>
  );
}

// One tile per ATT&CK tactic: detection hits summed over its techniques, coloured by the worst level seen.
function TacticStrip({ matrix }) {
  if (!matrix) return <Skeleton lines={3} />;
  if (matrix.tactics.length === 0) return <Empty>No ATT&CK coverage data.</Empty>;
  const tiles = matrix.tactics.map((col) => {
    const hits = col.techniques.reduce((sum, t) => sum + t.hit_count, 0);
    const worst = col.techniques.reduce(
      (best, t) => (LEVEL_ORDER.indexOf(t.max_risk_level) > LEVEL_ORDER.indexOf(best) ? t.max_risk_level : best),
      null,
    );
    return { tactic: col.tactic, hits, worst };
  });
  return (
    <div className="dash-tactics">
      {tiles.map((t) => (
        <Link
          key={t.tactic}
          to="/attack"
          className="dash-tactic rounded border"
          style={t.worst ? { borderColor: LEVEL_COLORS[t.worst], boxShadow: `inset 0 3px 0 ${LEVEL_COLORS[t.worst]}` } : undefined}
          title={`${t.tactic}: ${t.hits} detection hit${t.hits === 1 ? "" : "s"}`}
        >
          <span className={`text-xl font-semibold tabular-nums ${t.hits ? "text-slate-100" : "text-slate-600"}`}>{t.hits}</span>
          <span className="text-xs leading-tight text-slate-400">{t.tactic}</span>
        </Link>
      ))}
    </div>
  );
}

export default function Dashboard() {
  const { can } = useAuth();
  const [data, setData] = useState({});
  const [error, setError] = useState("");
  const [autoRefresh, setAutoRefresh, tick] = useAutoRefresh(15);

  useEffect(() => {
    // Fetch on mount and on every auto-refresh tick; widgets update in place.
    if (!can("read")) return;
    const keys = Object.keys(SOURCES);
    Promise.allSettled(keys.map((k) => get(SOURCES[k]))).then((results) => {
      const next = {};
      let failed = 0;
      results.forEach((r, i) => {
        if (r.status === "fulfilled") next[keys[i]] = r.value;
        else failed += 1;
      });
      setData((prev) => ({ ...prev, ...next }));
      setError(failed ? "Some dashboard data could not be loaded." : "");
    });
  }, [tick, can]);

  if (!can("read")) return <p className="text-slate-400">Your role cannot view the dashboard.</p>;

  const { incidents = null, detections = null, events = null, devices = null, matrix = null } = data;
  const online = devices ? devices.filter((d) => d.status === "online").length : null;
  const top = incidents?.reduce((best, i) => (!best || i.risk_score > best.risk_score ? i : best), null);

  return (
    <div className="dash">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-xl font-semibold text-slate-100">Dashboard</h1>
        <AutoRefreshToggle enabled={autoRefresh} onChange={setAutoRefresh} />
      </div>
      {error && <p className="mb-3 text-sm text-amber-400">{error}</p>}

      <div className="dash-grid">
        <div className="dash-stats span-12">
          <StatTile label="Incidents" value={incidents && incidents.length} />
          <StatTile label="Detections" value={detections && detections.length} />
          <StatTile label="Events collected" value={events && events.total} />
          <StatTile label="Online devices" value={online}>
            <CountUp value={online ?? 0} />
            <span className="text-base font-normal text-slate-500"> / {devices?.length ?? 0}</span>
          </StatTile>
          <StatTile label="Highest risk" value={incidents && (top ? top.risk_score : 0)}>
            {top ? (
              <span style={{ color: LEVEL_COLORS[top.risk_level] }}>
                <CountUp value={Math.round(top.risk_score)} />
                <span className="ml-2 text-sm font-medium">{top.risk_level}</span>
              </span>
            ) : (
              <span className="text-slate-500">—</span>
            )}
          </StatTile>
        </div>

        <Panel title="Detections by severity" span="span-4"><SeverityChart detections={detections} /></Panel>
        <Panel title="Top ATT&CK techniques" span="span-5"><TechniqueChart detections={detections} /></Panel>
        <Panel title="Incidents by risk" span="span-3"><RiskDonut incidents={incidents} /></Panel>

        <Panel title="Recent incidents" span="span-5"
          action={<Link to="/incidents" className="text-xs text-sky-400 hover:text-sky-300">All incidents &rarr;</Link>}>
          <RecentIncidents incidents={incidents} />
        </Panel>
        <Panel title="Live event feed" span="span-4"
          action={<span className={`live-dot${autoRefresh ? "" : " off"}`} title={autoRefresh ? "Auto-refresh on" : "Auto-refresh off"} />}>
          <EventFeed events={events} />
        </Panel>
        <Panel title="Devices" span="span-3"
          action={<Link to="/devices" className="text-xs text-sky-400 hover:text-sky-300">Details &rarr;</Link>}>
          <DeviceTiles devices={devices} />
        </Panel>

        <Panel title="Top hosts by risk" span="span-5"><TopHosts incidents={incidents} /></Panel>
        <Panel title="ATT&CK tactics" span="span-7"
          action={<Link to="/attack" className="text-xs text-sky-400 hover:text-sky-300">Matrix &rarr;</Link>}>
          <TacticStrip matrix={matrix} />
        </Panel>
      </div>
    </div>
  );
}
