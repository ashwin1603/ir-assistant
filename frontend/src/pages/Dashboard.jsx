import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { get } from "../lib/api";
import { useAuth } from "../auth/AuthContext";
import { AutoRefreshToggle, liveDotClass, useAutoRefresh } from "../components/AutoRefresh";
import { useLive } from "../components/LiveProvider";
import { Skeleton } from "../components/Skeleton";
import { CountUp } from "../components/CountUp";
import { RiskBadge } from "../components/RiskBadge";
import { SEV_LEVELS, SevIcon, sevColor, sevInk } from "../components/Severity";
import { StatusBadge } from "../components/StatusBadge";
import { useNewIds } from "../components/useNewIds";
import { TimeAgo } from "../components/TimeAgo";
import { Sparkline } from "../components/Sparkline";
import { EmptyState, ErrorBanner } from "../components/States";


const LEVEL_ORDER = SEV_LEVELS;

// Matches RiskBadge's existing color language so the dashboard reads as one system with the rest of the app.
const LEVEL_COLORS = Object.fromEntries(SEV_LEVELS.map((l) => [l, sevColor(l)]));

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


const basename = (path) => (path ? path.split(/[\\/]/).pop() : "—");

// Counts of timestamps in `buckets` equal slices from the oldest one up to now (sparklines).
function bucketCounts(timestamps, buckets = 12) {
  if (!timestamps.length) return [];
  const times = timestamps.map((t) => new Date(t).getTime());
  const end = Date.now();
  const start = Math.min(...times);
  const size = Math.max(1, (end - start) / buckets);
  const counts = Array(buckets).fill(0);
  for (const t of times) counts[Math.min(buckets - 1, Math.floor((t - start) / size))] += 1;
  return counts;
}

// Values seen on earlier refreshes this session (events total, online devices), for the
// sparklines of numbers the API only reports as a current total. Module-level so it
// survives navigating away and back.
const HISTORY_SIZE = 20;
const history = { events: [], online: [] };
function remember(key, value) {
  if (value === null || value === undefined) return;
  history[key] = [...history[key], value].slice(-HISTORY_SIZE);
}

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

function Empty({ children, hint, action }) {
  return (
    <div className="dash-empty">
      <EmptyState compact title={children} hint={hint} action={action} />
    </div>
  );
}

function StatTile({ label, value, spark, sparkTip, sparkColor, children }) {
  return (
    <div className="glass dash-stat rounded border p-4">
      <p className="text-xs font-semibold uppercase tracking-wide text-slate-400">{label}</p>
      {value === null ? (
        <span className="skeleton mt-2" style={{ width: "4rem", height: "1.6rem" }} />
      ) : (
        <p className="mt-1 text-2xl font-semibold tabular-nums text-slate-100">{children ?? <CountUp value={value} />}</p>
      )}
      <Sparkline values={spark} tip={sparkTip} color={sparkColor} />
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

// Plain CSS bars: always render, no SVG sizing issues inside the flex panels.
function SeverityChart({ detections }) {
  if (!detections) return <Skeleton lines={5} />;
  if (detections.length === 0) return <Empty hint="Rules flag suspicious events as they arrive.">No detections yet.</Empty>;
  const data = LEVEL_ORDER.map((level) => ({ name: level, count: detections.filter((d) => d.risk_level === level).length }));
  const max = Math.max(1, ...data.map((d) => d.count));
  return (
    <div className="dash-cols" role="list" aria-label="Detections by severity">
      {data.map((d) => (
        <div key={d.name} className="dash-col" role="listitem" data-tip={`${d.name}: ${d.count} detection${d.count === 1 ? "" : "s"}`}>
          <span className="text-sm font-semibold tabular-nums text-slate-200">{d.count}</span>
          <div className="dash-col-track">
            <span style={{ height: `${(d.count / max) * 100}%`, background: LEVEL_COLORS[d.name] }} />
          </div>
          <span className="sev text-xs text-slate-400"><SevIcon level={d.name} style={{ color: LEVEL_COLORS[d.name] }} />{d.name}</span>
        </div>
      ))}
    </div>
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
  if (data.length === 0) return <Empty hint="ATT&CK techniques appear with the first detection.">No techniques observed yet.</Empty>;
  const max = data[0].count;
  const riskiest = detections.reduce((best, d) => (!best || d.risk_score > best.risk_score ? d : best), null);
  const tacticCounts = {};
  for (const d of detections) for (const t of d.tactics) tacticCounts[t] = (tacticCounts[t] || 0) + 1;
  const tactics = Object.entries(tacticCounts).sort((a, b) => b[1] - a[1]);
  const tacticTotal = tactics.reduce((sum, [, n]) => sum + n, 0);
  return (
    <div className="flex h-full flex-col gap-4">
    <ul className="space-y-2 text-sm">
      {data.map((d) => (
        <li key={d.name} className="dash-hbar" data-tip={`${d.name}: ${d.count} detection${d.count === 1 ? "" : "s"}`}>
          <Link to={`/attack/${d.name}`} className="truncate font-mono text-xs text-slate-300 hover:text-sky-300">{d.name}</Link>
          <div className="dash-bar">
            <span className="ir-bar-fill" style={{ width: `${(d.count / max) * 100}%` }} />
          </div>
          <span className="text-right tabular-nums text-slate-400">{d.count}</span>
        </li>
      ))}
    </ul>
    {/* Fills the rest of the card: the riskiest technique and the tactic mix. */}
    <div className="dash-subcard mt-auto">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2 text-sm">
        <span className="text-xs uppercase tracking-wide text-slate-400">Highest-risk technique</span>
        <span className="flex items-center gap-2">
          <Link to={`/attack/${riskiest.technique_ids[0]}`} className="font-mono text-xs text-slate-200 hover:text-sky-300">
            {riskiest.technique_ids[0]}
          </Link>
          <RiskBadge level={riskiest.risk_level} score={riskiest.risk_score} />
        </span>
      </div>
      <p className="mb-1.5 text-xs uppercase tracking-wide text-slate-400">Tactic mix</p>
      <div className="dash-mix" role="img" aria-label={tactics.map(([t, n]) => `${t} ${n}`).join(", ")}>
        {tactics.map(([t, n], i) => (
          <span key={t} data-tip={`${t}: ${n} (${Math.round((n / tacticTotal) * 100)}%)`}
            style={{ width: `${(n / tacticTotal) * 100}%`, opacity: 1 - (i % 6) * 0.13 }} />
        ))}
      </div>
    </div>
    </div>
  );
}

// Incidents per risk level as a donut, with the total in the middle.
function RiskDonut({ incidents }) {
  if (!incidents) return <Skeleton lines={5} />;
  if (incidents.length === 0) return <Empty>No incidents yet.</Empty>;
  const legend = LEVEL_ORDER.map((level) => ({ name: level, count: incidents.filter((i) => i.risk_level === level).length }));
  const data = legend.filter((d) => d.count > 0); // zero slices are not drawn, but stay in the legend
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
        {legend.map((d) => (
          <li key={d.name} className={`flex items-center gap-1.5${d.count ? "" : " opacity-60"}`}>
            <SevIcon level={d.name} style={{ color: LEVEL_COLORS[d.name] }} />
            {d.name} {d.count}
          </li>
        ))}
      </ul>
    </div>
  );
}

function RecentIncidents({ incidents }) {
  if (!incidents) return <Skeleton lines={6} />;
  if (incidents.length === 0) {
    return <Empty hint="Related detections on a host are grouped into incidents." action={{ to: "/detections", label: "View detections" }}>No incidents yet.</Empty>;
  }
  const recent = [...incidents].sort((a, b) => new Date(b.started_at) - new Date(a.started_at)).slice(0, 7);
  return (
    <table className="w-full text-left text-sm">
      <thead>
        <tr>
          <th className="px-2 py-1.5">Host</th>
          <th className="px-2 py-1.5">Risk</th>
          <th className="px-2 py-1.5">Status</th>
          <th className="px-2 py-1.5">Started</th>
          <th className="px-2 py-1.5"><span className="sr-only">Open</span></th>
        </tr>
      </thead>
      <tbody>
        {recent.map((i) => (
          <tr key={i.id}>
            <td className="max-w-[14rem] truncate px-2 py-1.5 text-slate-200" title={i.host}>{i.host}</td>
            <td className="px-2 py-1.5"><RiskBadge level={i.risk_level} score={i.risk_score} /></td>
            <td className="px-2 py-1.5"><StatusBadge status={i.status} /></td>
            <td className="px-2 py-1.5 text-xs text-slate-400"><TimeAgo ts={i.started_at} /></td>
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
  if (items.length === 0) {
    return <Empty hint="Run python scripts/collector.py --watch from an elevated terminal, or upload a log file.">No events collected yet.</Empty>;
  }
  return (
    <ul className="dash-feed text-sm">
      {items.map((ev) => (
        <li key={ev.id} className={`dash-feed-row ${fresh.has(ev.id) ? "row-flash" : ""}`}>
          <TimeAgo ts={ev.timestamp} className="text-xs tabular-nums text-slate-400" />
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
  if (devices.length === 0) return <Empty hint="The collector checks in every few seconds while it runs.">No devices have checked in yet.</Empty>;
  return (
    <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
      {devices.map((d) => (
        <div key={`${d.host}|${d.source}`} className="dash-tile rounded border p-2.5"
          data-tip={`${d.host} · ${d.source} · last seen ${d.last_seen ? new Date(d.last_seen).toLocaleString() : "never"}`}>
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
  if (hosts.length === 0) return <Empty hint="Hosts are ranked once they have an incident.">No hosts with incidents.</Empty>;
  return (
    <ul className="space-y-2.5 text-sm">
      {hosts.map((h) => (
        <li key={h.host} data-tip={`${h.host}: highest risk ${Math.round(h.score)} (${h.level}), ${h.count} incident${h.count === 1 ? "" : "s"}`}>
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
  if (matrix.tactics.length === 0) return <Empty hint="Coverage comes from the enabled detection rules.">No ATT&CK coverage data.</Empty>;
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
          data-tip={`${t.tactic}: ${t.hits} detection hit${t.hits === 1 ? "" : "s"}${t.worst ? `, worst ${t.worst}` : ""}`}
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
  const [reload, setReload] = useState(0); // bumped by Retry
  const [autoRefresh, setAutoRefresh, tick] = useAutoRefresh();
  const { status: liveStatus } = useLive();

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
      remember("events", next.events?.total);
      remember("online", next.devices?.filter((d) => d.status === "online").length);
      setData((prev) => ({ ...prev, ...next }));
      setError(failed ? "Some dashboard data could not be loaded." : "");
    });
  }, [tick, can, reload]);

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
      <ErrorBanner message={error} onRetry={() => setReload((n) => n + 1)} />

      <div className="dash-grid">
        <div className="dash-stats span-12">
          <StatTile label="Incidents" value={incidents && incidents.length}
            spark={incidents && bucketCounts(incidents.map((i) => i.started_at))} sparkTip="New incidents over time" />
          <StatTile label="Detections" value={detections && detections.length}
            spark={detections && bucketCounts(detections.map((d) => d.first_seen))} sparkTip="New detections over time" />
          <StatTile label="Events collected" value={events && events.total}
            spark={history.events} sparkTip="Total events at each refresh this session" />
          <StatTile label="Online devices" value={online}
            spark={history.online} sparkTip="Online devices at each refresh this session" sparkColor="var(--ir-live)">
            {online === 0 ? (
              <span className="text-lg font-medium text-slate-500" title="Run collector.py --watch to stream live events">
                Collector idle
              </span>
            ) : (
              <>
                <CountUp value={online ?? 0} />
                <span className="text-base font-normal text-slate-500"> / {devices?.length ?? 0}</span>
              </>
            )}
          </StatTile>
          <StatTile label="Highest risk" value={incidents && (top ? top.risk_score : 0)}
            spark={incidents && [...incidents].sort((a, b) => new Date(a.started_at) - new Date(b.started_at)).map((i) => i.risk_score)}
            sparkTip="Risk score of each incident, oldest first" sparkColor={top ? LEVEL_COLORS[top.risk_level] : undefined}>
            {top ? (
              <span style={{ color: sevInk(top.risk_level) }}>
                <CountUp value={Math.round(top.risk_score)} />
                <span className="sev ml-2 text-sm font-medium"><SevIcon level={top.risk_level} />{top.risk_level}</span>
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
          action={<span className={`live-dot ${liveDotClass(liveStatus)}`} data-tip={autoRefresh ? `Live updates: ${liveStatus}` : "Live updates off"} />}>
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
