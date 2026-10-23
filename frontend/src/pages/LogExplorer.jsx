import { useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { get } from "../lib/api";
import { rowOpenProps } from "../lib/a11y";
import { EventDrawer } from "../components/DetailDrawers";
import { TIBadge } from "../components/TIBadge";
import { TimeAgo } from "../components/TimeAgo";
import { ErrorBanner, EmptyRow, SkeletonRows } from "../components/States";
import { TableToolbar, useCsvExport, useTableView } from "../components/TableTools";
import { useAutoRefresh } from "../components/AutoRefresh";
import { useNewIds } from "../components/useNewIds";

const PAGE_SIZE = 25;

const SOURCE_BADGE = {
  agent: "bg-cyan-900/60 text-cyan-300",
  local: "bg-cyan-900/60 text-cyan-300",
  upload: "bg-violet-900/60 text-violet-300",
  simulated: "bg-amber-900/60 text-amber-300",
  "local-net": "bg-emerald-900/60 text-emerald-300",
};

const CHANNELS = ["Security", "System", "Microsoft-Windows-PowerShell/Operational", "Network"];

// Table columns. `exports` = the server's CSV columns for it (GET /events/export).
const COLUMNS = [
  { key: "timestamp", label: "Timestamp", exports: ["timestamp"], cell: (ev) => <TimeAgo ts={ev.timestamp} />, className: "whitespace-nowrap text-slate-300" },
  {
    key: "source",
    label: "Source",
    exports: ["source"],
    cell: (ev) => (
      <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${SOURCE_BADGE[ev.source] || "bg-slate-800 text-slate-300"}`}>
        {ev.source}
      </span>
    ),
  },
  { key: "host", label: "Host", exports: ["host"], cell: (ev) => ev.host, className: "text-slate-300" },
  { key: "channel", label: "Channel", exports: ["channel"], cell: (ev) => ev.channel, className: "text-slate-300" },
  {
    key: "event_id",
    label: "Event ID",
    exports: ["event_id"],
    className: "text-slate-300",
    cell: (ev, flagged) => (
      <span className="inline-flex items-center gap-1.5">
        {flagged && <span className="h-1.5 w-1.5 rounded-full bg-red-500" aria-label="flagged by a rule" />}
        {ev.event_id}
      </span>
    ),
  },
  { key: "user", label: "User", exports: ["user"], cell: (ev) => ev.user || "—", className: "text-slate-300" },
  { key: "process", label: "Process", exports: ["process"], cell: (ev) => <span title={ev.process || ""}>{ev.process || "—"}</span>, className: "max-w-[12rem] truncate text-slate-300" },
  {
    key: "destination",
    label: "Destination",
    exports: ["dst_ip", "dst_port"],
    className: "whitespace-nowrap font-mono text-xs text-slate-300",
    cell: (ev) => (ev.channel === "Network" && ev.dst_ip ? `${ev.dst_ip}${ev.dst_port != null ? `:${ev.dst_port}` : ""}` : "—"),
  },
  {
    key: "message",
    label: "Message",
    exports: ["command_line", "message"],
    className: "max-w-[20rem] truncate text-slate-400",
    cell: (ev) => (
      <span title={ev.message || ""}>
        <TIBadge matches={ev.ti_matches} /> {ev.message || ev.command_line || "—"}
      </span>
    ),
  },
];

export default function LogExplorer() {
  const [params] = useSearchParams();
  const [q, setQ] = useState(params.get("q") || "");
  const [channel, setChannel] = useState("");
  const [host, setHost] = useState(params.get("host") || "");
  const [eventId, setEventId] = useState("");
  const [page, setPage] = useState(1);

  const [data, setData] = useState({ total: 0, items: [] });
  // event id -> detections whose evidence includes it (flags rows, feeds the drawer)
  const [flagged, setFlagged] = useState(new Map());
  const [selectedId, setSelectedId] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [reload, setReload] = useState(0); // bumped by Retry
  const view = useTableView("events", COLUMNS);
  const [exporting, runExport] = useCsvExport();
  const [, , tick] = useAutoRefresh(); // live signal: reload in place
  const lastQuery = useRef(null);
  const fresh = useNewIds(loading ? [] : data.items); // a filter change flashes nothing

  useEffect(() => {
    get("/detections")
      .then((detections) => {
        const byEvent = new Map();
        detections.forEach((d) =>
          d.matched_event_ids.forEach((id) => byEvent.set(id, [...(byEvent.get(id) || []), d])),
        );
        setFlagged(byEvent);
      })
      .catch(() => {
        // Detections are a highlight-only enhancement; ignore failures here.
      });
  }, [tick]);

  const filterParams = useMemo(() => {
    const p = new URLSearchParams();
    if (q) p.set("q", q);
    if (channel) p.set("channel", channel);
    if (host) p.set("host", host);
    if (eventId) p.set("event_id", eventId);
    return p.toString();
  }, [q, channel, host, eventId]);

  useEffect(() => {
    // Skeleton only when the query changed; a live refresh updates rows in place.
    const query = `${filterParams}|${page}|${reload}`;
    if (lastQuery.current !== query) setLoading(true);
    lastQuery.current = query;
    setError("");
    get(`/events?${filterParams}&page=${page}&page_size=${PAGE_SIZE}`)
      .then(setData)
      .catch((err) => setError(err.message || "Failed to load events"))
      .finally(() => setLoading(false));
  }, [filterParams, page, reload, tick]);

  const totalPages = useMemo(
    () => Math.max(1, Math.ceil(data.total / PAGE_SIZE)),
    [data.total],
  );

  function applyFilters(f) {
    setQ(f.q || "");
    setChannel(f.channel || "");
    setHost(f.host || "");
    setEventId(f.eventId || "");
    setPage(1);
  }

  const clearFilters = () => applyFilters({});

  function resetToFirstPage(setter) {
    return (value) => {
      setter(value);
      setPage(1);
    };
  }

  function exportCsv() {
    const columns = ["id", ...view.visible.flatMap((c) => c.exports)].join(",");
    runExport(`/events/export?${filterParams}${filterParams ? "&" : ""}columns=${columns}`, "events.csv");
  }

  return (
    <div>
      <h1 className="mb-4 text-xl font-semibold text-slate-100">Log Explorer</h1>

      <div className="ir-filterbar">
        <div className="flex flex-wrap gap-3">
          <input
            placeholder="Search message, command, user, process..."
            aria-label="Search events"
            value={q}
            onChange={(e) => resetToFirstPage(setQ)(e.target.value)}
            className="w-72 rounded border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-100 outline-none focus:border-sky-600"
          />
          <select
            value={channel}
            aria-label="Channel"
            onChange={(e) => resetToFirstPage(setChannel)(e.target.value)}
            className="w-48 rounded border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-100 outline-none focus:border-sky-600"
          >
            <option value="">All channels</option>
            {CHANNELS.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
          <input
            placeholder="Host"
            aria-label="Host"
            value={host}
            onChange={(e) => resetToFirstPage(setHost)(e.target.value)}
            className="w-40 rounded border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-100 outline-none focus:border-sky-600"
          />
          <input
            placeholder="Event ID"
            aria-label="Event ID"
            value={eventId}
            onChange={(e) => resetToFirstPage(setEventId)(e.target.value.replace(/\D/g, ""))}
            className="w-28 rounded border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-100 outline-none focus:border-sky-600"
          />
        </div>
        <TableToolbar
          table="events"
          columns={COLUMNS}
          view={view}
          filters={{ q, channel, host, eventId }}
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
            {!loading && !error && data.items.length === 0 && (
              <EmptyRow colSpan={view.visible.length} title="No events found"
                hint="Try a broader search or clear the filters. Live events arrive when scripts/collector.py runs from an elevated terminal."
                action={{ onClick: clearFilters, label: "Clear filters" }} />
            )}
            {!loading &&
              data.items.map((ev) => {
                const isFlagged = flagged.has(ev.id);
                return (
                  <tr
                    key={ev.id}
                    className={`border-t border-slate-800 ${isFlagged ? "bg-red-950/40" : "hover:bg-slate-900/60"}${fresh.has(ev.id) ? " row-flash" : ""}`}
                    {...rowOpenProps(() => setSelectedId(ev.id), ev.id === selectedId)}
                  >
                    {view.visible.map((c) => (
                      <td key={c.key} className={`px-3 py-2 ${c.className || ""}`}>{c.cell(ev, isFlagged)}</td>
                    ))}
                  </tr>
                );
              })}
          </tbody>
        </table>
      </div>

      <div className="mt-4 flex items-center justify-between text-sm text-slate-400">
        <span>
          {data.total} event{data.total === 1 ? "" : "s"} · page {page} of {totalPages}
        </span>
        <div className="flex gap-2">
          <button
            disabled={page <= 1}
            onClick={() => setPage((p) => p - 1)}
            className="rounded border border-slate-700 px-3 py-1 disabled:opacity-40"
          >
            Prev
          </button>
          <button
            disabled={page >= totalPages}
            onClick={() => setPage((p) => p + 1)}
            className="rounded border border-slate-700 px-3 py-1 disabled:opacity-40"
          >
            Next
          </button>
        </div>
      </div>
      <EventDrawer
        event={data.items.find((ev) => ev.id === selectedId)}
        detections={flagged.get(selectedId)}
        onClose={() => setSelectedId(null)}
        onFilterHost={(h) => {
          setSelectedId(null);
          resetToFirstPage(setHost)(h);
        }}
      />
    </div>
  );
}
