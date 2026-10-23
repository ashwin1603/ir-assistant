import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { get } from "../lib/api";
import { rowOpenProps } from "../lib/a11y";
import { EventDrawer } from "../components/DetailDrawers";
import { TIBadge } from "../components/TIBadge";
import { TimeAgo } from "../components/TimeAgo";
import { ErrorBanner, EmptyRow, SkeletonRows } from "../components/States";

const PAGE_SIZE = 25;

const SOURCE_BADGE = {
  agent: "bg-cyan-900/60 text-cyan-300",
  local: "bg-cyan-900/60 text-cyan-300",
  upload: "bg-violet-900/60 text-violet-300",
  simulated: "bg-amber-900/60 text-amber-300",
  "local-net": "bg-emerald-900/60 text-emerald-300",
};

const CHANNELS = ["Security", "System", "Microsoft-Windows-PowerShell/Operational", "Network"];

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
  }, []);

  useEffect(() => {
    const params = new URLSearchParams();
    if (q) params.set("q", q);
    if (channel) params.set("channel", channel);
    if (host) params.set("host", host);
    if (eventId) params.set("event_id", eventId);
    params.set("page", String(page));
    params.set("page_size", String(PAGE_SIZE));

    setLoading(true);
    setError("");
    get(`/events?${params.toString()}`)
      .then(setData)
      .catch((err) => setError(err.message || "Failed to load events"))
      .finally(() => setLoading(false));
  }, [q, channel, host, eventId, page, reload]);

  const totalPages = useMemo(
    () => Math.max(1, Math.ceil(data.total / PAGE_SIZE)),
    [data.total],
  );

  function clearFilters() {
    setQ("");
    setChannel("");
    setHost("");
    setEventId("");
    setPage(1);
  }

  function resetToFirstPage(setter) {

    return (value) => {
      setter(value);
      setPage(1);
    };
  }

  return (
    <div>
      <h1 className="mb-4 text-xl font-semibold text-slate-100">Log Explorer</h1>

      <div className="mb-4 flex flex-wrap gap-3">
        <input
          placeholder="Search message, command, user, process..."
          value={q}
          onChange={(e) => resetToFirstPage(setQ)(e.target.value)}
          className="w-72 rounded border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-100 outline-none focus:border-sky-600"
        />
        <select
          value={channel}
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
          value={host}
          onChange={(e) => resetToFirstPage(setHost)(e.target.value)}
          className="w-40 rounded border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-100 outline-none focus:border-sky-600"
        />
        <input
          placeholder="Event ID"
          value={eventId}
          onChange={(e) => resetToFirstPage(setEventId)(e.target.value.replace(/\D/g, ""))}
          className="w-28 rounded border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-100 outline-none focus:border-sky-600"
        />
      </div>

      <ErrorBanner message={error} onRetry={() => setReload((n) => n + 1)} />

      <div className="overflow-x-auto rounded border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900 text-slate-400">
            <tr>
              <th className="px-3 py-2">Timestamp</th>
              <th className="px-3 py-2">Source</th>
              <th className="px-3 py-2">Host</th>
              <th className="px-3 py-2">Channel</th>
              <th className="px-3 py-2">Event ID</th>
              <th className="px-3 py-2">User</th>
              <th className="px-3 py-2">Process</th>
              <th className="px-3 py-2">Destination</th>
              <th className="px-3 py-2">Message</th>
            </tr>
          </thead>
          <tbody>
            {loading && <SkeletonRows cols={9} />}
            {!loading && !error && data.items.length === 0 && <EmptyRow colSpan={9} title="No events found" hint="Try a broader search or clear the filters. Live events arrive when scripts/collector.py runs from an elevated terminal." action={{ onClick: clearFilters, label: "Clear filters" }} />}
            {!loading &&
              data.items.map((ev) => {
                const isFlagged = flagged.has(ev.id);
                return (
                  <tr
                    key={ev.id}
                    className={`border-t border-slate-800 ${
                      isFlagged ? "bg-red-950/40" : "hover:bg-slate-900/60"
                    }`}
                    {...rowOpenProps(() => setSelectedId(ev.id), ev.id === selectedId)}
                  >
                    <td className="whitespace-nowrap px-3 py-2 text-slate-300">
                      <TimeAgo ts={ev.timestamp} />
                    </td>
                    <td className="px-3 py-2">
                      <span
                        className={`rounded px-1.5 py-0.5 text-xs font-medium ${
                          SOURCE_BADGE[ev.source] || "bg-slate-800 text-slate-300"
                        }`}
                      >
                        {ev.source}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-slate-300">{ev.host}</td>
                    <td className="px-3 py-2 text-slate-300">{ev.channel}</td>
                    <td className="px-3 py-2 text-slate-300">
                      <span className="inline-flex items-center gap-1.5">
                        {isFlagged && <span className="h-1.5 w-1.5 rounded-full bg-red-500" />}
                        {ev.event_id}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-slate-300">{ev.user || "—"}</td>
                    <td className="max-w-[12rem] truncate px-3 py-2 text-slate-300" title={ev.process || ""}>
                      {ev.process || "—"}
                    </td>
                    <td className="whitespace-nowrap px-3 py-2 font-mono text-xs text-slate-300">
                      {ev.channel === "Network" && ev.dst_ip
                        ? `${ev.dst_ip}${ev.dst_port != null ? `:${ev.dst_port}` : ""}`
                        : "—"}
                    </td>
                    <td className="max-w-[20rem] truncate px-3 py-2 text-slate-400" title={ev.message || ""}>
                      <TIBadge matches={ev.ti_matches} /> {ev.message || ev.command_line || "—"}
                    </td>
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
