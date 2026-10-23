import { useEffect, useMemo, useState } from "react";
import { get } from "../lib/api";
import { TIBadge } from "../components/TIBadge";

const PAGE_SIZE = 25;

const SOURCE_BADGE = {
  agent: "bg-sky-900/60 text-sky-300",
  local: "bg-sky-900/60 text-sky-300",
  upload: "bg-violet-900/60 text-violet-300",
  simulated: "bg-amber-900/60 text-amber-300",
};

export default function LogExplorer() {
  const [q, setQ] = useState("");
  const [channel, setChannel] = useState("");
  const [host, setHost] = useState("");
  const [eventId, setEventId] = useState("");
  const [page, setPage] = useState(1);

  const [data, setData] = useState({ total: 0, items: [] });
  const [flaggedIds, setFlaggedIds] = useState(new Set());
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    get("/detections")
      .then((detections) => {
        const ids = new Set();
        detections.forEach((d) => d.matched_event_ids.forEach((id) => ids.add(id)));
        setFlaggedIds(ids);
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
  }, [q, channel, host, eventId, page]);

  const totalPages = useMemo(
    () => Math.max(1, Math.ceil(data.total / PAGE_SIZE)),
    [data.total],
  );

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
        <input
          placeholder="Channel"
          value={channel}
          onChange={(e) => resetToFirstPage(setChannel)(e.target.value)}
          className="w-40 rounded border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-100 outline-none focus:border-sky-600"
        />
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

      {error && <p className="mb-3 text-sm text-red-400">{error}</p>}

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
              <th className="px-3 py-2">Message</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td colSpan={8} className="px-3 py-6 text-center text-slate-500">
                  Loading...
                </td>
              </tr>
            )}
            {!loading && data.items.length === 0 && (
              <tr>
                <td colSpan={8} className="px-3 py-6 text-center text-slate-500">
                  No events found.
                </td>
              </tr>
            )}
            {!loading &&
              data.items.map((ev) => {
                const flagged = flaggedIds.has(ev.id);
                return (
                  <tr
                    key={ev.id}
                    className={`border-t border-slate-800 ${
                      flagged ? "bg-red-950/40" : "hover:bg-slate-900/60"
                    }`}
                  >
                    <td className="whitespace-nowrap px-3 py-2 text-slate-300">
                      {new Date(ev.timestamp).toLocaleString()}
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
                        {flagged && <span className="h-1.5 w-1.5 rounded-full bg-red-500" />}
                        {ev.event_id}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-slate-300">{ev.user || "—"}</td>
                    <td className="max-w-[12rem] truncate px-3 py-2 text-slate-300" title={ev.process || ""}>
                      {ev.process || "—"}
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
    </div>
  );
}
