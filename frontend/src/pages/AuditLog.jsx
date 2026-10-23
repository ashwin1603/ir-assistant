import { useEffect, useState } from "react";
import { get } from "../lib/api";
import { useAuth } from "../auth/AuthContext";

const PAGE_SIZE = 25;

export default function AuditLog() {
  const { can } = useAuth();
  const isAdmin = can("read_audit");

  const [entries, setEntries] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!isAdmin) return;
    setLoading(true);
    get(`/audit?page=${page}&page_size=${PAGE_SIZE}`)
      .then((data) => {
        setEntries(data.items ?? []);
        setTotal(data.total ?? 0);
      })
      .catch((err) => setError(err.message || "Failed to load audit log"))
      .finally(() => setLoading(false));
  }, [page, isAdmin]);

  if (!isAdmin) {
    return <p className="text-slate-500">Admins only.</p>;
  }

  const lastPage = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div>
      <h1 className="mb-4 text-xl font-semibold text-slate-100">Audit Log</h1>

      {error && <p className="mb-3 text-sm text-red-400">{error}</p>}

      <div className="overflow-x-auto rounded border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900 text-slate-400">
            <tr>
              <th className="px-3 py-2">Timestamp</th>
              <th className="px-3 py-2">Actor</th>
              <th className="px-3 py-2">Action</th>
              <th className="px-3 py-2">Detail</th>
              <th className="px-3 py-2">Result</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td colSpan={5} className="px-3 py-6 text-center text-slate-500">
                  Loading...
                </td>
              </tr>
            )}
            {!loading && entries.length === 0 && (
              <tr>
                <td colSpan={5} className="px-3 py-6 text-center text-slate-500">
                  No audit entries found.
                </td>
              </tr>
            )}
            {!loading &&
              entries.map((e) => (
                <tr key={e.id} className="border-t border-slate-800 align-top hover:bg-slate-900/60">
                  <td className="whitespace-nowrap px-3 py-2 text-slate-400">
                    {new Date(e.timestamp).toLocaleString()}
                  </td>
                  <td className="px-3 py-2 text-slate-200">{e.actor || "—"}</td>
                  <td className="px-3 py-2 text-slate-300">{e.action}</td>
                  <td className="px-3 py-2 text-slate-400">{e.detail || "—"}</td>
                  <td className="px-3 py-2">
                    <span
                      className={`rounded px-2 py-0.5 text-xs font-medium ${
                        e.success ? "bg-emerald-900/60 text-emerald-300" : "bg-red-900/70 text-red-300"
                      }`}
                    >
                      {e.success ? "Success" : "Failed"}
                    </span>
                  </td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>

      {total > PAGE_SIZE && (
        <div className="mt-3 flex items-center justify-between text-sm text-slate-400">
          <span>
            Page {page} of {lastPage} &middot; {total} entries
          </span>
          <div className="flex gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
              className="rounded border border-slate-700 px-3 py-1 text-slate-300 hover:border-slate-500 hover:text-white disabled:opacity-40"
            >
              Previous
            </button>
            <button
              onClick={() => setPage((p) => Math.min(lastPage, p + 1))}
              disabled={page >= lastPage}
              className="rounded border border-slate-700 px-3 py-1 text-slate-300 hover:border-slate-500 hover:text-white disabled:opacity-40"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
