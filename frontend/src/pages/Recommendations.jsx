import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { get, post, ApiError } from "../lib/api";
import { useAuth } from "../auth/AuthContext";
import { Skeleton } from "../components/Skeleton";

const STATUS_STYLES = {
  pending: "bg-slate-800 text-slate-300",
  approved: "bg-emerald-900/60 text-emerald-300",
  rejected: "bg-red-900/70 text-red-300",
};

export default function Recommendations() {
  const { can } = useAuth();
  const canDecide = can("decide_actions");

  const [actions, setActions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [busyId, setBusyId] = useState(null);

  function load() {
    setLoading(true);
    get("/actions")
      .then(setActions)
      .catch((err) => setError(err.message || "Failed to load recommendations"))
      .finally(() => setLoading(false));
  }

  useEffect(load, []);

  async function decide(action, decision) {
    setBusyId(action.id);
    setError("");
    try {
      const updated = await post(`/actions/${action.id}/${decision}`);
      setActions((prev) => prev.map((a) => (a.id === updated.id ? updated : a)));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to update action");
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div>
      <h1 className="mb-1 text-xl font-semibold text-slate-100">Recommendations</h1>
      <p className="mb-4 text-sm text-slate-500">
        Approve/Reject is <span className="font-medium text-slate-400">simulated</span> — no action is
        actually executed against the host.
      </p>

      {error && <p className="mb-3 text-sm text-red-400">{error}</p>}

      <div className="overflow-x-auto rounded border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900 text-slate-400">
            <tr>
              <th className="px-3 py-2">Recommended action</th>
              <th className="px-3 py-2">Incident</th>
              <th className="px-3 py-2">Status</th>
              <th className="px-3 py-2">Decided by</th>
              <th className="px-3 py-2" />
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td colSpan={5} className="px-3 py-4">
                  <Skeleton lines={4} />
                </td>
              </tr>
            )}
            {!loading && actions.length === 0 && (
              <tr>
                <td colSpan={5} className="px-3 py-6 text-center text-slate-500">
                  No recommendations yet. Run an AI analysis on an incident first.
                </td>
              </tr>
            )}
            {!loading &&
              actions.map((a) => (
                <tr key={a.id} className="border-t border-slate-800 align-top hover:bg-slate-900/60">
                  <td className="px-3 py-2 text-slate-200">{a.action_text}</td>
                  <td className="whitespace-nowrap px-3 py-2">
                    <Link to={`/incidents/${a.incident_id}`} className="text-sky-400 hover:text-sky-300">
                      {a.incident_host} &middot; {new Date(a.incident_started_at).toLocaleString()}
                    </Link>
                  </td>
                  <td className="px-3 py-2">
                    <span
                      className={`rounded px-2 py-0.5 text-xs font-medium capitalize ${
                        STATUS_STYLES[a.status] || "bg-slate-800 text-slate-300"
                      }`}
                    >
                      {a.status}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-slate-400">{a.decided_by || "—"}</td>
                  <td className="px-3 py-2 text-right">
                    {a.status === "pending" && canDecide && (
                      <div className="flex justify-end gap-2">
                        <button
                          disabled={busyId === a.id}
                          onClick={() => decide(a, "approve")}
                          className="rounded border border-emerald-700 px-2 py-1 text-xs text-emerald-300 hover:bg-emerald-900/40 disabled:opacity-50"
                        >
                          Approve
                        </button>
                        <button
                          disabled={busyId === a.id}
                          onClick={() => decide(a, "reject")}
                          className="rounded border border-red-700 px-2 py-1 text-xs text-red-300 hover:bg-red-900/40 disabled:opacity-50"
                        >
                          Reject
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
