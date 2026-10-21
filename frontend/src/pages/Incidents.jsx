import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { get } from "../lib/api";
import { RiskBadge } from "../components/RiskBadge";

export default function Incidents() {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    get("/incidents")
      .then(setIncidents)
      .catch((err) => setError(err.message || "Failed to load incidents"))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div>
      <h1 className="mb-4 text-xl font-semibold text-slate-100">Incidents</h1>

      {error && <p className="mb-3 text-sm text-red-400">{error}</p>}

      <div className="overflow-x-auto rounded border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900 text-slate-400">
            <tr>
              <th className="px-3 py-2">Host</th>
              <th className="px-3 py-2">Started</th>
              <th className="px-3 py-2">Ended</th>
              <th className="px-3 py-2">Detections</th>
              <th className="px-3 py-2">Risk</th>
              <th className="px-3 py-2" />
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
            {!loading && incidents.length === 0 && (
              <tr>
                <td colSpan={6} className="px-3 py-6 text-center text-slate-500">
                  No incidents found.
                </td>
              </tr>
            )}
            {!loading &&
              incidents.map((inc) => (
                <tr key={inc.id} className="border-t border-slate-800 hover:bg-slate-900/60">
                  <td className="px-3 py-2 text-slate-200">{inc.host}</td>
                  <td className="whitespace-nowrap px-3 py-2 text-slate-400">
                    {new Date(inc.started_at).toLocaleString()}
                  </td>
                  <td className="whitespace-nowrap px-3 py-2 text-slate-400">
                    {new Date(inc.ended_at).toLocaleString()}
                  </td>
                  <td className="px-3 py-2 text-slate-300">{inc.detection_count}</td>
                  <td className="px-3 py-2">
                    <RiskBadge level={inc.risk_level} score={inc.risk_score} />
                  </td>
                  <td className="px-3 py-2 text-right">
                    <Link to={`/incidents/${inc.id}`} className="text-sky-400 hover:text-sky-300">
                      View &rarr;
                    </Link>
                  </td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
