import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { get } from "../lib/api";
import { RiskBadge } from "../components/RiskBadge";

const STATUS_STYLES = {
  pending: "bg-slate-800 text-slate-300",
  approved: "bg-emerald-900/60 text-emerald-300",
  rejected: "bg-red-900/70 text-red-300",
};

export default function Report() {
  const { id } = useParams();
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    setLoading(true);
    get(`/incidents/${id}/report`)
      .then(setReport)
      .catch((err) => setError(err.message || "Failed to load report"))
      .finally(() => setLoading(false));
  }, [id]);

  if (loading) return <p className="text-slate-500">Loading...</p>;
  if (error) return <p className="text-red-400">{error}</p>;
  if (!report) return null;

  const { incident, analysis, actions, generated_at } = report;

  return (
    <div className="mx-auto max-w-4xl text-slate-100 print:text-black">
      <div className="mb-4 flex items-center justify-between print:hidden">
        <Link to={`/incidents/${id}`} className="text-sm text-sky-400 hover:text-sky-300">
          &larr; Back to incident
        </Link>
        <button
          onClick={() => window.print()}
          className="rounded bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-500"
        >
          Print / Save PDF
        </button>
      </div>

      <h1 className="text-2xl font-semibold">Incident Report</h1>
      <p className="mb-6 text-sm text-slate-500 print:text-neutral-600">
        Generated {new Date(generated_at).toLocaleString()}
      </p>

      <section className="mb-6">
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-400 print:text-neutral-700">
          Summary
        </h2>
        <div className="rounded border border-slate-800 p-4 print:border-neutral-300">
          <dl className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
            <div>
              <dt className="text-slate-500 print:text-neutral-600">Host</dt>
              <dd className="font-medium">{incident.host}</dd>
            </div>
            <div>
              <dt className="text-slate-500 print:text-neutral-600">Started</dt>
              <dd>{new Date(incident.started_at).toLocaleString()}</dd>
            </div>
            <div>
              <dt className="text-slate-500 print:text-neutral-600">Ended</dt>
              <dd>{new Date(incident.ended_at).toLocaleString()}</dd>
            </div>
            <div>
              <dt className="text-slate-500 print:text-neutral-600">Detections</dt>
              <dd>{incident.detection_count}</dd>
            </div>
          </dl>
          <div className="mt-3">
            <RiskBadge level={incident.risk_level} score={incident.risk_score} />
          </div>
        </div>
      </section>

      <section className="mb-6">
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-400 print:text-neutral-700">
          Timeline &amp; ATT&amp;CK mapping
        </h2>
        <div className="overflow-x-auto rounded border border-slate-800 print:border-neutral-300">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-900 text-slate-400 print:bg-neutral-100 print:text-neutral-600">
              <tr>
                <th className="px-3 py-2">First seen</th>
                <th className="px-3 py-2">Rule</th>
                <th className="px-3 py-2">ATT&amp;CK</th>
                <th className="px-3 py-2">Tactics</th>
                <th className="px-3 py-2">Severity</th>
                <th className="px-3 py-2">Risk</th>
              </tr>
            </thead>
            <tbody>
              {incident.timeline.map((entry) => (
                <tr key={entry.detection_id} className="border-t border-slate-800 print:border-neutral-200">
                  <td className="whitespace-nowrap px-3 py-2">{new Date(entry.first_seen).toLocaleString()}</td>
                  <td className="px-3 py-2">{entry.rule_name}</td>
                  <td className="px-3 py-2">{entry.technique_ids.join(", ")}</td>
                  <td className="px-3 py-2">{entry.tactics.join(", ")}</td>
                  <td className="px-3 py-2">{entry.severity}/10</td>
                  <td className="px-3 py-2">
                    {entry.risk_level} &middot; {Math.round(entry.risk_score)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="mb-6">
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-400 print:text-neutral-700">
          AI analysis
        </h2>
        {!analysis ? (
          <p className="text-sm text-slate-500 print:text-neutral-600">
            No AI analysis has been run for this incident yet.
          </p>
        ) : (
          <div className="space-y-3 rounded border border-slate-800 p-4 text-sm print:border-neutral-300">
            <p>
              <span className="font-semibold uppercase">{analysis.verdict}</span>{" "}
              <span className="text-slate-500 print:text-neutral-600">
                (confidence {Math.round(analysis.confidence * 100)}%, provider {analysis.provider})
              </span>
            </p>
            <div>
              <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500 print:text-neutral-600">
                Narrative
              </h3>
              <p>{analysis.narrative}</p>
            </div>
            <div>
              <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500 print:text-neutral-600">
                Risk explanation
              </h3>
              <p>{analysis.risk_explanation}</p>
            </div>
            <div>
              <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500 print:text-neutral-600">
                Verified findings
              </h3>
              {analysis.findings.length === 0 ? (
                <p className="text-slate-500 print:text-neutral-600">No findings survived evidence verification.</p>
              ) : (
                <ul className="list-disc space-y-1 pl-5">
                  {analysis.findings.map((f, i) => (
                    <li key={i}>
                      <span className="font-medium">{f.technique_id}</span> &mdash; {f.claim} (evidence:{" "}
                      {f.event_ids.join(", ")})
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        )}
      </section>

      <section className="mb-6">
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-400 print:text-neutral-700">
          Recommended actions
        </h2>
        {actions.length === 0 ? (
          <p className="text-sm text-slate-500 print:text-neutral-600">No recommended actions for this incident.</p>
        ) : (
          <div className="overflow-x-auto rounded border border-slate-800 print:border-neutral-300">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-900 text-slate-400 print:bg-neutral-100 print:text-neutral-600">
                <tr>
                  <th className="px-3 py-2">Action</th>
                  <th className="px-3 py-2">Status</th>
                  <th className="px-3 py-2">Decided by</th>
                  <th className="px-3 py-2">Decided at</th>
                </tr>
              </thead>
              <tbody>
                {actions.map((a) => (
                  <tr key={a.id} className="border-t border-slate-800 print:border-neutral-200">
                    <td className="px-3 py-2">{a.action_text}</td>
                    <td className="px-3 py-2">
                      <span
                        className={`rounded px-2 py-0.5 text-xs font-medium capitalize print:bg-transparent print:px-0 print:font-semibold ${
                          STATUS_STYLES[a.status] || "bg-slate-800 text-slate-300"
                        }`}
                      >
                        {a.status}
                      </span>
                    </td>
                    <td className="px-3 py-2">{a.decided_by || "—"}</td>
                    <td className="px-3 py-2">{a.decided_at ? new Date(a.decided_at).toLocaleString() : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="mt-2 text-xs text-slate-500 print:text-neutral-600">
          Approved actions are simulated only and were never executed against the host.
        </p>
      </section>
    </div>
  );
}
