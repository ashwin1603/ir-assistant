import { useEffect, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { get } from "../lib/api";
import { RiskBadge } from "../components/RiskBadge";
import { Skeleton } from "../components/Skeleton";
import { TimeAgo } from "../components/TimeAgo";
import { ErrorBanner } from "../components/States";

export default function TechniqueDetail() {
  const { techniqueId } = useParams();
  const [searchParams] = useSearchParams();
  const host = searchParams.get("host") || "";
  const [technique, setTechnique] = useState(null);
  const [error, setError] = useState("");
  const [reload, setReload] = useState(0); // bumped by Retry

  useEffect(() => {
    setError("");
    get(`/attack/techniques/${encodeURIComponent(techniqueId)}${host ? `?host=${encodeURIComponent(host)}` : ""}`)
      .then(setTechnique)
      .catch((err) => setError(err.message || "Failed to load technique"));
  }, [techniqueId, host, reload]);

  const backLink = `/attack${host ? `?host=${encodeURIComponent(host)}` : ""}`;

  if (error) return <ErrorBanner message={error} onRetry={() => setReload((n) => n + 1)} />;
  if (!technique) return <Skeleton lines={6} />;

  return (
    <div className="space-y-6">
      <div>
        <Link to={backLink} className="text-sm text-sky-400 hover:underline">
          ← ATT&CK matrix
        </Link>
        <h1 className="mt-2 text-xl font-semibold text-slate-100">
          <span className="font-mono text-sky-300">{technique.technique_id}</span> {technique.name}
        </h1>
        <p className="text-sm text-slate-400">
          Tactic: {technique.tactic} · {technique.hit_count} detection(s){host && ` on ${host}`}
          {technique.max_risk_level && (
            <>
              {" "}· max risk <RiskBadge level={technique.max_risk_level} score={technique.max_risk_score} />
            </>
          )}
        </p>
        <p className="mt-3 max-w-3xl text-sm text-slate-300">{technique.description}</p>
      </div>

      <section>
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-400">Rules covering it</h2>
        <ul className="space-y-1 text-sm text-slate-300">
          {technique.rules.map((r) => (
            <li key={r.id}>
              {r.name} <span className="text-slate-500">· {r.kind} · severity {r.severity}/10 · confidence {Math.round(r.confidence * 100)}%</span>
            </li>
          ))}
        </ul>
      </section>

      <section>
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-400">Recent detections</h2>
        {technique.recent_detections.length === 0 ? (
          <p className="text-sm text-slate-500">Not seen in current detections.</p>
        ) : (
          <div className="overflow-x-auto rounded border border-slate-800">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-900 text-slate-400">
                <tr>
                  <th className="px-3 py-2">Rule</th>
                  <th className="px-3 py-2">Host</th>
                  <th className="px-3 py-2">Events</th>
                  <th className="px-3 py-2">Risk</th>
                  <th className="px-3 py-2">Last seen</th>
                  <th className="px-3 py-2">Incident</th>
                </tr>
              </thead>
              <tbody>
                {technique.recent_detections.map((d) => (
                  <tr key={d.id} className="border-t border-slate-800">
                    <td className="px-3 py-2 text-slate-200">{d.rule_name}</td>
                    <td className="px-3 py-2 text-slate-300">{d.host}</td>
                    <td className="px-3 py-2 text-slate-300">{d.event_count}</td>
                    <td className="px-3 py-2">
                      <RiskBadge level={d.risk_level} score={d.risk_score} />
                    </td>
                    <td className="whitespace-nowrap px-3 py-2 text-slate-400"><TimeAgo ts={d.last_seen} /></td>
                    <td className="px-3 py-2">
                      {d.incident_id ? (
                        <Link to={`/incidents/${d.incident_id}`} className="text-sky-400 hover:underline">
                          Open
                        </Link>
                      ) : (
                        <span className="text-slate-600">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section>
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-400">Playbook mitigations</h2>
        <ul className="list-disc space-y-1 pl-5 text-sm text-slate-300">
          {technique.mitigations.map((m) => (
            <li key={m}>{m}</li>
          ))}
        </ul>
      </section>
    </div>
  );
}
