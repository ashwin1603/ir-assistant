import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { get, post, put, download, ApiError } from "../lib/api";
import { RiskBadge } from "../components/RiskBadge";
import { StatusBadge, INCIDENT_STATUSES } from "../components/StatusBadge";
import { useAuth } from "../auth/AuthContext";

const ANALYZE_TIMEOUT_MS = 40_000;

const VERDICT_STYLES = {
  benign: "bg-emerald-900/60 text-emerald-300",
  suspicious: "bg-amber-900/60 text-amber-300",
  malicious: "bg-red-900/70 text-red-300",
};

export default function IncidentDetail() {
  const { id } = useParams();
  const [incident, setIncident] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [analysis, setAnalysis] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [analyzeError, setAnalyzeError] = useState("");

  const { session } = useAuth();
  const canEdit = session?.role === "admin" || session?.role === "analyst";
  const [noteText, setNoteText] = useState("");
  const [caseError, setCaseError] = useState("");

  useEffect(() => {
    setLoading(true);
    get(`/incidents/${id}`)
      .then(setIncident)
      .catch((err) => setError(err.message || "Failed to load incident"))
      .finally(() => setLoading(false));
  }, [id]);

  async function runAnalysis() {
    setAnalyzing(true);
    setAnalyzeError("");
    try {
      const result = await post(`/incidents/${id}/analyze`, undefined, ANALYZE_TIMEOUT_MS);
      setAnalysis(result);
    } catch (err) {
      setAnalyzeError(err instanceof ApiError ? err.message : "AI analysis failed");
    } finally {
      setAnalyzing(false);
    }
  }

  async function changeStatus(status) {
    setCaseError("");
    try {
      const updated = await put(`/incidents/${id}/status`, { status });
      setIncident((prev) => ({ ...prev, status: updated.status }));
    } catch (err) {
      setCaseError(err.message || "Failed to update status");
    }
  }

  async function addNote(e) {
    e.preventDefault();
    if (!noteText.trim()) return;
    setCaseError("");
    try {
      const note = await post(`/incidents/${id}/notes`, { text: noteText.trim() });
      setIncident((prev) => ({ ...prev, notes: [...prev.notes, note] }));
      setNoteText("");
    } catch (err) {
      setCaseError(err.message || "Failed to add note");
    }
  }

  async function downloadArtifact(path, filename) {
    setCaseError("");
    try {
      await download(`/incidents/${id}/${path}`, filename);
    } catch (err) {
      setCaseError(err.message || "Download failed");
    }
  }

  if (loading) return <p className="text-slate-500">Loading...</p>;
  if (error) return <p className="text-red-400">{error}</p>;
  if (!incident) return null;

  return (
    <div>
      <div className="mb-4 flex items-center justify-between">
        <Link to="/incidents" className="inline-block text-sm text-sky-400 hover:text-sky-300">
          &larr; Back to incidents
        </Link>
        <Link to={`/incidents/${id}/report`} className="text-sm text-sky-400 hover:text-sky-300">
          View printable report &rarr;
        </Link>
      </div>

      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">{incident.host}</h1>
          <p className="text-sm text-slate-500">
            {new Date(incident.started_at).toLocaleString()} &ndash;{" "}
            {new Date(incident.ended_at).toLocaleString()}
          </p>
        </div>
        <div className="flex items-center gap-3">
          {canEdit ? (
            <select
              value={incident.status}
              onChange={(e) => changeStatus(e.target.value)}
              className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-sm text-slate-200"
            >
              {INCIDENT_STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          ) : (
            <StatusBadge status={incident.status} />
          )}
          <RiskBadge level={incident.risk_level} score={incident.risk_score} />
        </div>
      </div>

      {caseError && <p className="mb-3 text-sm text-red-400">{caseError}</p>}

      <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-400">Artifacts</h2>
      <div className="mb-6 rounded border border-slate-800 bg-slate-900/40 p-4">
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => downloadArtifact("iocs?format=csv", `iocs-${id.slice(0, 8)}.csv`)}
            className="rounded border border-slate-700 px-3 py-1.5 text-sm text-slate-200 hover:bg-slate-800"
          >
            IOCs (CSV)
          </button>
          <button
            onClick={() => downloadArtifact("iocs?format=json", `iocs-${id.slice(0, 8)}.json`)}
            className="rounded border border-slate-700 px-3 py-1.5 text-sm text-slate-200 hover:bg-slate-800"
          >
            IOCs (JSON)
          </button>
          {canEdit && (
            <>
              <button
                onClick={() => downloadArtifact("scripts/firewall", `firewall-${id.slice(0, 8)}.ps1.txt`)}
                className="rounded border border-amber-700 px-3 py-1.5 text-sm text-amber-300 hover:bg-amber-900/30"
              >
                Firewall block commands
              </button>
              <button
                onClick={() => downloadArtifact("scripts/isolation", `isolation-${id.slice(0, 8)}.ps1.txt`)}
                className="rounded border border-amber-700 px-3 py-1.5 text-sm text-amber-300 hover:bg-amber-900/30"
              >
                Host isolation script
              </button>
            </>
          )}
        </div>
        {canEdit && (
          <p className="mt-2 text-xs text-amber-400">
            Scripts are text only and are never executed by this app. Review before use.
          </p>
        )}
      </div>

      <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-400">Analyst notes</h2>
      <div className="mb-6 rounded border border-slate-800 bg-slate-900/40 p-4">
        {incident.notes.length === 0 && <p className="text-sm text-slate-500">No notes yet.</p>}
        <ul className="space-y-2">
          {incident.notes.map((n) => (
            <li key={n.id} className="text-sm">
              <p className="whitespace-pre-wrap text-slate-300">{n.text}</p>
              <p className="text-xs text-slate-500">
                {n.author} · {new Date(n.created_at).toLocaleString()}
              </p>
            </li>
          ))}
        </ul>
        {canEdit && (
          <form onSubmit={addNote} className="mt-3 flex gap-2">
            <textarea
              value={noteText}
              onChange={(e) => setNoteText(e.target.value)}
              maxLength={2000}
              rows={2}
              placeholder="Add a note..."
              className="flex-1 rounded border border-slate-700 bg-slate-950 px-2 py-1 text-sm text-slate-200"
            />
            <button
              type="submit"
              disabled={!noteText.trim()}
              className="self-end rounded bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-500 disabled:opacity-50"
            >
              Add note
            </button>
          </form>
        )}
      </div>

      <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-400">
        Timeline &amp; ATT&amp;CK mapping
      </h2>
      <div className="mb-6 overflow-x-auto rounded border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900 text-slate-400">
            <tr>
              <th className="px-3 py-2">First seen</th>
              <th className="px-3 py-2">Rule</th>
              <th className="px-3 py-2">ATT&amp;CK</th>
              <th className="px-3 py-2">Tactics</th>
              <th className="px-3 py-2">Severity</th>
              <th className="px-3 py-2">Confidence</th>
              <th className="px-3 py-2">Risk</th>
              <th className="px-3 py-2">Events</th>
            </tr>
          </thead>
          <tbody>
            {incident.timeline.map((entry) => (
              <tr key={entry.detection_id} className="border-t border-slate-800">
                <td className="whitespace-nowrap px-3 py-2 text-slate-400">
                  {new Date(entry.first_seen).toLocaleString()}
                </td>
                <td className="px-3 py-2 text-slate-200">{entry.rule_name}</td>
                <td className="px-3 py-2">
                  <div className="flex flex-wrap gap-1">
                    {entry.technique_ids.map((tid) => (
                      <span key={tid} className="rounded bg-sky-900/50 px-1.5 py-0.5 text-xs text-sky-300">
                        {tid}
                      </span>
                    ))}
                  </div>
                </td>
                <td className="px-3 py-2 text-slate-400">{entry.tactics.join(", ")}</td>
                <td className="px-3 py-2 text-slate-300">{entry.severity}/10</td>
                <td className="px-3 py-2 text-slate-300">{Math.round(entry.confidence * 100)}%</td>
                <td className="px-3 py-2">
                  <RiskBadge level={entry.risk_level} score={entry.risk_score} />
                </td>
                <td className="px-3 py-2 text-slate-400">{entry.event_ids.length}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="mb-4 flex items-center gap-3">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">AI analysis</h2>
        <button
          onClick={runAnalysis}
          disabled={analyzing}
          className="rounded bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-500 disabled:opacity-50"
        >
          {analyzing ? "Analyzing... (up to 35s)" : "Run AI analysis"}
        </button>
      </div>

      {analyzing && (
        <p className="mb-4 text-sm text-slate-500">
          Waiting for the AI provider to triage this incident. This can take up to 35 seconds.
        </p>
      )}
      {analyzeError && <p className="mb-4 text-sm text-red-400">{analyzeError}</p>}

      {analysis && (
        <div className="space-y-4 rounded border border-slate-800 bg-slate-900/40 p-5">
          <div className="flex items-center gap-3">
            <span
              className={`rounded px-2 py-0.5 text-xs font-medium uppercase ${
                VERDICT_STYLES[analysis.verdict] || "bg-slate-800 text-slate-300"
              }`}
            >
              {analysis.verdict}
            </span>
            <span className="text-xs text-slate-500">
              confidence {Math.round(analysis.confidence * 100)}% · provider {analysis.provider}
            </span>
          </div>

          <div>
            <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">Narrative</h3>
            <p className="text-sm text-slate-300">{analysis.narrative}</p>
          </div>

          <div>
            <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">Reasoning</h3>
            <p className="text-sm text-slate-300">{analysis.reasoning}</p>
          </div>

          <div>
            <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">
              Risk explanation
            </h3>
            <p className="text-sm text-slate-300">{analysis.risk_explanation}</p>
          </div>

          <div>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">
              Findings &amp; verified evidence
            </h3>
            {analysis.findings.length === 0 && (
              <p className="text-sm text-slate-500">No findings survived evidence verification.</p>
            )}
            <ul className="space-y-2">
              {analysis.findings.map((f, i) => (
                <li key={i} className="rounded border border-slate-800 bg-slate-950/60 p-3">
                  <div className="mb-1 flex items-center gap-2">
                    <span className="rounded bg-sky-900/50 px-1.5 py-0.5 text-xs text-sky-300">
                      {f.technique_id}
                    </span>
                    <span className="rounded bg-emerald-900/50 px-1.5 py-0.5 text-xs text-emerald-300">
                      Verified
                    </span>
                  </div>
                  <p className="mb-1 text-sm text-slate-300">{f.claim}</p>
                  <p className="text-xs text-slate-500">
                    Evidence: {f.event_ids.join(", ")}
                  </p>
                </li>
              ))}
            </ul>
          </div>

          <p className="text-xs text-slate-500">
            Recommended actions are queued on the{" "}
            <Link to="/recommendations" className="text-sky-400 hover:text-sky-300">
              Recommendations
            </Link>{" "}
            page for analyst approval.
          </p>
        </div>
      )}
    </div>
  );
}
