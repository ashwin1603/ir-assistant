import { useEffect, useState } from "react";
import { Link, useLocation, useNavigate, useParams } from "react-router-dom";
import { get, post, put, download, ApiError } from "../lib/api";
import { useToast } from "../components/Toast";
import { RiskBadge } from "../components/RiskBadge";
import { TIBadge } from "../components/TIBadge";
import { StatusBadge, INCIDENT_STATUSES } from "../components/StatusBadge";
import { useAuth } from "../auth/AuthContext";
import { AskPanel } from "../components/AskPanel";
import { InvestigatePanel } from "../components/InvestigatePanel";
import { AttackGraph } from "../components/AttackGraph";
import { PageSkeleton } from "../components/Skeleton";
import { Segmented } from "../components/Segmented";
import { TimeAgo } from "../components/TimeAgo";
import { ErrorBanner } from "../components/States";

const ANALYZE_TIMEOUT_MS = 40_000;

// Tabs; the active one lives in the URL hash (#investigate etc.) so reloads and links keep it.
const TABS = [
  { value: "overview", label: "Overview" },
  { value: "timeline", label: "Timeline & graph" },
  { value: "investigate", label: "Investigate" },
  { value: "ai", label: "AI & chat" },
  { value: "notes", label: "Notes & artifacts" },
];

function useHashTab() {
  const { hash } = useLocation();
  const navigate = useNavigate();
  const current = hash.slice(1);
  const tab = TABS.some((t) => t.value === current) ? current : "overview";
  const setTab = (value) => navigate({ hash: value === "overview" ? "" : value }, { replace: true });
  return [tab, setTab];
}

const VERDICT_STYLES = {
  benign: "bg-emerald-900/60 text-emerald-300",
  suspicious: "bg-amber-900/60 text-amber-300",
  malicious: "bg-red-900/70 text-red-300",
};

const sectionTitle = "mb-2 text-sm font-semibold uppercase tracking-wide text-slate-400";

export default function IncidentDetail() {
  const { id } = useParams();
  const [incident, setIncident] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [reload, setReload] = useState(0); // bumped by Retry

  const [analysis, setAnalysis] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [analyzeError, setAnalyzeError] = useState("");

  const { can } = useAuth();
  const canEdit = can("update_incident"); // status and notes
  const canRunAi = can("run_ai");
  const canDownload = can("download_artifacts"); // IOCs and scripts (analyst+)
  const [noteText, setNoteText] = useState("");
  const [caseError, setCaseError] = useState("");

  const [tab, setTab] = useHashTab();
  // Panels mount on first visit and then stay mounted, so chat history survives tab switches.
  const [visited, setVisited] = useState(() => new Set([tab]));
  if (!visited.has(tab)) setVisited(new Set([...visited, tab]));

  useEffect(() => {
    setLoading(true);
    get(`/incidents/${id}`)
      .then(setIncident)
      .catch((err) => setError(err.message || "Failed to load incident"))
      .finally(() => setLoading(false));
  }, [id, reload]);

  const toast = useToast();

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
      toast.success(`Status changed to ${updated.status}`);
    } catch (err) {
      setCaseError(err.message || "Failed to update status");
      toast.error("Status update failed");
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
      toast.success("Note added");
    } catch (err) {
      setCaseError(err.message || "Failed to add note");
      toast.error("Note could not be added");
    }
  }

  async function downloadArtifact(path, filename) {
    setCaseError("");
    try {
      await download(`/incidents/${id}/${path}`, filename);
      toast.success(`Downloaded ${filename}`);
    } catch (err) {
      setCaseError(err.message || "Download failed");
      toast.error("Download failed");
    }
  }

  if (loading) return <PageSkeleton />;
  if (error) return <ErrorBanner message={error} onRetry={() => setReload((n) => n + 1)} />;
  if (!incident) return null;

  const tactics = [...new Set(incident.timeline.flatMap((e) => e.tactics))];
  const techniques = [...new Set(incident.timeline.flatMap((e) => e.technique_ids))];
  const eventCount = new Set(incident.timeline.flatMap((e) => e.event_ids)).size;
  const worst = incident.timeline.reduce((best, e) => (!best || e.risk_score > best.risk_score ? e : best), null);

  return (
    <div>
      <Link to="/incidents" className="mb-3 inline-block text-sm text-sky-400 hover:text-sky-300">
        &larr; Back to incidents
      </Link>

      <div className="ir-sticky-head">
        <div className="min-w-0">
          <h1 className="truncate text-xl font-semibold text-slate-100">{incident.host}</h1>
          <p className="text-xs text-slate-400">
            <TimeAgo ts={incident.started_at} /> &ndash; <TimeAgo ts={incident.ended_at} />
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <RiskBadge level={incident.risk_level} score={incident.risk_score} />
          {canEdit ? (
            <select
              value={incident.status}
              onChange={(e) => changeStatus(e.target.value)}
              aria-label="Incident status"
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
          <Link to={`/incidents/${id}/report`} className="ir-btn sm">
            Report &rarr;
          </Link>
        </div>
      </div>

      <div className="mb-5 overflow-x-auto pb-1">
        <Segmented tabs label="Incident sections" options={TABS} value={tab} onChange={setTab} />
      </div>

      {caseError && <p className="mb-3 text-sm text-red-400">{caseError}</p>}

      <div role="tabpanel" hidden={tab !== "overview"} aria-label="Overview">
        <div className="mb-4 grid grid-cols-2 gap-4 lg:grid-cols-4">
          {[
            ["Detections", incident.timeline.length],
            ["Evidence events", eventCount],
            ["Techniques", techniques.length],
            ["Tactics", tactics.length],
          ].map(([label, value]) => (
            <div key={label} className="glass rounded border p-4">
              <p className="text-xs font-semibold uppercase tracking-wide text-slate-400">{label}</p>
              <p className="mt-1 text-2xl font-semibold tabular-nums text-slate-100">{value}</p>
            </div>
          ))}
        </div>
        <div className="grid gap-4 lg:grid-cols-2">
          <section className="rounded border p-4">
            <h2 className={sectionTitle}>Highest-risk detection</h2>
            {worst ? (
              <>
                <div className="mb-2 flex flex-wrap items-center gap-2 text-slate-200">
                  {worst.rule_name} <RiskBadge level={worst.risk_level} score={worst.risk_score} />
                </div>
                {worst.summary && <p className="text-sm text-slate-400">{worst.summary}</p>}
              </>
            ) : (
              <p className="text-sm text-slate-400">No detections.</p>
            )}
          </section>
          <section className="rounded border p-4">
            <h2 className={sectionTitle}>ATT&amp;CK coverage</h2>
            <div className="mb-2 flex flex-wrap gap-1.5">
              {techniques.map((tid) => (
                <Link key={tid} to={`/attack/${tid}`} className="badge rounded bg-indigo-900/50 px-1.5 py-0.5 text-xs text-indigo-300">
                  {tid}
                </Link>
              ))}
            </div>
            <p className="text-xs text-slate-400">{tactics.join(" · ")}</p>
          </section>
        </div>
        <div className="mt-4 flex flex-wrap gap-2">
          <button type="button" className="ir-btn" onClick={() => setTab("timeline")}>View timeline &rarr;</button>
          <button type="button" className="ir-btn" onClick={() => setTab("investigate")}>Investigate &rarr;</button>
          <button type="button" className="ir-btn" onClick={() => setTab("ai")}>AI analysis &rarr;</button>
        </div>
      </div>

      <div role="tabpanel" hidden={tab !== "timeline"} aria-label="Timeline and graph">
        <h2 className={sectionTitle}>Attack graph</h2>
        {visited.has("timeline") && <AttackGraph incidentId={id} />}

        <h2 className={sectionTitle}>Timeline &amp; ATT&amp;CK mapping</h2>
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
                    <TimeAgo ts={entry.first_seen} />
                  </td>
                  <td className="px-3 py-2 text-slate-200">
                    <div className="flex flex-wrap items-center gap-2">
                      {entry.rule_name}
                      <TIBadge matches={entry.ti_matches} />
                    </div>
                    {entry.summary && <p className="mt-1 text-xs text-slate-400">{entry.summary}</p>}
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex flex-wrap gap-1">
                      {entry.technique_ids.map((tid) => (
                        <span key={tid} className="rounded bg-indigo-900/50 px-1.5 py-0.5 text-xs text-indigo-300">
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
      </div>

      <div role="tabpanel" hidden={tab !== "investigate"} aria-label="Investigate">
        {visited.has("investigate") && <InvestigatePanel incidentId={id} canRun={canRunAi} />}
      </div>

      <div role="tabpanel" hidden={tab !== "ai"} aria-label="AI and chat">
        <div className="mb-4 flex items-center gap-3">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">AI analysis</h2>
          <button
            onClick={runAnalysis}
            disabled={analyzing || !canRunAi}
            title={canRunAi ? undefined : "Analysts and admins only"}
            className="rounded bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-500 disabled:opacity-50"
          >
            {analyzing ? "Analyzing... (up to 35s)" : "Run AI analysis"}
          </button>
        </div>

        {analyzing && (
          <p className="mb-4 text-sm text-slate-400">
            Waiting for the AI provider to triage this incident. This can take up to 35 seconds.
          </p>
        )}
        {analyzeError && <p className="mb-4 text-sm text-red-400">{analyzeError}</p>}

        {analysis && (
          <div className="mb-6 space-y-4 rounded border border-slate-800 bg-slate-900/40 p-5">
            <div className="flex items-center gap-3">
              <span
                className={`rounded px-2 py-0.5 text-xs font-medium uppercase ${
                  VERDICT_STYLES[analysis.verdict] || "bg-slate-800 text-slate-300"
                }`}
              >
                {analysis.verdict}
              </span>
              <span className="text-xs text-slate-400">
                confidence {Math.round(analysis.confidence * 100)}% · provider {analysis.provider}
              </span>
            </div>

            <div>
              <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-400">Narrative</h3>
              <p className="text-sm text-slate-300">{analysis.narrative}</p>
            </div>

            <div>
              <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-400">Reasoning</h3>
              <p className="text-sm text-slate-300">{analysis.reasoning}</p>
            </div>

            <div>
              <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-400">Risk explanation</h3>
              <p className="text-sm text-slate-300">{analysis.risk_explanation}</p>
            </div>

            <div>
              <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-400">
                Findings &amp; verified evidence
              </h3>
              {analysis.findings.length === 0 && (
                <p className="text-sm text-slate-400">No findings survived evidence verification.</p>
              )}
              <ul className="space-y-2">
                {analysis.findings.map((f, i) => (
                  <li key={i} className="rounded border border-slate-800 bg-slate-950/60 p-3">
                    <div className="mb-1 flex items-center gap-2">
                      <span className="rounded bg-indigo-900/50 px-1.5 py-0.5 text-xs text-indigo-300">
                        {f.technique_id}
                      </span>
                      <span className="rounded bg-emerald-900/50 px-1.5 py-0.5 text-xs text-emerald-300">
                        Verified
                      </span>
                    </div>
                    <p className="mb-1 text-sm text-slate-300">{f.claim}</p>
                    <p className="text-xs text-slate-400">Evidence: {f.event_ids.join(", ")}</p>
                  </li>
                ))}
              </ul>
            </div>

            <p className="text-xs text-slate-400">
              Recommended actions are queued on the{" "}
              <Link to="/recommendations" className="text-sky-400 hover:text-sky-300">
                Recommendations
              </Link>{" "}
              page for analyst approval.
            </p>
          </div>
        )}

        <h2 className={sectionTitle}>Ask about this incident</h2>
        {visited.has("ai") && <AskPanel incidentId={id} />}
      </div>

      <div role="tabpanel" hidden={tab !== "notes"} aria-label="Notes and artifacts">
        <h2 className={sectionTitle}>Analyst notes</h2>
        <div className="mb-6 rounded border border-slate-800 bg-slate-900/40 p-4">
          {incident.notes.length === 0 && <p className="text-sm text-slate-400">No notes yet.</p>}
          <ul className="space-y-2">
            {incident.notes.map((n) => (
              <li key={n.id} className="text-sm">
                <p className="whitespace-pre-wrap text-slate-300">{n.text}</p>
                <p className="text-xs text-slate-400">
                  {n.author} · <TimeAgo ts={n.created_at} />
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
                aria-label="New note"
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

        {canDownload && (
          <>
            <h2 className={sectionTitle}>Artifacts</h2>
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
              </div>
              <p className="mt-2 text-xs text-amber-400">
                Scripts are text only and are never executed by this app. Review before use.
              </p>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
