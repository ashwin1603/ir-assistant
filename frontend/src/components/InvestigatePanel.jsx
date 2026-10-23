import { useEffect, useState } from "react";
import { get, post, ApiError } from "../lib/api";

const INVESTIGATE_TIMEOUT_MS = 40_000;

const SUMMARY_MODE_LABELS = {
  ai: "model wording, checked against step results",
  template: "template wording",
  fallback: "template wording (model output rejected)",
};

function StepBadge({ status }) {
  const found = status === "found";
  return (
    <span
      className={`rounded px-1.5 py-0.5 text-xs font-medium ${
        found ? "bg-amber-900/50 text-amber-300" : "bg-slate-800 text-slate-400"
      }`}
    >
      {found ? "found" : "not found"}
    </span>
  );
}

export function InvestigatePanel({ incidentId, canRun }) {
  const [result, setResult] = useState(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    get(`/incidents/${incidentId}/investigate`)
      .then(setResult)
      .catch(() => setResult(null));
  }, [incidentId]);

  async function run() {
    setRunning(true);
    setError("");
    try {
      setResult(await post(`/incidents/${incidentId}/investigate`, undefined, INVESTIGATE_TIMEOUT_MS));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Investigation failed");
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="mb-6 rounded border border-slate-800 bg-slate-900/40 p-4">
      <div className="mb-3 flex flex-wrap items-center gap-3">
        {canRun && (
          <button
            onClick={run}
            disabled={running}
            className="rounded bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-500 disabled:opacity-50"
          >
            {running ? "Investigating..." : result ? "Re-check" : "Investigate"}
          </button>
        )}
        <span className="text-xs text-slate-500">Code-driven investigation, model wording only</span>
      </div>
      {error && <p className="mb-2 text-sm text-red-400">{error}</p>}

      {!result ? (
        <p className="text-sm text-slate-500">
          {canRun ? "No investigation has been run for the current detections." : "No investigation available yet (read-only)."}
        </p>
      ) : (
        <>
          <div className="mb-3 rounded bg-slate-950/60 p-3 text-sm text-slate-300">
            <p className="whitespace-pre-wrap">{result.summary}</p>
            <p className="mt-1 text-xs text-slate-500">
              {SUMMARY_MODE_LABELS[result.summary_mode] || result.summary_mode} · run by {result.created_by}
            </p>
          </div>

          <ol className="mb-3 space-y-2">
            {result.steps.map((s) => (
              <li key={s.key} className="rounded border border-slate-800 p-2 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium text-slate-200">{s.name}</span>
                  <StepBadge status={s.status} />
                  <span className="text-xs text-slate-500">
                    {Object.entries(s.counts)
                      .map(([k, v]) => `${k.replaceAll("_", " ")}: ${v}`)
                      .join(" · ")}
                  </span>
                </div>
                {s.items.length > 0 && (
                  <ul className="mt-1 list-disc pl-5 text-xs text-slate-400">
                    {s.items.map((item, i) => (
                      <li key={i} className="break-all font-mono">
                        {item}
                      </li>
                    ))}
                  </ul>
                )}
                {s.evidence_event_ids.length > 0 && (
                  <p className="mt-1 break-all font-mono text-xs text-slate-500">
                    evidence: {s.evidence_event_ids.join(", ")}
                  </p>
                )}
              </li>
            ))}
          </ol>

          {result.next_actions.length > 0 && (
            <div className="text-sm">
              <p className="mb-1 text-xs uppercase tracking-wide text-slate-500">Suggested next actions (playbook)</p>
              <ul className="list-disc pl-5 text-slate-300">
                {result.next_actions.map((a) => (
                  <li key={a}>{a}</li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
    </div>
  );
}
