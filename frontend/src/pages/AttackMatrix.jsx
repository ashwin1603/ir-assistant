import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { get } from "../lib/api";
import { Skeleton } from "../components/Skeleton";
import { ErrorBanner } from "../components/States";
import { SEV_LEVELS, SevIcon, sevClass } from "../components/Severity";

// Cell style = highest risk level among current detections; grey = covered by a rule, not seen.
const UNSEEN_STYLE = "rounded border border-slate-800 bg-slate-900 text-slate-500";
const LEGEND_HINTS = {
  Low: "outline",
  Medium: "light tint",
  High: "strong tint",
  Critical: "solid + glow",
};

export default function AttackMatrix() {
  const [searchParams, setSearchParams] = useSearchParams();
  const host = searchParams.get("host") || "";
  const [matrix, setMatrix] = useState(null);
  const [error, setError] = useState("");
  const [reload, setReload] = useState(0); // bumped by Retry

  useEffect(() => {
    setError("");
    get(`/attack/matrix${host ? `?host=${encodeURIComponent(host)}` : ""}`)
      .then(setMatrix)
      .catch((err) => setError(err.message || "Failed to load ATT&CK matrix"));
  }, [host, reload]);

  return (
    <div>
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-xl font-semibold text-slate-100">ATT&CK Coverage</h1>
        <select
          value={host}
          onChange={(e) => setSearchParams(e.target.value ? { host: e.target.value } : {})}
          className="rounded border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-100"
        >
          <option value="">All hosts</option>
          {matrix?.hosts.map((h) => (
            <option key={h} value={h}>
              {h}
            </option>
          ))}
        </select>
      </div>

      <div className="mb-4 flex flex-wrap items-center gap-3 text-xs text-slate-400">
        <span>Highest risk seen:</span>
        {SEV_LEVELS.map((level) => (
          <span key={level} className={`sev-cell px-2 py-0.5 ${sevClass(level)}`}>
            <SevIcon level={level} />
            {level.toUpperCase()}
            <span className="opacity-80">· {LEGEND_HINTS[level]}</span>
          </span>
        ))}
        <span className={`px-2 py-0.5 ${UNSEEN_STYLE}`}>Covered by a rule, not seen</span>
        <span>Number = detection hits.</span>
      </div>

      <ErrorBanner message={error} onRetry={() => setReload((n) => n + 1)} />
      {!matrix && !error && <Skeleton lines={6} />}

      {matrix && (
        <div className="flex gap-3 overflow-x-auto pb-2">
          {matrix.tactics.map((column) => (
            <div key={column.tactic} className="w-44 shrink-0">
              <div className="mb-2 border-b border-slate-700 pb-1 text-xs font-semibold uppercase tracking-wide text-slate-300">
                {column.tactic}
              </div>
              <div className="flex flex-col gap-2">
                {column.techniques.map((t) => (
                  <Link
                    key={t.technique_id}
                    to={`/attack/${t.technique_id}${host ? `?host=${encodeURIComponent(host)}` : ""}`}
                    className={`block p-2 text-xs hover:brightness-125 ${
                      t.max_risk_level ? `sev-cell ${sevClass(t.max_risk_level)}` : UNSEEN_STYLE
                    }`}
                  >
                    <div className="flex flex-wrap justify-between gap-1 font-mono">
                      <span>{t.technique_id}</span>
                      {t.max_risk_level && (
                        <span className="sev font-semibold">
                          <SevIcon level={t.max_risk_level} />
                          {t.max_risk_level.toUpperCase()} · {t.hit_count}
                        </span>
                      )}
                    </div>
                    <div className="mt-1 leading-tight">{t.name}</div>
                  </Link>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
