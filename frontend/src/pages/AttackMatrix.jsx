import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { get } from "../lib/api";

// Cell colour = highest risk level among current detections; grey = covered by a rule, not seen.
const CELL_STYLES = {
  Low: "border-sky-800 bg-sky-950/60 text-sky-200",
  Medium: "border-amber-700 bg-amber-900/50 text-amber-200",
  High: "border-orange-700 bg-orange-900/60 text-orange-200",
  Critical: "border-red-700 bg-red-900/70 text-red-200",
};
const UNSEEN_STYLE = "border-slate-800 bg-slate-900 text-slate-500";

export default function AttackMatrix() {
  const [searchParams, setSearchParams] = useSearchParams();
  const host = searchParams.get("host") || "";
  const [matrix, setMatrix] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    setError("");
    get(`/attack/matrix${host ? `?host=${encodeURIComponent(host)}` : ""}`)
      .then(setMatrix)
      .catch((err) => setError(err.message || "Failed to load ATT&CK matrix"));
  }, [host]);

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

      <div className="mb-4 flex flex-wrap gap-3 text-xs text-slate-400">
        <span className={`rounded border px-2 py-0.5 ${UNSEEN_STYLE}`}>Covered, not seen</span>
        {Object.entries(CELL_STYLES).map(([level, style]) => (
          <span key={level} className={`rounded border px-2 py-0.5 ${style}`}>
            {level}
          </span>
        ))}
      </div>

      {error && <p className="mb-3 text-sm text-red-400">{error}</p>}
      {!matrix && !error && <p className="text-sm text-slate-500">Loading...</p>}

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
                    className={`rounded border p-2 text-xs hover:brightness-125 ${
                      CELL_STYLES[t.max_risk_level] || UNSEEN_STYLE
                    }`}
                  >
                    <div className="flex justify-between font-mono">
                      <span>{t.technique_id}</span>
                      {t.hit_count > 0 && <span className="font-semibold">{t.hit_count}</span>}
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
