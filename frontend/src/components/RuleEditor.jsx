import { useState } from "react";
import { post, put } from "../lib/api";

// Admin-only custom rule editor (Settings -> Detection). The server re-validates
// everything; the limits here only give early feedback.
const FIELDS = ["command_line", "process", "parent_process", "user", "message", "channel"];
const OPS = ["contains", "startswith", "endswith", "equals", "regex"];
const LEVELS = ["informational", "low", "medium", "high", "critical"];
const MAX_CONDITIONS = 10;
const TECHNIQUE_RE = /^T\d{4}(\.\d{3})?$/;

const inputClass =
  "rounded border border-slate-700 bg-slate-900 px-2 py-1 text-sm text-slate-100 focus:border-slate-500 focus:outline-none";
const buttonClass =
  "rounded border border-slate-700 px-3 py-1 text-sm text-slate-300 hover:border-slate-500 hover:text-white disabled:opacity-40";

const emptyCondition = () => ({ field: "command_line", op: "contains", value: "" });

export const EMPTY_RULE = {
  title: "",
  description: "",
  level: "medium",
  confidence: 0.6,
  technique_ids: [],
  event_id: 4688,
  groups: [{ conditions: [emptyCondition()] }],
  threshold: null,
};

export default function RuleEditor({ initial, ruleId, onSaved, onCancel, onError }) {
  const [form, setForm] = useState(initial);
  const [techniques, setTechniques] = useState(initial.technique_ids.join(", "));
  const [testResult, setTestResult] = useState(null);
  const [busy, setBusy] = useState(false);

  const set = (patch) => setForm((f) => ({ ...f, ...patch }));
  const conditionCount = form.groups.reduce((n, g) => n + g.conditions.length, 0);
  const techniqueIds = techniques.split(/[\s,]+/).filter(Boolean).map((t) => t.toUpperCase());
  const badTechnique = techniqueIds.find((t) => !TECHNIQUE_RE.test(t));
  const invalid = !form.title.trim() || !techniqueIds.length || badTechnique ||
    form.groups.some((g) => g.conditions.some((c) => !c.value.trim()));

  function setCondition(gi, ci, patch) {
    set({
      groups: form.groups.map((g, i) => i !== gi ? g : {
        conditions: g.conditions.map((c, j) => (j === ci ? { ...c, ...patch } : c)),
      }),
    });
  }

  function removeCondition(gi, ci) {
    const groups = form.groups
      .map((g, i) => (i !== gi ? g : { conditions: g.conditions.filter((_, j) => j !== ci) }))
      .filter((g) => g.conditions.length);
    set({ groups: groups.length ? groups : [{ conditions: [emptyCondition()] }] });
  }

  const payload = () => ({
    ...form,
    technique_ids: techniqueIds,
    event_id: form.event_id === "" || form.event_id === null ? null : Number(form.event_id),
    confidence: Number(form.confidence),
  });

  async function run(fn) {
    setBusy(true);
    try {
      await fn();
    } catch (err) {
      onError(err.message);
    } finally {
      setBusy(false);
    }
  }

  const test = () => run(async () => setTestResult(await post("/settings/rules/custom/test", payload())));
  const save = () => run(async () => {
    const saved = ruleId ? await put(`/settings/rules/custom/${ruleId}`, payload()) : await post("/settings/rules/custom", payload());
    onSaved(saved, !ruleId);
  });

  return (
    <div className="mt-6 rounded border border-slate-700 p-4">
      <h2 className="mb-3 text-sm font-semibold text-slate-200">{ruleId ? "Edit custom rule" : "New custom rule"}</h2>

      <div className="grid gap-3 sm:grid-cols-2">
        <label className="text-xs text-slate-400">Title
          <input className={`${inputClass} mt-1 w-full`} maxLength={120} value={form.title} onChange={(e) => set({ title: e.target.value })} />
        </label>
        <label className="text-xs text-slate-400">ATT&CK technique IDs (comma separated)
          <input className={`${inputClass} mt-1 w-full`} placeholder="T1059.001, T1027" value={techniques}
            onChange={(e) => setTechniques(e.target.value)} />
          {badTechnique && <span className="text-red-400">Invalid technique id: {badTechnique}</span>}
        </label>
        <label className="text-xs text-slate-400 sm:col-span-2">Description
          <input className={`${inputClass} mt-1 w-full`} maxLength={500} value={form.description}
            onChange={(e) => set({ description: e.target.value })} />
        </label>
        <div className="flex flex-wrap gap-3 sm:col-span-2">
          <label className="text-xs text-slate-400">Level (sets severity)
            <select className={`${inputClass} mt-1 block`} value={form.level} onChange={(e) => set({ level: e.target.value })}>
              {LEVELS.map((l) => <option key={l}>{l}</option>)}
            </select>
          </label>
          <label className="text-xs text-slate-400">Confidence
            <input className={`${inputClass} mt-1 block w-20`} type="number" min={0.1} max={1} step={0.05}
              value={form.confidence} onChange={(e) => set({ confidence: e.target.value })} />
          </label>
          <label className="text-xs text-slate-400">Event ID (optional)
            <input className={`${inputClass} mt-1 block w-24`} type="number" min={0} max={65535}
              value={form.event_id ?? ""} onChange={(e) => set({ event_id: e.target.value })} />
          </label>
          <label className="flex items-end gap-2 text-xs text-slate-400">
            <input type="checkbox" checked={!!form.threshold}
              onChange={(e) => set({ threshold: e.target.checked ? { count: 5, minutes: 5 } : null })} />
            Threshold
          </label>
          {form.threshold && (
            <div className="flex items-end gap-2 text-xs text-slate-400">
              <input className={`${inputClass} w-16`} type="number" min={2} max={1000} value={form.threshold.count}
                onChange={(e) => set({ threshold: { ...form.threshold, count: Number(e.target.value) } })} />
              events in
              <input className={`${inputClass} w-16`} type="number" min={1} max={1440} value={form.threshold.minutes}
                onChange={(e) => set({ threshold: { ...form.threshold, minutes: Number(e.target.value) } })} />
              min (per host)
            </div>
          )}
        </div>
      </div>

      <p className="mt-4 text-xs text-slate-500">
        Conditions in a group must all match (AND); any group may match (OR). Max {MAX_CONDITIONS} conditions.
        Regex uses RE2 syntax (no lookarounds/backreferences, max 200 chars), case-insensitive.
      </p>
      {form.groups.map((g, gi) => (
        <div key={gi}>
          {gi > 0 && <div className="my-1 text-xs font-semibold text-amber-400">OR</div>}
          <div className="mt-2 space-y-2 rounded border border-slate-800 p-2">
            {g.conditions.map((c, ci) => (
              <div key={ci} className="flex flex-wrap items-center gap-2">
                <span className="w-8 text-xs text-slate-500">{ci > 0 ? "AND" : ""}</span>
                <select className={inputClass} value={c.field} onChange={(e) => setCondition(gi, ci, { field: e.target.value })}>
                  {FIELDS.map((f) => <option key={f}>{f}</option>)}
                </select>
                <select className={inputClass} value={c.op} onChange={(e) => setCondition(gi, ci, { op: e.target.value })}>
                  {OPS.map((o) => <option key={o}>{o}</option>)}
                </select>
                <input className={`${inputClass} min-w-0 flex-1 font-mono`} maxLength={200} value={c.value}
                  onChange={(e) => setCondition(gi, ci, { value: e.target.value })} />
                <button className={buttonClass} onClick={() => removeCondition(gi, ci)}>Remove</button>
              </div>
            ))}
            <button className={buttonClass} disabled={conditionCount >= MAX_CONDITIONS}
              onClick={() => set({ groups: form.groups.map((x, i) => (i === gi ? { conditions: [...x.conditions, emptyCondition()] } : x)) })}>
              + AND condition
            </button>
          </div>
        </div>
      ))}
      <button className={`${buttonClass} mt-2`} disabled={conditionCount >= MAX_CONDITIONS}
        onClick={() => set({ groups: [...form.groups, { conditions: [emptyCondition()] }] })}>
        + OR group
      </button>

      <div className="mt-4 flex gap-2">
        <button className={buttonClass} disabled={busy || invalid} onClick={test}>Test rule</button>
        <button className={buttonClass} disabled={busy || invalid} onClick={save}>{ruleId ? "Save changes" : "Save (disabled)"}</button>
        <button className={buttonClass} onClick={onCancel}>Cancel</button>
      </div>

      {testResult && (
        <div className="mt-4 rounded border border-slate-800 p-3 text-sm">
          <p className="text-slate-200">
            Dry run (nothing saved): <b>{testResult.match_count}</b> matching events
            {testResult.cluster_count !== null && <>, <b>{testResult.cluster_count}</b> threshold hits</>}
          </p>
          {testResult.samples.length > 0 && (
            <table className="mt-2 w-full text-left text-xs">
              <thead className="text-slate-500">
                <tr><th className="pr-2">Time</th><th className="pr-2">Host</th><th className="pr-2">Event</th><th>Command line</th></tr>
              </thead>
              <tbody>
                {testResult.samples.map((s) => (
                  <tr key={s.id} className="border-t border-slate-800 text-slate-400">
                    <td className="pr-2">{new Date(s.timestamp).toLocaleString()}</td>
                    <td className="pr-2">{s.host}</td>
                    <td className="pr-2">{s.event_id}</td>
                    <td className="break-all font-mono">{s.command_line || s.process}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}
