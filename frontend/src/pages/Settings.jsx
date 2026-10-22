import { useCallback, useEffect, useState } from "react";
import { get, patch, post, put } from "../lib/api";
import { useAuth } from "../auth/AuthContext";

const TABS = ["Users", "Detection", "System"];
const ROLES = ["admin", "analyst", "viewer"];

const inputClass =
  "rounded border border-slate-700 bg-slate-900 px-2 py-1 text-sm text-slate-100 focus:border-slate-500 focus:outline-none";
const buttonClass =
  "rounded border border-slate-700 px-3 py-1 text-sm text-slate-300 hover:border-slate-500 hover:text-white disabled:opacity-40";

function Message({ error, notice }) {
  if (error) return <p className="mb-3 text-sm text-red-400">{error}</p>;
  if (notice) return <p className="mb-3 text-sm text-emerald-400">{notice}</p>;
  return null;
}

function UsersTab() {
  const [users, setUsers] = useState([]);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [form, setForm] = useState({ username: "", password: "", role: "viewer" });

  const load = useCallback(() => {
    get("/settings/users").then(setUsers).catch((err) => setError(err.message));
  }, []);
  useEffect(load, [load]);

  async function run(fn, successMessage) {
    setError("");
    setNotice("");
    try {
      await fn();
      setNotice(successMessage);
      load();
    } catch (err) {
      setError(err.message);
    }
  }

  function createUser(e) {
    e.preventDefault();
    run(async () => {
      await post("/settings/users", form);
      setForm({ username: "", password: "", role: "viewer" });
    }, `User ${form.username} created`);
  }

  function resetPassword(user) {
    const newPassword = window.prompt(`New password for ${user.username} (min 12 characters):`);
    if (!newPassword) return;
    run(() => post(`/settings/users/${user.id}/reset-password`, { new_password: newPassword }), `Password reset for ${user.username}`);
  }

  return (
    <div>
      <Message error={error} notice={notice} />

      <form onSubmit={createUser} className="mb-4 flex flex-wrap items-end gap-2 rounded border border-slate-800 p-3">
        <input className={inputClass} placeholder="Username" value={form.username}
          onChange={(e) => setForm({ ...form, username: e.target.value })} required />
        <input className={inputClass} type="password" placeholder="Password (12+ chars)" value={form.password}
          onChange={(e) => setForm({ ...form, password: e.target.value })} minLength={12} required />
        <select className={inputClass} value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
          {ROLES.map((r) => <option key={r}>{r}</option>)}
        </select>
        <button className={buttonClass} type="submit">Create user</button>
      </form>

      <div className="overflow-x-auto rounded border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900 text-slate-400">
            <tr>
              <th className="px-3 py-2">Username</th>
              <th className="px-3 py-2">Role</th>
              <th className="px-3 py-2">Status</th>
              <th className="px-3 py-2">Created</th>
              <th className="px-3 py-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id} className="border-t border-slate-800">
                <td className="px-3 py-2 text-slate-200">{u.username}</td>
                <td className="px-3 py-2">
                  <select className={inputClass} value={u.role}
                    onChange={(e) => run(() => patch(`/settings/users/${u.id}`, { role: e.target.value }), `Role updated for ${u.username}`)}>
                    {ROLES.map((r) => <option key={r}>{r}</option>)}
                  </select>
                </td>
                <td className="px-3 py-2">
                  <span className={`rounded px-2 py-0.5 text-xs font-medium ${
                    u.is_active ? "bg-emerald-900/60 text-emerald-300" : "bg-slate-800 text-slate-400"}`}>
                    {u.is_active ? "Active" : "Disabled"}
                  </span>
                </td>
                <td className="px-3 py-2 text-slate-400">{new Date(u.created_at).toLocaleDateString()}</td>
                <td className="flex gap-2 px-3 py-2">
                  <button className={buttonClass}
                    onClick={() => run(() => patch(`/settings/users/${u.id}`, { is_active: !u.is_active }),
                      `${u.username} ${u.is_active ? "disabled" : "enabled"}`)}>
                    {u.is_active ? "Disable" : "Enable"}
                  </button>
                  <button className={buttonClass} onClick={() => resetPassword(u)}>Reset password</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function RuleRow({ rule, onSaved, onError }) {
  const [minCount, setMinCount] = useState(rule.min_count ?? "");
  const [windowMinutes, setWindowMinutes] = useState(rule.window_minutes ?? "");
  const isCluster = rule.kind === "cluster";
  const dirty = isCluster && (Number(minCount) !== rule.min_count || Number(windowMinutes) !== rule.window_minutes);

  async function save(body) {
    try {
      onSaved(await patch(`/settings/rules/${rule.id}`, body));
    } catch (err) {
      onError(err.message);
    }
  }

  return (
    <tr className="border-t border-slate-800">
      <td className="px-3 py-2">
        <input type="checkbox" checked={rule.enabled} onChange={(e) => save({ enabled: e.target.checked })} />
      </td>
      <td className="px-3 py-2 text-slate-200">{rule.name}</td>
      <td className="px-3 py-2 text-slate-400">{rule.technique_ids.join(", ")}</td>
      <td className="px-3 py-2 text-slate-400">{rule.severity}</td>
      <td className="px-3 py-2">
        {isCluster ? (
          <div className="flex items-center gap-2 text-slate-400">
            <input className={`${inputClass} w-16`} type="number" min={1} max={1000} value={minCount}
              onChange={(e) => setMinCount(e.target.value)} />
            events in
            <input className={`${inputClass} w-16`} type="number" min={1} max={1440} value={windowMinutes}
              onChange={(e) => setWindowMinutes(e.target.value)} />
            min
            <button className={buttonClass} disabled={!dirty}
              onClick={() => save({ min_count: Number(minCount), window_minutes: Number(windowMinutes) })}>
              Save
            </button>
          </div>
        ) : (
          <span className="text-slate-600">per event</span>
        )}
      </td>
    </tr>
  );
}

function DetectionTab() {
  const [rules, setRules] = useState([]);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  useEffect(() => {
    get("/settings/rules").then(setRules).catch((err) => setError(err.message));
  }, []);

  function onSaved(updated) {
    setError("");
    setNotice(`${updated.name} saved; applies on the next detection run`);
    setRules((rs) => rs.map((r) => (r.id === updated.id ? updated : r)));
  }

  return (
    <div>
      <Message error={error} notice={notice} />
      <div className="overflow-x-auto rounded border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900 text-slate-400">
            <tr>
              <th className="px-3 py-2">On</th>
              <th className="px-3 py-2">Rule</th>
              <th className="px-3 py-2">ATT&CK</th>
              <th className="px-3 py-2">Severity</th>
              <th className="px-3 py-2">Threshold</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((r) => (
              <RuleRow key={r.id} rule={r} onSaved={onSaved} onError={setError} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function StatusDot({ ok, label }) {
  return (
    <span className="flex items-center gap-2">
      <span className={`h-2 w-2 rounded-full ${ok ? "bg-emerald-400" : "bg-red-400"}`} />
      {label}: {ok ? "yes" : "no"}
    </span>
  );
}

function SystemTab() {
  const [status, setStatus] = useState(null);
  const [cap, setCap] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const load = useCallback(() => {
    get("/settings/system")
      .then((s) => {
        setStatus(s);
        setCap(s.ai_calls_per_hour);
      })
      .catch((err) => setError(err.message));
  }, []);
  useEffect(load, [load]);

  async function saveCap() {
    setError("");
    try {
      await put("/settings/system", { ai_calls_per_hour: Number(cap) });
      setNotice("AI call cap saved");
      load();
    } catch (err) {
      setError(err.message);
    }
  }

  if (!status) return <Message error={error} notice="" />;

  return (
    <div className="space-y-4 text-sm text-slate-300">
      <Message error={error} notice={notice} />

      <section className="rounded border border-slate-800 p-4">
        <h2 className="mb-2 font-semibold text-slate-100">AI</h2>
        <p>Provider: {status.llm_provider} · Model: {status.llm_model}</p>
        <p>AI calls in the last hour (all users): {status.ai_calls_last_hour}</p>
        <div className="mt-2 flex items-center gap-2">
          Cap per user per hour:
          <input className={`${inputClass} w-20`} type="number" min={1} max={1000} value={cap}
            onChange={(e) => setCap(e.target.value)} />
          <button className={buttonClass} disabled={Number(cap) === status.ai_calls_per_hour} onClick={saveCap}>
            Save
          </button>
        </div>
      </section>

      <section className="rounded border border-slate-800 p-4">
        <h2 className="mb-2 font-semibold text-slate-100">Ollama</h2>
        {status.ollama ? (
          <div className="flex gap-6">
            <StatusDot ok={status.ollama.reachable} label="Reachable" />
            <StatusDot ok={status.ollama.model_installed} label="Model installed" />
            <StatusDot ok={status.ollama.model_loaded} label="Model loaded" />
          </div>
        ) : (
          <p className="text-slate-500">Not in use (provider is {status.llm_provider}).</p>
        )}
      </section>

      <section className="rounded border border-slate-800 p-4">
        <h2 className="mb-2 font-semibold text-slate-100">Collector</h2>
        <p>
          Last seen:{" "}
          {status.collector_last_seen ? new Date(status.collector_last_seen).toLocaleString() : "never"}
        </p>
      </section>

      <button className={buttonClass} onClick={load}>Refresh</button>
    </div>
  );
}

export default function Settings() {
  const { session } = useAuth();
  const [tab, setTab] = useState("Users");

  if (session?.role !== "admin") {
    return <p className="text-slate-500">Admins only.</p>;
  }

  return (
    <div>
      <h1 className="mb-4 text-xl font-semibold text-slate-100">Settings</h1>
      <div className="mb-4 flex gap-2">
        {TABS.map((t) => (
          <button key={t} onClick={() => setTab(t)}
            className={`rounded px-3 py-1.5 text-sm ${tab === t ? "bg-slate-800 text-white" : "text-slate-400 hover:text-slate-200"}`}>
            {t}
          </button>
        ))}
      </div>
      {tab === "Users" && <UsersTab />}
      {tab === "Detection" && <DetectionTab />}
      {tab === "System" && <SystemTab />}
    </div>
  );
}
