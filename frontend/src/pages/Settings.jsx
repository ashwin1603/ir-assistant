import { useCallback, useEffect, useState } from "react";
import { del, get, patch, post, put, upload } from "../lib/api";
import { useAuth } from "../auth/AuthContext";

const ADMIN_TABS = ["Users", "Detection", "Threat intel", "System"];
const TI_MAX_BYTES = 1024 * 1024;
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
              <th className="px-3 py-2">MFA</th>
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
                <td className="px-3 py-2 text-slate-400">{u.mfa_enabled ? "On" : "Off"}</td>
                <td className="px-3 py-2 text-slate-400">{new Date(u.created_at).toLocaleDateString()}</td>
                <td className="flex gap-2 px-3 py-2">
                  <button className={buttonClass}
                    onClick={() => run(() => patch(`/settings/users/${u.id}`, { is_active: !u.is_active }),
                      `${u.username} ${u.is_active ? "disabled" : "enabled"}`)}>
                    {u.is_active ? "Disable" : "Enable"}
                  </button>
                  <button className={buttonClass} onClick={() => resetPassword(u)}>Reset password</button>
                  <button className={buttonClass} disabled={!u.mfa_enabled}
                    onClick={() => window.confirm(`Turn off MFA for ${u.username}?`) &&
                      run(() => post(`/settings/users/${u.id}/reset-mfa`), `MFA reset for ${u.username}`)}>
                    Reset MFA
                  </button>
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

const SIGMA_MAX_BYTES = 50 * 1024;

function SigmaImport({ onImported, onError }) {
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);

  async function onFile(e) {
    const file = e.target.files[0];
    e.target.value = "";
    if (!file) return;
    if (!/\.ya?ml$/i.test(file.name)) return onError("Choose a .yml or .yaml file");
    if (file.size > SIGMA_MAX_BYTES) return onError("Rule too large (max 50 KB)");
    setText(await file.text());
  }

  async function submit() {
    setBusy(true);
    try {
      onImported(await post("/settings/rules/import-sigma", { yaml: text }));
      setText("");
    } catch (err) {
      onError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mt-6 rounded border border-slate-800 p-4">
      <h2 className="mb-1 text-sm font-semibold text-slate-200">Import Sigma rule</h2>
      <p className="mb-3 text-xs text-slate-500">
        Paste YAML or choose a .yml file (max 50 KB). Fields: CommandLine, Image, ParentImage, EventID, User,
        TargetUserName, ServiceFileName. Modifiers: contains, startswith, endswith, re, all. Imported rules start disabled.
      </p>
      <textarea value={text} onChange={(e) => setText(e.target.value)} rows={10} spellCheck={false}
        placeholder="title: ...&#10;logsource: ...&#10;detection: ..." className={`${inputClass} w-full font-mono text-xs`} />
      <div className="mt-2 flex items-center gap-3">
        <input type="file" accept=".yml,.yaml" onChange={onFile} className="text-xs text-slate-400" />
        <button onClick={submit} disabled={busy || !text.trim()} className={buttonClass}>
          {busy ? "Importing..." : "Import"}
        </button>
      </div>
    </div>
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

  function onImported(rule) {
    setError("");
    setNotice(`Imported "${rule.name}" (disabled) - tick its box to enable it`);
    setRules((rs) => [...rs, rule]);
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
      <SigmaImport onImported={onImported} onError={(msg) => { setNotice(""); setError(msg); }} />
    </div>
  );
}

function ThreatIntelTab() {
  const [indicators, setIndicators] = useState([]);
  const [q, setQ] = useState("");
  const [type, setType] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [importErrors, setImportErrors] = useState([]);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    const params = new URLSearchParams();
    if (q.trim()) params.set("q", q.trim());
    if (type) params.set("type", type);
    get(`/settings/ti?${params}`).then(setIndicators).catch((err) => setError(err.message));
  }, [q, type]);

  useEffect(() => {
    load();
  }, [load]);

  async function onFile(e) {
    const file = e.target.files[0];
    e.target.value = "";
    if (!file) return;
    setError(""); setNotice(""); setImportErrors([]);
    if (!/\.(csv|txt)$/i.test(file.name)) return setError("Choose a .csv or .txt file");
    if (file.size > TI_MAX_BYTES) return setError("File too large (max 1 MB)");
    setBusy(true);
    try {
      const result = await upload("/settings/ti/import", file);
      setNotice(`Added ${result.added}, skipped ${result.duplicates} duplicate(s), ${result.errors.length} invalid line(s)`);
      setImportErrors(result.errors);
      load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function remove(indicator) {
    if (!window.confirm(`Delete ${indicator.type} ${indicator.value}?`)) return;
    try {
      await del(`/settings/ti/${indicator.id}`);
      setIndicators((list) => list.filter((i) => i.id !== indicator.id));
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div>
      <Message error={error} notice={notice} />
      {importErrors.length > 0 && (
        <ul className="mb-3 list-disc pl-5 text-xs text-amber-300">
          {importErrors.map((e) => (
            <li key={e.line}>Line {e.line}: {e.reason}</li>
          ))}
        </ul>
      )}
      <div className="mb-4 rounded border border-slate-800 p-4">
        <h2 className="mb-1 text-sm font-semibold text-slate-200">Import indicators</h2>
        <p className="mb-3 text-xs text-slate-500">
          CSV or TXT, max 1 MB, one per line: <code>type,value,source,tags</code> (type is ip, domain or sha256;
          separate tags with ;). Private/loopback IPs are rejected and duplicates are skipped. Matching is local only.
        </p>
        <input type="file" accept=".csv,.txt" onChange={onFile} disabled={busy} className="text-xs text-slate-400" />
      </div>
      <div className="mb-3 flex gap-2">
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search value, source or tag" maxLength={200}
          className={`${inputClass} w-64`} />
        <select value={type} onChange={(e) => setType(e.target.value)} className={inputClass}>
          <option value="">All types</option>
          <option value="ip">ip</option>
          <option value="domain">domain</option>
          <option value="sha256">sha256</option>
        </select>
      </div>
      <div className="overflow-x-auto rounded border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900 text-slate-400">
            <tr>
              <th className="px-3 py-2">Type</th>
              <th className="px-3 py-2">Value</th>
              <th className="px-3 py-2">Source</th>
              <th className="px-3 py-2">Tags</th>
              <th className="px-3 py-2">Added</th>
              <th className="px-3 py-2"></th>
            </tr>
          </thead>
          <tbody>
            {indicators.length === 0 && (
              <tr>
                <td colSpan={6} className="px-3 py-6 text-center text-slate-500">No indicators.</td>
              </tr>
            )}
            {indicators.map((i) => (
              <tr key={i.id} className="border-t border-slate-800">
                <td className="px-3 py-2 text-slate-300">{i.type}</td>
                <td className="max-w-[24rem] truncate px-3 py-2 font-mono text-xs text-slate-200" title={i.value}>{i.value}</td>
                <td className="px-3 py-2 text-slate-300">{i.source}</td>
                <td className="px-3 py-2 text-slate-400">{i.tags || "—"}</td>
                <td className="whitespace-nowrap px-3 py-2 text-slate-400">{new Date(i.added_at).toLocaleString()}</td>
                <td className="px-3 py-2">
                  <button onClick={() => remove(i)} className={buttonClass}>Delete</button>
                </td>
              </tr>
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

function MyAccountTab() {
  const [status, setStatus] = useState(null);
  const [setup, setSetup] = useState(null); // { secret, otpauth_uri } while enrolling
  const [recoveryCodes, setRecoveryCodes] = useState(null); // shown once after enabling
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const load = useCallback(() => {
    get("/auth/mfa").then(setStatus).catch((err) => setError(err.message));
  }, []);
  useEffect(load, [load]);

  async function run(fn) {
    setError("");
    setNotice("");
    try {
      await fn();
      setCode("");
      setPassword("");
      load();
    } catch (err) {
      setError(err.message);
    }
  }

  const startSetup = () => run(async () => { setRecoveryCodes(null); setSetup(await post("/auth/mfa/setup")); });
  const confirmSetup = (e) => {
    e.preventDefault();
    run(async () => {
      setRecoveryCodes((await post("/auth/mfa/enable", { code })).recovery_codes);
      setSetup(null);
      setNotice("MFA enabled");
    });
  };
  const disable = (e) => {
    e.preventDefault();
    run(async () => {
      await post("/auth/mfa/disable", { password, code });
      setNotice("MFA disabled");
    });
  };

  if (!status) return <Message error={error} notice="" />;

  return (
    <div className="space-y-4 text-sm text-slate-300">
      <Message error={error} notice={notice} />
      <section className="rounded border border-slate-800 p-4">
        <h2 className="mb-2 font-semibold text-slate-100">Two-factor authentication (TOTP)</h2>
        <p className="mb-3">
          Status: {status.enabled ? `On · ${status.recovery_codes_left} recovery codes left` : "Off"}
        </p>

        {recoveryCodes && (
          <div className="mb-3 rounded border border-amber-700 bg-amber-950/40 p-3">
            <p className="mb-2 text-amber-300">Save these recovery codes now. Each works once; they will not be shown again.</p>
            <pre className="font-mono text-xs text-slate-100">{recoveryCodes.join("\n")}</pre>
          </div>
        )}

        {!status.enabled && !setup && <button className={buttonClass} onClick={startSetup}>Enable MFA</button>}

        {setup && (
          <form onSubmit={confirmSetup} className="space-y-2">
            <p>Add this account to your authenticator app, then enter the 6-digit code it shows.</p>
            <p>Secret: <code className="break-all font-mono text-slate-100">{setup.secret}</code></p>
            <p>URI: <code className="break-all font-mono text-xs text-slate-400">{setup.otpauth_uri}</code></p>
            <div className="flex gap-2">
              <input className={`${inputClass} w-32`} placeholder="123456" value={code} maxLength={6}
                inputMode="numeric" autoComplete="one-time-code" onChange={(e) => setCode(e.target.value.trim())} required />
              <button className={buttonClass} type="submit">Confirm</button>
              <button className={buttonClass} type="button" onClick={() => setSetup(null)}>Cancel</button>
            </div>
          </form>
        )}

        {status.enabled && (
          <form onSubmit={disable} className="flex flex-wrap gap-2">
            <input className={inputClass} type="password" placeholder="Password" value={password}
              autoComplete="current-password" onChange={(e) => setPassword(e.target.value)} required />
            <input className={`${inputClass} w-40`} placeholder="Code or recovery code" value={code} maxLength={20}
              autoComplete="one-time-code" onChange={(e) => setCode(e.target.value.trim())} required />
            <button className={buttonClass} type="submit">Disable MFA</button>
          </form>
        )}
      </section>
    </div>
  );
}

export default function Settings() {
  const { session } = useAuth();
  const isAdmin = session?.role === "admin";
  // Every user gets "My account"; the admin tabs are also enforced by the backend.
  const tabs = isAdmin ? ["My account", ...ADMIN_TABS] : ["My account"];
  const [tab, setTab] = useState("My account");

  return (
    <div>
      <h1 className="mb-4 text-xl font-semibold text-slate-100">Settings</h1>
      <div className="mb-4 flex gap-2">
        {tabs.map((t) => (
          <button key={t} onClick={() => setTab(t)}
            className={`rounded px-3 py-1.5 text-sm ${tab === t ? "bg-slate-800 text-white" : "text-slate-400 hover:text-slate-200"}`}>
            {t}
          </button>
        ))}
      </div>
      {tab === "My account" && <MyAccountTab />}
      {isAdmin && tab === "Users" && <UsersTab />}
      {isAdmin && tab === "Detection" && <DetectionTab />}
      {isAdmin && tab === "Threat intel" && <ThreatIntelTab />}
      {isAdmin && tab === "System" && <SystemTab />}
    </div>
  );
}
