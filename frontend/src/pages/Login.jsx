import { useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { ApiError } from "../lib/api";

export default function Login() {
  const { login, verifyMfa, beginForcedSetup, finishForcedSetup } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [mfaToken, setMfaToken] = useState(null);
  // Forced MFA enrolment ("Require MFA for admin"): setup-only token, secret, then recovery codes.
  const [setupToken, setSetupToken] = useState(null);
  const [setup, setSetup] = useState(null);
  const [enrolled, setEnrolled] = useState(null); // { recoveryCodes, enter }
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const from = location.state?.from?.pathname || "/events";

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      if (enrolled) {
        await enrolled.enter();
      } else if (setupToken) {
        setEnrolled(await finishForcedSetup(username, setupToken, code));
        setCode("");
        return;
      } else if (mfaToken) {
        await verifyMfa(username, mfaToken, code);
      } else {
        const result = await login(username, password);
        if (result.setupToken) {
          setSetupToken(result.setupToken);
          setSetup(await beginForcedSetup(result.setupToken));
          setPassword("");
          return;
        }
        if (result.mfaToken) {
          setMfaToken(result.mfaToken);
          setPassword("");
          return;
        }
      }
      navigate(from, { replace: true });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Login failed");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-950 px-4">
      <form
        onSubmit={handleSubmit}
        className="glass page-enter w-full max-w-sm rounded-lg border p-8"
      >
        <h1 className="mb-1 text-lg font-semibold text-slate-100">IR Assistant</h1>
        <p className="mb-6 text-sm text-slate-500">
          {enrolled
            ? "MFA is on. Save your recovery codes, then continue."
            : setupToken
              ? "MFA is required for admin accounts. Set it up to continue."
              : mfaToken
                ? "Enter the 6-digit code from your authenticator app, or a recovery code"
                : "Sign in to continue"}
        </p>

        {enrolled ? (
          <div className="mb-4 rounded border border-amber-700 bg-amber-950/40 p-3">
            <p className="mb-2 text-xs text-amber-300">Each code works once; they will not be shown again.</p>
            <pre className="font-mono text-xs text-slate-100">{enrolled.recoveryCodes.join("\n")}</pre>
          </div>
        ) : setupToken ? (
          <>
            {setup && (
              <div className="mb-4 space-y-1 text-xs text-slate-400">
                <p>Add this account to your authenticator app, then enter the 6-digit code.</p>
                <p>Secret: <code className="break-all font-mono text-slate-100">{setup.secret}</code></p>
                <p>URI: <code className="break-all font-mono">{setup.otpauth_uri}</code></p>
              </div>
            )}
            <label className="mb-1 block text-xs font-medium text-slate-400">Authentication code</label>
            <input
              autoFocus
              value={code}
              onChange={(e) => setCode(e.target.value.trim())}
              maxLength={6}
              inputMode="numeric"
              autoComplete="one-time-code"
              className="mb-4 w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 text-sm tracking-widest text-slate-100 outline-none focus:border-sky-600"
            />
          </>
        ) : mfaToken ? (
          <>
            <label className="mb-1 block text-xs font-medium text-slate-400">Authentication code</label>
            <input
              autoFocus
              value={code}
              onChange={(e) => setCode(e.target.value.trim())}
              maxLength={20}
              className="mb-4 w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 text-sm tracking-widest text-slate-100 outline-none focus:border-sky-600"
              autoComplete="one-time-code"
              inputMode="text"
            />
          </>
        ) : (
        <>
        <label className="mb-1 block text-xs font-medium text-slate-400">Username</label>
        <input
          autoFocus
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          className="mb-4 w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-sky-600"
          autoComplete="username"
        />

        <label className="mb-1 block text-xs font-medium text-slate-400">Password</label>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="mb-4 w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-sky-600"
          autoComplete="current-password"
        />
        </>
        )}

        {error && <p className="mb-4 text-sm text-red-400">{error}</p>}

        <button
          type="submit"
          disabled={submitting}
          className="w-full rounded bg-sky-600 py-2 text-sm font-medium text-white transition-colors hover:bg-sky-500 disabled:opacity-50"
        >
          {submitting ? "Signing in..." : enrolled ? "Continue" : setupToken ? "Enable MFA" : mfaToken ? "Verify" : "Sign in"}
        </button>
        {(mfaToken || (setupToken && !enrolled)) && (
          <button type="button" onClick={() => { setMfaToken(null); setSetupToken(null); setSetup(null); setCode(""); setError(""); }}
            className="mt-3 w-full text-xs text-slate-500 hover:text-slate-300">
            Back
          </button>
        )}
      </form>
    </div>
  );
}
