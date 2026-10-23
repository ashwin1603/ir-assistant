import { useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { ApiError } from "../lib/api";
import Logo from "../components/Logo";
import { useCopy, useDocumentTitle } from "../components/Toast";

// Decorative background only: public ATT&CK technique names and generic words. No real data, no API calls.
const TILE_ROWS = [
  ["T1110 Brute Force", "Detect", "T1059.001 PowerShell", "Investigate", "T1027 Obfuscated Files", "Respond"],
  ["Respond", "T1136.001 Local Account", "Detect", "T1098 Account Manipulation", "Investigate", "T1053.005 Scheduled Task"],
  ["T1543.003 Windows Service", "Investigate", "T1070.001 Clear Event Logs", "Detect", "T1033 Owner Discovery", "Respond"],
  ["Detect", "T1087 Account Discovery", "Respond", "T1082 System Discovery", "Investigate", "T1110 Brute Force"],
  ["T1027 Obfuscated Files", "Respond", "T1059.001 PowerShell", "Detect", "T1098 Account Manipulation", "Investigate"],
];

function TileWall() {
  return (
    <div className="lg-wall" aria-hidden="true">
      <div className="lg-wall-inner">
        {TILE_ROWS.map((row, r) => (
          <div key={r} className={`lg-row ${r % 2 ? "rev" : ""}`}>
            {/* Rendered twice so the -50% loop is seamless. */}
            {[...row, ...row].map((label, i) => (
              <span key={i} className={`lg-tile ${label.startsWith("T1") ? "" : "word"}`}>{label}</span>
            ))}
          </div>
        ))}
      </div>
      <div className="lg-vignette" />
    </div>
  );
}

function Field({ id, label, type = "text", value, onChange, autoFocus, autoComplete, onKeyUp, children }) {
  return (
    <div className="lg-field">
      <input id={id} type={type} value={value} onChange={onChange} onKeyUp={onKeyUp}
        placeholder=" " autoFocus={autoFocus} autoComplete={autoComplete} required />
      <label htmlFor={id}>{label}</label>
      {children}
    </div>
  );
}

// Six single-digit boxes with auto-advance, backspace-to-previous and paste of the whole code.
function OtpBoxes({ value, onChange }) {
  const refs = useRef([]);
  // value is a plain string of up to 6 digits; box i shows value[i].
  const digits = Array.from({ length: 6 }, (_, i) => value[i] || "");

  function handleChange(i, e) {
    const d = e.target.value.replace(/\D/g, "").slice(-1);
    if (!d) return;
    const at = Math.min(i, value.length); // no gaps: fill the first empty box
    onChange((value.slice(0, at) + d + value.slice(at + 1)).slice(0, 6));
    refs.current[at + 1]?.focus();
  }

  function handleKeyDown(i, e) {
    if (e.key === "Backspace") {
      e.preventDefault();
      if (value[i]) onChange(value.slice(0, i) + value.slice(i + 1));
      else if (i > 0) { onChange(value.slice(0, i - 1) + value.slice(i)); refs.current[i - 1]?.focus(); }
    } else if (e.key === "ArrowLeft") refs.current[i - 1]?.focus();
    else if (e.key === "ArrowRight") refs.current[i + 1]?.focus();
  }

  function handlePaste(e) {
    const pasted = e.clipboardData.getData("text").replace(/\D/g, "").slice(0, 6);
    if (!pasted) return;
    e.preventDefault();
    onChange(pasted);
    refs.current[Math.min(pasted.length, 5)]?.focus();
  }

  return (
    <div className="lg-otp" role="group" aria-label="6-digit authentication code">
      {digits.map((d, i) => (
        <input key={i} ref={(el) => { refs.current[i] = el; }} value={d} inputMode="numeric"
          autoComplete={i === 0 ? "one-time-code" : "off"} autoFocus={i === 0} maxLength={1}
          aria-label={`Digit ${i + 1}`} onChange={(e) => handleChange(i, e)}
          onKeyDown={(e) => handleKeyDown(i, e)} onPaste={handlePaste} onFocus={(e) => e.target.select()} />
      ))}
    </div>
  );
}

// Generic messages only: never reveal whether the username exists.
function friendlyError(err, step) {
  if (err instanceof ApiError && err.status === 429) return "Too many attempts. Please wait and try again.";
  if (err instanceof ApiError && err.status === 0) return "Can't reach the server. Check your connection.";
  return step === "password" ? "Incorrect username or password." : "That code didn't work. Try again.";
}

const EyeIcon = ({ open }) => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z" />
    <circle cx="12" cy="12" r="3" />
    {!open && <path d="M3 3l18 18" />}
  </svg>
);

const LockIcon = () => (
  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
    <rect x="4" y="11" width="16" height="10" rx="2" />
    <path d="M8 11V7a4 4 0 0 1 8 0v4" />
  </svg>
);

export default function Login() {
  const { login, verifyMfa, beginForcedSetup, finishForcedSetup } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const copy = useCopy();
  useDocumentTitle("Sign in");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [capsLock, setCapsLock] = useState(false);
  const [mfaToken, setMfaToken] = useState(null);
  const [useRecovery, setUseRecovery] = useState(false);
  // Forced MFA enrolment ("Require MFA for admin"): setup-only token, secret, then recovery codes.
  const [setupToken, setSetupToken] = useState(null);
  const [setup, setSetup] = useState(null);
  const [enrolled, setEnrolled] = useState(null); // { recoveryCodes, enter }
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const from = location.state?.from?.pathname || "/events";
  const step = enrolled ? "enrolled" : setupToken ? "setup" : mfaToken ? "mfa" : "password";

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
      setError(friendlyError(err, step));
    } finally {
      setSubmitting(false);
    }
  }

  function back() {
    setMfaToken(null); setSetupToken(null); setSetup(null); setCode(""); setError(""); setUseRecovery(false);
  }

  const subline = {
    password: "Rules detect, AI explains.",
    mfa: useRecovery ? "Enter one of your recovery codes." : "Enter the 6-digit code from your authenticator app.",
    setup: "MFA is required for admin accounts. Set it up to continue.",
    enrolled: "MFA is on. Save your recovery codes, then continue.",
  }[step];
  const heading = step === "password" ? "Sign in" : step === "enrolled" ? "You're all set" : "Verify it's you";
  const buttonLabel = { password: "Sign in", mfa: "Verify", setup: "Enable MFA", enrolled: "Continue" }[step];
  const codeIncomplete = (step === "setup" || (step === "mfa" && !useRecovery)) && code.length !== 6;

  return (
    <div className="lg-page">
      <TileWall />
      <div className="lg-brand"><Logo size="lg" /></div>

      <main className="lg-center">
        <form onSubmit={handleSubmit} className="lg-card page-enter" noValidate={step !== "password"}>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-100">{heading}</h1>
          <p className="mb-6 mt-1 text-sm text-slate-400">{subline}</p>

          {step === "enrolled" && (
            <div className="mb-5 rounded-xl border border-amber-700/70 bg-amber-950/40 p-3">
              <p className="mb-2 text-xs text-amber-300">Each code works once; they will not be shown again.</p>
              <pre className="font-mono text-xs text-slate-100">{enrolled.recoveryCodes.join("\n")}</pre>
              <button type="button" className="lg-link mt-2" onClick={() => copy(enrolled.recoveryCodes.join("\n"), "Recovery codes copied")}>
                Copy codes
              </button>
            </div>
          )}

          {step === "setup" && (
            <>
              {setup && (
                <div className="mb-4 space-y-1 text-xs text-slate-400">
                  <p>Add this account to your authenticator app, then enter the 6-digit code.</p>
                  <p>Secret: <code className="break-all font-mono text-slate-100">{setup.secret}</code></p>
                  <p>URI: <code className="break-all font-mono">{setup.otpauth_uri}</code></p>
                </div>
              )}
              <OtpBoxes value={code} onChange={setCode} />
            </>
          )}

          {step === "mfa" && (
            useRecovery ? (
              <Field id="recovery" label="Recovery code" value={code} autoFocus autoComplete="one-time-code"
                onChange={(e) => setCode(e.target.value.trim().slice(0, 20))} />
            ) : (
              <OtpBoxes value={code} onChange={setCode} />
            )
          )}

          {step === "password" && (
            <>
              <Field id="username" label="Username" value={username} autoFocus autoComplete="username"
                onChange={(e) => setUsername(e.target.value)} />
              <Field id="password" label="Password" type={showPassword ? "text" : "password"} value={password}
                autoComplete="current-password" onChange={(e) => setPassword(e.target.value)}
                onKeyUp={(e) => setCapsLock(e.getModifierState?.("CapsLock") ?? false)}>
                <button type="button" className="lg-eye" onClick={() => setShowPassword((s) => !s)}
                  aria-label={showPassword ? "Hide password" : "Show password"} aria-pressed={showPassword}>
                  <EyeIcon open={!showPassword} />
                </button>
              </Field>
              {capsLock && <p className="-mt-2 mb-3 text-xs text-amber-300" role="status">Caps Lock is on</p>}
            </>
          )}

          {error && <p className="mb-4 text-sm text-red-400" role="alert">{error}</p>}

          <button type="submit" disabled={submitting || codeIncomplete} className="lg-submit">
            {submitting && <span className="lg-spinner" aria-hidden="true" />}
            {submitting ? "Please wait…" : buttonLabel}
          </button>

          {step === "mfa" && (
            <button type="button" className="lg-link mt-4 block w-full text-center"
              onClick={() => { setUseRecovery((u) => !u); setCode(""); setError(""); }}>
              {useRecovery ? "Use authenticator code" : "Use a recovery code"}
            </button>
          )}
          {(step === "mfa" || step === "setup") && (
            <button type="button" onClick={back} className="mt-2 w-full text-xs text-slate-500 hover:text-slate-300">
              Back
            </button>
          )}

          <p className="mt-6 flex items-center justify-center gap-1.5 text-xs text-slate-500">
            <LockIcon /> Sessions expire automatically
          </p>
        </form>
      </main>
    </div>
  );
}
