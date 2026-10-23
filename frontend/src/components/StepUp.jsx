import { useCallback, useEffect, useState } from "react";
import { ApiError, get, post } from "../lib/api";

// Must match STEP_UP_REQUIRED in backend/app/auth/step_up.py.
const STEP_UP_REQUIRED = "Step-up authentication required";

const inputClass =
  "w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-sky-600";

function StepUpDialog({ onDone, onCancel }) {
  const [mfa, setMfa] = useState(null); // null while loading
  const [value, setValue] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    get("/auth/mfa").then((s) => setMfa(s.enabled)).catch(() => setMfa(false));
  }, []);

  async function submit(e) {
    e.preventDefault();
    setError("");
    try {
      await post("/auth/step-up", mfa ? { code: value } : { password: value });
      onDone();
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4">
      <form onSubmit={submit} className="w-full max-w-sm rounded-lg border border-slate-700 bg-slate-900 p-6">
        <h2 className="mb-1 font-semibold text-slate-100">Confirm it's you</h2>
        <p className="mb-4 text-sm text-slate-400">
          This action needs re-authentication (valid for 5 minutes).{" "}
          {mfa ? "Enter a code from your authenticator app." : "Enter your password."}
        </p>
        {mfa !== null && (
          <input
            autoFocus
            type={mfa ? "text" : "password"}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            autoComplete={mfa ? "one-time-code" : "current-password"}
            maxLength={mfa ? 20 : 200}
            className={inputClass}
          />
        )}
        {error && <p className="mt-2 text-sm text-red-400">{error}</p>}
        <div className="mt-4 flex justify-end gap-2">
          <button type="button" onClick={onCancel} className="rounded px-3 py-1.5 text-sm text-slate-400 hover:text-slate-200">
            Cancel
          </button>
          <button type="submit" disabled={!value} className="rounded bg-sky-600 px-3 py-1.5 text-sm text-white hover:bg-sky-500 disabled:opacity-50">
            Confirm
          </button>
        </div>
      </form>
    </div>
  );
}

// Returns [dialog, withStepUp]. withStepUp(fn) runs fn; if the backend answers
// "step-up required", it shows the dialog and retries fn once after re-authentication.
export function useStepUp() {
  const [pending, setPending] = useState(null);

  const withStepUp = useCallback(async (fn) => {
    try {
      return await fn();
    } catch (err) {
      if (!(err instanceof ApiError && err.status === 403 && err.message === STEP_UP_REQUIRED)) throw err;
      await new Promise((resolve, reject) => setPending({ resolve, reject }));
      return fn();
    }
  }, []);

  const dialog = pending ? (
    <StepUpDialog
      onDone={() => { pending.resolve(); setPending(null); }}
      onCancel={() => { pending.reject(new Error("Cancelled: re-authentication is required for this action")); setPending(null); }}
    />
  ) : null;

  return [dialog, withStepUp];
}
