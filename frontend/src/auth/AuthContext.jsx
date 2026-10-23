import { createContext, useCallback, useContext, useMemo, useState } from "react";
import { get, post, postWithToken, setAuthToken } from "../lib/api";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  // Token lives only in React state (memory) — never persisted to localStorage,
  // so a page refresh always requires a fresh login.
  const [session, setSession] = useState(null);

  // Role and permissions come from /auth/me (the backend's permission table). They only
  // hide or disable controls; the backend enforces every permission on its own.
  const start = useCallback(async (data, username) => {
    setAuthToken(data.access_token);
    const me = await get("/auth/me");
    setSession({ token: data.access_token, role: me.role, username: me.username || username, permissions: me.permissions || [] });
  }, []);

  // Returns { mfaToken } when a second step is needed, or { setupToken } when an admin
  // must enrol in MFA first. Both tokens stay in the Login page's state only.
  const login = useCallback(async (username, password) => {
    const data = await post("/auth/login", { username, password });
    if (data.mfa_setup_required) return { setupToken: data.mfa_token };
    if (data.mfa_required) return { mfaToken: data.mfa_token };
    await start(data, username);
    return {};
  }, [start]);

  const verifyMfa = useCallback(async (username, mfaToken, code) => {
    await start(await post("/auth/mfa/verify", { mfa_token: mfaToken, code }), username);
  }, [start]);

  // Forced enrolment: the setup token works only for these two calls.
  const beginForcedSetup = useCallback((setupToken) => postWithToken("/auth/mfa/setup", undefined, setupToken), []);
  const finishForcedSetup = useCallback(async (username, setupToken, code) => {
    const data = await postWithToken("/auth/mfa/enable", { code }, setupToken);
    return { recoveryCodes: data.recovery_codes, enter: () => start(data, username) };
  }, [start]);

  const logout = useCallback(() => {
    setAuthToken(null);
    setSession(null);
  }, []);

  const can = useCallback((action) => !!session?.permissions?.includes(action), [session]);

  const value = useMemo(
    () => ({
      session,
      isAuthenticated: !!session,
      can,
      login,
      verifyMfa,
      beginForcedSetup,
      finishForcedSetup,
      logout,
    }),
    [session, can, login, verifyMfa, beginForcedSetup, finishForcedSetup, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
