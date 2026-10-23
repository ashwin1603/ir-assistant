import { createContext, useCallback, useContext, useMemo, useState } from "react";
import { post, setAuthToken } from "../lib/api";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  // Token lives only in React state (memory) — never persisted to localStorage,
  // so a page refresh always requires a fresh login.
  const [session, setSession] = useState(null);

  const start = useCallback((data, username) => {
    setAuthToken(data.access_token);
    setSession({ token: data.access_token, role: data.role, username });
  }, []);

  // Returns { mfaToken } when a second step is needed; the mfa_token is kept only
  // in the Login page's state and is useless for anything except /auth/mfa/verify.
  const login = useCallback(async (username, password) => {
    const data = await post("/auth/login", { username, password });
    if (data.mfa_required) return { mfaToken: data.mfa_token };
    start(data, username);
    return {};
  }, [start]);

  const verifyMfa = useCallback(async (username, mfaToken, code) => {
    start(await post("/auth/mfa/verify", { mfa_token: mfaToken, code }), username);
  }, [start]);

  const logout = useCallback(() => {
    setAuthToken(null);
    setSession(null);
  }, []);

  const value = useMemo(
    () => ({
      session,
      isAuthenticated: !!session,
      login,
      verifyMfa,
      logout,
    }),
    [session, login, verifyMfa, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
