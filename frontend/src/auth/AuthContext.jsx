import { createContext, useCallback, useContext, useMemo, useState } from "react";
import { post, setAuthToken } from "../lib/api";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  // Token lives only in React state (memory) — never persisted to localStorage,
  // so a page refresh always requires a fresh login.
  const [session, setSession] = useState(null);

  const login = useCallback(async (username, password) => {
    const data = await post("/auth/login", { username, password });
    setAuthToken(data.access_token);
    setSession({ token: data.access_token, role: data.role, username });
    return data;
  }, []);

  const logout = useCallback(() => {
    setAuthToken(null);
    setSession(null);
  }, []);

  const value = useMemo(
    () => ({
      session,
      isAuthenticated: !!session,
      login,
      logout,
    }),
    [session, login, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
