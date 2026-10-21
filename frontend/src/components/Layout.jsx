import { NavLink, Outlet } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";

const navItems = [
  { to: "/events", label: "Log Explorer" },
  { to: "/detections", label: "Detections" },
  { to: "/incidents", label: "Incidents" },
  { to: "/recommendations", label: "Recommendations" },
];

export default function Layout() {
  const { session, logout } = useAuth();

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <header className="border-b border-slate-800 bg-slate-900/60">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-3">
          <div className="flex items-center gap-8">
            <span className="text-sm font-semibold tracking-wide text-slate-200">
              IR Assistant
            </span>
            <nav className="flex gap-4 text-sm">
              {navItems.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  className={({ isActive }) =>
                    `rounded px-3 py-1.5 transition-colors ${
                      isActive
                        ? "bg-slate-800 text-white"
                        : "text-slate-400 hover:text-slate-200"
                    }`
                  }
                >
                  {item.label}
                </NavLink>
              ))}
            </nav>
          </div>
          <div className="flex items-center gap-4 text-sm text-slate-400">
            <span>
              {session?.username} <span className="text-slate-600">·</span>{" "}
              {session?.role}
            </span>
            <button
              onClick={logout}
              className="rounded border border-slate-700 px-3 py-1 text-slate-300 hover:border-slate-500 hover:text-white"
            >
              Logout
            </button>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-6 py-6">
        <Outlet />
      </main>
    </div>
  );
}
