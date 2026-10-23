import { useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import ErrorBoundary from "./ErrorBoundary";

const navItems = [
  { to: "/dashboard", label: "Dashboard" },
  { to: "/events", label: "Log Explorer" },
  { to: "/detections", label: "Detections" },
  { to: "/anomalies", label: "Anomalies" },
  { to: "/network", label: "Network" },
  { to: "/devices", label: "Devices" },
  { to: "/attack", label: "ATT&CK" },
  { to: "/incidents", label: "Incidents" },
  { to: "/recommendations", label: "Recommendations" },
];

const navClass = ({ isActive }) => `ir-navlink rounded px-1.5 py-1.5${isActive ? " active" : ""}`;

export default function Layout() {
  const { session, can, logout } = useAuth();
  const location = useLocation();
  const [menuOpen, setMenuOpen] = useState(false);
  const items = [...navItems];
  if (can("upload")) items.push({ to: "/upload", label: "Upload" });
  if (can("read_audit")) items.push({ to: "/audit", label: "Audit Log" });
  items.push({ to: "/settings", label: "Settings" }); // non-admins see only "My account"

  return (
    <div className="min-h-screen text-slate-100 print:bg-white print:text-black">
      <header className="ir-topbar sticky top-0 z-20 print:hidden">
        <div className="mx-auto flex max-w-[1400px] items-center justify-between gap-4 px-4 py-2.5">
          <div className="flex min-w-0 items-center gap-5">
            <span className="flex shrink-0 items-center gap-2 text-sm font-semibold tracking-tight text-slate-100">
              <span className="inline-block h-2.5 w-2.5 rounded-sm bg-sky-600" aria-hidden="true" />
              IR Assistant
            </span>
            <nav className="hidden items-center gap-0.5 text-[13px] xl:flex">
              {items.map((item) => (
                <NavLink key={item.to} to={item.to} className={navClass}>
                  {item.label}
                </NavLink>
              ))}
            </nav>
          </div>
          <div className="flex shrink-0 items-center gap-3 text-[13px] text-slate-400">
            <span className="hidden whitespace-nowrap 2xl:inline">
              {session?.username} <span className="text-slate-600">·</span> {session?.role}
            </span>
            <button
              onClick={logout}
              title={`${session?.username} (${session?.role})`}
              className="rounded border border-slate-700 px-3 py-1 text-slate-300 hover:border-sky-600 hover:text-white"
            >
              Logout
            </button>
            <button
              onClick={() => setMenuOpen((o) => !o)}
              aria-expanded={menuOpen}
              aria-label="Toggle navigation"
              className="rounded border border-slate-700 px-2.5 py-1 text-slate-300 hover:border-slate-500 xl:hidden"
            >
              {menuOpen ? "✕" : "☰"}
            </button>
          </div>
        </div>
        {menuOpen && (
          <nav className="ir-mobile-nav page-enter grid gap-0.5 border-t border-slate-800 px-4 py-2 text-sm xl:hidden">
            <span className="px-2 py-1 text-xs text-slate-500">
              {session?.username} · {session?.role}
            </span>
            {items.map((item) => (
              <NavLink key={item.to} to={item.to} className={navClass} onClick={() => setMenuOpen(false)}>
                {item.label}
              </NavLink>
            ))}
          </nav>
        )}
      </header>
      <main className="mx-auto max-w-[1400px] px-4 py-6 sm:px-6 print:max-w-none print:p-0">
        <ErrorBoundary key={location.pathname}>
          <div className="page-enter">
            <Outlet />
          </div>
        </ErrorBoundary>
      </main>
    </div>
  );
}
