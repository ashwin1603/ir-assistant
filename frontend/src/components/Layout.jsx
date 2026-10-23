import { useEffect, useState } from "react";
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

const navClass = ({ isActive }) => `ir-navlink${isActive ? " active" : ""}`;

// Browser connectivity drives the status dot next to the user menu.
function useOnline() {
  const [online, setOnline] = useState(navigator.onLine);
  useEffect(() => {
    const update = () => setOnline(navigator.onLine);
    window.addEventListener("online", update);
    window.addEventListener("offline", update);
    return () => {
      window.removeEventListener("online", update);
      window.removeEventListener("offline", update);
    };
  }, []);
  return online;
}

export default function Layout() {
  const { session, can, logout } = useAuth();
  const location = useLocation();
  const online = useOnline();
  const [menuOpen, setMenuOpen] = useState(false);
  const items = [...navItems];
  if (can("upload")) items.push({ to: "/upload", label: "Upload" });
  if (can("read_audit")) items.push({ to: "/audit", label: "Audit Log" });
  items.push({ to: "/settings", label: "Settings" }); // non-admins see only "My account"

  return (
    <div className="min-h-screen text-slate-100 print:bg-white print:text-black">
      <div className="ir-topbar-wrap ir-container print:hidden">
        <header className="ir-topbar">
          <div className="flex items-center justify-between gap-4 py-2 pl-4 pr-2.5">
            <span className="flex shrink-0 items-center gap-2 text-sm font-semibold tracking-tight text-slate-100">
              <span className="inline-block h-3 w-3 rounded-full bg-gradient-to-br from-sky-400 to-violet-500" aria-hidden="true" />
              IR Assistant
            </span>
            <nav className="ir-nav hidden text-[13px] min-[1100px]:flex" aria-label="Main">
              {items.map((item) => (
                <NavLink key={item.to} to={item.to} className={navClass}>
                  {item.label}
                </NavLink>
              ))}
            </nav>
            <div className="flex shrink-0 items-center gap-2.5 text-[13px] text-slate-300">
              <span className={`live-dot${online ? "" : " off"}`} title={online ? "Online" : "Offline"} />
              <span className="hidden max-w-[10rem] truncate 2xl:inline">{session?.username}</span>
              <span className="ir-role">{session?.role}</span>
              <button
                onClick={logout}
                title={`${session?.username} (${session?.role})`}
                className="rounded-full border border-slate-700 px-3 py-1 text-slate-300"
              >
                Logout
              </button>
              <button
                onClick={() => setMenuOpen((o) => !o)}
                aria-expanded={menuOpen}
                aria-label="Toggle navigation"
                className="rounded-full border border-slate-700 px-2.5 py-1 text-slate-300 min-[1100px]:hidden"
              >
                {menuOpen ? "✕" : "☰"}
              </button>
            </div>
          </div>
          {menuOpen && (
            <nav className="ir-mobile-nav page-enter grid gap-0.5 border-t border-white/10 p-2 text-sm min-[1100px]:hidden">
              <span className="px-3 py-1 text-xs text-slate-400">
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
      </div>
      <main className="ir-container print:max-w-none print:p-0">
        <ErrorBoundary key={location.pathname}>
          <div className="page-enter">
            <Outlet />
          </div>
        </ErrorBoundary>
      </main>
    </div>
  );
}
