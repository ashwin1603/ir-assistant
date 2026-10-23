// Main navigation, shared by the top bar and the command palette.
// Role-aware: items whose permission the session lacks are left out
// (the backend still enforces every permission on its own).
const NAV_ITEMS = [
  { to: "/dashboard", label: "Dashboard" },
  { to: "/events", label: "Log Explorer" },
  { to: "/detections", label: "Detections" },
  { to: "/anomalies", label: "Anomalies" },
  { to: "/network", label: "Network" },
  { to: "/devices", label: "Devices" },
  { to: "/attack", label: "ATT&CK" },
  { to: "/incidents", label: "Incidents" },
  { to: "/recommendations", label: "Recommendations" },
  { to: "/upload", label: "Upload", permission: "upload" },
  { to: "/audit", label: "Audit Log", permission: "read_audit" },
  { to: "/settings", label: "Settings" }, // non-admins see only "My account"
];

export function navItemsFor(can) {
  return NAV_ITEMS.filter((item) => !item.permission || can(item.permission));
}
