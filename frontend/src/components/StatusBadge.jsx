export const INCIDENT_STATUSES = ["new", "investigating", "contained", "closed"];

const STYLES = {
  new: "bg-cyan-900/60 text-cyan-300",
  investigating: "bg-amber-900/60 text-amber-300",
  contained: "bg-violet-900/60 text-violet-300",
  closed: "bg-slate-800 text-slate-400",
};

export function StatusBadge({ status }) {
  return (
    <span className={`rounded px-2 py-0.5 text-xs font-medium uppercase ${STYLES[status] || STYLES.new}`}>
      {status}
    </span>
  );
}
