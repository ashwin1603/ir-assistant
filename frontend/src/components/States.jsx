import { Link } from "react-router-dom";

// Shared loading / empty / error states, so every page looks and behaves the same.
// Styles: .ir-empty, .ir-error, .ir-skel-row in ux.css.

// Friendly empty state with a hint about what to do next.
// action: { to, label } for a link, or { onClick, label } for a button.
export function EmptyState({ title, hint, action, compact = false }) {
  return (
    <div className={`ir-empty${compact ? " compact" : ""}`}>
      <span className="ir-empty-icon" aria-hidden="true" />
      <p className="font-medium text-slate-200">{title}</p>
      {hint && <p className="mt-1 max-w-md text-sm text-slate-400">{hint}</p>}
      {action &&
        (action.to ? (
          <Link to={action.to} className="ir-btn sm mt-3">{action.label}</Link>
        ) : (
          <button type="button" onClick={action.onClick} className="ir-btn sm mt-3">{action.label}</button>
        ))}
    </div>
  );
}

// Empty state as the single row of a table body.
export function EmptyRow({ colSpan, ...props }) {
  return (
    <tr>
      <td colSpan={colSpan} className="px-3 py-2">
        <EmptyState {...props} />
      </td>
    </tr>
  );
}

// Same banner for every failed load; Retry re-runs the request.
export function ErrorBanner({ message, onRetry }) {
  if (!message) return null;
  return (
    <div className="ir-error" role="alert">
      <span className="ir-error-icon" aria-hidden="true">!</span>
      <span className="min-w-0 flex-1">{message}</span>
      {onRetry && (
        <button type="button" onClick={onRetry} className="ir-btn sm">
          Retry
        </button>
      )}
    </div>
  );
}

// Content-shaped table placeholder: `rows` rows of `cols` cells with varied widths.
const CELL_WIDTHS = ["70%", "45%", "85%", "55%", "35%", "60%", "40%", "75%", "50%"];

export function SkeletonRows({ cols, rows = 6 }) {
  return Array.from({ length: rows }, (_, r) => (
    <tr key={r} className="ir-skel-row" aria-hidden={r > 0 || undefined}>
      {Array.from({ length: cols }, (_, c) => (
        <td key={c} className="px-3 py-2.5" aria-busy={r === 0 && c === 0 ? "true" : undefined}>
          <span className="skeleton" style={{ width: CELL_WIDTHS[(r + c * 3) % CELL_WIDTHS.length] }} />
        </td>
      ))}
    </tr>
  ));
}
