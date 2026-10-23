import { useEffect, useRef } from "react";
import { createPortal } from "react-dom";
import { trapTab } from "../lib/a11y";

// Right-hand glass slide-over. Esc or a click on the scrim closes it; Tab stays inside;
// focus returns to the row that opened it without scrolling the page (styles: .ir-drawer in ux.css).
export function Drawer({ open, title, subtitle, onClose, children, actions }) {
  const panel = useRef(null);
  const closeRef = useRef(onClose);
  useEffect(() => {
    closeRef.current = onClose;
  });

  useEffect(() => {
    if (!open) return undefined;
    const opener = document.activeElement;
    panel.current?.focus({ preventScroll: true });
    function onKey(e) {
      if (e.key === "Escape") {
        e.stopPropagation();
        closeRef.current();
      } else {
        trapTab(e, panel.current);
      }
    }
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      opener?.focus?.({ preventScroll: true });
    };
  }, [open]);

  if (!open) return null;
  return createPortal(
    <>
      <div className="ir-scrim" onClick={() => closeRef.current()} aria-hidden="true" />
      <aside ref={panel} className="ir-drawer" role="dialog" aria-modal="true" aria-label={title} tabIndex={-1}>
        <header className="ir-drawer-head">
          <div className="min-w-0">
            <h2 className="truncate text-base font-semibold text-slate-100">{title}</h2>
            {subtitle && <p className="mt-0.5 truncate text-xs text-slate-400">{subtitle}</p>}
          </div>
          <button type="button" onClick={() => closeRef.current()} aria-label="Close details" className="ir-icon-btn">
            ✕
          </button>
        </header>
        <div className="ir-drawer-body">{children}</div>
        {actions && <footer className="ir-drawer-foot">{actions}</footer>}
      </aside>
    </>,
    document.body,
  );
}
