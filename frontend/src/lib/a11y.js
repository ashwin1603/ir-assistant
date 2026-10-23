// Keyboard helpers shared by the drawer, command palette and clickable table rows.

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

// Keeps Tab / Shift+Tab inside `container`.
export function trapTab(e, container) {
  if (e.key !== "Tab" || !container) return;
  const items = [...container.querySelectorAll(FOCUSABLE)];
  if (items.length === 0) {
    e.preventDefault();
    return;
  }
  const first = items[0];
  const last = items[items.length - 1];
  if (e.shiftKey && (document.activeElement === first || document.activeElement === container)) {
    e.preventDefault();
    last.focus();
  } else if (!e.shiftKey && document.activeElement === last) {
    e.preventDefault();
    first.focus();
  }
}

// Props for a table row that opens the drawer on click or Enter. Clicks on links and
// buttons inside the row keep their own behaviour.
export function rowOpenProps(onOpen, selected) {
  return {
    tabIndex: 0,
    "aria-selected": selected || undefined,
    onClick: (e) => {
      if (!e.target.closest("a, button, input, select")) onOpen();
    },
    onKeyDown: (e) => {
      if (e.key === "Enter" && e.target === e.currentTarget) onOpen();
    },
  };
}
