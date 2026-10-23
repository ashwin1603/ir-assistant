// Segmented control for tabs and filters. options: [{ value, label }].
// tabs=true uses tab semantics (page sections); otherwise a radio group (filters).
// Arrow keys move the selection. Styles: .ir-seg in theme.css.
export function Segmented({ options, value, onChange, label, tabs = false }) {
  const itemRole = tabs ? "tab" : "radio";

  function onKeyDown(e) {
    const step = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 }[e.key];
    if (!step) return;
    e.preventDefault();
    const i = options.findIndex((o) => o.value === value);
    const next = (i + step + options.length) % options.length;
    onChange(options[next].value);
    e.currentTarget.querySelectorAll("button")[next]?.focus();
  }

  return (
    <div className="ir-seg" role={tabs ? "tablist" : "radiogroup"} aria-label={label} onKeyDown={onKeyDown}>
      {options.map((o) => {
        const selected = o.value === value;
        return (
          <button
            key={o.value}
            type="button"
            role={itemRole}
            aria-selected={tabs ? selected : undefined}
            aria-checked={tabs ? undefined : selected}
            tabIndex={selected ? 0 : -1}
            onClick={() => onChange(o.value)}
            className="ir-seg-btn"
          >
            {o.label}
          </button>
        );
      })}
    </div>
  );
}
