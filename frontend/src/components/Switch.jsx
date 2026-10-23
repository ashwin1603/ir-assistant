// Accessible on/off switch (replaces checkboxes used as toggles).
// A real <button role="switch">, so Space/Enter and focus work natively. Styles: .ir-switch in theme.css.
export function Switch({ checked, onChange, label, disabled = false, children }) {
  const control = (
    <button
      type="button"
      role="switch"
      aria-checked={!!checked}
      aria-label={children ? undefined : label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className="ir-switch"
    >
      <span className="ir-switch-knob" aria-hidden="true" />
    </button>
  );
  if (!children) return control;
  // With visible text, the label wraps both so clicking the text toggles too.
  return (
    <label className={`inline-flex items-center gap-2 ${disabled ? "cursor-not-allowed opacity-60" : "cursor-pointer"}`}>
      {control}
      <span>{children}</span>
    </label>
  );
}
