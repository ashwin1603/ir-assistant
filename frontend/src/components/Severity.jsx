// Shared severity helpers. Colours live in theme.css (--ir-sev-*); this file only
// names them, so no page hard-codes a severity colour.
export const SEV_LEVELS = ["Low", "Medium", "High", "Critical"];

const key = (level) => (SEV_LEVELS.includes(level) ? level : "Low").toLowerCase();

// Mark colour (bars, chart slices, graph strokes).
export const sevColor = (level) => `var(--ir-sev-${key(level)})`;
// Text colour that passes AA on the dark background.
export const sevInk = (level) => `var(--ir-sev-${key(level)}-ink)`;
// Badge/cell classes: outline (Low), light tint (Medium), strong tint + left bar (High), solid + glow (Critical).
export const sevClass = (level) => `sev sev-${key(level)}`;

// One shape per level so severity reads without colour: circle, triangle, diamond, octagon.
const SHAPES = {
  low: <circle cx="5" cy="5" r="3.6" />,
  medium: <path d="M5 1 9.4 9H.6z" />,
  high: <path d="M5 .4 9.6 5 5 9.6.4 5z" />,
  critical: <path d="M3.1.5h3.8l2.6 2.6v3.8L6.9 9.5H3.1L.5 6.9V3.1z" />,
};

export function SevIcon({ level, size = 10, ...rest }) {
  return (
    <svg className="sev-icon" viewBox="0 0 10 10" width={size} height={size} fill="currentColor"
      aria-hidden="true" focusable="false" {...rest}>
      {SHAPES[key(level)]}
    </svg>
  );
}
