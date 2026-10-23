import { useId } from "react";

// Original brand mark: a shield outline crossed by a pulse line, with one node dot.
// The gradient stroke becomes a single colour in print (.ir-logo rules in theme.css).
const SIZES = {
  sm: { mark: 22, text: "text-sm" },
  lg: { mark: 34, text: "text-xl" },
};

export function LogoMark({ size = 22, className = "" }) {
  const gradId = `ir-logo-${useId().replace(/:/g, "")}`;
  const stroke = `url(#${gradId})`;
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" fill="none" aria-hidden="true" className={`ir-logo-mark ${className}`}>
      <defs>
        <linearGradient id={gradId} x1="4" y1="3" x2="28" y2="29" gradientUnits="userSpaceOnUse">
          <stop offset="0" style={{ stopColor: "var(--ir-logo-from)" }} />
          <stop offset="1" style={{ stopColor: "var(--ir-logo-to)" }} />
        </linearGradient>
      </defs>
      <path d="M16 3 6 7v8c0 6.6 4.2 11.4 10 14 5.8-2.6 10-7.4 10-14V7L16 3Z"
        stroke={stroke} strokeWidth="2" strokeLinejoin="round" />
      <path d="M3 16.5h7l2-4 3 8 3-6 1.5 2H29"
        stroke={stroke} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx="24" cy="10" r="1.8" fill={stroke} className="ir-logo-dot" />
    </svg>
  );
}

export default function Logo({ size = "sm", className = "" }) {
  const s = SIZES[size] || SIZES.sm;
  return (
    <span className={`ir-logo inline-flex items-center gap-2 ${className}`}>
      <LogoMark size={s.mark} />
      <span className={`${s.text} font-semibold tracking-tight text-slate-100`} style={{ letterSpacing: "-0.02em" }}>
        IR Assistant
      </span>
    </span>
  );
}
