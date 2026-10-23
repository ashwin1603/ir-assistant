import { useEffect, useRef, useState } from "react";

const DURATION_MS = 250;

// Animates a number from its previous value to `value` (instant when reduced motion is preferred).
export function CountUp({ value }) {
  const [shown, setShown] = useState(0);
  const from = useRef(0);

  useEffect(() => {
    const reduce = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    const start = from.current;
    from.current = value;
    if (reduce || start === value) {
      setShown(value);
      return undefined;
    }
    let frame;
    const t0 = performance.now();
    const step = (now) => {
      const p = Math.min(1, (now - t0) / DURATION_MS);
      setShown(Math.round(start + (value - start) * (1 - (1 - p) ** 3)));
      if (p < 1) frame = requestAnimationFrame(step);
    };
    frame = requestAnimationFrame(step);
    return () => cancelAnimationFrame(frame);
  }, [value]);

  return <>{shown.toLocaleString()}</>;
}
