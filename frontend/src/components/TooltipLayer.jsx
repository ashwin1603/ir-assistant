import { useEffect, useState } from "react";
import { createPortal } from "react-dom";

// One floating glass tooltip for every element with a data-tip attribute (chart bars,
// relative times, sparklines). Fixed-positioned in a portal, so scrolling card bodies
// never clip it. Shows on hover and on keyboard focus.
export function TooltipLayer() {
  const [tip, setTip] = useState(null);

  useEffect(() => {
    function show(e) {
      const el = e.target.closest?.("[data-tip]");
      if (!el) return;
      const r = el.getBoundingClientRect();
      const below = r.top < 48; // no room above: show it underneath
      setTip({ text: el.dataset.tip, x: r.left + r.width / 2, y: below ? r.bottom + 8 : r.top - 8, below });
    }
    function hide(e) {
      const from = e.target.closest?.("[data-tip]");
      if (from && !from.contains(e.relatedTarget)) setTip(null);
    }
    const clear = () => setTip(null);
    document.addEventListener("pointerover", show);
    document.addEventListener("pointerout", hide);
    document.addEventListener("focusin", show);
    document.addEventListener("focusout", hide);
    window.addEventListener("scroll", clear, true);
    return () => {
      document.removeEventListener("pointerover", show);
      document.removeEventListener("pointerout", hide);
      document.removeEventListener("focusin", show);
      document.removeEventListener("focusout", hide);
      window.removeEventListener("scroll", clear, true);
    };
  }, []);

  if (!tip) return null;
  const x = Math.min(Math.max(tip.x, 90), window.innerWidth - 90); // keep it on screen
  return createPortal(
    <div role="tooltip" className={`ir-tooltip${tip.below ? " below" : ""}`} style={{ left: x, top: tip.y }}>
      {tip.text}
    </div>,
    document.body,
  );
}
