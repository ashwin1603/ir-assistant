import { useEffect, useRef, useState } from "react";

// Returns the set of row keys that were not in the previous list, so rows that appear on
// auto-refresh can be highlighted (.row-flash). A load after an empty list flashes nothing.
export function useNewIds(items, keyOf = (item) => item.id) {
  const seen = useRef(new Set());
  const [fresh, setFresh] = useState(new Set());
  const signature = items.map(keyOf).join("\n");

  useEffect(() => {
    const keys = signature ? signature.split("\n") : [];
    if (seen.current.size) setFresh(new Set(keys.filter((k) => !seen.current.has(k))));
    seen.current = new Set(keys);
  }, [signature]);

  return fresh;
}
