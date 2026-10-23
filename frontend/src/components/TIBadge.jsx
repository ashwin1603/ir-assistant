// "TI match" badge: shown when an event/detection contains an imported
// threat-intel indicator. Hover shows each matched indicator and its source.
export function TIBadge({ matches }) {
  if (!matches || matches.length === 0) return null;
  const sources = [...new Set(matches.map((m) => m.source))].join(", ");
  const title = matches.map((m) => `${m.type} ${m.value} (${m.source}${m.tags ? `: ${m.tags}` : ""})`).join("\n");
  return (
    <span title={title} className="whitespace-nowrap rounded bg-fuchsia-900/60 px-1.5 py-0.5 text-xs font-medium text-fuchsia-300">
      TI match · {sources}
    </span>
  );
}
