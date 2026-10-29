import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { get } from "../lib/api";
import { Skeleton } from "./Skeleton";
import { SEV_LEVELS, SevIcon, sevColor } from "./Severity";

// Plain SVG attack graph: host (and user) on the left, detections left-to-right by time.
const COL_W = 190;
const NODE_W = 160;
const HOST_H = 56;
const LINE_H = 15;
const PER_ROW = 6;
const PAD = 20;
const LABEL_SPACE = 26; // room above each row for tactic group labels
const ROW_GAP = 70; // vertical space between rows (holds the wrap-around arrow and labels)

function shorten(text, max = 22) {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

// Greedy word wrap so full rule names fit inside a node.
function wrapWords(text, maxChars = 22) {
  const lines = [];
  let line = "";
  text.split(/\s+/).forEach((word) => {
    if (line && (line + " " + word).length > maxChars) {
      lines.push(line);
      line = word;
    } else {
      line = line ? `${line} ${word}` : word;
    }
  });
  if (line) lines.push(line);
  return lines;
}

export function AttackGraph({ incidentId }) {
  const [graph, setGraph] = useState(null);
  const [error, setError] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    get(`/incidents/${incidentId}/graph`)
      .then(setGraph)
      .catch((err) => setError(err.message || "Failed to load attack graph"));
  }, [incidentId]);

  if (error) return <p className="mb-6 text-sm text-red-400">{error}</p>;
  if (!graph) return <div className="glass mb-6 rounded border p-4"><Skeleton lines={5} /></div>;

  const detections = graph.nodes.filter((n) => n.type === "detection");
  const wrapped = Object.fromEntries(detections.map((n) => [n.id, wrapWords(n.rule)]));
  // Every detection node gets the same height: enough for the longest wrapped rule name.
  const maxLines = Math.max(2, ...Object.values(wrapped).map((l) => l.length));
  const NODE_H = 10 + maxLines * LINE_H + 34;
  const ROW_H = NODE_H + ROW_GAP;
  const rowTop = (r) => PAD + LABEL_SPACE + r * ROW_H;

  // Layout: column 0 = host (user below it); detections fill columns 1..6, wrapping into new rows.
  const pos = {};
  const hostY = rowTop(0) + (NODE_H - HOST_H) / 2;
  graph.nodes.forEach((n) => {
    if (n.type === "host") pos[n.id] = { x: PAD, y: hostY, h: HOST_H };
    if (n.type === "user") pos[n.id] = { x: PAD, y: hostY + HOST_H + 30, h: HOST_H };
  });
  detections.forEach((n, i) => {
    const row = Math.floor(i / PER_ROW);
    pos[n.id] = { x: PAD + ((i % PER_ROW) + 1) * COL_W, y: rowTop(row), h: NODE_H, row };
  });
  const rows = Math.max(1, Math.ceil(detections.length / PER_ROW));
  const width = PAD * 2 + Math.min(detections.length, PER_ROW) * COL_W + NODE_W;
  const height = Math.max(rowTop(rows - 1) + NODE_H, hostY + HOST_H * 2 + 30) + PAD;

  // Runs of consecutive detections sharing a tactic (within one row) get one shaded group box.
  const groups = [];
  detections.forEach((n, i) => {
    const last = groups[groups.length - 1];
    if (last && last.tactic === n.tactic && pos[detections[last.start].id].row === pos[n.id].row) last.end = i;
    else groups.push({ tactic: n.tactic, start: i, end: i });
  });

  function edgePath(e) {
    const a = pos[e.source];
    const b = pos[e.target];
    if (!a || !b) return null;
    if (e.kind === "account") {
      // user sits below host: vertical line up into host
      return `M${a.x + NODE_W / 2},${a.y} L${b.x + NODE_W / 2},${b.y + b.h}`;
    }
    if (a.row !== undefined && b.row !== undefined && b.row > a.row) {
      // wrap to next row: down from source, left along the gap, down into target
      const midY = a.y + a.h + 14;
      return `M${a.x + NODE_W / 2},${a.y + a.h} V${midY} H${b.x + NODE_W / 2} V${b.y}`;
    }
    return `M${a.x + NODE_W},${a.y + a.h / 2} L${b.x},${b.y + b.h / 2}`;
  }

  return (
    <div className="mb-6 rounded border border-slate-800 bg-slate-900/40 p-4">
      <div className="mb-3 flex flex-wrap items-center gap-4 text-xs text-slate-400">
        {SEV_LEVELS.map((level) => (
          <span key={level} className="flex items-center gap-1">
            <SevIcon level={level} style={{ color: sevColor(level) }} />
            {level}
          </span>
        ))}
        <span className="flex items-center gap-1">
          <span className="inline-block h-3 w-3 rounded-sm border border-sky-500 bg-slate-800" />
          Host / user
        </span>
        <span>— next step</span>
        <span>┄ same tactic</span>
        <span className="text-slate-500">Click a detection to open its technique page.</span>
      </div>

      {detections.length === 0 ? (
        <p className="text-sm text-slate-500">No detections to graph.</p>
      ) : (
        <div className="overflow-x-auto">
          <svg width={width} height={height} role="img" aria-label="Attack graph" className="block">
            <defs>
              <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto">
                <path d="M0,0 L10,5 L0,10 z" fill="var(--ir-graph-line)" />
              </marker>
            </defs>

            {groups
              .filter((g) => g.end > g.start)
              .map((g) => {
                const first = pos[detections[g.start].id];
                const x = first.x - 8;
                const w = (g.end - g.start) * COL_W + NODE_W + 16;
                return (
                  <g key={`${g.tactic}-${g.start}`}>
                    <rect x={x} y={first.y - LABEL_SPACE} width={w} height={NODE_H + LABEL_SPACE + 8} rx="8"
                      fill="var(--ir-graph-line)" fillOpacity="0.05" stroke="var(--ir-graph-line)" strokeOpacity="0.3" strokeDasharray="4 3" />
                    <text x={x + 8} y={first.y - 12} fontSize="11" fill="var(--ir-graph-label)">{g.tactic}</text>
                  </g>
                );
              })}

            {graph.edges.map((e) => {
              const d = edgePath(e);
              return d ? (
                <path key={`${e.source}-${e.target}`} d={d} fill="none" stroke="var(--ir-graph-line)" strokeWidth="1.5"
                  pathLength={e.kind === "same_tactic" ? undefined : 1}
                  className={e.kind === "same_tactic" ? "ag-fade" : "ag-draw"}
                  strokeDasharray={e.kind === "same_tactic" ? "5 4" : undefined} markerEnd="url(#arrow)" />
              ) : null;
            })}

            {graph.nodes.map((n) => {
              const p = pos[n.id];
              if (!p) return null;
              if (n.type !== "detection") {
                return (
                  <g key={n.id} className="ag-node">
                    <rect x={p.x} y={p.y} width={NODE_W} height={p.h} rx="6" fill="var(--ir-graph-node)" stroke="var(--ir-accent)" />
                    <text x={p.x + 10} y={p.y + 22} fontSize="10" fill="var(--ir-graph-line)">{n.type.toUpperCase()}</text>
                    <text x={p.x + 10} y={p.y + 40} fontSize="13" fill="var(--ir-graph-text)">{shorten(n.label)}</text>
                  </g>
                );
              }
              const clickable = Boolean(n.technique);
              return (
                <g key={n.id} className={`ag-node${clickable ? " cursor-pointer" : ""}${n.risk_level === "Critical" ? " ag-critical" : ""}`}
                  onClick={() => clickable && navigate(`/attack/${n.technique}`)}>
                  <title>{`${n.rule}\n${n.technique_ids.join(", ")} · ${n.tactic}\nRisk ${n.risk_level} ${Math.round(n.risk_score)}\n${new Date(n.first_seen).toLocaleString()}`}</title>
                  <rect x={p.x} y={p.y} width={NODE_W} height={p.h} rx="6"
                    fill="var(--ir-graph-node)" stroke={sevColor(n.risk_level)} strokeWidth={n.risk_level === "Critical" ? 2 : 1} />
                  <rect x={p.x} y={p.y} width="4" height={p.h} rx="2" fill={sevColor(n.risk_level)} />
                  <SevIcon level={n.risk_level} x={p.x + NODE_W - 16} y={p.y + 7} style={{ color: sevColor(n.risk_level) }} />
                  <text x={p.x + 10} y={p.y + 18} fontSize="12" fontWeight="600" fill="var(--ir-graph-text)">
                    {wrapped[n.id].map((line, i) => (
                      <tspan key={i} x={p.x + 10} dy={i === 0 ? 0 : LINE_H}>{line}</tspan>
                    ))}
                  </text>
                  <text x={p.x + 10} y={p.y + NODE_H - 22} fontSize="11" fill="var(--ir-graph-text)">
                    {n.technique || "—"} · {(n.risk_level || "Low").toUpperCase()} {Math.round(n.risk_score)}
                  </text>
                  <text x={p.x + 10} y={p.y + NODE_H - 8} fontSize="10" fill="var(--ir-graph-text)">
                    {new Date(n.first_seen).toLocaleTimeString()}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>
      )}
    </div>
  );
}
