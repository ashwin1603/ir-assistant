import { Link } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { Drawer } from "./Drawer";
import { RiskBadge } from "./RiskBadge";
import { TIBadge } from "./TIBadge";
import { useCopy } from "./Toast";
import { TimeAgo } from "./TimeAgo";

// Drawer contents for one detection, event or anomaly. Everything shown comes from data the
// page already loaded, so viewers see exactly what the API redacted for them.

const EVIDENCE_SHOWN = 25;

function Section({ title, children }) {
  return (
    <section className="ir-drawer-section">
      <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-400">{title}</h3>
      {children}
    </section>
  );
}

function Fields({ rows }) {
  return (
    <dl className="ir-fields">
      {rows
        .filter(([, value]) => value !== null && value !== undefined && value !== "")
        .map(([label, value, mono]) => (
          <div key={label} className="contents">
            <dt>{label}</dt>
            <dd className={mono ? "font-mono text-xs break-all" : "break-words"}>{value}</dd>
          </div>
        ))}
    </dl>
  );
}

function Techniques({ ids, tactics }) {
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {ids.map((tid) => (
        <Link key={tid} to={`/attack/${tid}`} className="badge rounded bg-indigo-900/50 px-1.5 py-0.5 text-xs text-indigo-300 hover:text-slate-100">
          {tid}
        </Link>
      ))}
      {tactics?.length > 0 && <span className="text-xs text-slate-400">{tactics.join(" · ")}</span>}
    </div>
  );
}

function EvidenceIds({ ids }) {
  return (
    <>
      <ul className="space-y-1 font-mono text-xs text-slate-300">
        {ids.slice(0, EVIDENCE_SHOWN).map((id) => (
          <li key={id} className="truncate" title={id}>{id}</li>
        ))}
      </ul>
      {ids.length > EVIDENCE_SHOWN && <p className="mt-1 text-xs text-slate-400">+{ids.length - EVIDENCE_SHOWN} more</p>}
    </>
  );
}

const btn = "ir-btn";
const primary = "ir-btn primary";

export function DetectionDrawer({ detection: d, onClose }) {
  const { can } = useAuth();
  const copy = useCopy();
  if (!d) return null;
  return (
    <Drawer
      open
      onClose={onClose}
      title={d.rule_name}
      subtitle={`${d.host} · ${new Date(d.first_seen).toLocaleString()}`}
      actions={
        <>
          {d.incident_id && <Link to={`/incidents/${d.incident_id}`} className={primary}>Open incident</Link>}
          {d.incident_id && can("run_ai") && <Link to={`/incidents/${d.incident_id}#investigate`} className={btn}>Investigate</Link>}
          <button type="button" className={btn} onClick={() => copy(d.matched_event_ids.join("\n"), "Evidence IDs copied")}>Copy evidence IDs</button>
          <Link to={`/events?host=${encodeURIComponent(d.host)}`} className={btn}>Host events</Link>
          {can("manage_rules") && <Link to="/settings" className={btn}>Edit rules</Link>}
        </>
      }
    >
      <div className="flex flex-wrap items-center gap-2">
        <RiskBadge level={d.risk_level} score={d.risk_score} />
        <TIBadge matches={d.ti_matches} />
      </div>
      {d.summary && <p className="text-sm text-slate-300">{d.summary}</p>}
      <Section title="ATT&CK">
        <Techniques ids={d.technique_ids} tactics={d.tactics} />
      </Section>
      <Section title="Rule">
        <Fields
          rows={[
            ["Rule", d.rule_name],
            ["Severity", `${d.severity}/10`],
            ["Confidence", `${Math.round(d.confidence * 100)}%`],
            ["First seen", <TimeAgo key="f" ts={d.first_seen} />],
            ["Last seen", <TimeAgo key="l" ts={d.last_seen} />],

          ]}
        />
      </Section>
      {d.ti_matches?.length > 0 && (
        <Section title="Threat intel">
          <ul className="space-y-1 text-xs text-slate-300">
            {d.ti_matches.map((m) => (
              <li key={`${m.type}|${m.value}`}><span className="font-mono">{m.value}</span> · {m.type} · {m.source}</li>
            ))}
          </ul>
        </Section>
      )}
      <Section title={`Evidence (${d.matched_event_ids.length} events)`}>
        <EvidenceIds ids={d.matched_event_ids} />
      </Section>
      <Section title="Related incident">
        {d.incident_id ? (
          <Link to={`/incidents/${d.incident_id}`} className="text-sm text-sky-400 hover:text-sky-300">
            Incident {d.incident_id.slice(0, 8)} on {d.host} &rarr;
          </Link>
        ) : (
          <p className="text-sm text-slate-400">Not grouped into an incident yet.</p>
        )}
      </Section>
    </Drawer>
  );
}

// `detections` = detections whose evidence includes this event (from the page's flag map).
export function EventDrawer({ event: ev, detections = [], onClose, onFilterHost }) {
  const copy = useCopy();
  if (!ev) return null;
  const incidentIds = [...new Set(detections.map((d) => d.incident_id).filter(Boolean))];
  return (
    <Drawer
      open
      onClose={onClose}
      title={`Event ${ev.event_id} · ${ev.channel}`}
      subtitle={`${ev.host} · ${new Date(ev.timestamp).toLocaleString()}`}
      actions={
        <>
          {incidentIds[0] && <Link to={`/incidents/${incidentIds[0]}`} className={primary}>Open incident</Link>}
          <button type="button" className={btn} onClick={() => copy(ev.id, "Event ID copied")}>Copy event ID</button>
          {onFilterHost && <button type="button" className={btn} onClick={() => onFilterHost(ev.host)}>Filter to this host</button>}
        </>
      }
    >
      <div className="flex flex-wrap items-center gap-2">
        {detections.length > 0 && <span className="badge rounded bg-red-900/70 px-2 py-0.5 text-xs font-medium text-red-300">Flagged by {detections.length} rule{detections.length === 1 ? "" : "s"}</span>}
        <TIBadge matches={ev.ti_matches} />
      </div>
      <Section title="Event">
        <Fields
          rows={[
            ["ID", ev.id, true],
            ["Source", ev.source],
            ["Provider", ev.provider],
            ["User", ev.user],
            ["Logon type", ev.logon_type],
            ["Process", ev.process, true],
            ["Parent", ev.parent_process, true],
            ["Command line", ev.command_line, true],
            ["Source IP", ev.src_ip, true],
            ["Destination", ev.dst_ip ? `${ev.dst_ip}${ev.dst_port != null ? `:${ev.dst_port}` : ""}` : null, true],
            ["Protocol", ev.protocol],
          ]}
        />
      </Section>
      {ev.message && (
        <Section title="Message">
          <p className="max-h-48 overflow-y-auto whitespace-pre-wrap break-words text-xs text-slate-300">{ev.message}</p>
        </Section>
      )}
      {detections.length > 0 && (
        <Section title="Matched rules & ATT&CK">
          <ul className="space-y-2.5">
            {detections.map((d) => (
              <li key={d.id} className="text-sm">
                <div className="mb-1 flex flex-wrap items-center gap-2 text-slate-200">
                  {d.rule_name} <RiskBadge level={d.risk_level} score={d.risk_score} />
                </div>
                <Techniques ids={d.technique_ids} tactics={d.tactics} />
              </li>
            ))}
          </ul>
        </Section>
      )}
    </Drawer>
  );
}

export function AnomalyDrawer({ anomaly: a, onClose }) {
  const copy = useCopy();
  if (!a) return null;
  return (
    <Drawer
      open
      onClose={onClose}
      title={`Anomaly #${a.rank}`}
      subtitle={`${a.host} · ${new Date(a.timestamp).toLocaleString()}`}
      actions={
        <>
          <Link to={`/events?host=${encodeURIComponent(a.host)}`} className={primary}>Host events</Link>
          <button type="button" className={btn} onClick={() => copy(a.event_id, "Event ID copied")}>Copy event ID</button>
        </>
      }
    >
      <div className="flex flex-wrap items-center gap-2">
        <span className={`badge rounded px-2 py-0.5 text-xs font-medium ${a.is_anomaly ? "bg-violet-900/60 text-violet-300" : "bg-slate-800 text-slate-300"}`}>
          score {a.score.toFixed(3)}
        </span>
        <span className="text-xs text-slate-400">{a.label}</span>
        {a.source === "simulated" && <span className="text-xs text-amber-400">simulated</span>}
      </div>
      <p className="text-xs text-slate-400">ML hint only: not mapped to ATT&CK and never merged into incidents.</p>
      <Section title="Process">
        <Fields
          rows={[
            ["Event ID", a.event_id, true],
            ["Process", a.process, true],
            ["Parent", a.parent_process, true],
            ["Command line", a.command_line, true],
            ["Rule match", a.also_matched_rule ? "Yes, also flagged by a rule" : "No"],
          ]}
        />
      </Section>
      <Section title="Why it looks unusual">
        <ul className="space-y-1 text-xs text-slate-300">
          {a.top_features.map((f) => (
            <li key={f.name}>
              {f.name}: <span className="text-slate-100">{f.value}</span> <span className="text-slate-400">(typical {f.typical})</span>
            </li>
          ))}
        </ul>
      </Section>
    </Drawer>
  );
}
