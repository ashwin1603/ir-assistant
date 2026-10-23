import hashlib
import json
import threading
import uuid
from dataclasses import replace
from datetime import timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.analysis.incidents import group_into_incidents
from app.analysis.risk import compute_risk
from app.detection.attack_map import tactics_for
from app.detection.network_rules import NETWORK_RULES, NetworkRule, network_events
from app.detection.rules import ALLOWLIST, RULES, Rule, is_allowlisted
from app.detection.threat_intel import TI_RULE, load_index, match_event
from app.detection import rules as rules_module
from app.models import AppSetting, Detection, Event, Incident, RuleOverride, ThreatIndicator


def _cluster_events(events: list[Event], window_minutes: int, min_count: int, group_by: tuple[str, ...]) -> list[list[Event]]:
    groups: dict[tuple, list[Event]] = {}
    for event in events:
        key = tuple(getattr(event, field) for field in group_by)
        groups.setdefault(key, []).append(event)

    clusters: list[list[Event]] = []
    for group_events in groups.values():
        group_events.sort(key=lambda e: e.timestamp)
        i, n = 0, len(group_events)
        while i < n:
            window_end = group_events[i].timestamp + timedelta(minutes=window_minutes)
            j = i
            while j < n and group_events[j].timestamp <= window_end:
                j += 1
            cluster = group_events[i:j]
            if len(cluster) >= min_count:
                clusters.append(cluster)
                i = j
            else:
                i += 1
    return clusters


# Detection/incident ids are content-addressed (not random) so that re-running
# detection on an unchanged set of events yields the same ids every time -
# run_detection may recompute at any time, and clients hold onto ids across requests.
NAMESPACE = uuid.UUID("5c3f8f2a-6b1b-4c2a-9e8d-1b9f2a7d4e60")

# "filter" rules (e.g. encoded PowerShell, local user created) have no window
# of their own - without one, every matching event on a host, however far
# apart, would be merged into a single detection spanning its whole lifetime,
# which then drags the incident grouping below into one incident spanning
# months. Bound them to the same 30-minute gap incidents use, so a detection
# (and the incident it lands in) never spans longer than genuinely-related
# activity.
FILTER_RULE_WINDOW_MINUTES = 30


def _build_detection(rule: Rule, matched_events: list[Event]) -> Detection:
    matched_ids = sorted(e.id for e in matched_events)
    count = len(matched_ids)
    score, level = compute_risk(rule.severity, rule.confidence, count)
    detection_id = str(uuid.uuid5(NAMESPACE, f"detection|{rule.name}|{','.join(matched_ids)}"))
    return Detection(
        id=detection_id,
        rule_name=rule.name,
        technique_ids=json.dumps(list(rule.technique_ids)),
        tactics=json.dumps(tactics_for(list(rule.technique_ids))),
        severity=rule.severity,
        confidence=rule.confidence,
        host=matched_events[0].host,
        matched_event_ids=json.dumps(matched_ids),
        event_count=count,
        first_seen=min(e.timestamp for e in matched_events),
        last_seen=max(e.timestamp for e in matched_events),
        risk_score=score,
        risk_level=level,
    )


def effective_rules(db: Session) -> list[Rule]:
    """The YAML rules with admin overrides (Settings page) applied: disabled
    rules are dropped and cluster thresholds replaced where set."""
    overrides = {o.rule_id: o for o in db.query(RuleOverride).all()}
    rules = []
    for rule in RULES:
        override = overrides.get(rule.id)
        if override is None:
            if rule.enabled_by_default:
                rules.append(rule)
            continue
        if not override.enabled:
            continue
        if rule.kind == "cluster":
            rule = replace(
                rule,
                min_count=override.min_count or rule.min_count,
                window_minutes=override.window_minutes or rule.window_minutes,
            )
        rules.append(rule)
    return rules


def rule_params(network_rule: NetworkRule, override: RuleOverride | None) -> dict:
    """The rule's default thresholds with any admin overrides on top."""
    params = network_rule.defaults()
    if override and override.params:
        params.update({k: v for k, v in json.loads(override.params).items() if k in params})
    return params


def effective_network_rules(db: Session) -> list[tuple[NetworkRule, dict]]:
    """Enabled network rules, each with its effective thresholds."""
    overrides = {o.rule_id: o for o in db.query(RuleOverride).all()}
    enabled = []
    for network_rule in NETWORK_RULES:
        override = overrides.get(network_rule.rule.id)
        if override is None or override.enabled:
            enabled.append((network_rule, rule_params(network_rule, override)))
    return enabled


FINGERPRINT_KEY = "detection_fingerprint"
_recompute_lock = threading.Lock()


def detection_fingerprint(db: Session) -> str:
    """Cheap summary of everything detection depends on: events (count, newest id and
    ingest time), rule overrides, threat-intel indicators and the loaded rules (built-in,
    custom and imported). If it is unchanged, the stored detections are still correct."""
    count, newest_id, newest_ingest = db.query(func.count(Event.id), func.max(Event.id), func.max(Event.created_at)).one()
    overrides = sorted(
        (o.rule_id, o.enabled, o.min_count, o.window_minutes, o.params) for o in db.query(RuleOverride).all()
    )
    indicators = sorted(db.query(ThreatIndicator.type, ThreatIndicator.value).all())
    rules = [repr(r) for r in rules_module.RULES]
    payload = json.dumps([count, newest_id, newest_ingest, overrides, indicators, rules], default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _stored_fingerprint(db: Session) -> str | None:
    # Column query (not db.get) so another thread's commit is seen, not a cached object.
    return db.query(AppSetting.value).filter(AppSetting.key == FINGERPRINT_KEY).scalar()


def run_detection(db: Session, force: bool = False) -> bool:
    """Bring stored detections/incidents up to date. Recomputes only when the inputs
    changed (or force=True); otherwise the stored rows are already right. One
    recompute at a time: concurrent callers wait, then see the fresh fingerprint and
    skip. Returns True if it recomputed."""
    if not force and _stored_fingerprint(db) == detection_fingerprint(db):
        return False
    with _recompute_lock:
        # Computed BEFORE reading events: if new events arrive mid-run, the stored
        # fingerprint is older than the data and the next call simply recomputes again.
        fingerprint = detection_fingerprint(db)
        if not force and _stored_fingerprint(db) == fingerprint:
            return False  # another request just finished the same recompute
        try:
            _recompute(db, fingerprint)
        except Exception:
            db.rollback()
            raise
    return True


def _recompute(db: Session, fingerprint: str) -> None:
    """Recompute all detections and incidents from the current events table."""
    events = db.query(Event).order_by(Event.timestamp.asc()).all()

    detections: list[Detection] = []
    for rule in effective_rules(db):
        candidates = [e for e in events if rule.matches(e) and not is_allowlisted(rule, e, ALLOWLIST)]

        if rule.kind == "filter":
            clusters = _cluster_events(candidates, FILTER_RULE_WINDOW_MINUTES, min_count=1, group_by=("host",))
        else:
            clusters = _cluster_events(candidates, rule.window_minutes, rule.min_count, rule.group_by)
        detections.extend(_build_detection(rule, cluster) for cluster in clusters)

    # Threat-intel rule: fires on any event containing an imported indicator.
    ti_index = load_index(db)
    if ti_index:
        ti_events = [e for e in events if match_event(e, ti_index)]
        clusters = _cluster_events(ti_events, FILTER_RULE_WINDOW_MINUTES, min_count=1, group_by=("host",))
        detections.extend(_build_detection(TI_RULE, cluster) for cluster in clusters)

    # Network rules: Network-channel events only, each rule with its own logic.
    net_events = network_events(events)
    for network_rule, params in effective_network_rules(db):
        for matched, summary in network_rule.detect(net_events, params):
            detection = _build_detection(network_rule.rule, matched)
            detection.summary = summary
            detections.append(detection)

    incidents = group_into_incidents(detections)

    db.query(Detection).delete()
    db.query(Incident).delete()
    db.add_all(incidents)
    db.add_all(detections)
    row = db.get(AppSetting, FINGERPRINT_KEY)
    if row:
        row.value = fingerprint
    else:
        db.add(AppSetting(key=FINGERPRINT_KEY, value=fingerprint))
    db.commit()  # detections and their fingerprint in one transaction
