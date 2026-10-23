"""Admin-written detection rules (Settings -> Detection -> New rule).

The editor form (schemas.CustomRuleIn) is translated into the same YAML rule
format as the built-in rules and saved to backend/rules/custom/<uuid>.yml, so
the detection engine treats it like any other rule. The form itself is also
stored under `editor:` so the rule can be reopened for editing.

Safety:
  - regex conditions are compiled with google-re2 (linear time, no ReDoS);
    patterns RE2 can't compile are rejected, and they run with the `re2` modifier
  - at most MAX_CONDITIONS conditions per rule
  - new rules are saved disabled; the admin turns them on with the existing toggle
  - built-in and imported rules are read-only (they can be cloned into a custom rule)
  - dry_run() evaluates a rule against stored events without saving anything
"""

import itertools
import re
import uuid

import re2
import yaml
from sqlalchemy.orm import Session

from app.ai.triage import _SECRET_PATTERN
from app.detection import rules as rules_module
from app.detection.engine import _cluster_events
from app.detection.rules import ALLOWLIST, Rule, _rule_from_yaml, is_allowlisted
from app.detection.sigma_import import LEVEL_SEVERITY
from app.models import Event
from app.schemas import CustomRuleIn

MAX_CONDITIONS = 10
MAX_REGEX_LENGTH = 200
SAMPLE_COUNT = 5
SAMPLE_TEXT_LIMIT = 120
DRY_RUN_EVENT_LIMIT = 50_000

# form operator -> rule YAML modifier ("" = exact match)
OP_MODIFIER = {"equals": "", "contains": "contains", "startswith": "startswith", "endswith": "endswith", "regex": "re2"}
MODIFIER_OP = {"": "equals", "contains": "contains", "startswith": "startswith", "endswith": "endswith", "re": "regex", "re2": "regex"}
EDITOR_FIELDS = {"command_line", "process", "parent_process", "user", "message", "channel"}

# Extra masking for sample command lines shown in the UI (on top of the AI layer's token pattern).
_PASSWORD_PATTERN = re.compile(r"(?i)(pass(word)?|pwd|secret)(\s*[:=]\s*|\s+)(\S+)")
_NET_USER_PASSWORD = re.compile(r"(?i)(\bnet1?(\.exe)?\s+user\s+\S+\s+)(?!/)(\S+)")


class CustomRuleError(ValueError):
    """Invalid custom rule. The message is safe to show the admin."""


# ---------- validation and form -> YAML ----------


def validate(form: CustomRuleIn) -> None:
    conditions = [c for g in form.groups for c in g.conditions]
    if len(conditions) > MAX_CONDITIONS:
        raise CustomRuleError(f"Too many conditions ({len(conditions)}); the limit is {MAX_CONDITIONS}")
    for c in conditions:
        if c.op != "regex":
            continue
        if len(c.value) > MAX_REGEX_LENGTH:
            raise CustomRuleError(f"Regex too long (max {MAX_REGEX_LENGTH} characters)")
        try:
            re2.compile(c.value)
        except re2.error:
            raise CustomRuleError(f"Regex not supported by RE2 (no lookarounds or backreferences): {c.value[:60]}")


def _group_to_selection(group) -> dict:
    """One OR-group -> one selection map. Repeated field+operator pairs become `|all` lists."""
    values: dict[str, list[str]] = {}
    for c in group.conditions:
        key = "|".join(p for p in (c.field, OP_MODIFIER[c.op]) if p)
        values.setdefault(key, []).append(c.value)
    return {(f"{k}|all" if len(v) > 1 else k): (v if len(v) > 1 else v[0]) for k, v in values.items()}


def to_yaml_doc(form: CustomRuleIn, rule_id: str) -> dict:
    validate(form)
    detection: dict = {}
    if form.event_id is not None:
        detection["selection"] = {"event_id": form.event_id}
    detection["match"] = [_group_to_selection(g) for g in form.groups]
    detection["condition"] = "selection and match" if form.event_id is not None else "match"
    if form.threshold:
        detection["timeframe"] = f"{form.threshold.minutes}m"
        detection["group_by"] = ["host"]
        detection["min_count"] = form.threshold.count
    return {
        "title": form.title,
        "id": rule_id,
        "status": "custom",
        "description": form.description,
        "logsource": {"product": "windows"},
        "detection": detection,
        "level": form.level,
        "tags": [f"attack.{t.lower()}" for t in form.technique_ids],
        "severity": LEVEL_SEVERITY[form.level],
        "confidence": form.confidence,
        "enabled": False,
        "source": "custom",
        "editor": form.model_dump(),
    }


def build_rule(form: CustomRuleIn, rule_id: str | None = None) -> tuple[Rule, dict]:
    doc = to_yaml_doc(form, rule_id or str(uuid.uuid4()))
    try:
        return _rule_from_yaml(doc, "custom"), doc
    except (KeyError, ValueError) as e:
        raise CustomRuleError(f"Rule could not be built: {e}")


# ---------- save / delete ----------


def find_rule(rule_id: str) -> Rule | None:
    return next((r for r in rules_module.RULES if r.id == rule_id), None)


def _path(rule_id: str):
    return rules_module.CUSTOM_DIR / f"{uuid.UUID(rule_id)}.yml"  # UUID-only filename: no path traversal


def _write(doc: dict) -> None:
    rules_module.CUSTOM_DIR.mkdir(parents=True, exist_ok=True)
    _path(doc["id"]).write_text(yaml.safe_dump(doc, sort_keys=False, allow_unicode=True), encoding="utf-8")


def create(form: CustomRuleIn) -> Rule:
    rule, doc = build_rule(form)
    _write(doc)
    rules_module.RULES.append(rule)
    return rule


def update(rule_id: str, form: CustomRuleIn) -> Rule:
    rule, doc = build_rule(form, rule_id)
    _write(doc)
    rules_module.RULES[:] = [rule if r.id == rule_id else r for r in rules_module.RULES]
    return rule


def delete(rule_id: str) -> None:
    _path(rule_id).unlink(missing_ok=True)
    rules_module.RULES[:] = [r for r in rules_module.RULES if r.id != rule_id]


# ---------- rule -> form (edit a custom rule, or clone any rule) ----------


def _selection_alternatives(selection) -> list[list[dict]]:
    """A selection as OR-alternatives, each a list of {field, op, value} conditions (ANDed)."""
    if isinstance(selection, list):
        return [alt for s in selection for alt in _selection_alternatives(s)]
    per_key = []
    for key, value in selection.items():
        field_name, *mods = key.split("|")
        modifier = next((m for m in mods if m != "all"), "")
        if value is None or modifier not in MODIFIER_OP:
            raise CustomRuleError("This rule uses features the editor can't represent")
        values = [str(v) for v in (value if isinstance(value, list) else [value])]
        conds = [{"field": field_name, "op": MODIFIER_OP[modifier], "value": v} for v in values]
        per_key.append([conds] if "all" in mods else [[c] for c in conds])
    return [sum(combo, []) for combo in itertools.product(*per_key)]


def rule_to_form(rule: Rule) -> dict:
    path = rules_module.CUSTOM_DIR / f"{rule.id}.yml"
    if rule.source == "custom" and path.exists():
        return yaml.safe_load(path.read_text(encoding="utf-8"))["editor"]

    if any(negated for negated, _ in rule.condition):
        raise CustomRuleError("This rule uses 'not' filters, which the editor can't represent")
    groups = [[]]
    for _, name in rule.condition:  # AND of selections = cross product of their alternatives
        groups = [g + alt for g in groups for alt in _selection_alternatives(rule.selections[name])]

    event_ids = {c["value"] for g in groups for c in g if c["field"] == "event_id"}
    groups = [[c for c in g if c["field"] != "event_id"] for g in groups]
    if len(event_ids) > 1 or any(c["field"] not in EDITOR_FIELDS for g in groups for c in g) or not all(groups):
        raise CustomRuleError("This rule uses fields or event ids the editor can't represent")
    if sum(len(g) for g in groups) > MAX_CONDITIONS:
        raise CustomRuleError(f"This rule expands to more than {MAX_CONDITIONS} conditions")

    level = rule.level if rule.level in LEVEL_SEVERITY else "medium"
    return {
        "title": f"Copy of {rule.name}"[:120],
        "description": "",
        "level": level,
        "confidence": rule.confidence,
        "technique_ids": list(rule.technique_ids),
        "event_id": int(event_ids.pop()) if event_ids else None,
        "groups": [{"conditions": g} for g in groups],
        "threshold": {"count": rule.min_count, "minutes": rule.window_minutes} if rule.kind == "cluster" else None,
    }


# ---------- dry run ----------


def mask(text: str | None) -> str | None:
    if not text:
        return text
    text = _SECRET_PATTERN.sub(r"\1=[REDACTED]", text)
    text = _NET_USER_PASSWORD.sub(r"\1[REDACTED]", text)
    text = _PASSWORD_PATTERN.sub(r"\1\3[REDACTED]", text)
    return text[:SAMPLE_TEXT_LIMIT]


def dry_run(db: Session, form: CustomRuleIn) -> dict:
    """Evaluate the rule against stored events. Read-only: saves no rule and creates no detections."""
    rule, _ = build_rule(form)
    events = db.query(Event).order_by(Event.timestamp.desc()).limit(DRY_RUN_EVENT_LIMIT).all()
    matched = [e for e in events if rule.matches(e) and not is_allowlisted(rule, e, ALLOWLIST)]

    cluster_count = None
    if rule.kind == "cluster":
        clusters = _cluster_events(list(reversed(matched)), rule.window_minutes, rule.min_count, rule.group_by)
        cluster_count = len(clusters)

    samples = [
        {
            "id": e.id,
            "timestamp": e.timestamp,
            "host": e.host,
            "event_id": e.event_id,
            "user": e.user,
            "process": mask(e.process),
            "command_line": mask(e.command_line),
        }
        for e in matched[:SAMPLE_COUNT]
    ]
    return {"match_count": len(matched), "cluster_count": cluster_count, "samples": samples}
