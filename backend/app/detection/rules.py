"""Loads Sigma-style detection rules and allowlists from YAML in backend/rules/.

Add new rules as YAML files there, not in code. Supported subset of Sigma:
  detection:
    <name>:  {field: value, field|contains: [..], field|re: [..]}   -> all keys must match (AND)
    <name>:  [ {..}, {..} ]                                         -> any map may match (OR)
    condition: "selection and not filter_x and ..."                 -> terms ANDed, each optionally negated
    timeframe: 5m, group_by: [..], min_count: N                     -> optional: makes it a cluster rule
A list of values means "any of". `field: null` means the field is empty.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from app.models import Event

RULES_DIR = Path(__file__).resolve().parents[2] / "rules"
ALLOWLIST_DIR = RULES_DIR / "allowlist"

_DETECTION_META_KEYS = {"condition", "timeframe", "group_by", "min_count"}


def _as_list(value) -> list:
    return value if isinstance(value, list) else [value]


def _field_matches(event: Event, key: str, expected) -> bool:
    field_name, _, modifier = key.partition("|")
    actual = getattr(event, field_name)

    if expected is None:
        return not str(actual or "").strip()

    if modifier == "":
        return actual in _as_list(expected)

    text = str(actual or "")
    if modifier == "contains":
        return any(str(v).lower() in text.lower() for v in _as_list(expected))
    if modifier == "re":
        return any(re.search(v, text, re.IGNORECASE) for v in _as_list(expected))
    raise ValueError(f"Unsupported modifier: {modifier}")


def _selection_matches(event: Event, selection) -> bool:
    if isinstance(selection, list):
        return any(_selection_matches(event, s) for s in selection)
    return all(_field_matches(event, key, expected) for key, expected in selection.items())


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    technique_ids: tuple[str, ...]
    severity: int  # 1-10
    confidence: float  # 0-1
    level: str
    selections: dict = field(hash=False, compare=False)
    condition: tuple[tuple[bool, str], ...] = ()  # (negated, selection name)
    kind: str = "filter"  # "filter" -> one detection per matching event; "cluster" -> group matching events
    window_minutes: int | None = None
    min_count: int | None = None
    group_by: tuple[str, ...] = ()

    def matches(self, event: Event) -> bool:
        return all(_selection_matches(event, self.selections[name]) != negated for negated, name in self.condition)


def _parse_condition(text: str, selections: dict) -> tuple[tuple[bool, str], ...]:
    terms = []
    for term in text.split(" and "):
        negated = term.strip().startswith("not ")
        name = term.strip().removeprefix("not ").strip()
        if name not in selections:
            raise ValueError(f"Condition references unknown selection: {name}")
        terms.append((negated, name))
    return tuple(terms)


def _parse_minutes(timeframe: str) -> int:
    match = re.fullmatch(r"(\d+)([mh])", str(timeframe))
    if not match:
        raise ValueError(f"Unsupported timeframe: {timeframe}")
    return int(match.group(1)) * (60 if match.group(2) == "h" else 1)


def _rule_from_yaml(doc: dict) -> Rule:
    detection = doc["detection"]
    selections = {k: v for k, v in detection.items() if k not in _DETECTION_META_KEYS}
    # ATT&CK technique ids come from tags like "attack.t1059.001".
    techniques = tuple(t.removeprefix("attack.").upper() for t in doc["tags"] if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t))
    is_cluster = "timeframe" in detection
    return Rule(
        id=doc["id"],
        name=doc["title"],
        technique_ids=techniques,
        severity=int(doc["severity"]),
        confidence=float(doc["confidence"]),
        level=doc["level"],
        selections=selections,
        condition=_parse_condition(detection["condition"], selections),
        kind="cluster" if is_cluster else "filter",
        window_minutes=_parse_minutes(detection["timeframe"]) if is_cluster else None,
        min_count=detection.get("min_count") if is_cluster else None,
        group_by=tuple(detection.get("group_by", ())),
    )


def load_rules(directory: Path = RULES_DIR) -> tuple[Rule, ...]:
    rules = tuple(_rule_from_yaml(yaml.safe_load(p.read_text(encoding="utf-8"))) for p in sorted(directory.glob("*.yml")))
    ids = [r.id for r in rules]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate rule id in rules directory")
    return rules


@dataclass(frozen=True)
class AllowlistEntry:
    name: str
    rule_ids: frozenset[str]
    match: dict = field(hash=False, compare=False)


def load_allowlist(directory: Path = ALLOWLIST_DIR) -> tuple[AllowlistEntry, ...]:
    entries = []
    for path in sorted(directory.glob("*.yml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        rule_ids = frozenset(doc["applies_to"])
        entries.extend(AllowlistEntry(e["name"], rule_ids, e["match"]) for e in doc["entries"])
    return tuple(entries)


def is_allowlisted(rule: Rule, event: Event, allowlist: tuple[AllowlistEntry, ...]) -> bool:
    return any(rule.id in entry.rule_ids and _selection_matches(event, entry.match) for entry in allowlist)


# Loaded once at import (i.e. at app startup); a bad YAML file fails startup loudly.
RULES: tuple[Rule, ...] = load_rules()
ALLOWLIST: tuple[AllowlistEntry, ...] = load_allowlist()
