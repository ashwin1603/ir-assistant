"""Loads Sigma-style detection rules and allowlists from YAML in backend/rules/.

Add new rules as YAML files there, not in code. Supported subset of Sigma:
  detection:
    <name>:  {field: value, field|contains: [..], field|re: [..]}   -> all keys must match (AND)
             (modifiers: contains, startswith, endswith, re, re2; add |all to require every value)
    <name>:  [ {..}, {..} ]                                         -> any map may match (OR)
    condition: "selection and not filter_x and ..."                 -> terms ANDed, each optionally negated
    timeframe: 5m, group_by: [..], min_count: N                     -> optional: makes it a cluster rule
A list of values means "any of". `field: null` means the field is empty.
`enabled: false` makes a rule off until an admin enables it (used for imported Sigma rules,
which live in backend/rules/imported/ and for admin-written rules in backend/rules/custom/).
Only custom rules are editable from the UI; built-in and imported rules are read-only.
"""

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import re2
import yaml

from app.models import Event

RULES_DIR = Path(__file__).resolve().parents[2] / "rules"
ALLOWLIST_DIR = RULES_DIR / "allowlist"
IMPORTED_DIR = RULES_DIR / "imported"
CUSTOM_DIR = RULES_DIR / "custom"

_DETECTION_META_KEYS = {"condition", "timeframe", "group_by", "min_count"}


def _as_list(value) -> list:
    return value if isinstance(value, list) else [value]


SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "re", "all"}


@lru_cache(maxsize=512)
def _re2_compile(pattern: str):
    # RE2 runs in linear time (no catastrophic backtracking), so admin-written
    # custom rules use it instead of Python's re.
    return re2.compile("(?i)" + pattern)


def _field_matches(event: Event, key: str, expected) -> bool:
    field_name, *modifiers = key.split("|")
    actual = getattr(event, field_name)
    combine = all if "all" in modifiers else any
    modifier = next((m for m in modifiers if m != "all"), "")

    if expected is None:
        return not str(actual or "").strip()

    if modifier == "":
        return combine(actual == v for v in _as_list(expected))

    raw = str(actual or "")
    text = raw.lower()
    values = [str(v) for v in _as_list(expected)]
    if modifier == "contains":
        return combine(v.lower() in text for v in values)
    if modifier == "startswith":
        return combine(text.startswith(v.lower()) for v in values)
    if modifier == "endswith":
        return combine(text.endswith(v.lower()) for v in values)
    if modifier == "re":
        return combine(re.search(v, raw, re.IGNORECASE) is not None for v in values)
    if modifier == "re2":
        return combine(_re2_compile(v).search(raw) is not None for v in values)
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
    enabled_by_default: bool = True
    source: str = "builtin"  # "builtin" | "imported" | "custom" (only custom is editable)

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


def _rule_from_yaml(doc: dict, source: str = "builtin") -> Rule:
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
        enabled_by_default=bool(doc.get("enabled", True)),
        source=source,
    )


def load_rules(directory: Path = RULES_DIR) -> list[Rule]:
    sources = [("builtin", directory), ("imported", directory / "imported"), ("custom", directory / "custom")]
    rules = [
        _rule_from_yaml(yaml.safe_load(p.read_text(encoding="utf-8")), source)
        for source, folder in sources
        for p in sorted(folder.glob("*.yml"))
    ]
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
# A list (not tuple) so a Sigma import can append to it without a restart.
RULES: list[Rule] = load_rules()
ALLOWLIST: tuple[AllowlistEntry, ...] = load_allowlist()
