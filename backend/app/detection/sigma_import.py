"""Import a Sigma rule (YAML text) into our internal rule format.

pySigma parses and validates the rule (structure, log source, modifiers,
condition syntax). We then translate the small subset we can run ourselves:
  - fields in FIELD_MAP only (Sigma field name -> our normalized event field)
  - modifiers in SUPPORTED_MODIFIERS only (contains, startswith, endswith, re, all)
  - conditions of the form "a and not b and ..." (no or / 1 of / parentheses)
Anything else is rejected with a clear message rather than silently half-working.
The result is saved to backend/rules/imported/<id>.yml with `enabled: false`.
"""

import re
import uuid

import yaml
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule

from app.detection import rules as rules_module
from app.detection.rules import SUPPORTED_MODIFIERS, Rule, _rule_from_yaml

MAX_BYTES = 50 * 1024

FIELD_MAP = {
    "EventID": "event_id",
    "CommandLine": "command_line",
    "Image": "process",
    "ParentImage": "parent_process",
    "User": "user",
    "TargetUserName": "user",
    "ServiceFileName": "command_line",  # System 7045: the service ImagePath is normalized into command_line
}

# Sigma has no severity/confidence; derive them from its level.
LEVEL_SEVERITY = {"informational": 2, "low": 3, "medium": 5, "high": 7, "critical": 9}
DEFAULT_CONFIDENCE = 0.6

_CONDITION_RE = re.compile(r"(not )?\w+( and (not )?\w+)*")
_TECHNIQUE_RE = re.compile(r"attack\.t\d{4}(\.\d{3})?")


class SigmaImportError(ValueError):
    """The rule is invalid or uses Sigma features we don't support. Message is safe to show the admin."""


def _convert_key(key: str) -> str:
    sigma_field, *modifiers = key.split("|")
    if sigma_field not in FIELD_MAP:
        raise SigmaImportError(f"Unsupported field '{sigma_field}'. Supported: {', '.join(FIELD_MAP)}")
    unsupported = [m for m in modifiers if m not in SUPPORTED_MODIFIERS]
    if unsupported:
        raise SigmaImportError(f"Unsupported modifier '{unsupported[0]}'. Supported: {', '.join(sorted(SUPPORTED_MODIFIERS))}")
    if len([m for m in modifiers if m != "all"]) > 1:
        raise SigmaImportError(f"Only one match modifier per field is supported: '{key}'")
    return "|".join([FIELD_MAP[sigma_field], *modifiers])


def _check_values(key: str, value) -> None:
    for v in value if isinstance(value, list) else [value]:
        if v is not None and not isinstance(v, (str, int)):
            raise SigmaImportError(f"Unsupported value type for '{key}'")
        if isinstance(v, str) and "|re" not in key and ("*" in v or "?" in v):
            raise SigmaImportError(f"Wildcards are not supported in '{key}'; use contains/startswith/endswith")


def _convert_selection(name: str, selection):
    if isinstance(selection, list):
        if not all(isinstance(s, dict) for s in selection):
            raise SigmaImportError(f"Selection '{name}': keyword lists are not supported, use field: value maps")
        return [_convert_selection(name, s) for s in selection]
    if not isinstance(selection, dict):
        raise SigmaImportError(f"Selection '{name}' must be a map of field: value")
    converted = {}
    for key, value in selection.items():
        _check_values(key, value)
        new_key = _convert_key(str(key))
        if new_key in converted:  # e.g. User and TargetUserName both map to user
            raise SigmaImportError(f"Selection '{name}' maps two Sigma fields onto '{new_key}'")
        converted[new_key] = value
    return converted


def convert_sigma(text: str) -> dict:
    """Validate Sigma YAML with pySigma and return our internal rule document (not yet saved)."""
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        raise SigmaImportError("Invalid YAML")
    if not isinstance(doc, dict):
        raise SigmaImportError("Invalid YAML: expected a single Sigma rule (a mapping)")
    try:
        sigma = SigmaRule.from_dict(doc)
    except SigmaError as e:
        raise SigmaImportError(f"Invalid Sigma rule: {e}")

    detection = dict(doc["detection"])
    condition = detection.pop("condition")
    if isinstance(condition, list) or "timeframe" in detection:
        raise SigmaImportError("Multiple conditions and timeframe/correlation rules are not supported")
    condition = " ".join(str(condition).split())
    if not _CONDITION_RE.fullmatch(condition):
        raise SigmaImportError(f"Unsupported condition '{condition}': only 'selection and not filter' style is supported")

    converted = {name: _convert_selection(name, sel) for name, sel in detection.items()}
    converted["condition"] = condition

    tags = [str(t) for t in sigma.tags]
    if not any(_TECHNIQUE_RE.fullmatch(t) for t in tags):
        raise SigmaImportError("Rule needs at least one ATT&CK technique tag (e.g. attack.t1059.001)")

    level = sigma.level.name.lower() if sigma.level else "medium"
    return {
        "title": sigma.title,
        "id": str(sigma.id or uuid.uuid4()),
        "status": "imported",
        "description": sigma.description or "",
        "logsource": doc.get("logsource", {}),
        "detection": converted,
        "level": level,
        "tags": tags,
        "severity": LEVEL_SEVERITY.get(level, 5),
        "confidence": DEFAULT_CONFIDENCE,
        "enabled": False,
        "source": "sigma",
    }


def import_sigma(text: str) -> Rule:
    """Convert, save to rules/imported/<id>.yml and register the rule (disabled) without a restart."""
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise SigmaImportError("Rule too large (max 50 KB)")
    doc = convert_sigma(text)
    try:
        rule = _rule_from_yaml(doc)  # same parser as built-in rules: proves it will load at startup
    except (KeyError, ValueError) as e:
        raise SigmaImportError(f"Rule could not be converted: {e}")
    if any(r.id == rule.id for r in rules_module.RULES):
        raise SigmaImportError("A rule with this id already exists")

    rules_module.IMPORTED_DIR.mkdir(parents=True, exist_ok=True)
    path = rules_module.IMPORTED_DIR / f"{uuid.UUID(rule.id)}.yml"  # UUID-only filename: no path traversal
    path.write_text(yaml.safe_dump(doc, sort_keys=False, allow_unicode=True), encoding="utf-8")
    rules_module.RULES.append(rule)
    return rule
