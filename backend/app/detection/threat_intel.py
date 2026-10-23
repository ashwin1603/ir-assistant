"""Local threat-intel enrichment. Indicators (IPs, domains, SHA-256 hashes) live
in the ti_indicators table and are imported by an admin from a CSV/TXT file;
nothing here makes a network call.

Matching: observables are pulled out of an event's command_line, message and
src_ip, normalised (lower-case, canonical IP form) and looked up in the
indicator set. Private/loopback addresses are never extracted, because they
are internal machines, not threat intel.
"""

import csv
import io
import ipaddress
import re
from datetime import datetime, timezone
from functools import lru_cache

from sqlalchemy.orm import Session

from app.detection.rules import Rule
from app.models import AppSetting, Event, ThreatIndicator

INDICATOR_TYPES = ("ip", "domain", "sha256")
MAX_IMPORT_BYTES = 1024 * 1024  # 1 MB
MAX_REPORTED_ERRORS = 50

# The "Known-bad indicator seen" rule. Defined in code (not YAML) because it
# matches against the indicator table, not against fixed field values.
TI_RULE = Rule(
    id="c0a1f3e2-7d4b-4e8a-9b61-2f5d8e3c1a70",
    name="Known-bad indicator seen",
    technique_ids=("T1071",),
    severity=7,
    confidence=0.8,
    level="high",
    selections={},
)

# Internal ranges to skip. ipaddress.is_private is NOT used on purpose: it also
# treats the documentation ranges (203.0.113.0/24, 198.51.100.0/24) as private,
# and those are exactly the ranges our demo indicators use.
_SKIP_NETWORKS = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "255.255.255.255/32",
        "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
    )
]

_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

# Patterns used to find observables inside free text.
_IPV4_IN_TEXT = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_URL_HOST_IN_TEXT = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://\[?([^/\s:\]\"']+)")
_DOMAIN_IN_TEXT = re.compile(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b")
_SHA256_IN_TEXT = re.compile(r"(?i)\b[0-9a-f]{64}\b")

# Clearly labelled demo indicators. They use reserved documentation ranges and
# .example domains (RFC 5737 / RFC 2606), so they can never match real traffic.
# 203.0.113.10 is the download server in scripts/seed_simulated_events.py.
DEMO_SOURCE = "demo"
DEMO_INDICATORS = [
    ("ip", "203.0.113.10", "demo,payload-server"),
    ("ip", "203.0.113.25", "demo,c2"),
    ("ip", "203.0.113.77", "demo,scanner"),
    ("ip", "198.51.100.23", "demo,c2"),
    ("ip", "198.51.100.66", "demo,brute-force"),
    ("domain", "payload-cdn.example", "demo,payload-server"),
    ("domain", "update-check.example", "demo,c2"),
    ("domain", "c2.bad-actor.example", "demo,c2"),
    ("domain", "login-portal.example", "demo,phishing"),
    ("sha256", "0" * 63 + "1", "demo,placeholder-hash"),
]
_DEMO_SEEDED_KEY = "ti_demo_seeded"


class IndicatorError(ValueError):
    pass


def _is_internal(ip: ipaddress._BaseAddress) -> bool:
    return any(ip.version == net.version and ip in net for net in _SKIP_NETWORKS)


def is_internal_ip(text: str) -> bool:
    """Public wrapper for the network rules: True for private/loopback/etc."""
    return _is_internal(ipaddress.ip_address(text))


def normalize_indicator(ioc_type: str, value: str) -> str:
    """Validate one indicator and return its canonical form, or raise IndicatorError."""
    ioc_type = ioc_type.strip().lower()
    value = value.strip().lower()
    if ioc_type not in INDICATOR_TYPES:
        raise IndicatorError(f"unknown type '{ioc_type[:20]}' (use ip, domain or sha256)")
    if ioc_type == "ip":
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            raise IndicatorError("invalid IP address")
        if _is_internal(ip):
            raise IndicatorError("private/loopback/internal IP address")
        return str(ip)
    if ioc_type == "domain":
        value = value.rstrip(".")
        if not _DOMAIN_RE.match(value):
            raise IndicatorError("invalid domain")
        return value
    if not _SHA256_RE.match(value):
        raise IndicatorError("invalid SHA-256 (need 64 hex characters)")
    return value


def _clean_label(text: str, limit: int) -> str:
    # Source/tags are shown in the UI and sent to the AI facts: keep them short and plain.
    return re.sub(r"[^A-Za-z0-9 ._,:/-]", "", text).strip()[:limit]


def parse_import(text: str) -> tuple[list[dict], list[dict]]:
    """Parse "type,value,source,tags" lines. Tags inside the tags column are
    separated by ';'. Blank lines, '#' comments and a header row are skipped.
    Returns (valid rows deduplicated within the file, errors)."""
    rows: dict[tuple[str, str], dict] = {}
    errors: list[dict] = []
    for line_no, cols in enumerate(csv.reader(io.StringIO(text)), start=1):
        cols = [c.strip() for c in cols]
        if not cols or not any(cols) or cols[0].startswith("#"):
            continue
        if line_no == 1 and cols[0].lower() == "type":
            continue
        if len(cols) < 2:
            errors.append({"line": line_no, "reason": "expected type,value[,source,tags]"})
            continue
        try:
            value = normalize_indicator(cols[0], cols[1])
        except IndicatorError as e:
            errors.append({"line": line_no, "reason": str(e)})
            continue
        ioc_type = cols[0].lower()
        source = _clean_label(cols[2], 64) if len(cols) > 2 and cols[2] else "import"
        tags = _clean_label(",".join(t.strip() for t in (cols[3] if len(cols) > 3 else "").split(";") if t.strip()), 200)
        rows.setdefault((ioc_type, value), {"type": ioc_type, "value": value, "source": source or "import", "tags": tags})
    return list(rows.values()), errors[:MAX_REPORTED_ERRORS]


def import_indicators(db: Session, rows: list[dict], added_by: str) -> tuple[int, int]:
    """Insert rows not already in the table. Returns (added, duplicates)."""
    existing = {(t, v) for t, v in db.query(ThreatIndicator.type, ThreatIndicator.value).all()}
    new = [r for r in rows if (r["type"], r["value"]) not in existing]
    db.add_all(ThreatIndicator(**r, added_by=added_by) for r in new)
    db.commit()
    return len(new), len(rows) - len(new)


def seed_demo_indicators(db: Session) -> None:
    """Insert the demo indicators once. A flag records that seeding happened, so
    an admin who deletes them does not get them back on the next restart."""
    if db.get(AppSetting, _DEMO_SEEDED_KEY):
        return
    rows = [{"type": t, "value": v, "source": DEMO_SOURCE, "tags": tags} for t, v, tags in DEMO_INDICATORS]
    import_indicators(db, rows, added_by="system")
    db.add(AppSetting(key=_DEMO_SEEDED_KEY, value=datetime.now(timezone.utc).isoformat()))
    db.commit()


# ---------- Matching ----------


def _external_ip(text: str) -> str | None:
    try:
        ip = ipaddress.ip_address(text.strip("[]"))
    except ValueError:
        return None
    return None if _is_internal(ip) else str(ip)


def extract_observables(event: Event) -> set[tuple[str, str]]:
    """(type, value) pairs found in the event, normalised for lookup."""
    return set(_observables(event.src_ip, event.command_line, event.message))


# The regex scan is most of a detection run's cost and events never change, so the
# result is cached on the exact field values (a pure function: same text, same answer).
@lru_cache(maxsize=100_000)
def _observables(src_ip: str | None, command_line: str | None, message: str | None) -> frozenset[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    if src_ip and (ip := _external_ip(src_ip.strip())):
        found.add(("ip", ip))
    for text in (command_line, message):
        if not text:
            continue
        for candidate in _IPV4_IN_TEXT.findall(text) + _URL_HOST_IN_TEXT.findall(text):
            if ip := _external_ip(candidate):
                found.add(("ip", ip))
        for domain in _DOMAIN_IN_TEXT.findall(text):
            found.add(("domain", domain.lower()))
        for digest in _SHA256_IN_TEXT.findall(text):
            found.add(("sha256", digest.lower()))
    return frozenset(found)


def load_index(db: Session) -> dict[tuple[str, str], ThreatIndicator]:
    return {(i.type, i.value): i for i in db.query(ThreatIndicator).all()}


def match_event(event: Event, index: dict[tuple[str, str], ThreatIndicator]) -> list[dict]:
    if not index:
        return []
    hits = [index[o] for o in sorted(extract_observables(event)) if o in index]
    return [{"type": i.type, "value": i.value, "source": i.source, "tags": i.tags} for i in hits]


def matches_for_event_ids(db: Session, event_ids: list[str] | set[str]) -> dict[str, list[dict]]:
    """event id -> TI matches, for events that have at least one match."""
    index = load_index(db)
    if not index or not event_ids:
        return {}
    result: dict[str, list[dict]] = {}
    ids = list(event_ids)
    for start in range(0, len(ids), 500):  # stay under SQLite's bound-parameter limit
        for event in db.query(Event).filter(Event.id.in_(ids[start : start + 500])).all():
            if hits := match_event(event, index):
                result[event.id] = hits
    return result


def unique_matches(matches_by_event: dict[str, list[dict]], event_ids: list[str]) -> list[dict]:
    """The distinct indicators matched across the given events."""
    seen: dict[tuple[str, str], dict] = {}
    for event_id in event_ids:
        for m in matches_by_event.get(event_id, []):
            seen.setdefault((m["type"], m["value"]), m)
    return [seen[k] for k in sorted(seen)]
