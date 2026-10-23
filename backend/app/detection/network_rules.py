"""Network detection rules (events on the "Network" channel only).

Defined in code, not YAML, because each one needs a calculation the YAML
subset cannot express: distinct-port counts, beacon interval regularity,
byte sums, subdomain entropy. Each rule has named thresholds (Param) that an
admin can change on the Settings page; the overrides are stored in
rule_overrides.params and passed to detect() as a plain dict.

detect() returns (matched events, summary) pairs. The summary is one
plain-language sentence built only from validated values (IPs, ports,
numbers, sanitised names) and is shown in the report and the AI facts.
"""

import ipaddress
import json
import math
import re
import statistics
from collections import Counter
from dataclasses import dataclass
from datetime import timedelta
from typing import Callable

from app.collector.network import NETWORK_CHANNEL
from app.detection.rules import Rule
from app.detection.threat_intel import is_internal_ip
from app.models import Event

# Ports commonly used by reverse shells / C2 frameworks (Metasploit 4444,
# "leet" 1337/31337, Tor 9001, alt-HTTP 8888). Edit here to change the list.
UNCOMMON_PORTS: frozenset[int] = frozenset({4444, 1337, 31337, 8888, 9001})

# Activity this close together is treated as one burst, as for filter rules.
GROUP_WINDOW = timedelta(minutes=30)


@dataclass(frozen=True)
class Param:
    key: str
    label: str
    default: float
    min: float
    max: float
    integer: bool = True


@dataclass(frozen=True)
class NetworkRule:
    rule: Rule  # id, name, ATT&CK ids, severity, confidence - same fields as a YAML rule
    description: str
    params: tuple[Param, ...]
    detect: Callable[[list[Event], dict], list[tuple[list[Event], str]]]

    def defaults(self) -> dict:
        return {p.key: p.default for p in self.params}


# ---------- helpers ----------


def _safe_name(text: str | None, limit: int = 64) -> str:
    """Process/domain names come from logs, so keep only harmless characters."""
    return re.sub(r"[^A-Za-z0-9._-]", "", text or "")[:limit] or "unknown"


def _valid_ip(text: str | None) -> str | None:
    try:
        return str(ipaddress.ip_address((text or "").strip("[]")))
    except ValueError:
        return None


def _is_external(text: str | None) -> bool:
    ip = _valid_ip(text)
    return ip is not None and not is_internal_ip(ip)


def _connections(events: list[Event]) -> list[Event]:
    return [e for e in events if e.provider == "network_connection"]


def _group(events: list[Event], key) -> dict[tuple, list[Event]]:
    groups: dict[tuple, list[Event]] = {}
    for event in events:
        groups.setdefault(key(event), []).append(event)
    for group in groups.values():
        group.sort(key=lambda e: e.timestamp)
    return groups


def _windows(events: list[Event], window: timedelta, is_hit: Callable[[list[Event]], bool]) -> list[list[Event]]:
    """Slide a time window over time-sorted events; return non-overlapping
    windows where is_hit() is true (same idea as engine._cluster_events)."""
    hits, i, n = [], 0, len(events)
    while i < n:
        j = i
        while j < n and events[j].timestamp <= events[i].timestamp + window:
            j += 1
        if is_hit(events[i:j]):
            hits.append(events[i:j])
            i = j
        else:
            i += 1
    return hits


def _mb(nbytes: int) -> str:
    return f"{nbytes / (1024 * 1024):.1f} MB"


# ---------- 1. Port scan (T1046) ----------


def detect_port_scan(events: list[Event], p: dict) -> list[tuple[list[Event], str]]:
    min_ports, window = int(p["min_ports"]), timedelta(seconds=p["window_seconds"])
    conns = [e for e in _connections(events) if e.dst_ip and e.dst_port is not None]
    results = []
    for (_host, src, dst), group in _group(conns, lambda e: (e.host, e.src_ip, e.dst_ip)).items():
        for hit in _windows(group, window, lambda w: len({e.dst_port for e in w}) >= min_ports):
            ports = len({e.dst_port for e in hit})
            results.append((hit, f"{_valid_ip(src) or 'this host'} probed {ports} distinct ports on "
                                 f"{_valid_ip(dst) or 'one target'} within {int(p['window_seconds'])} seconds."))
    return results


# ---------- 2. Beaconing (T1071) ----------


def beacon_stats(group: list[Event]) -> tuple[float, float] | None:
    """(median interval in seconds, jitter as % of the median). Jitter is the
    median absolute deviation of the intervals, so one missed check-in does
    not hide an otherwise regular beacon."""
    times = [e.timestamp for e in group]
    intervals = [(b - a).total_seconds() for a, b in zip(times, times[1:])]
    if not intervals:
        return None
    median = statistics.median(intervals)
    if median < 1:  # a burst of simultaneous connections is not a beacon
        return None
    jitter = statistics.median(abs(i - median) for i in intervals)
    return median, jitter / median * 100


def detect_beaconing(events: list[Event], p: dict) -> list[tuple[list[Event], str]]:
    min_conns, max_jitter = int(p["min_connections"]), p["max_jitter_pct"]
    conns = [e for e in _connections(events) if e.dst_ip and e.dst_port is not None]
    results = []
    for (_host, process, dst, port), group in _group(conns, lambda e: (e.host, e.process, e.dst_ip, e.dst_port)).items():
        if len(group) < min_conns:
            continue
        stats = beacon_stats(group)
        if stats and stats[1] <= max_jitter:
            median, jitter = stats
            results.append((group, f"{_safe_name(process)} connected to {_valid_ip(dst) or 'one destination'}:{port} "
                                   f"{len(group)} times about every {median:.0f} seconds (jitter {jitter:.1f}%)."))
    return results


# ---------- 3. Large outbound transfer (T1041) ----------


def detect_large_transfer(events: list[Event], p: dict) -> list[tuple[list[Event], str]]:
    min_bytes = p["min_mb"] * 1024 * 1024
    window = timedelta(minutes=p["window_minutes"])
    conns = [e for e in _connections(events) if e.bytes_out and _is_external(e.dst_ip)]
    results = []
    for (_host, dst), group in _group(conns, lambda e: (e.host, _valid_ip(e.dst_ip))).items():
        for hit in _windows(group, window, lambda w: sum(e.bytes_out for e in w) >= min_bytes):
            total = sum(e.bytes_out for e in hit)
            processes = ", ".join(sorted({_safe_name(e.process) for e in hit}))
            results.append((hit, f"{_mb(total)} sent to external address {dst} by {processes} "
                                 f"within {int(p['window_minutes'])} minutes."))
    return results


# ---------- 4. Uncommon port (T1571) ----------


def detect_uncommon_port(events: list[Event], p: dict) -> list[tuple[list[Event], str]]:
    conns = [e for e in _connections(events) if e.dst_port in UNCOMMON_PORTS and _is_external(e.dst_ip)]
    results = []
    for (_host,), group in _group(conns, lambda e: (e.host,)).items():
        for hit in _windows(group, GROUP_WINDOW, lambda w: True):
            targets = ", ".join(sorted({f"{_safe_name(e.process)} -> {_valid_ip(e.dst_ip)}:{e.dst_port}" for e in hit}))
            results.append((hit, f"Outbound connection on a port often used by reverse shells/C2: {targets}."))
    return results


# ---------- 5. DNS tunnelling (T1071.004) ----------

_QUERY_IN_MESSAGE = re.compile(r"DNS query (\S+)")


def query_name(event: Event) -> str | None:
    """The queried name: raw.Entry (local collector), raw.name (seeder), else the message."""
    try:
        raw = json.loads(event.raw or "{}")
    except ValueError:
        raw = {}
    name = (raw.get("Entry") or raw.get("name")) if isinstance(raw, dict) else None
    if not name and (m := _QUERY_IN_MESSAGE.search(event.message or "")):
        name = m.group(1)
    return name.lower().rstrip(".") if isinstance(name, str) and name else None


def split_domain(name: str) -> tuple[str, str]:
    """(subdomain part, base domain). Base = last two labels; this is naive for
    suffixes like .co.uk, which only makes the rule group slightly coarser."""
    labels = name.split(".")
    if len(labels) < 3:
        return "", name
    return ".".join(labels[:-2]), ".".join(labels[-2:])


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    return -sum(c / len(text) * math.log2(c / len(text)) for c in counts.values())


def subdomain_stats(subdomains: set[str]) -> tuple[float, float]:
    """(average label length, average Shannon entropy) over the subdomains."""
    labels = [label for s in subdomains for label in s.split(".")]
    avg_label = sum(map(len, labels)) / len(labels)
    avg_entropy = sum(shannon_entropy(s.replace(".", "")) for s in subdomains) / len(subdomains)
    return avg_label, avg_entropy


def detect_dns_tunnelling(events: list[Event], p: dict) -> list[tuple[list[Event], str]]:
    min_subs, window = int(p["min_subdomains"]), timedelta(minutes=p["window_minutes"])
    min_label, min_entropy = p["min_avg_label_length"], p["min_entropy"]

    named: list[tuple[Event, str, str]] = []  # (event, subdomain, base domain)
    for e in events:
        if e.provider == "dns_query" and (name := query_name(e)):
            sub, base = split_domain(name)
            if sub:
                named.append((e, sub, base))
    sub_of = {e.id: sub for e, sub, _ in named}

    def unique_subs(w: list[Event]) -> set[str]:
        return {sub_of[e.id] for e in w}

    def looks_like_tunnel(w: list[Event]) -> bool:
        subs = unique_subs(w)
        if len(subs) < min_subs:
            return False
        avg_label, avg_entropy = subdomain_stats(subs)
        return avg_label >= min_label or avg_entropy >= min_entropy

    results = []
    base_of = {e.id: base for e, _, base in named}
    for (_host, base), group in _group([e for e, _, _ in named], lambda e: (e.host, base_of[e.id])).items():
        for hit in _windows(group, window, looks_like_tunnel):
            subs = unique_subs(hit)
            avg_label, avg_entropy = subdomain_stats(subs)
            results.append((hit, f"{len(subs)} unique subdomains of {_safe_name(base, 253)} queried within "
                                 f"{int(p['window_minutes'])} minutes (average label length {avg_label:.0f}, "
                                 f"entropy {avg_entropy:.1f} bits/char)."))
    return results


# ---------- registry ----------


def _rule(rule_id: str, name: str, techniques: tuple[str, ...], severity: int, confidence: float, level: str) -> Rule:
    return Rule(id=rule_id, name=name, technique_ids=techniques, severity=severity, confidence=confidence,
                level=level, selections={}, kind="network", source="network")


NETWORK_RULES: list[NetworkRule] = [
    NetworkRule(
        rule=_rule("7b1e4c90-2f3a-4d5e-8a61-0c9f1e2d3a01", "Port scan", ("T1046",), 5, 0.7, "medium"),
        description="One source connected to many different ports on one destination in a short time.",
        params=(
            Param("min_ports", "distinct ports", 15, 2, 1000),
            Param("window_seconds", "window (seconds)", 60, 5, 3600),
        ),
        detect=detect_port_scan,
    ),
    NetworkRule(
        rule=_rule("7b1e4c90-2f3a-4d5e-8a61-0c9f1e2d3a02", "Network beaconing", ("T1071",), 6, 0.7, "high"),
        description="The same process kept connecting to the same destination and port at regular intervals, "
        "like malware checking in with a command-and-control server.",
        params=(
            Param("min_connections", "connections", 6, 3, 1000),
            Param("max_jitter_pct", "max jitter (% of median)", 10, 1, 100),
        ),
        detect=detect_beaconing,
    ),
    NetworkRule(
        rule=_rule("7b1e4c90-2f3a-4d5e-8a61-0c9f1e2d3a03", "Large outbound transfer", ("T1041",), 8, 0.7, "high"),
        description="A large amount of data was sent to one external address (possible exfiltration). "
        "Needs bytes_out, e.g. from an uploaded flow CSV.",
        params=(
            Param("min_mb", "MB sent", 50, 1, 100000),
            Param("window_minutes", "window (minutes)", 60, 1, 1440),
        ),
        detect=detect_large_transfer,
    ),
    NetworkRule(
        rule=_rule("7b1e4c90-2f3a-4d5e-8a61-0c9f1e2d3a04", "Connection to uncommon port", ("T1571",), 6, 0.6, "medium"),
        description="A process connected out to a port commonly used by reverse shells and C2 tools "
        f"({', '.join(map(str, sorted(UNCOMMON_PORTS)))}).",
        params=(),
        detect=detect_uncommon_port,
    ),
    NetworkRule(
        rule=_rule("7b1e4c90-2f3a-4d5e-8a61-0c9f1e2d3a05", "Possible DNS tunnelling", ("T1071.004",), 6, 0.6, "high"),
        description="Many unique, long or random-looking subdomains of one domain were looked up in a short time, "
        "which is how data is smuggled out inside DNS queries.",
        params=(
            Param("min_subdomains", "unique subdomains", 10, 2, 1000),
            Param("window_minutes", "window (minutes)", 2, 1, 60),
            Param("min_avg_label_length", "avg label length", 25, 5, 63),
            Param("min_entropy", "entropy (bits/char)", 3.5, 1, 6, integer=False),
        ),
        detect=detect_dns_tunnelling,
    ),
]


def find_network_rule(rule_id: str) -> NetworkRule | None:
    return next((r for r in NETWORK_RULES if r.rule.id == rule_id), None)


def network_events(events: list[Event]) -> list[Event]:
    return [e for e in events if e.channel == NETWORK_CHANNEL]
