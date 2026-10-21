"""Validate the detection engine against known ground truth.

Reads docs/ground_truth.json, re-runs detection on the current database (the
same thing every API GET does) and writes docs/validation_results.md with a
per-technique table plus precision/recall for:
  - real attacks run on DESKTOP-M35SOM0 (matched by rule + time window)
  - simulated events on SIM-WS01 (matched per event)

    python scripts/validate.py
"""

import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = ROOT / "backend"
GROUND_TRUTH = ROOT / "docs" / "ground_truth.json"
OUTPUT = ROOT / "docs" / "validation_results.md"

# The app's settings use a relative DB path, so run from backend/ like the API does.
os.chdir(BACKEND_DIR)
sys.path.insert(0, str(BACKEND_DIR))

from app.db import SessionLocal  # noqa: E402
from app.detection.engine import run_detection  # noqa: E402
from app.models import Detection, Event  # noqa: E402


def _to_utc(date: str, hhmm: str, offset: str) -> datetime:
    """Local "HH:MM" on a date -> naive UTC datetime (how events are stored)."""
    sign = -1 if offset.startswith("-") else 1
    hours, minutes = offset.lstrip("+-").split(":")
    local = datetime.fromisoformat(f"{date}T{hhmm}")
    return local - sign * timedelta(hours=int(hours), minutes=int(minutes))


def _pct(num: int, den: int) -> str:
    return f"{num / den:.0%} ({num}/{den})" if den else "n/a"


def _technique_table(rows: list[tuple[str, bool]]) -> list[str]:
    """rows: (technique, detected?) -> markdown table lines."""
    counts: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for technique, detected in rows:
        counts[technique][0] += 1
        counts[technique][1] += int(detected)
    lines = ["| Technique | Expected | Detected | Missed |", "|---|---|---|---|"]
    for technique in sorted(counts):
        expected, detected = counts[technique]
        lines.append(f"| {technique} | {expected} | {detected} | {expected - detected} |")
    return lines


def validate_real(db, gt: dict) -> list[str]:
    date, offset = gt["date"], gt["utc_offset"]
    win_start = _to_utc(date, gt["evaluation_window"]["start"], offset)
    win_end = _to_utc(date, gt["evaluation_window"]["end"], offset)

    detections = (
        db.query(Detection)
        .filter(Detection.host == gt["host"], Detection.first_seen <= win_end, Detection.last_seen >= win_start)
        .order_by(Detection.first_seen)
        .all()
    )

    rows, true_positive_ids = [], set()
    for attack in gt["attacks"]:
        start = _to_utc(date, attack["start"], offset)
        end = _to_utc(date, attack["end"], offset)
        hits = [d for d in detections if d.rule_name == attack["rule"] and d.first_seen <= end and d.last_seen >= start]
        true_positive_ids.update(d.id for d in hits)
        rows.append((attack["technique"], bool(hits)))

    false_positives = [d for d in detections if d.id not in true_positive_ids]
    detected_items = sum(detected for _, detected in rows)

    lines = [
        f"## Real attacks - {gt['host']} ({date}, {gt['evaluation_window']['start']}-{gt['evaluation_window']['end']} local)",
        "",
        *_technique_table(rows),
        "",
        f"- **Recall:** {_pct(detected_items, len(rows))} expected technique instances detected",
        f"- **Precision:** {_pct(len(true_positive_ids), len(detections))} detections in the window match ground truth",
        f"- **False positives:** {len(false_positives)}",
    ]
    for d in false_positives:
        label = gt["known_noise"].get(d.rule_name, "unexpected")
        lines.append(f"  - {d.rule_name} x{d.event_count} ({label})")
    return lines


def validate_simulated(db, gt: dict) -> list[str]:
    events = db.query(Event).filter(Event.host == gt["host"], Event.source == "simulated").all()

    flagged: dict[str, set[str]] = defaultdict(set)
    for d in db.query(Detection).filter(Detection.host == gt["host"]).all():
        for event_id in json.loads(d.matched_event_ids):
            flagged[event_id].add(d.rule_name)

    rows, malicious_ids, true_positives = [], set(), 0
    for item in gt["malicious"]:
        matches = [e for e in events if e.event_id == item["event_id"] and item["contains"] in (e.command_line or "")]
        malicious_ids.update(e.id for e in matches)
        detected = any(item["rule"] in flagged[e.id] for e in matches)
        true_positives += int(detected)
        rows.append((item["technique"], detected))

    benign = [e for e in events if e.id not in malicious_ids]
    benign_flagged = [e for e in benign if flagged[e.id]]

    lines = [
        f"## Simulated events - {gt['host']}",
        "",
        *_technique_table(rows),
        "",
        f"- **Recall:** {_pct(true_positives, len(rows))} malicious events caught by the expected rule",
        f"- **Precision:** {_pct(true_positives, true_positives + len(benign_flagged))}",
        f"- **Benign events:** {len(benign)} (expected {gt['benign_count']}), false positives: {len(benign_flagged)}",
    ]
    for e in benign_flagged:
        lines.append(f"  - `{e.command_line}` flagged by {', '.join(sorted(flagged[e.id]))}")
    return lines


def main() -> int:
    gt = json.loads(GROUND_TRUTH.read_text(encoding="utf-8"))
    db = SessionLocal()
    try:
        run_detection(db)
        lines = [
            "# Detection validation results",
            "",
            f"Generated {datetime.now():%Y-%m-%d %H:%M} by `scripts/validate.py` from `docs/ground_truth.json`.",
            "",
            *validate_real(db, gt["real"]),
            "",
            *validate_simulated(db, gt["simulated"]),
            "",
        ]
    finally:
        db.close()

    OUTPUT.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
