import socket
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(BACKEND_DIR))

import httpx
from dotenv import dotenv_values

from app.collector.normalize import normalize_events
from app.collector.windows_events import CHANNELS, fetch_events, max_events_for

API_BASE_URL = "http://127.0.0.1:8000"
BATCH_SIZE = 200


def main() -> int:
    env = dotenv_values(BACKEND_DIR / ".env")
    collector_key = env.get("COLLECTOR_API_KEY")
    if not collector_key:
        print("COLLECTOR_API_KEY not found in backend/.env. Aborting.")
        return 1

    host = socket.gethostname()
    all_normalized = []

    for channel, event_ids in CHANNELS.items():
        for event_id in event_ids:
            max_events = max_events_for(event_id)
            try:
                raw_events = fetch_events(channel, [event_id], max_events)
            except Exception as exc:
                print(f"[warn] could not read {channel} id={event_id}: {exc}")
                continue
            normalized = normalize_events(raw_events, host=host, source="agent")
            all_normalized.extend(normalized)
            print(f"[ok] {channel} id={event_id}: {len(normalized)} events (max {max_events})")

    if not all_normalized:
        print("No events collected. Are you running this from an elevated terminal?")
        return 1

    headers = {"X-Collector-Key": collector_key}
    ingested_total = 0
    skipped_total = 0
    with httpx.Client(timeout=30) as client:
        for i in range(0, len(all_normalized), BATCH_SIZE):
            batch = all_normalized[i : i + BATCH_SIZE]
            resp = client.post(f"{API_BASE_URL}/api/events/ingest", json={"events": batch}, headers=headers)
            if resp.status_code >= 400:
                print(f"[error] ingest failed for batch {i // BATCH_SIZE + 1} with status {resp.status_code}")
                try:
                    detail = resp.json().get("detail")
                except ValueError:
                    detail = resp.text
                if isinstance(detail, list):
                    for err in detail:
                        print(f"  field: {err.get('loc')}  type: {err.get('type')}")
                else:
                    print(f"  detail: {detail}")
                return 1
            body = resp.json()
            ingested_total += body.get("ingested", 0)
            skipped_total += body.get("skipped", 0)

    print(f"Done. Ingested {ingested_total} new events, skipped {skipped_total} duplicates.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
