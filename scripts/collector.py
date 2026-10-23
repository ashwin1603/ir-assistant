"""Push Windows events to the API (run from an elevated terminal).

    python scripts/collector.py                          # Windows event logs (admin)
    python scripts/collector.py --watch [--interval 15]   # near-real-time loop (admin)
    python scripts/collector.py --network [--interval 15] # TCP + DNS telemetry, no admin
"""
import argparse
import json
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(BACKEND_DIR))

import httpx
from dotenv import dotenv_values

from app.collector.network import (
    NetworkDeduper,
    connection_to_event,
    dns_to_event,
    fetch_dns_cache,
    fetch_tcp_connections,
)
from app.collector.normalize import normalize_events
from app.collector.windows_events import CHANNELS, fetch_events, max_events_for

API_BASE_URL = "http://127.0.0.1:8000"
BATCH_SIZE = 200
# Last RecordId seen per "channel|event_id", so --watch only fetches new records (gitignored).
STATE_FILE = Path(__file__).resolve().parent / ".collector_state.json"
MAX_BACKOFF = 300


def load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text())
    except (OSError, ValueError):
        return {}


def save_state(state: dict) -> None:
    STATE_FILE.write_text(json.dumps(state, indent=2))


def post_batches(client: httpx.Client, events: list[dict], headers: dict) -> int:
    """POST events in batches; returns how many were newly ingested. Raises on API errors."""
    ingested = 0
    for i in range(0, len(events), BATCH_SIZE):
        resp = client.post(f"{API_BASE_URL}/api/events/ingest", json={"events": events[i : i + BATCH_SIZE]}, headers=headers)
        resp.raise_for_status()
        ingested += resp.json().get("ingested", 0)
    return ingested


def run_watch(collector_key: str, interval: int) -> int:
    """Poll each channel/event id for records newer than the last seen RecordId until Ctrl+C."""
    host = socket.gethostname()
    headers = {"X-Collector-Key": collector_key}
    state = load_state()
    failures = 0
    print(f"Watching Windows event logs every {interval}s (Ctrl+C to stop)")
    with httpx.Client(timeout=30) as client:
        try:
            while True:
                events, newest = [], {}
                for channel, event_ids in CHANNELS.items():
                    for event_id in event_ids:
                        key = f"{channel}|{event_id}"
                        try:
                            raw = fetch_events(channel, [event_id], max_events_for(event_id), state.get(key))
                        except Exception as exc:
                            print(f"[warn] could not read {key}: {exc}")
                            continue
                        record_ids = [int(r["RecordId"]) for r in raw if r.get("RecordId") is not None]
                        if record_ids:
                            newest[key] = max(record_ids)
                        events += normalize_events(raw, host=host, source="agent")
                try:
                    ingested = post_batches(client, events, headers)
                    client.post(
                        f"{API_BASE_URL}/api/devices/heartbeat",
                        json={"host": host, "source": "agent", "events_sent": len(events)},
                        headers=headers,
                    ).raise_for_status()
                except httpx.HTTPError as exc:
                    # State is not advanced, so the same records are retried next cycle.
                    failures += 1
                    wait = min(MAX_BACKOFF, interval * 2**failures)
                    print(f"[{datetime.now():%H:%M:%S}] API error ({exc.__class__.__name__}); retrying in {wait}s")
                    time.sleep(wait)
                    continue
                failures = 0
                state.update(newest)
                save_state(state)
                print(f"[{datetime.now():%H:%M:%S}] fetched {len(events)} new, ingested {ingested}")
                time.sleep(interval)
        except KeyboardInterrupt:
            print("Stopped.")
    return 0


def run_network(collector_key: str, interval: int) -> int:
    """Poll TCP connections and the DNS cache until Ctrl+C; post only new items."""
    host = socket.gethostname()
    deduper = NetworkDeduper()
    headers = {"X-Collector-Key": collector_key}
    print(f"Network telemetry every {interval}s (Ctrl+C to stop)")
    with httpx.Client(timeout=30) as client:
        try:
            while True:
                now = datetime.now(timezone.utc).isoformat()
                events = []
                try:
                    events += [connection_to_event(c, host, now) for c in deduper.new_connections(fetch_tcp_connections())]
                    events += [dns_to_event(d, host, now) for d in deduper.new_dns(fetch_dns_cache())]
                except Exception as exc:
                    print(f"[warn] network poll failed: {exc}")
                for i in range(0, len(events), BATCH_SIZE):
                    resp = client.post(
                        f"{API_BASE_URL}/api/events/ingest", json={"events": events[i : i + BATCH_SIZE]}, headers=headers
                    )
                    if resp.status_code >= 400:
                        print(f"[error] ingest failed with status {resp.status_code}")
                        break
                print(f"[ok] {len(events)} new network events")
                time.sleep(interval)
        except KeyboardInterrupt:
            print("Stopped.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--network", action="store_true", help="collect TCP connections and DNS lookups (no admin)")
    parser.add_argument("--watch", action="store_true", help="keep polling Windows logs for new events (admin)")
    parser.add_argument("--interval", type=int, default=15, help="seconds between polls (default 15)")
    args = parser.parse_args()

    env = dotenv_values(BACKEND_DIR / ".env")
    collector_key = env.get("COLLECTOR_API_KEY")
    if not collector_key:
        print("COLLECTOR_API_KEY not found in backend/.env. Aborting.")
        return 1

    if args.network:
        return run_network(collector_key, max(1, args.interval))
    if args.watch:
        return run_watch(collector_key, max(1, args.interval))

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
