"""Seed synthetic network telemetry for demoing network detections.

Nothing touches the network: these are just events posted to the API, tagged
source="simulated" on host SIM-NET01, spread over the last 20 minutes.
Patterns: port scan, C2 beaconing, large exfil upload, outbound to 4444,
DNS tunnelling-style long subdomains, plus ~60 benign events.

    python scripts/seed_simulated_network.py          # post events
    python scripts/seed_simulated_network.py --wipe   # delete SIM-NET01 events
"""

import argparse
import random
import string
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(BACKEND_DIR))

import httpx
from dotenv import dotenv_values

from app.collector.network import make_network_event

API_BASE_URL = "http://127.0.0.1:8000"
HOST = "SIM-NET01"
HOST_IP = "10.0.0.50"

# Documentation-only ranges (RFC 5737) for "bad" addresses.
SCAN_TARGET = "10.0.0.20"
BEACON_IP = "203.0.113.25"
EXFIL_IP = "198.51.100.66"
SHELL_IP = "203.0.113.77"
BENIGN_DESTS = [("142.250.183.14", "chrome.exe"), ("20.190.160.20", "OneDrive.exe"),
                ("13.107.42.14", "msedge.exe"), ("151.101.1.69", "chrome.exe")]
UPDATE_DESTS = [("13.107.4.50", "svchost.exe"), ("23.35.230.10", "MoUsoCoreWorker.exe")]
BENIGN_NAMES = ["www.google.com", "login.microsoftonline.com", "github.com",
                "www.bing.com", "update.microsoft.com", "settings-win.data.microsoft.com"]


def _conn(ts, dst_ip, dst_port, process, bytes_out=None, src_ip=HOST_IP):
    return make_network_event(
        "network_connection", host=HOST, timestamp=ts.isoformat(), source="simulated",
        src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port, protocol="tcp", bytes_out=bytes_out,
        process=process, message=f"{process} -> {dst_ip}:{dst_port} (simulated)",
        raw={"simulated": True},
    )


def _dns(ts, name, answer=None):
    return make_network_event(
        "dns_query", host=HOST, timestamp=ts.isoformat(), source="simulated",
        dst_ip=answer, protocol="dns",
        message=f"DNS query {name}" + (f" -> {answer}" if answer else "") + " (simulated)",
        raw={"simulated": True, "name": name},
    )


def _build_events() -> list[dict]:
    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=20)
    events = []

    # 1. Port scan: 25 ports, one source -> one target, within 40s.
    scan_start = start + timedelta(minutes=3)
    for i, port in enumerate(random.sample(range(20, 3390), 25)):
        events.append(_conn(scan_start + timedelta(seconds=i * 40 / 25), SCAN_TARGET, port, "nmap.exe"))

    # 2. Beaconing: 8 connections ~60s apart (+/- 3s jitter).
    beacon_start = start + timedelta(minutes=6)
    for i in range(8):
        ts = beacon_start + timedelta(seconds=i * 60 + random.uniform(-3, 3))
        events.append(_conn(ts, BEACON_IP, 443, "rundll32.exe", bytes_out=random.randint(300, 600)))

    # 3. Large outbound transfer (120 MB).
    events.append(_conn(start + timedelta(minutes=15), EXFIL_IP, 443, "rclone.exe", bytes_out=120 * 1024 * 1024))

    # 4. Outbound to 4444 (default Metasploit handler port).
    events.append(_conn(start + timedelta(minutes=16), SHELL_IP, 4444, "powershell.exe", bytes_out=2048))

    # 5. DNS queries with long random subdomains (tunnelling-style): 12 in ~80s.
    for i in range(12):
        label = "".join(random.choices(string.ascii_lowercase + string.digits, k=48))
        events.append(_dns(start + timedelta(minutes=10, seconds=i * 7), f"{label}.data.exfil-example.net"))

    # Benign background: ~60 web, update and DNS events across the window.
    for _ in range(36):
        ip, proc = random.choice(BENIGN_DESTS)
        ts = start + timedelta(seconds=random.randint(0, 20 * 60))
        events.append(_conn(ts, ip, random.choice([443, 443, 443, 80]), proc, bytes_out=random.randint(500, 200_000)))
    for _ in range(8):
        ip, proc = random.choice(UPDATE_DESTS)
        ts = start + timedelta(seconds=random.randint(0, 20 * 60))
        events.append(_conn(ts, ip, 443, proc, bytes_out=random.randint(1_000, 50_000)))
    for _ in range(16):
        ts = start + timedelta(seconds=random.randint(0, 20 * 60))
        events.append(_dns(ts, random.choice(BENIGN_NAMES), random.choice(BENIGN_DESTS)[0]))

    return events


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--wipe", action="store_true", help=f"delete simulated events for {HOST} instead of seeding")
    args = parser.parse_args()

    collector_key = dotenv_values(BACKEND_DIR / ".env").get("COLLECTOR_API_KEY")
    if not collector_key:
        print("COLLECTOR_API_KEY not found in backend/.env. Aborting.")
        return 1
    headers = {"X-Collector-Key": collector_key}

    with httpx.Client(base_url=API_BASE_URL, headers=headers, timeout=30) as client:
        if args.wipe:
            resp = client.delete("/api/events/simulated", params={"host": HOST})
        else:
            resp = client.post("/api/events/ingest", json={"events": _build_events()})

    if resp.status_code >= 400:
        print(f"[error] API returned status {resp.status_code}")
        return 1
    print(f"Done: {resp.json()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
