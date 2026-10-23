"""Network telemetry: TCP connections and DNS lookups as normalized events.

No admin rights needed: Get-NetTCPConnection and Get-DnsClientCache are
readable by a normal user. Events go on the "Network" channel; the provider
field holds the event type and event_id reuses the matching Sysmon ids
(3 = network connection, 22 = DNS query) so analysts recognise them.
"""
import ipaddress
import json
import subprocess
import uuid

NETWORK_CHANNEL = "Network"
EVENT_TYPES = {"network_connection": 3, "dns_query": 22}


def is_local_address(ip: str | None) -> bool:
    """True for addresses we never report: loopback, link-local, unspecified."""
    try:
        addr = ipaddress.ip_address(ip or "")
    except ValueError:
        return True  # not an IP at all - skip it
    return addr.is_loopback or addr.is_link_local or addr.is_unspecified


def make_network_event(
    event_type: str,
    *,
    host: str,
    timestamp: str,
    source: str,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    dst_port: int | None = None,
    protocol: str | None = None,
    bytes_out: int | None = None,
    process: str | None = None,
    message: str = "",
    raw: dict | None = None,
) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "record_id": None,
        "source": source,
        "host": host,
        "timestamp": timestamp,
        "channel": NETWORK_CHANNEL,
        "provider": event_type,
        "event_id": EVENT_TYPES[event_type],
        "user": None,
        "process": process,
        "command_line": None,
        "parent_process": None,
        "src_ip": src_ip,
        "logon_type": None,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": protocol,
        "bytes_out": bytes_out,
        "message": message,
        "raw": json.dumps(raw if raw is not None else {}),
    }


class NetworkDeduper:
    """Remembers what was already reported so each poll only yields new items.
    Connections are keyed by (pid, remote ip, remote port); DNS by name."""

    def __init__(self):
        self.seen_connections: set[tuple] = set()
        self.seen_names: set[str] = set()

    def new_connections(self, conns: list[dict]) -> list[dict]:
        fresh = []
        for c in conns:
            if is_local_address(c.get("RemoteAddress")):
                continue
            key = (c.get("OwningProcess"), c.get("RemoteAddress"), c.get("RemotePort"))
            if key not in self.seen_connections:
                self.seen_connections.add(key)
                fresh.append(c)
        return fresh

    def new_dns(self, entries: list[dict]) -> list[dict]:
        fresh = []
        for d in entries:
            name = (d.get("Entry") or "").lower()
            if name and name not in self.seen_names:
                self.seen_names.add(name)
                fresh.append(d)
        return fresh


def connection_to_event(conn: dict, host: str, timestamp: str, source: str = "local-net") -> dict:
    process = conn.get("ProcessName")
    return make_network_event(
        "network_connection",
        host=host,
        timestamp=timestamp,
        source=source,
        src_ip=conn.get("LocalAddress"),
        dst_ip=conn.get("RemoteAddress"),
        dst_port=int(conn["RemotePort"]) if conn.get("RemotePort") is not None else None,
        protocol="tcp",
        process=process,
        message=f"{process or 'unknown'} (pid {conn.get('OwningProcess')}) -> "
        f"{conn.get('RemoteAddress')}:{conn.get('RemotePort')} [{conn.get('State')}]",
        raw=conn,
    )


def dns_to_event(entry: dict, host: str, timestamp: str, source: str = "local-net") -> dict:
    name = entry.get("Entry") or ""
    data = entry.get("Data")
    return make_network_event(
        "dns_query",
        host=host,
        timestamp=timestamp,
        source=source,
        dst_ip=data if data and not is_local_address(data) else None,
        protocol="dns",
        message=f"DNS query {name}" + (f" -> {data}" if data else ""),
        raw=entry,
    )


def _run_ps_json(script: str) -> list[dict]:
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())
    data = json.loads(result.stdout.strip() or "[]")
    return [data] if isinstance(data, dict) else data


# PID -> process name is resolved in the same PowerShell call.
_TCP_SCRIPT = (
    "$names = @{}; Get-Process | ForEach-Object { $names[$_.Id] = $_.ProcessName }; "
    "$c = Get-NetTCPConnection -ErrorAction SilentlyContinue | "
    "Where-Object { $_.State -ne 'Listen' -and $_.State -ne 'Bound' } | ForEach-Object { "
    "[PSCustomObject]@{ LocalAddress = $_.LocalAddress; LocalPort = $_.LocalPort; "
    "RemoteAddress = $_.RemoteAddress; RemotePort = $_.RemotePort; State = [string]$_.State; "
    "OwningProcess = $_.OwningProcess; ProcessName = $names[[int]$_.OwningProcess] } }; "
    "if ($c) { $c | ConvertTo-Json -Depth 3 } else { '[]' }"
)

_DNS_SCRIPT = (
    "$d = Get-DnsClientCache -ErrorAction SilentlyContinue | ForEach-Object { "
    "[PSCustomObject]@{ Entry = $_.Entry; Data = [string]$_.Data; Type = [int]$_.Type } }; "
    "if ($d) { $d | ConvertTo-Json -Depth 3 } else { '[]' }"
)


def fetch_tcp_connections() -> list[dict]:
    return _run_ps_json(_TCP_SCRIPT)


def fetch_dns_cache() -> list[dict]:
    return _run_ps_json(_DNS_SCRIPT)
