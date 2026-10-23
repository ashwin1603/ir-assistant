"""Parse uploaded log files (.json / .csv / .evtx) into normalized events.

Everything in an uploaded file is untrusted: we only check its shape here,
and the route re-validates every event against the EventIn Pydantic schema.
"""
import csv
import io
import json
import re
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from app.collector.network import make_network_event
from app.collector.normalize import normalize_event

ALLOWED_EXTENSIONS = {".json", ".csv", ".evtx"}
MAX_EVENTS_PER_FILE = 50_000

EVTX_MAGIC = b"ElfFile\x00"
_EVTX_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
_MS_DATE = re.compile(r"^/Date\((-?\d+)\)/$")  # ConvertTo-Json's DateTime format


class UploadParseError(Exception):
    """Raised for any file that cannot be turned into events (message is safe to show)."""


def content_matches_extension(ext: str, head: bytes) -> bool:
    """Magic-byte / content sniff on the first bytes of the file."""
    if ext == ".evtx":
        return head.startswith(EVTX_MAGIC)
    if b"\x00" in head:  # binary data is never valid JSON or CSV
        return False
    text = head.lstrip(b"\xef\xbb\xbf").lstrip()  # optional UTF-8 BOM
    if ext == ".json":
        return text[:1] in (b"[", b"{")
    if ext == ".csv":
        first_line = text.split(b"\n", 1)[0]
        return b"," in first_line
    return False


def _decode_text(data: bytes) -> str:
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise UploadParseError("File is not valid UTF-8 text")


def _fix_time(value) -> str:
    """Accept ISO 8601 or PowerShell's /Date(ms)/ and return ISO 8601 UTC."""
    if value is None or value == "":
        raise UploadParseError("Event is missing a timestamp")
    if isinstance(value, dict):  # ConvertTo-Json sometimes nests DateTime
        value = value.get("value") or value.get("DateTime")
    match = _MS_DATE.match(str(value))
    if match:
        return datetime.fromtimestamp(int(match.group(1)) / 1000, tz=timezone.utc).isoformat()
    return str(value)


def _flatten_properties(properties) -> list:
    # Raw Get-WinEvent exports give [{"Value": x}, ...]; our collector gives [x, ...].
    if not isinstance(properties, list):
        return []
    return [p.get("Value") if isinstance(p, dict) else p for p in properties]


def parse_json(data: bytes) -> list[dict]:
    try:
        parsed = json.loads(_decode_text(data))
    except json.JSONDecodeError:
        raise UploadParseError("File is not valid JSON")
    if isinstance(parsed, dict):
        parsed = [parsed]
    if not isinstance(parsed, list):
        raise UploadParseError("JSON must be an event object or a list of events")

    events = []
    for raw in parsed:
        if not isinstance(raw, dict) or "Id" not in raw:
            raise UploadParseError("JSON events must look like a Get-WinEvent export (missing 'Id')")
        raw = {
            **raw,
            "TimeCreated": _fix_time(raw.get("TimeCreated")),
            "Properties": _flatten_properties(raw.get("Properties")),
        }
        try:
            events.append(normalize_event(raw, host=raw.get("MachineName") or "", source="upload"))
        except (TypeError, ValueError):
            raise UploadParseError("JSON event has an invalid 'Id'")
    return events


# CSV column aliases: Get-WinEvent | Export-Csv names first, our own schema names second.
_CSV_ALIASES = {
    "event_id": ("Id", "EventID", "event_id"),
    "timestamp": ("TimeCreated", "timestamp"),
    "channel": ("LogName", "channel"),
    "provider": ("ProviderName", "provider"),
    "host": ("MachineName", "host"),
    "message": ("Message", "message"),
    "record_id": ("RecordId", "record_id"),
    "user": ("user",),
    "process": ("process",),
    "command_line": ("command_line",),
    "parent_process": ("parent_process",),
    "src_ip": ("src_ip",),
    "logon_type": ("logon_type",),
}


def _csv_value(row: dict, field: str):
    for column in _CSV_ALIASES[field]:
        value = row.get(column)
        if value not in (None, ""):
            return value
    return None


# Network flow logs: ts,src_ip,dst_ip,dst_port,proto,bytes_out,process
FLOW_COLUMNS = ("ts", "src_ip", "dst_ip", "dst_port", "proto", "bytes_out", "process")


def _optional_int(value):
    return int(value) if value not in (None, "") else None


def parse_flow_csv(reader: csv.DictReader) -> list[dict]:
    events = []
    try:
        for row in reader:
            if not row.get("dst_ip"):
                raise ValueError("missing dst_ip")
            events.append(
                make_network_event(
                    "network_connection",
                    host=row.get("host") or row.get("src_ip") or "unknown",
                    timestamp=_fix_time(row.get("ts")),
                    source="upload",
                    src_ip=row.get("src_ip") or None,
                    dst_ip=row["dst_ip"],
                    dst_port=_optional_int(row.get("dst_port")),
                    protocol=(row.get("proto") or "").lower() or None,
                    bytes_out=_optional_int(row.get("bytes_out")),
                    process=row.get("process") or None,
                    message=f"flow {row.get('src_ip')} -> {row['dst_ip']}:{row.get('dst_port')} "
                    f"{row.get('proto') or ''} {row.get('bytes_out') or 0} bytes",
                    raw=row,
                )
            )
    except (TypeError, ValueError, csv.Error):
        raise UploadParseError("Flow CSV row has an invalid or missing dst_ip / dst_port / bytes_out")
    return events


def parse_csv(data: bytes) -> list[dict]:
    reader = csv.DictReader(io.StringIO(_decode_text(data)))
    if reader.fieldnames and {"ts", "dst_ip"} <= set(reader.fieldnames):
        return parse_flow_csv(reader)
    if not reader.fieldnames or _csv_value(dict.fromkeys(reader.fieldnames, "x"), "event_id") is None:
        raise UploadParseError("CSV needs a header row with an 'Id' or 'event_id' column")

    events = []
    try:
        for row in reader:
            record_id = _csv_value(row, "record_id")
            events.append(
                {
                    "id": str(uuid.uuid4()),
                    "record_id": int(record_id) if record_id else None,
                    "source": "upload",
                    "host": _csv_value(row, "host") or "unknown",
                    "timestamp": _fix_time(_csv_value(row, "timestamp")),
                    "channel": _csv_value(row, "channel") or "",
                    "provider": _csv_value(row, "provider") or "",
                    "event_id": int(_csv_value(row, "event_id")),
                    "user": _csv_value(row, "user"),
                    "process": _csv_value(row, "process"),
                    "command_line": _csv_value(row, "command_line"),
                    "parent_process": _csv_value(row, "parent_process"),
                    "src_ip": _csv_value(row, "src_ip"),
                    "logon_type": _csv_value(row, "logon_type"),
                    "message": _csv_value(row, "message") or "",
                    "raw": json.dumps(row),
                }
            )
    except (TypeError, ValueError, csv.Error):
        raise UploadParseError("CSV row has an invalid or missing event id / record id")
    return events


def _evtx_record_to_raw(xml_text: str) -> dict:
    root = ET.fromstring(xml_text)
    system = root.find("e:System", _EVTX_NS)
    provider = system.find("e:Provider", _EVTX_NS)
    created = system.find("e:TimeCreated", _EVTX_NS)
    # EventData (most events) or UserData (e.g. 1102) holds the positional properties.
    data_nodes = root.findall("e:EventData/e:Data", _EVTX_NS)
    if not data_nodes:
        user_data = root.find("e:UserData", _EVTX_NS)
        data_nodes = list(user_data[0]) if user_data is not None and len(user_data) else []
    return {
        "Id": int(system.findtext("e:EventID", namespaces=_EVTX_NS)),
        "RecordId": system.findtext("e:EventRecordID", namespaces=_EVTX_NS),
        "TimeCreated": created.get("SystemTime") if created is not None else None,
        "LogName": system.findtext("e:Channel", namespaces=_EVTX_NS) or "",
        "ProviderName": provider.get("Name") if provider is not None else "",
        "MachineName": system.findtext("e:Computer", namespaces=_EVTX_NS) or "",
        "Message": "",  # rendered messages are not stored in .evtx files
        "Properties": [node.text for node in data_nodes],
    }


def parse_evtx(path: str) -> list[dict]:
    from Evtx.Evtx import Evtx  # python-evtx

    events = []
    try:
        with Evtx(path) as log:
            for record in log.records():
                raw = _evtx_record_to_raw(record.xml())
                raw["TimeCreated"] = _fix_time(raw["TimeCreated"])
                events.append(normalize_event(raw, host=raw["MachineName"], source="upload"))
                if len(events) > MAX_EVENTS_PER_FILE:
                    break
    except UploadParseError:
        raise
    except Exception:  # python-evtx raises many different errors on corrupt files
        raise UploadParseError("File is not a readable .evtx log")
    return events


def parse_upload(ext: str, data: bytes, path: str) -> list[dict]:
    if ext == ".json":
        events = parse_json(data)
    elif ext == ".csv":
        events = parse_csv(data)
    elif ext == ".evtx":
        events = parse_evtx(path)
    else:
        raise UploadParseError("Unsupported file type")

    if not events:
        raise UploadParseError("No events found in file")
    if len(events) > MAX_EVENTS_PER_FILE:
        raise UploadParseError(f"Too many events (max {MAX_EVENTS_PER_FILE})")
    return events
