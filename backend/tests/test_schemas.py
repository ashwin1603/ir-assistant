from datetime import datetime

from app.schemas import AuditLogOut


def test_naive_datetime_from_sqlite_serializes_with_utc_offset():
    """SQLite drops tzinfo on round-trip (see app.schemas._as_utc), so a value
    read back from the DB is a naive datetime that actually represents UTC. If
    it were serialized without an offset, the browser's `new Date(...)` would
    parse it as local time instead of UTC, double-shifting the displayed time."""
    naive_utc = datetime(2026, 10, 21, 5, 0, 0)

    out = AuditLogOut(id="1", timestamp=naive_utc, actor="x", action="login", detail=None, success=True)
    serialized = out.model_dump_json()

    assert "+00:00" in serialized or "Z" in serialized
