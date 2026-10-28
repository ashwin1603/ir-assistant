import logging
import time

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import settings

logger = logging.getLogger("ir_assistant")

IS_SQLITE = settings.database_url.startswith("sqlite")
BUSY_TIMEOUT_SECONDS = 15
# timeout: how long the driver waits for a lock before "database is locked".
connect_args = {"check_same_thread": False, "timeout": BUSY_TIMEOUT_SECONDS} if IS_SQLITE else {}
engine = create_engine(settings.database_url, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def set_sqlite_pragmas(dbapi_connection, _record) -> None:
    """WAL lets readers and the (single) writer run at the same time instead of blocking
    each other; busy_timeout makes a blocked writer wait instead of failing at once;
    synchronous=NORMAL is the recommended (still crash-safe) setting for WAL."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_SECONDS * 1000}")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()


if IS_SQLITE:
    event.listen(engine, "connect", set_sqlite_pragmas)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def add_missing_columns() -> None:
    """create_all() never alters existing tables, so columns added after a DB
    was created are added here. Fixed DDL strings only - no user input."""
    columns = {c["name"] for c in inspect(engine).get_columns("users")}
    new_columns = {
        "is_active": "ALTER TABLE users ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT 1",
        # Existing users start with MFA off.
        "mfa_enabled": "ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN NOT NULL DEFAULT 0",
        "mfa_secret": "ALTER TABLE users ADD COLUMN mfa_secret VARCHAR",
        "mfa_pending_secret": "ALTER TABLE users ADD COLUMN mfa_pending_secret VARCHAR",
        "mfa_last_step": "ALTER TABLE users ADD COLUMN mfa_last_step INTEGER",
        "mfa_recovery_codes": "ALTER TABLE users ADD COLUMN mfa_recovery_codes TEXT",
        "step_up_at": "ALTER TABLE users ADD COLUMN step_up_at DATETIME",
    }
    audit_columns = {c["name"] for c in inspect(engine).get_columns("audit_log")}
    missing_audit = {
        "previous_hash": "ALTER TABLE audit_log ADD COLUMN previous_hash VARCHAR NOT NULL DEFAULT ''",
        "entry_hash": "ALTER TABLE audit_log ADD COLUMN entry_hash VARCHAR NOT NULL DEFAULT ''",
    }
    event_columns = {c["name"] for c in inspect(engine).get_columns("events")}
    new_event_columns = {
        "dst_ip": "ALTER TABLE events ADD COLUMN dst_ip VARCHAR",
        "dst_port": "ALTER TABLE events ADD COLUMN dst_port INTEGER",
        "protocol": "ALTER TABLE events ADD COLUMN protocol VARCHAR",
        "bytes_out": "ALTER TABLE events ADD COLUMN bytes_out INTEGER",
    }
    other_columns = {
        ("detections", "summary"): "ALTER TABLE detections ADD COLUMN summary TEXT",
        ("rule_overrides", "params"): "ALTER TABLE rule_overrides ADD COLUMN params TEXT",
    }
    missing_other = [ddl for (table, name), ddl in other_columns.items()
                     if name not in {c["name"] for c in inspect(engine).get_columns(table)}]
    with engine.begin() as conn:
        for name, ddl in new_columns.items():
            if name not in columns:
                conn.execute(text(ddl))
        for name, ddl in missing_audit.items():
            if name not in audit_columns:
                conn.execute(text(ddl))
        for name, ddl in new_event_columns.items():
            if name not in event_columns:
                conn.execute(text(ddl))
        for ddl in missing_other:
            conn.execute(text(ddl))


# Columns the detection engine and the event/device queries filter or sort on.
# create_all() only indexes tables it creates, so older DBs get them here.
# Fixed DDL strings only - no user input.
INDEXES = {
    "ix_events_host": "CREATE INDEX IF NOT EXISTS ix_events_host ON events (host)",
    "ix_events_event_id": "CREATE INDEX IF NOT EXISTS ix_events_event_id ON events (event_id)",
    "ix_events_channel": "CREATE INDEX IF NOT EXISTS ix_events_channel ON events (channel)",
    "ix_events_timestamp": "CREATE INDEX IF NOT EXISTS ix_events_timestamp ON events (timestamp)",
    "ix_events_source": "CREATE INDEX IF NOT EXISTS ix_events_source ON events (source)",
    "ix_events_created_at": "CREATE INDEX IF NOT EXISTS ix_events_created_at ON events (created_at)",
    "ix_detections_incident_id": "CREATE INDEX IF NOT EXISTS ix_detections_incident_id ON detections (incident_id)",
}


def ensure_indexes() -> None:
    with engine.begin() as conn:
        for ddl in INDEXES.values():
            conn.execute(text(ddl))


def is_lock_error(exc: Exception) -> bool:
    return isinstance(exc, OperationalError) and "locked" in str(exc).lower()


def retry_on_lock(db: Session, fn, attempts: int = 4, delay: float = 0.25):
    """Run fn() (which must do its own adds + commit); if SQLite still reports
    "database is locked" after busy_timeout, roll back and retry with backoff."""
    for attempt in range(attempts):
        try:
            return fn()
        except OperationalError as exc:
            if not is_lock_error(exc) or attempt == attempts - 1:
                raise
            db.rollback()
            logger.warning("database locked, retry %d/%d", attempt + 1, attempts - 1)
            time.sleep(delay * 2**attempt)
