from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.config import settings

connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


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
        for name, ddl in new_event_columns.items():
            if name not in event_columns:
                conn.execute(text(ddl))
        for ddl in missing_other:
            conn.execute(text(ddl))
