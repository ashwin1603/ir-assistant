import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base

ROLES = ("admin", "analyst", "viewer")


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username: Mapped[str] = mapped_column(String, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String)
    role: Mapped[str] = mapped_column(String, default="viewer")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    actor: Mapped[str | None] = mapped_column(String, nullable=True)
    action: Mapped[str] = mapped_column(String)
    detail: Mapped[str | None] = mapped_column(String, nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, default=True)


class Event(Base):
    __tablename__ = "events"
    __table_args__ = (Index("ix_events_dedup", "record_id", "host", "channel"),)

    id: Mapped[str] = mapped_column(String, primary_key=True)
    record_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    source: Mapped[str] = mapped_column(String, index=True)
    host: Mapped[str] = mapped_column(String, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True)
    channel: Mapped[str] = mapped_column(String, index=True)
    provider: Mapped[str] = mapped_column(String)
    event_id: Mapped[int] = mapped_column(Integer, index=True)
    user: Mapped[str | None] = mapped_column(String, nullable=True)
    process: Mapped[str | None] = mapped_column(String, nullable=True)
    command_line: Mapped[str | None] = mapped_column(Text, nullable=True)
    parent_process: Mapped[str | None] = mapped_column(String, nullable=True)
    src_ip: Mapped[str | None] = mapped_column(String, nullable=True)
    logon_type: Mapped[str | None] = mapped_column(String, nullable=True)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
