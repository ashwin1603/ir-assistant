import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base

ROLES = ("admin", "analyst", "viewer")


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username: Mapped[str] = mapped_column(String, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String)
    role: Mapped[str] = mapped_column(String, default="viewer")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # Optional TOTP MFA. mfa_pending_secret holds a secret during enrolment until
    # the user confirms a code; recovery codes are a JSON list of argon2 hashes.
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_secret: Mapped[str | None] = mapped_column(String, nullable=True)
    mfa_pending_secret: Mapped[str | None] = mapped_column(String, nullable=True)
    mfa_last_step: Mapped[int | None] = mapped_column(Integer, nullable=True)  # replay protection
    mfa_recovery_codes: Mapped[str | None] = mapped_column(Text, nullable=True)
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


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    host: Mapped[str] = mapped_column(String, index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    ended_at: Mapped[datetime] = mapped_column(DateTime)
    risk_score: Mapped[float] = mapped_column(Float)
    risk_level: Mapped[str] = mapped_column(String)
    detection_count: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


class Detection(Base):
    __tablename__ = "detections"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id: Mapped[str | None] = mapped_column(String, ForeignKey("incidents.id"), nullable=True, index=True)
    rule_name: Mapped[str] = mapped_column(String, index=True)
    technique_ids: Mapped[str] = mapped_column(Text)  # JSON list[str]
    tactics: Mapped[str] = mapped_column(Text)  # JSON list[str]
    severity: Mapped[int] = mapped_column(Integer)
    confidence: Mapped[float] = mapped_column(Float)
    host: Mapped[str] = mapped_column(String, index=True)
    matched_event_ids: Mapped[str] = mapped_column(Text)  # JSON list[str]
    event_count: Mapped[int] = mapped_column(Integer)
    first_seen: Mapped[datetime] = mapped_column(DateTime, index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime)
    risk_score: Mapped[float] = mapped_column(Float)
    risk_level: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


class Action(Base):
    __tablename__ = "actions"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id: Mapped[str] = mapped_column(String, ForeignKey("incidents.id"), index=True)
    analysis_id: Mapped[str] = mapped_column(String, ForeignKey("ai_analyses.id"), index=True)
    action_text: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String, default="pending", index=True)  # pending | approved | rejected
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    decided_by: Mapped[str | None] = mapped_column(String, nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class AIAnalysis(Base):
    __tablename__ = "ai_analyses"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id: Mapped[str] = mapped_column(String, ForeignKey("incidents.id"), index=True)
    detections_hash: Mapped[str] = mapped_column(String, index=True)  # cache key: sha256 of this incident's detection ids
    provider: Mapped[str] = mapped_column(String)
    degraded: Mapped[bool] = mapped_column(Boolean, default=False)
    verdict: Mapped[str] = mapped_column(String)
    confidence: Mapped[float] = mapped_column(Float)
    reasoning: Mapped[str] = mapped_column(Text)
    narrative: Mapped[str] = mapped_column(Text)
    risk_explanation: Mapped[str] = mapped_column(Text)
    findings: Mapped[str] = mapped_column(Text)  # JSON list[{technique_id, claim, event_ids}]
    recommended_actions: Mapped[str] = mapped_column(Text)  # JSON list[str]
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


INCIDENT_STATUSES = ("new", "investigating", "contained", "closed")


class IncidentCase(Base):
    """Analyst-owned state for an incident. Incident ids are hash-derived and
    change whenever detections are regrouped, so this is keyed by
    case_key = "host|started_at" instead, which survives regrouping."""

    __tablename__ = "incident_cases"

    case_key: Mapped[str] = mapped_column(String, primary_key=True)
    status: Mapped[str] = mapped_column(String, default="new")
    updated_by: Mapped[str | None] = mapped_column(String, nullable=True)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class IncidentNote(Base):
    """Append-only analyst notes (never edited or deleted, for an audit trail)."""

    __tablename__ = "incident_notes"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_key: Mapped[str] = mapped_column(String, index=True)
    author: Mapped[str] = mapped_column(String)
    text: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


class RuleOverride(Base):
    """Admin overrides for a YAML rule (keyed by the rule's YAML id). Applied by
    the detection engine on its next run; a missing row means "use the YAML"."""

    __tablename__ = "rule_overrides"

    rule_id: Mapped[str] = mapped_column(String, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    min_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    window_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    updated_by: Mapped[str | None] = mapped_column(String, nullable=True)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class AppSetting(Base):
    """Admin-editable runtime settings (key/value). Falls back to config.py defaults."""

    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String, primary_key=True)
    value: Mapped[str] = mapped_column(String)


class ThreatIndicator(Base):
    """Local threat-intel indicator (admin-imported). Values are stored normalised
    (lower-case, canonical IP) so matching is a simple exact lookup."""

    __tablename__ = "ti_indicators"
    __table_args__ = (UniqueConstraint("type", "value", name="uq_ti_type_value"),)

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    type: Mapped[str] = mapped_column(String, index=True)  # ip | domain | sha256
    value: Mapped[str] = mapped_column(String, index=True)
    source: Mapped[str] = mapped_column(String)
    tags: Mapped[str] = mapped_column(String, default="")  # comma-separated
    added_by: Mapped[str | None] = mapped_column(String, nullable=True)
    added_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
