from datetime import datetime, timezone
from typing import Annotated

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field


def _as_utc(value: datetime) -> datetime:
    """SQLite drops tzinfo on round-trip, so values read back from the DB are
    naive but represent UTC. Stamp UTC back on before serializing, otherwise
    the JSON timestamp has no offset and browsers parse it as local time
    instead of UTC, double-shifting it when the UI converts to local time."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


UTCDateTime = Annotated[datetime, BeforeValidator(_as_utc)]


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=200)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str


class UserOut(BaseModel):
    username: str
    role: str


class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    timestamp: UTCDateTime
    actor: str | None
    action: str
    detail: str | None
    success: bool


class EventIn(BaseModel):
    id: str = Field(min_length=1, max_length=64)
    record_id: int | None = None
    source: str = Field(pattern="^(local|upload|agent)$")
    host: str = Field(min_length=1, max_length=255)
    timestamp: datetime
    channel: str = Field(min_length=1, max_length=255)
    provider: str = Field(max_length=255)
    event_id: int
    user: str | None = Field(default=None, max_length=255)
    process: str | None = Field(default=None, max_length=512)
    command_line: str | None = Field(default=None, max_length=50000)
    parent_process: str | None = Field(default=None, max_length=512)
    src_ip: str | None = Field(default=None, max_length=64)
    logon_type: str | None = Field(default=None, max_length=32)
    message: str | None = Field(default=None, max_length=50000)
    raw: str = Field(max_length=100000)


class EventIngestRequest(BaseModel):
    events: list[EventIn] = Field(min_length=1, max_length=1000)


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    source: str
    host: str
    timestamp: UTCDateTime
    channel: str
    provider: str
    event_id: int
    user: str | None
    process: str | None
    command_line: str | None
    parent_process: str | None
    src_ip: str | None
    logon_type: str | None
    message: str | None


class EventPage(BaseModel):
    total: int
    items: list[EventOut]


class DetectionOut(BaseModel):
    id: str
    incident_id: str | None
    rule_name: str
    technique_ids: list[str]
    tactics: list[str]
    severity: int
    confidence: float
    host: str
    event_count: int
    matched_event_ids: list[str]
    first_seen: UTCDateTime
    last_seen: UTCDateTime
    risk_score: float
    risk_level: str


class IncidentOut(BaseModel):
    id: str
    host: str
    started_at: UTCDateTime
    ended_at: UTCDateTime
    risk_score: float
    risk_level: str
    detection_count: int


class TimelineEntry(BaseModel):
    detection_id: str
    rule_name: str
    technique_ids: list[str]
    tactics: list[str]
    severity: int
    confidence: float
    risk_score: float
    risk_level: str
    first_seen: UTCDateTime
    last_seen: UTCDateTime
    event_ids: list[str]


class IncidentDetail(IncidentOut):
    timeline: list[TimelineEntry]


class FindingOut(BaseModel):
    technique_id: str
    claim: str
    event_ids: list[str]


class ActionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    incident_id: str
    analysis_id: str
    action_text: str
    status: str
    created_at: UTCDateTime
    decided_by: str | None
    decided_at: UTCDateTime | None


class AnalysisOut(BaseModel):
    incident_id: str
    provider: str
    degraded: bool
    verdict: str
    confidence: float
    reasoning: str
    narrative: str
    risk_explanation: str
    findings: list[FindingOut]
    recommended_actions: list[str]
    created_at: UTCDateTime
