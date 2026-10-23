from datetime import datetime, timezone
from typing import Annotated, Literal

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


Role = Literal["admin", "analyst", "viewer"]
# Admin-set passwords: length is the policy (NIST 800-63B style), no composition rules.
Password = Annotated[str, Field(min_length=12, max_length=200)]


class AdminUserOut(BaseModel):
    """Never includes password_hash."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    username: str
    role: str
    is_active: bool
    created_at: UTCDateTime


class AdminUserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$")
    password: Password
    role: Role = "viewer"


class AdminUserUpdate(BaseModel):
    role: Role | None = None
    is_active: bool | None = None


class PasswordReset(BaseModel):
    new_password: Password


class RuleSettingOut(BaseModel):
    id: str
    name: str
    kind: str
    level: str
    severity: int
    technique_ids: list[str]
    enabled: bool
    min_count: int | None
    window_minutes: int | None
    default_min_count: int | None
    default_window_minutes: int | None


class RuleSettingUpdate(BaseModel):
    enabled: bool | None = None
    min_count: int | None = Field(default=None, ge=1, le=1000)
    window_minutes: int | None = Field(default=None, ge=1, le=1440)


class OllamaStatus(BaseModel):
    reachable: bool
    model_installed: bool
    model_loaded: bool


class SystemStatusOut(BaseModel):
    llm_provider: str
    llm_model: str
    ai_calls_per_hour: int
    ai_calls_last_hour: int
    ollama: OllamaStatus | None  # None when the provider isn't ollama
    collector_last_seen: UTCDateTime | None


class SystemSettingsUpdate(BaseModel):
    ai_calls_per_hour: int = Field(ge=1, le=1000)


class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    timestamp: UTCDateTime
    actor: str | None
    action: str
    detail: str | None
    success: bool


class AuditLogPage(BaseModel):
    total: int
    items: list[AuditLogOut]


class EventIn(BaseModel):
    id: str = Field(min_length=1, max_length=64)
    record_id: int | None = None
    source: str = Field(pattern="^(local|upload|agent|simulated)$")
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


class TechniqueCell(BaseModel):
    technique_id: str
    name: str
    hit_count: int
    max_risk_score: float | None  # None = covered by a rule but not seen
    max_risk_level: str | None


class TacticColumn(BaseModel):
    tactic: str
    techniques: list[TechniqueCell]


class AttackMatrixOut(BaseModel):
    tactics: list[TacticColumn]
    hosts: list[str]


class TechniqueRule(BaseModel):
    id: str
    name: str
    severity: int
    confidence: float
    kind: str


class TechniqueDetailOut(TechniqueCell):
    tactic: str
    description: str
    rules: list[TechniqueRule]
    recent_detections: list[DetectionOut]
    mitigations: list[str]


class IncidentOut(BaseModel):
    id: str
    host: str
    started_at: UTCDateTime
    ended_at: UTCDateTime
    risk_score: float
    risk_level: str
    detection_count: int
    status: str = "new"


class IncidentStatusUpdate(BaseModel):
    status: str = Field(pattern="^(new|investigating|contained|closed)$")


class NoteCreate(BaseModel):
    text: str = Field(min_length=1, max_length=2000)


class NoteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    author: str
    text: str
    created_at: UTCDateTime


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
    notes: list[NoteOut] = []


class GraphNode(BaseModel):
    id: str
    type: str  # host | user | detection
    label: str
    rule: str | None = None
    technique: str | None = None
    technique_ids: list[str] = []
    tactic: str | None = None
    risk_score: float | None = None
    risk_level: str | None = None
    first_seen: UTCDateTime | None = None


class GraphEdge(BaseModel):
    source: str
    target: str
    kind: str  # account | start | sequence | same_tactic


class IncidentGraph(BaseModel):
    incident_id: str
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class FindingOut(BaseModel):
    technique_id: str
    claim: str
    event_ids: list[str]


class ActionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    incident_id: str
    incident_host: str
    incident_started_at: UTCDateTime
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


class IOCOut(BaseModel):
    type: str
    value: str
    event_count: int
    event_ids: list[str]


class AttackRow(BaseModel):
    technique_id: str
    name: str
    tactic: str
    rule_names: list[str]
    detection_count: int
    event_ids: list[str]


class ReportAction(BaseModel):
    # Only what the report prints; the incident context is already in the report header.
    model_config = ConfigDict(from_attributes=True)

    id: str
    action_text: str
    status: str
    decided_by: str | None
    decided_at: UTCDateTime | None


class ExecutiveSummary(BaseModel):
    what_happened: list[str]
    impact: str
    top_actions: list[ReportAction]


class ReportOut(BaseModel):
    incident: IncidentDetail
    analysis: AnalysisOut | None
    actions: list[ReportAction]
    attack: list[AttackRow]
    iocs: list[IOCOut]
    executive: ExecutiveSummary
    simulated: bool  # evidence came from the attack simulator, not real activity
    generated_at: UTCDateTime
    generated_by: str


class AskRequest(BaseModel):
    question: str = Field(min_length=1, max_length=500)


class AskResponse(BaseModel):
    answer: str
    mode: str  # deterministic | ai | out_of_scope | fallback
    cited: list[str]
