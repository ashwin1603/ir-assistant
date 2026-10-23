"""Admin-only Settings: user management, detection rule overrides, threat intel, system status.
Every route requires the admin role (enforced here, not just in the UI) and
every change is written to the audit log."""

from datetime import datetime, timedelta, timezone
from pathlib import PurePath

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.ai.client import ollama_status
from app.audit import log_action
from app.auth.deps import require_role
from app.auth.routes import clear_mfa
from app.auth.security import hash_password
from app.config import settings
from app.db import get_db
from app.detection import custom_rules
from app.detection.custom_rules import CustomRuleError
from app.detection.rules import RULES
from app.detection.sigma_import import MAX_BYTES, SigmaImportError, import_sigma
from app.detection.threat_intel import MAX_IMPORT_BYTES, import_indicators, parse_import
from app.models import AuditLog, RuleOverride, ThreatIndicator, User
from app.runtime_settings import get_ai_calls_per_hour, set_ai_calls_per_hour
from app.schemas import (
    AdminUserCreate,
    CustomRuleIn,
    RuleTestResult,
    AdminUserOut,
    AdminUserUpdate,
    PasswordReset,
    RuleSettingOut,
    RuleSettingUpdate,
    SigmaImport,
    SystemSettingsUpdate,
    SystemStatusOut,
    TIImportResult,
    TIIndicatorOut,
)

router = APIRouter(prefix="/api/settings", tags=["settings"])

require_admin = require_role("admin")


# ---------- Users ----------


def _get_user_or_404(db: Session, user_id: str) -> User:
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


@router.get("/users", response_model=list[AdminUserOut])
def list_users(db: Session = Depends(get_db), _admin: User = Depends(require_admin)):
    return db.query(User).order_by(User.username).all()


@router.post("/users", response_model=AdminUserOut, status_code=201)
def create_user(body: AdminUserCreate, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    if db.query(User).filter(User.username == body.username).first():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists")
    user = User(username=body.username, password_hash=hash_password(body.password), role=body.role)
    db.add(user)
    db.flush()
    log_action(db, actor=admin.username, action="user_create", detail=f"user={user.username} role={user.role}")
    return user


@router.patch("/users/{user_id}", response_model=AdminUserOut)
def update_user(user_id: str, body: AdminUserUpdate, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    user = _get_user_or_404(db, user_id)
    new_role = body.role if body.role is not None else user.role
    new_active = body.is_active if body.is_active is not None else user.is_active

    # Never leave the system with no active admin (demoting or disabling the last one).
    loses_admin = user.role == "admin" and user.is_active and (new_role != "admin" or not new_active)
    if loses_admin:
        other_admins = db.query(User).filter(User.role == "admin", User.is_active.is_(True), User.id != user.id).count()
        if other_admins == 0:
            log_action(db, actor=admin.username, action="user_update", detail=f"user={user.username} blocked: last admin", success=False)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot demote or disable the last active admin")

    changes = []
    if new_role != user.role:
        changes.append(f"role {user.role} -> {new_role}")
    if new_active != user.is_active:
        changes.append("enabled" if new_active else "disabled")
    user.role, user.is_active = new_role, new_active
    if changes:
        log_action(db, actor=admin.username, action="user_update", detail=f"user={user.username} {', '.join(changes)}")
    return user


@router.post("/users/{user_id}/reset-password", status_code=204)
def reset_password(user_id: str, body: PasswordReset, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    user = _get_user_or_404(db, user_id)
    user.password_hash = hash_password(body.new_password)
    log_action(db, actor=admin.username, action="user_password_reset", detail=f"user={user.username}")


@router.post("/users/{user_id}/reset-mfa", status_code=204)
def reset_mfa(user_id: str, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    """For a user who lost their authenticator and recovery codes."""
    user = _get_user_or_404(db, user_id)
    clear_mfa(user)
    log_action(db, actor=admin.username, action="mfa_reset", detail=f"user={user.username}")


# ---------- Detection rules ----------


def _rule_out(rule, override: RuleOverride | None) -> RuleSettingOut:
    is_cluster = rule.kind == "cluster"
    return RuleSettingOut(
        id=rule.id,
        name=rule.name,
        kind=rule.kind,
        level=rule.level,
        severity=rule.severity,
        technique_ids=list(rule.technique_ids),
        enabled=override.enabled if override else rule.enabled_by_default,
        min_count=(override and override.min_count or rule.min_count) if is_cluster else None,
        window_minutes=(override and override.window_minutes or rule.window_minutes) if is_cluster else None,
        default_min_count=rule.min_count,
        default_window_minutes=rule.window_minutes,
        source=rule.source,
    )


@router.get("/rules", response_model=list[RuleSettingOut])
def list_rules(db: Session = Depends(get_db), _admin: User = Depends(require_admin)):
    overrides = {o.rule_id: o for o in db.query(RuleOverride).all()}
    return [_rule_out(r, overrides.get(r.id)) for r in RULES]


@router.patch("/rules/{rule_id}", response_model=RuleSettingOut)
def update_rule(rule_id: str, body: RuleSettingUpdate, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    rule = next((r for r in RULES if r.id == rule_id), None)
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    if rule.kind != "cluster" and (body.min_count is not None or body.window_minutes is not None):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Thresholds apply only to cluster rules")

    override = db.get(RuleOverride, rule_id) or RuleOverride(rule_id=rule_id, enabled=True)
    changes = []
    if body.enabled is not None and body.enabled != override.enabled:
        override.enabled = body.enabled
        changes.append("enabled" if body.enabled else "disabled")
    if body.min_count is not None:
        override.min_count = body.min_count
        changes.append(f"min_count={body.min_count}")
    if body.window_minutes is not None:
        override.window_minutes = body.window_minutes
        changes.append(f"window_minutes={body.window_minutes}")
    override.updated_by = admin.username
    override.updated_at = datetime.now(timezone.utc)
    db.add(override)
    log_action(db, actor=admin.username, action="rule_update", detail=f"rule={rule.name} {', '.join(changes) or 'no change'}")
    return _rule_out(rule, override)


@router.post("/rules/import-sigma", response_model=RuleSettingOut, status_code=201)
def import_sigma_rule(body: SigmaImport, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    if len(body.yaml.encode("utf-8")) > MAX_BYTES:
        log_action(db, actor=admin.username, action="sigma_import", detail="rejected: too large", success=False)
        raise HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail="Rule too large (max 50 KB)")
    try:
        rule = import_sigma(body.yaml)
    except SigmaImportError as e:
        log_action(db, actor=admin.username, action="sigma_import", detail=f"rejected: {e}"[:500], success=False)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    log_action(db, actor=admin.username, action="sigma_import", detail=f"rule={rule.name} id={rule.id} (disabled)")
    return _rule_out(rule, None)


# ---------- Custom rule editor ----------


def _custom_rule_or_error(rule_id: str):
    rule = custom_rules.find_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    if rule.source != "custom":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Built-in and imported rules are read-only; clone them instead")
    return rule


@router.get("/rules/{rule_id}/form", response_model=CustomRuleIn)
def rule_form(rule_id: str, _admin: User = Depends(require_admin)):
    """The editor form for a rule: to edit a custom rule, or as the starting point for a clone."""
    rule = custom_rules.find_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    try:
        return custom_rules.rule_to_form(rule)
    except CustomRuleError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/rules/custom", response_model=RuleSettingOut, status_code=201)
def create_custom_rule(body: CustomRuleIn, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    try:
        rule = custom_rules.create(body)
    except CustomRuleError as e:
        log_action(db, actor=admin.username, action="custom_rule_create", detail=f"rejected: {e}"[:500], success=False)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    log_action(db, actor=admin.username, action="custom_rule_create", detail=f"rule={rule.name} id={rule.id} (disabled)")
    return _rule_out(rule, None)


@router.put("/rules/custom/{rule_id}", response_model=RuleSettingOut)
def update_custom_rule(rule_id: str, body: CustomRuleIn, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    _custom_rule_or_error(rule_id)
    try:
        rule = custom_rules.update(rule_id, body)
    except CustomRuleError as e:
        log_action(db, actor=admin.username, action="custom_rule_edit", detail=f"id={rule_id} rejected: {e}"[:500], success=False)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    log_action(db, actor=admin.username, action="custom_rule_edit", detail=f"rule={rule.name} id={rule.id}")
    return _rule_out(rule, db.get(RuleOverride, rule.id))


@router.delete("/rules/custom/{rule_id}", status_code=204)
def delete_custom_rule(rule_id: str, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    rule = _custom_rule_or_error(rule_id)
    custom_rules.delete(rule_id)
    override = db.get(RuleOverride, rule_id)
    if override:
        db.delete(override)
    log_action(db, actor=admin.username, action="custom_rule_delete", detail=f"rule={rule.name} id={rule_id}")


@router.post("/rules/custom/test", response_model=RuleTestResult)
def test_custom_rule(body: CustomRuleIn, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    """Dry run against stored events: never saves the rule, never creates detections."""
    try:
        result = custom_rules.dry_run(db, body)
    except CustomRuleError as e:
        log_action(db, actor=admin.username, action="custom_rule_test", detail=f"rejected: {e}"[:500], success=False)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    log_action(db, actor=admin.username, action="custom_rule_test", detail=f"title={body.title} matches={result['match_count']}"[:500])
    return result


# ---------- Threat intel ----------

TI_EXTENSIONS = {".csv", ".txt"}
TI_LIST_LIMIT = 500


@router.get("/ti", response_model=list[TIIndicatorOut])
def list_indicators(
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
    q: str | None = Query(default=None, max_length=200),
    type: str | None = Query(default=None, pattern="^(ip|domain|sha256)$"),
):
    query = db.query(ThreatIndicator)
    if type:
        query = query.filter(ThreatIndicator.type == type)
    if q:
        like = f"%{q.strip().lower()}%"
        query = query.filter(or_(ThreatIndicator.value.like(like), ThreatIndicator.source.like(like), ThreatIndicator.tags.like(like)))
    return query.order_by(ThreatIndicator.type, ThreatIndicator.value).limit(TI_LIST_LIMIT).all()


@router.post("/ti/import", response_model=TIImportResult, status_code=201)
def import_ti(file: UploadFile = File(...), db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    name = PurePath((file.filename or "").replace("\\", "/")).name[:255]

    def reject(code: int, message: str):
        log_action(db, actor=admin.username, action="ti_import", detail=f"file={name} rejected: {message}", success=False)
        raise HTTPException(status_code=code, detail=message)

    if PurePath(name).suffix.lower() not in TI_EXTENSIONS:
        reject(400, "Unsupported file type. Allowed: .csv, .txt")
    data = file.file.read(MAX_IMPORT_BYTES + 1)  # read one byte past the limit to detect oversize
    if len(data) > MAX_IMPORT_BYTES:
        reject(413, "File too large (max 1 MB)")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        reject(400, "File must be UTF-8 text")

    rows, errors = parse_import(text)
    added, duplicates = import_indicators(db, rows, added_by=admin.username)
    log_action(db, actor=admin.username, action="ti_import", detail=f"file={name} added={added} duplicates={duplicates} errors={len(errors)}")
    return TIImportResult(added=added, duplicates=duplicates, errors=errors)


@router.delete("/ti/{indicator_id}", status_code=204)
def delete_indicator(indicator_id: str, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    indicator = db.get(ThreatIndicator, indicator_id)
    if not indicator:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Indicator not found")
    db.delete(indicator)
    log_action(db, actor=admin.username, action="ti_delete", detail=f"{indicator.type}={indicator.value} source={indicator.source}")


# ---------- System ----------


@router.get("/system", response_model=SystemStatusOut)
def system_status(db: Session = Depends(get_db), _admin: User = Depends(require_admin)):
    since = datetime.now(timezone.utc) - timedelta(hours=1)
    calls_last_hour = db.query(AuditLog).filter(AuditLog.action == "ai_analyze", AuditLog.timestamp >= since).count()
    last_ingest = (
        db.query(AuditLog)
        .filter(AuditLog.actor == "collector", AuditLog.action == "ingest")
        .order_by(AuditLog.timestamp.desc())
        .first()
    )
    return SystemStatusOut(
        llm_provider=settings.llm_provider,
        llm_model=settings.llm_model,
        ai_calls_per_hour=get_ai_calls_per_hour(db),
        ai_calls_last_hour=calls_last_hour,
        ollama=ollama_status() if settings.llm_provider == "ollama" else None,
        collector_last_seen=last_ingest.timestamp if last_ingest else None,
    )


@router.put("/system", status_code=204)
def update_system(body: SystemSettingsUpdate, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    old = get_ai_calls_per_hour(db)
    set_ai_calls_per_hour(db, body.ai_calls_per_hour)
    log_action(db, actor=admin.username, action="system_update", detail=f"ai_calls_per_hour {old} -> {body.ai_calls_per_hour}")
