"""Role-based access control: the ONE place that says who may do what.

PERMISSIONS maps an action to the roles allowed to perform it.
ROUTE_PERMISSIONS maps every API route (method, path) to exactly one action.
`authorize` runs before every route (it is an app-level dependency in main.py):
it looks the route up, authenticates the caller and checks the role. A route
that is missing from ROUTE_PERMISSIONS is denied (deny by default), and
tests/test_permissions_matrix.py fails if any route is missing.

Least privilege:
  viewer  - read dashboards, detections, incidents, network, ATT&CK, anomalies; ask the incident chat.
            Command lines are redacted server-side (see app/auth/redaction.py).
  analyst - viewer + full command lines, uploads, AI analysis/investigation,
            incident status/notes, approve/reject actions, IOC and script downloads.
  admin   - analyst + users, rules, Sigma import, threat intel, settings, audit log.
"""

import jwt
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.audit import log_action
from app.auth.security import decode_access_token, decode_mfa_setup_token
from app.config import settings
from app.db import get_db
from app.models import User

VIEWER = frozenset({"viewer", "analyst", "admin"})
ANALYST = frozenset({"analyst", "admin"})
ADMIN = frozenset({"admin"})

PERMISSIONS: dict[str, frozenset[str]] = {
    "account": VIEWER,  # own profile, own MFA, step-up re-authentication
    "read": VIEWER,  # dashboards, events, detections, incidents, network, ATT&CK, anomalies, devices, reports
    "chat": VIEWER,  # ask-the-incident chat
    "view_command_lines": ANALYST,  # not a route: checked by app/auth/redaction.py
    "upload": ANALYST,
    "run_ai": ANALYST,  # AI analysis and investigation
    "update_incident": ANALYST,  # status and notes
    "decide_actions": ANALYST,  # approve / reject recommended actions
    "download_artifacts": ANALYST,  # IOC CSV/JSON and response scripts
    "manage_users": ADMIN,
    "manage_rules": ADMIN,
    "import_sigma": ADMIN,
    "manage_threat_intel": ADMIN,
    "manage_settings": ADMIN,
    "read_audit": ADMIN,
}

# Route actions that are not role checks.
PUBLIC = "public"  # no authentication
COLLECTOR = "collector"  # X-Collector-Key header, never a user token
MFA_ENROLMENT = "mfa_enrolment"  # a normal access token, or the setup token from a forced-MFA login

ROUTE_PERMISSIONS: dict[tuple[str, str], str] = {
    ("GET", "/api/health"): PUBLIC,
    ("POST", "/api/auth/login"): PUBLIC,
    ("POST", "/api/auth/mfa/verify"): PUBLIC,  # needs the short-lived mfa_token in the body
    ("GET", "/api/auth/me"): "account",
    ("GET", "/api/auth/mfa"): "account",
    ("POST", "/api/auth/mfa/setup"): MFA_ENROLMENT,
    ("POST", "/api/auth/mfa/enable"): MFA_ENROLMENT,
    ("POST", "/api/auth/mfa/disable"): "account",
    ("POST", "/api/auth/step-up"): "account",
    ("POST", "/api/events/ingest"): COLLECTOR,
    ("DELETE", "/api/events/simulated"): COLLECTOR,
    ("POST", "/api/devices/heartbeat"): COLLECTOR,
    ("GET", "/api/events"): "read",
    ("GET", "/api/events/export"): "read",  # CSV of the current view; viewers get the redacted fields
    ("GET", "/api/devices"): "read",
    ("GET", "/api/detections"): "read",
    ("GET", "/api/detections/export"): "read",
    ("GET", "/api/anomalies"): "read",
    ("GET", "/api/network/summary"): "read",
    ("GET", "/api/attack/matrix"): "read",
    ("GET", "/api/attack/techniques/{technique_id}"): "read",
    ("GET", "/api/incidents"): "read",
    ("GET", "/api/incidents/{incident_id}"): "read",
    ("GET", "/api/incidents/{incident_id}/graph"): "read",
    ("GET", "/api/incidents/{incident_id}/investigate"): "read",
    ("GET", "/api/incidents/{incident_id}/report"): "read",
    ("GET", "/api/actions"): "read",
    ("POST", "/api/incidents/{incident_id}/ask"): "chat",
    ("PUT", "/api/incidents/{incident_id}/status"): "update_incident",
    ("POST", "/api/incidents/{incident_id}/notes"): "update_incident",
    ("POST", "/api/incidents/{incident_id}/analyze"): "run_ai",
    ("POST", "/api/incidents/{incident_id}/investigate"): "run_ai",
    ("GET", "/api/incidents/{incident_id}/iocs"): "download_artifacts",
    ("GET", "/api/incidents/{incident_id}/scripts/{kind}"): "download_artifacts",
    ("POST", "/api/actions/{action_id}/approve"): "decide_actions",
    ("POST", "/api/actions/{action_id}/reject"): "decide_actions",
    ("POST", "/api/uploads"): "upload",
    ("GET", "/api/settings/users"): "manage_users",
    ("POST", "/api/settings/users"): "manage_users",
    ("PATCH", "/api/settings/users/{user_id}"): "manage_users",
    ("POST", "/api/settings/users/{user_id}/reset-password"): "manage_users",
    ("POST", "/api/settings/users/{user_id}/reset-mfa"): "manage_users",
    ("GET", "/api/settings/rules"): "manage_rules",
    ("PATCH", "/api/settings/rules/{rule_id}"): "manage_rules",
    ("GET", "/api/settings/rules/{rule_id}/form"): "manage_rules",
    ("POST", "/api/settings/rules/custom"): "manage_rules",
    ("PUT", "/api/settings/rules/custom/{rule_id}"): "manage_rules",
    ("DELETE", "/api/settings/rules/custom/{rule_id}"): "manage_rules",
    ("POST", "/api/settings/rules/custom/test"): "manage_rules",
    ("POST", "/api/settings/rules/import-sigma"): "import_sigma",
    ("GET", "/api/settings/ti"): "manage_threat_intel",
    ("POST", "/api/settings/ti/import"): "manage_threat_intel",
    ("DELETE", "/api/settings/ti/{indicator_id}"): "manage_threat_intel",
    ("GET", "/api/settings/system"): "manage_settings",
    ("PUT", "/api/settings/system"): "manage_settings",
    ("GET", "/api/audit"): "read_audit",
}

CREDENTIALS_ERROR = "Could not validate credentials"


def can(user: User, action: str) -> bool:
    return user.role in PERMISSIONS.get(action, frozenset())


def allowed_actions(role: str) -> list[str]:
    return sorted(action for action, roles in PERMISSIONS.items() if role in roles)


def _unauthorized() -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=CREDENTIALS_ERROR)


def _bearer_token(request: Request) -> str | None:
    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    return token if scheme.lower() == "bearer" and token else None


def _load_user(db: Session, username: str | None) -> User:
    user = db.query(User).filter(User.username == username).first() if username else None
    if not user or not user.is_active:
        raise _unauthorized()
    return user


def deny(db: Session, user: User, request: Request, reason: str = "forbidden", detail: str = "Not authorized") -> HTTPException:
    """Audit-log a 403 (actor and route only, never the body) and return the exception to raise."""
    route = request.scope.get("route")
    path = getattr(route, "path", request.url.path)
    log_action(db, actor=user.username, action="access_denied", detail=f"{request.method} {path} ({reason})", success=False)
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


def authorize(request: Request, db: Session = Depends(get_db)) -> None:
    route = request.scope.get("route")
    method = "GET" if request.method == "HEAD" else request.method
    action = ROUTE_PERMISSIONS.get((method, getattr(route, "path", "")))

    if action == PUBLIC:
        return
    if action == COLLECTOR:
        key = request.headers.get("X-Collector-Key")
        if not key or key != settings.collector_api_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid collector key")
        return

    token = _bearer_token(request)
    if not token:
        raise _unauthorized()
    try:
        payload = decode_access_token(token)
    except jwt.PyJWTError:
        if action != MFA_ENROLMENT:
            raise _unauthorized()
        try:
            payload = decode_mfa_setup_token(token)
        except jwt.PyJWTError:
            raise _unauthorized()
        request.state.mfa_setup_only = True
    user = _load_user(db, payload.get("sub"))
    request.state.user = user

    if action is None:
        raise deny(db, user, request, "route not in permission table")
    if action != MFA_ENROLMENT and not can(user, action):
        raise deny(db, user, request)


def current_user(request: Request, _auth: None = Depends(authorize)) -> User:
    """The user that `authorize` authenticated for this request (it runs once; FastAPI caches it)."""
    user = getattr(request.state, "user", None)
    if user is None:
        raise _unauthorized()
    return user

