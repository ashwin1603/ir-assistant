import json
from datetime import datetime, timezone

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.audit import log_action
from app.auth import totp
from app.auth.permissions import allowed_actions, current_user
from app.auth.security import (
    create_access_token,
    create_mfa_setup_token,
    create_mfa_token,
    decode_mfa_token,
    hash_password,
    verify_password,
)
from app.db import get_db
from app.models import User
from app.rate_limit import limiter
from app.runtime_settings import get_require_admin_mfa
from app.schemas import (
    LoginRequest,
    LoginResponse,
    MfaDisableRequest,
    MfaEnableOut,
    MfaEnableRequest,
    MfaSetupOut,
    MfaStatusOut,
    MfaVerifyRequest,
    StepUpRequest,
    TokenResponse,
    UserOut,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])

GENERIC_AUTH_ERROR = "Invalid username or password"
GENERIC_MFA_ERROR = "Invalid or expired code"


@router.post("/login", response_model=LoginResponse, response_model_exclude_none=True)
@limiter.limit("5/minute")
def login(request: Request, payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()
    # Disabled accounts get the same generic error (no account-state enumeration).
    if not user or not verify_password(payload.password, user.password_hash) or not user.is_active:
        log_action(db, actor=payload.username, action="login", success=False)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=GENERIC_AUTH_ERROR)

    if user.mfa_enabled:
        # Password is right but no access token yet: only /auth/mfa/verify accepts this token.
        log_action(db, actor=user.username, action="mfa_challenge")
        return LoginResponse(mfa_required=True, mfa_token=create_mfa_token(user.username))

    if user.role == "admin" and get_require_admin_mfa(db):
        # No access token until MFA is set up; the setup token only works for MFA enrolment.
        log_action(db, actor=user.username, action="mfa_setup_forced")
        return LoginResponse(mfa_setup_required=True, mfa_token=create_mfa_setup_token(user.username))

    token = create_access_token(subject=user.username, role=user.role)
    log_action(db, actor=user.username, action="login", success=True)
    return LoginResponse(access_token=token, role=user.role)


@router.get("/me", response_model=UserOut)
def me(current_user: User = Depends(current_user)):
    return UserOut(username=current_user.username, role=current_user.role, permissions=allowed_actions(current_user.role))


# ---------- MFA ----------


def _check_second_factor(db: Session, user: User, code: str) -> str | None:
    """Accept a TOTP code or an unused recovery code. Returns "totp", "recovery" or None.
    Marks the code as used, so neither kind can be replayed."""
    code = code.strip()
    if code.isdigit():
        step = totp.verify_totp(user.mfa_secret, code, user.mfa_last_step)
        if step is None:
            return None
        user.mfa_last_step = step
        return "totp"

    hashes = json.loads(user.mfa_recovery_codes or "[]")
    for h in hashes:
        if verify_password(code.lower(), h):
            hashes.remove(h)  # single use
            user.mfa_recovery_codes = json.dumps(hashes)
            return "recovery"
    return None


@router.post("/mfa/verify", response_model=TokenResponse)
@limiter.limit("5/minute")
def mfa_verify(request: Request, body: MfaVerifyRequest, db: Session = Depends(get_db)):
    try:
        username = decode_mfa_token(body.mfa_token)["sub"]
    except jwt.PyJWTError:
        log_action(db, actor=None, action="mfa_verify", detail="invalid or expired mfa_token", success=False)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=GENERIC_MFA_ERROR)

    user = db.query(User).filter(User.username == username).first()
    method = _check_second_factor(db, user, body.code) if user and user.is_active and user.mfa_enabled else None
    if not method:
        db.rollback()
        log_action(db, actor=username, action="mfa_verify", success=False)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=GENERIC_MFA_ERROR)

    log_action(db, actor=user.username, action="login", detail=f"mfa={method}", success=True)
    return TokenResponse(access_token=create_access_token(subject=user.username, role=user.role), role=user.role)


@router.get("/mfa", response_model=MfaStatusOut)
def mfa_status(current_user: User = Depends(current_user)):
    left = len(json.loads(current_user.mfa_recovery_codes or "[]")) if current_user.mfa_enabled else 0
    return MfaStatusOut(enabled=current_user.mfa_enabled, recovery_codes_left=left)


@router.post("/mfa/setup", response_model=MfaSetupOut)
def mfa_setup(db: Session = Depends(get_db), current_user: User = Depends(current_user)):
    if current_user.mfa_enabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA is already enabled")
    secret = totp.new_secret()
    current_user.mfa_pending_secret = secret
    log_action(db, actor=current_user.username, action="mfa_setup_started")
    return MfaSetupOut(secret=secret, otpauth_uri=totp.otpauth_uri(secret, current_user.username))


@router.post("/mfa/enable", response_model=MfaEnableOut)
@limiter.limit("5/minute")
def mfa_enable(request: Request, body: MfaEnableRequest, db: Session = Depends(get_db), current_user: User = Depends(current_user)):
    secret = current_user.mfa_pending_secret
    step = totp.verify_totp(secret, body.code, None) if secret and not current_user.mfa_enabled else None
    if step is None:
        log_action(db, actor=current_user.username, action="mfa_enable", success=False)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=GENERIC_MFA_ERROR)

    codes = totp.new_recovery_codes()
    current_user.mfa_secret = secret
    current_user.mfa_pending_secret = None
    current_user.mfa_last_step = step  # the confirmation code can't then be reused to log in
    current_user.mfa_recovery_codes = json.dumps([hash_password(c) for c in codes])
    current_user.mfa_enabled = True
    log_action(db, actor=current_user.username, action="mfa_enable")
    if getattr(request.state, "mfa_setup_only", False):
        # Forced enrolment at login: now hand out the access token the login withheld.
        log_action(db, actor=current_user.username, action="login", detail="mfa=enrolled", success=True)
        token = create_access_token(subject=current_user.username, role=current_user.role)
        return MfaEnableOut(recovery_codes=codes, access_token=token, role=current_user.role)
    return MfaEnableOut(recovery_codes=codes)  # plaintext shown once, never stored


def clear_mfa(user: User) -> None:
    user.mfa_enabled = False
    user.mfa_secret = None
    user.mfa_pending_secret = None
    user.mfa_last_step = None
    user.mfa_recovery_codes = None


@router.post("/mfa/disable", status_code=204)
@limiter.limit("5/minute")
def mfa_disable(request: Request, body: MfaDisableRequest, db: Session = Depends(get_db), current_user: User = Depends(current_user)):
    ok = (
        current_user.mfa_enabled
        and verify_password(body.password, current_user.password_hash)
        and _check_second_factor(db, current_user, body.code)
    )
    if not ok:
        db.rollback()
        log_action(db, actor=current_user.username, action="mfa_disable", success=False)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid password or code")
    if current_user.role == "admin" and get_require_admin_mfa(db):
        db.rollback()  # don't burn the code on a refused request
        log_action(db, actor=current_user.username, action="mfa_disable", detail="blocked: admin MFA required", success=False)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA is required for admin accounts")
    clear_mfa(current_user)
    log_action(db, actor=current_user.username, action="mfa_disable")


# ---------- Step-up ----------


@router.post("/step-up", status_code=204)
@limiter.limit("5/minute")
def step_up(request: Request, body: StepUpRequest, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Re-authenticate for sensitive admin actions: an MFA code if MFA is on, otherwise the password."""
    if user.mfa_enabled:
        ok = bool(body.code) and _check_second_factor(db, user, body.code) is not None
    else:
        ok = bool(body.password) and verify_password(body.password, user.password_hash)
    if not ok:
        db.rollback()
        log_action(db, actor=user.username, action="step_up", success=False)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid password or code")
    user.step_up_at = datetime.now(timezone.utc)
    log_action(db, actor=user.username, action="step_up")
