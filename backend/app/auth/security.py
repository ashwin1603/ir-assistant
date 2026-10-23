from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from app.config import settings

_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return False
    except Exception:
        return False


MFA_TOKEN_MINUTES = 5


def create_access_token(subject: str, role: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expire_minutes)
    payload = {"sub": subject, "role": role, "purpose": "access", "exp": expire}
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def create_mfa_token(subject: str) -> str:
    """Short-lived token proving only "password was correct". Its purpose claim is
    "mfa", so get_current_user rejects it on every route except /auth/mfa/verify."""
    expire = datetime.now(timezone.utc) + timedelta(minutes=MFA_TOKEN_MINUTES)
    payload = {"sub": subject, "purpose": "mfa", "exp": expire}
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def _decode(token: str, purpose: str) -> dict:
    payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm], options={"require": ["exp", "sub"]})
    if payload.get("purpose") != purpose:
        raise jwt.InvalidTokenError("wrong token purpose")
    return payload


def decode_access_token(token: str) -> dict:
    return _decode(token, "access")


def decode_mfa_token(token: str) -> dict:
    return _decode(token, "mfa")
