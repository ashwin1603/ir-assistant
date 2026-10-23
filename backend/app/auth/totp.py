"""TOTP (RFC 6238) with the standard library only: HMAC-SHA1, 6 digits, 30 s steps.
Also generates one-time recovery codes (hashed with argon2 by the caller)."""

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

STEP_SECONDS = 30
DIGITS = 6
WINDOW = 1  # accept the previous, current and next step (clock drift)
ISSUER = "IR Assistant"
RECOVERY_CODE_COUNT = 8


def new_secret() -> str:
    """160-bit random secret, base32 without padding (what authenticator apps expect)."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def otpauth_uri(secret: str, username: str) -> str:
    label = quote(f"{ISSUER}:{username}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(ISSUER)}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}"


def _hotp(secret: str, counter: int) -> str:
    """RFC 4226 HOTP: HMAC-SHA1 over the 8-byte counter, then dynamic truncation."""
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**DIGITS).zfill(DIGITS)


def current_step(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // STEP_SECONDS)


def totp(secret: str, now: float | None = None) -> str:
    return _hotp(secret, current_step(now))


def verify_totp(secret: str, code: str, last_used_step: int | None, now: float | None = None) -> int | None:
    """Return the matched time step, or None. Steps at or before last_used_step are
    rejected, so a code can never be used twice (replay protection)."""
    if not (len(code) == DIGITS and code.isdigit()):
        return None
    step = current_step(now)
    matched = None
    for candidate in range(step - WINDOW, step + WINDOW + 1):
        # compare_digest is constant-time; check every step so timing doesn't leak which matched.
        if hmac.compare_digest(_hotp(secret, candidate), code) and matched is None:
            matched = candidate
    if matched is None or (last_used_step is not None and matched <= last_used_step):
        return None
    return matched


def new_recovery_codes() -> list[str]:
    """8 codes like 'a1b2c-3d4e5' (40 bits each)."""
    codes = []
    for _ in range(RECOVERY_CODE_COUNT):
        raw = secrets.token_hex(5)
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes
