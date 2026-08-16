"""
Step-up authentication for sensitive operations.

Before beneficiary changes, release finalize, or trusted-contact role changes,
the caller must re-prove possession of the password (or later MFA).

This is MFA-ready: the StepUpChallenge can later require TOTP in addition to password.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional
from pydantic import BaseModel, Field
import hashlib
import secrets
import uuid

from jose import jwt, JWTError

from app.core.config import get_settings
from app.core.security import verify_password


class StepUpRequest(BaseModel):
    password: str = Field(min_length=1)
    # Future: totp_code: Optional[str] = None


class StepUpTokenResponse(BaseModel):
    step_up_token: str
    expires_in: int
    scope: str


def create_step_up_token(user_id: str, scope: str) -> str:
    """Short-lived token proving recent re-authentication for a specific scope."""
    settings = get_settings()
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=5)  # tight window
    payload = {
        "sub": user_id,
        "type": "step_up",
        "scope": scope,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": expire,
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)



_consumed_jtis: set[str] = set()


def verify_step_up_token(token: str, user_id: str, required_scope: str) -> bool:
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={"require_exp": True, "require_sub": True},
        )
        if payload.get("type") != "step_up":
            return False
        if payload.get("sub") != user_id:
            return False
        jti = payload.get("jti")
        if jti and jti in _consumed_jtis:
            return False
        scope = payload.get("scope") or ""
        if scope != required_scope and scope != "sensitive":
            return False
        return True
    except JWTError:
        return False


def consume_step_up_token(token: str) -> None:
    """Mark step-up token jti as consumed (single-use)."""
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={"require_exp": True, "require_sub": True},
        )
        jti = payload.get("jti")
        if jti:
            _consumed_jtis.add(jti)
    except JWTError:
        pass


# Scopes used by the application
SCOPE_RELEASE_FINALIZE = "release_finalize"
SCOPE_BENEFICIARY_CHANGE = "beneficiary_change"
SCOPE_TRUSTED_CONTACT_CHANGE = "trusted_contact_change"
SCOPE_PASSWORD_CHANGE = "password_change"
SCOPE_SENSITIVE = "sensitive"
