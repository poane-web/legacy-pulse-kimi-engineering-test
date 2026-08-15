"""
Signed confirmation tokens for trusted-contact actions.

Prevents replay and binds confirmation to:
  - message id
  - trusted contact id
  - expected release state
  - expiry
  - unique nonce

Token is opaque to the client; signature is HMAC over the claims.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Optional

from app.core.config import get_settings


@dataclass
class ConfirmationClaims:
    message_id: str
    trusted_contact_id: str
    expected_state: str
    nonce: str
    exp: int  # unix timestamp

    def to_dict(self) -> dict:
        return {
            "mid": self.message_id,
            "tcid": self.trusted_contact_id,
            "st": self.expected_state,
            "n": self.nonce,
            "exp": self.exp,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ConfirmationClaims":
        return cls(
            message_id=d["mid"],
            trusted_contact_id=d["tcid"],
            expected_state=d["st"],
            nonce=d["n"],
            exp=int(d["exp"]),
        )


def _sign(payload_b64: str) -> str:
    settings = get_settings()
    key = settings.JWT_SECRET_KEY.encode("utf-8")
    return hmac.new(key, payload_b64.encode("utf-8"), hashlib.sha256).hexdigest()


def issue_confirmation_token(
    message_id: str,
    trusted_contact_id: str,
    expected_state: str,
    ttl_seconds: int = 3600,
) -> str:
    """Return token string: base64url(json).signature"""
    import base64
    claims = ConfirmationClaims(
        message_id=message_id,
        trusted_contact_id=trusted_contact_id,
        expected_state=expected_state,
        nonce=secrets.token_urlsafe(16),
        exp=int(time.time()) + ttl_seconds,
    )
    raw = json.dumps(claims.to_dict(), separators=(",", ":"), sort_keys=True)
    payload_b64 = base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")
    sig = _sign(payload_b64)
    return f"{payload_b64}.{sig}"


def verify_confirmation_token(
    token: str,
    message_id: str,
    trusted_contact_id: str,
    current_state: str,
) -> ConfirmationClaims:
    """
    Verify signature, expiry, binding. Raises ValueError on failure.
    """
    import base64
    parts = token.split(".")
    if len(parts) != 2:
        raise ValueError("Malformed confirmation token")
    payload_b64, sig = parts
    expected_sig = _sign(payload_b64)
    if not hmac.compare_digest(expected_sig, sig):
        raise ValueError("Invalid confirmation token signature")

    # pad
    pad = "=" * (-len(payload_b64) % 4)
    raw = base64.urlsafe_b64decode(payload_b64 + pad)
    claims = ConfirmationClaims.from_dict(json.loads(raw))

    if claims.exp < int(time.time()):
        raise ValueError("Confirmation token expired")
    if claims.message_id != message_id:
        raise ValueError("Token message mismatch")
    if claims.trusted_contact_id != trusted_contact_id:
        raise ValueError("Token contact mismatch")
    if claims.expected_state != current_state:
        raise ValueError(
            f"Token issued for state {claims.expected_state}, current is {current_state}"
        )
    return claims
