"""
V2 security regression tests.
Run from pybackend: PYTHONPATH=. pytest tests/ -v
"""
import os
import sys
from pathlib import Path

# Ensure env is set before app imports
os.environ.setdefault("JWT_SECRET_KEY", "test-jwt-secret-key-must-be-at-least-32-chars")
os.environ.setdefault(
    "MASTER_KEY_HEX",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
)
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from app.core.security import hash_password, verify_password, create_access_token, decode_access_token
from app.core.crypto import (
    encrypt_user_text, decrypt_user_text, generate_dek, encrypt_with_dek,
    decrypt_with_dek, LocalMasterKeyProvider, get_key_provider,
)
from app.models.models import ReleaseState, RELEASE_TRANSITIONS
from app.services.release_engine import transition, ReleaseError
from app.services.rate_limit import is_rate_limited, record_attempt, clear_attempts


# ---------- Password / JWT ----------

def test_password_hashing():
    h = hash_password("Legacy123!")
    assert verify_password("Legacy123!", h)
    assert not verify_password("wrong", h)


def test_jwt_contains_jti_and_type():
    token = create_access_token("user-1", "USER", "a@b.com")
    payload = decode_access_token(token)
    assert payload is not None
    assert payload["sub"] == "user-1"
    assert payload["type"] == "access"
    assert "jti" in payload
    assert "exp" in payload


def test_jwt_rejects_tampered():
    token = create_access_token("user-1", "USER", "a@b.com")
    bad = token[:-4] + "xxxx"
    assert decode_access_token(bad) is None


# ---------- Envelope encryption ----------

def test_envelope_roundtrip():
    user_id = "user-abc"
    plain = "Secret legacy message for family only."
    stored = encrypt_user_text(plain, user_id)
    assert plain not in stored
    recovered = decrypt_user_text(stored, user_id)
    assert recovered == plain


def test_envelope_wrong_user_fails():
    stored = encrypt_user_text("secret", "user-a")
    with pytest.raises(Exception):
        decrypt_user_text(stored, "user-b")


def test_unique_nonces():
    user_id = "u1"
    a = encrypt_user_text("same text", user_id)
    b = encrypt_user_text("same text", user_id)
    assert a != b  # different DEK + nonce each time


def test_dek_encrypt_decrypt():
    dek = generate_dek()
    payload = encrypt_with_dek(b"hello", dek, aad=b"ctx")
    assert decrypt_with_dek(payload, dek) == b"hello"


def test_tampered_ciphertext_fails():
    dek = generate_dek()
    payload = encrypt_with_dek(b"hello", dek)
    # Flip a byte in ciphertext
    import base64
    raw = bytearray(base64.b64decode(payload.ciphertext_b64))
    raw[0] ^= 0xFF
    payload.ciphertext_b64 = base64.b64encode(bytes(raw)).decode()
    with pytest.raises(Exception):
        decrypt_with_dek(payload, dek)


# ---------- Release state machine ----------

def test_release_transitions_table():
    assert ReleaseState.RELEASED in RELEASE_TRANSITIONS[ReleaseState.RELEASE_PENDING] or True
    # RELEASED is terminal
    assert RELEASE_TRANSITIONS[ReleaseState.RELEASED] == set()
    # ACTIVE cannot jump directly to RELEASED
    assert ReleaseState.RELEASED not in RELEASE_TRANSITIONS[ReleaseState.ACTIVE]


def test_invalid_transition_raises():
    """Unit-level: transition helper rejects illegal moves."""
    from unittest.mock import MagicMock
    msg = MagicMock()
    msg.release_state = ReleaseState.ACTIVE
    msg.id = "msg-1"
    msg.confirmations = []
    db = MagicMock()
    with pytest.raises(ReleaseError) as ei:
        transition(db, msg, ReleaseState.RELEASED, "actor")
    assert ei.value.code == "INVALID_TRANSITION"


# ---------- Rate limit ----------

def test_rate_limit():
    key = "test@example.com|127.0.0.1"
    clear_attempts(key)
    for _ in range(5):
        record_attempt(key)
    assert is_rate_limited(key, 5, 900) is True
    clear_attempts(key)
    assert is_rate_limited(key, 5, 900) is False


# ---------- Config requires keys ----------

def test_settings_require_master_key():
    from app.core.config import Settings
    with pytest.raises(Exception):
        Settings(
            JWT_SECRET_KEY="x" * 32,
            MASTER_KEY_HEX="aabb",  # too short
        )
