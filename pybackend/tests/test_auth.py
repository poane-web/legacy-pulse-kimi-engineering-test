"""Basic automated tests for authentication and encryption."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.security import hash_password, verify_password, encrypt_text, decrypt_text, create_access_token, decode_access_token


def test_password_hashing():
    hashed = hash_password("Legacy123!")
    assert verify_password("Legacy123!", hashed)
    assert not verify_password("wrong", hashed)


def test_encryption_roundtrip():
    plaintext = "This is a secret legacy message for my family."
    ct, iv, tag = encrypt_text(plaintext)
    recovered = decrypt_text(ct, iv, tag)
    assert recovered == plaintext


def test_jwt():
    token = create_access_token("user-123", "USER", "test@example.com")
    payload = decode_access_token(token)
    assert payload is not None
    assert payload["sub"] == "user-123"
    assert payload["role"] == "USER"
