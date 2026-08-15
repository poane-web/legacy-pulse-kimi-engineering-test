"""
Security utilities: password hashing, JWT, token hashing.
Encryption is handled by app.core.crypto (envelope scheme).
"""
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
import hashlib
import secrets
import uuid

from jose import jwt, JWTError
from passlib.context import CryptContext

from app.core.config import get_settings

# Explicit cost factor
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(subject: str, role: str, email: str) -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": subject,
        "role": role,
        "email": email,
        "type": "access",
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": expire,
    }
    return jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )


def create_refresh_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def decode_access_token(token: str) -> Optional[dict[str, Any]]:
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={"require_exp": True, "require_iat": True, "require_sub": True},
        )
        if payload.get("type") != "access":
            return None
        return payload
    except JWTError:
        return None


# ---------- Compatibility shims for V1 call sites (migrate to crypto.encrypt_user_text) ----------
# These still use a process-level key derived from MASTER for transitional reads/writes.
# New code should call app.core.crypto.encrypt_user_text / decrypt_user_text directly.

def encrypt_text(plaintext: str, key_hex: str | None = None) -> tuple[str, str, str]:
    """Legacy signature. Prefer encrypt_user_text with user_id."""
    from app.core.crypto import legacy_encrypt_text
    from app.core.config import get_settings
    key = key_hex or get_settings().MASTER_KEY_HEX
    ct, iv = legacy_encrypt_text(plaintext, key)
    return ct, iv, ""


def decrypt_text(ciphertext_b64: str, iv_b64: str, tag_b64: str = "", key_hex: str | None = None) -> str:
    from app.core.crypto import legacy_decrypt_text
    from app.core.config import get_settings
    key = key_hex or get_settings().MASTER_KEY_HEX
    return legacy_decrypt_text(ciphertext_b64, iv_b64, key)


def encrypt_file(data: bytes, key_hex: str | None = None) -> tuple[bytes, bytes]:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import secrets
    from app.core.config import get_settings
    key = bytes.fromhex(key_hex or get_settings().MASTER_KEY_HEX)
    aes = AESGCM(key)
    iv = secrets.token_bytes(12)
    return aes.encrypt(iv, data, None), iv


def decrypt_file(ciphertext: bytes, iv: bytes, key_hex: str | None = None) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from app.core.config import get_settings
    key = bytes.fromhex(key_hex or get_settings().MASTER_KEY_HEX)
    return AESGCM(key).decrypt(iv, ciphertext, None)
