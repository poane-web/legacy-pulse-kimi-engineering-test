"""
Security utilities: password hashing, JWT, encryption.
All sensitive operations happen here or in services that call these.
"""
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
import hashlib
import secrets
import base64

from jose import jwt, JWTError
from passlib.context import CryptContext
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import get_settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
settings = get_settings()


# ---------- Password ----------
def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# ---------- JWT ----------
def create_access_token(subject: str, role: str, email: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": subject,
        "role": role,
        "email": email,
        "type": "access",
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def decode_access_token(token: str) -> Optional[dict[str, Any]]:
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        if payload.get("type") != "access":
            return None
        return payload
    except JWTError:
        return None


# ---------- AES-256-GCM Encryption ----------
def _key_from_hex(hex_key: str) -> bytes:
    """Ensure we have a 32-byte key."""
    key = bytes.fromhex(hex_key)
    if len(key) != 32:
        # Derive if someone provided a different length
        key = hashlib.sha256(hex_key.encode()).digest()
    return key


def encrypt_text(plaintext: str, key_hex: str | None = None) -> tuple[str, str, str]:
    """
    Encrypt a string. Returns (ciphertext_b64, iv_b64, tag_b64).
    Encryption happens only in the backend service layer.
    """
    key = _key_from_hex(key_hex or settings.DATA_ENCRYPTION_KEY)
    aesgcm = AESGCM(key)
    iv = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(iv, plaintext.encode("utf-8"), None)
    # AESGCM returns ciphertext + tag concatenated; we split for storage clarity
    # Actually cryptography AESGCM.encrypt returns ciphertext||tag
    # We store the whole thing as ciphertext and keep iv separate.
    # For simplicity we return the full encrypted blob and iv.
    return (
        base64.b64encode(ciphertext).decode(),
        base64.b64encode(iv).decode(),
        "",  # tag is included in the ciphertext blob for AESGCM
    )


def decrypt_text(ciphertext_b64: str, iv_b64: str, tag_b64: str = "", key_hex: str | None = None) -> str:
    key = _key_from_hex(key_hex or settings.DATA_ENCRYPTION_KEY)
    aesgcm = AESGCM(key)
    iv = base64.b64decode(iv_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    return plaintext.decode("utf-8")


def encrypt_file(data: bytes, key_hex: str | None = None) -> tuple[bytes, bytes]:
    """Encrypt binary file content. Returns (ciphertext, iv)."""
    key = _key_from_hex(key_hex or settings.FILE_ENCRYPTION_KEY)
    aesgcm = AESGCM(key)
    iv = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(iv, data, None)
    return ciphertext, iv


def decrypt_file(ciphertext: bytes, iv: bytes, key_hex: str | None = None) -> bytes:
    key = _key_from_hex(key_hex or settings.FILE_ENCRYPTION_KEY)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext, None)
