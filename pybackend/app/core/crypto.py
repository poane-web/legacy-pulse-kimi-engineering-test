"""
Cryptography V2 — Envelope encryption with versioned keys.

Architecture (local MVP):
  MASTER_KEY (from env / future KMS)
       │
       ▼
  User Data Encryption Key (DEK)  — generated per user, wrapped by master
       │
       ▼
  Data / File ciphertext (AES-256-GCM, unique nonce per message)

KeyProvider abstraction allows swapping the local master-key implementation
for AWS KMS, GCP KMS, Azure Key Vault, or an HSM without changing call sites.

Metadata stored with every ciphertext:
  - key_version
  - algorithm
  - nonce (IV)
  - wrapped_dek (for user-scoped data) or key_id
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from app.core.config import get_settings

ALGORITHM = "AES-256-GCM"
KEY_VERSION = 1  # bump when rotation scheme changes
NONCE_SIZE = 12
KEY_SIZE = 32


@dataclass
class EncryptedPayload:
    """Versioned ciphertext package. Never contains plaintext."""
    ciphertext_b64: str
    nonce_b64: str
    key_version: int
    algorithm: str
    # For envelope: DEK wrapped under master (base64). Empty for master-direct.
    wrapped_dek_b64: str = ""
    aad: str = ""  # additional authenticated data (optional context)

    def to_storage(self) -> str:
        """Serialize for DB TEXT column."""
        return json.dumps({
            "ct": self.ciphertext_b64,
            "n": self.nonce_b64,
            "v": self.key_version,
            "alg": self.algorithm,
            "wd": self.wrapped_dek_b64,
            "aad": self.aad,
        })

    @classmethod
    def from_storage(cls, raw: str) -> "EncryptedPayload":
        d = json.loads(raw)
        return cls(
            ciphertext_b64=d["ct"],
            nonce_b64=d["n"],
            key_version=d.get("v", 1),
            algorithm=d.get("alg", ALGORITHM),
            wrapped_dek_b64=d.get("wd", ""),
            aad=d.get("aad", ""),
        )


class KeyProvider(ABC):
    """Abstraction for root key material. Swap for real KMS later."""

    @abstractmethod
    def wrap_dek(self, dek: bytes, context: bytes = b"") -> bytes:
        """Encrypt a DEK under the root key. Returns wrapped blob."""

    @abstractmethod
    def unwrap_dek(self, wrapped: bytes, context: bytes = b"") -> bytes:
        """Decrypt a DEK."""

    @abstractmethod
    def key_id(self) -> str:
        """Opaque identifier for the current root key version."""


class LocalMasterKeyProvider(KeyProvider):
    """
    Local implementation using MASTER_KEY_HEX from environment.
    NOT equivalent to production KMS. Suitable for evaluation and tests only.
    """

    def __init__(self, master_key: bytes):
        if len(master_key) != KEY_SIZE:
            raise ValueError("Master key must be 32 bytes")
        self._master = master_key
        self._id = hashlib.sha256(master_key).hexdigest()[:16]

    def _derive(self, info: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=None,
            info=info,
        ).derive(self._master)

    def wrap_dek(self, dek: bytes, context: bytes = b"") -> bytes:
        # Derive a wrapping key from master + context; encrypt DEK with AES-GCM
        wrap_key = self._derive(b"wrap|" + context)
        aes = AESGCM(wrap_key)
        nonce = secrets.token_bytes(NONCE_SIZE)
        ct = aes.encrypt(nonce, dek, context)
        return nonce + ct  # nonce || ciphertext+tag

    def unwrap_dek(self, wrapped: bytes, context: bytes = b"") -> bytes:
        if len(wrapped) < NONCE_SIZE + 16:
            raise ValueError("Invalid wrapped DEK")
        nonce, ct = wrapped[:NONCE_SIZE], wrapped[NONCE_SIZE:]
        wrap_key = self._derive(b"wrap|" + context)
        aes = AESGCM(wrap_key)
        return aes.decrypt(nonce, ct, context)

    def key_id(self) -> str:
        return self._id


def get_key_provider() -> KeyProvider:
    settings = get_settings()
    master = bytes.fromhex(settings.MASTER_KEY_HEX)
    return LocalMasterKeyProvider(master)


def generate_dek() -> bytes:
    return secrets.token_bytes(KEY_SIZE)


def encrypt_with_dek(
    plaintext: bytes,
    dek: bytes,
    aad: bytes = b"",
    key_version: int = KEY_VERSION,
) -> EncryptedPayload:
    if len(dek) != KEY_SIZE:
        raise ValueError("DEK must be 32 bytes")
    aes = AESGCM(dek)
    nonce = secrets.token_bytes(NONCE_SIZE)
    ct = aes.encrypt(nonce, plaintext, aad if aad else None)
    return EncryptedPayload(
        ciphertext_b64=base64.b64encode(ct).decode(),
        nonce_b64=base64.b64encode(nonce).decode(),
        key_version=key_version,
        algorithm=ALGORITHM,
        aad=aad.decode("utf-8", errors="replace") if aad else "",
    )


def decrypt_with_dek(payload: EncryptedPayload, dek: bytes) -> bytes:
    if len(dek) != KEY_SIZE:
        raise ValueError("DEK must be 32 bytes")
    aes = AESGCM(dek)
    nonce = base64.b64decode(payload.nonce_b64)
    ct = base64.b64decode(payload.ciphertext_b64)
    aad = payload.aad.encode("utf-8") if payload.aad else None
    return aes.decrypt(nonce, ct, aad)


# ---------- High-level helpers used by services ----------

def encrypt_user_text(plaintext: str, user_id: str, provider: Optional[KeyProvider] = None) -> str:
    """
    Envelope-encrypt text for a specific user.
    Generates a fresh DEK, wraps it under master with user context, encrypts data.
    Returns storage JSON string.
    """
    provider = provider or get_key_provider()
    dek = generate_dek()
    context = f"user:{user_id}".encode()
    wrapped = provider.wrap_dek(dek, context)
    payload = encrypt_with_dek(plaintext.encode("utf-8"), dek, aad=context)
    payload.wrapped_dek_b64 = base64.b64encode(wrapped).decode()
    return payload.to_storage()


def decrypt_user_text(storage: str, user_id: str, provider: Optional[KeyProvider] = None) -> str:
    provider = provider or get_key_provider()
    payload = EncryptedPayload.from_storage(storage)
    if not payload.wrapped_dek_b64:
        raise ValueError("Missing wrapped DEK — cannot decrypt under envelope scheme")
    context = f"user:{user_id}".encode()
    wrapped = base64.b64decode(payload.wrapped_dek_b64)
    dek = provider.unwrap_dek(wrapped, context)
    return decrypt_with_dek(payload, dek).decode("utf-8")


def encrypt_file_bytes(data: bytes, user_id: str, provider: Optional[KeyProvider] = None) -> tuple[bytes, str]:
    """
    Envelope-encrypt file content.
    Returns (ciphertext_bytes_for_disk, metadata_json_for_db).
    Disk stores only ciphertext; metadata (nonce, wrapped DEK, version) goes in DB.
    """
    provider = provider or get_key_provider()
    dek = generate_dek()
    context = f"file:{user_id}".encode()
    wrapped = provider.wrap_dek(dek, context)
    payload = encrypt_with_dek(data, dek, aad=context)
    payload.wrapped_dek_b64 = base64.b64encode(wrapped).decode()
    # Disk format: we store the raw AES-GCM output (already has tag).
    # Nonce and wrapped DEK live in DB metadata.
    disk_ct = base64.b64decode(payload.ciphertext_b64)
    return disk_ct, payload.to_storage()


def decrypt_file_bytes(disk_ct: bytes, metadata_json: str, user_id: str, provider: Optional[KeyProvider] = None) -> bytes:
    provider = provider or get_key_provider()
    payload = EncryptedPayload.from_storage(metadata_json)
    # Reconstruct payload with disk ciphertext
    payload.ciphertext_b64 = base64.b64encode(disk_ct).decode()
    context = f"file:{user_id}".encode()
    wrapped = base64.b64decode(payload.wrapped_dek_b64)
    dek = provider.unwrap_dek(wrapped, context)
    return decrypt_with_dek(payload, dek)


# ---------- Legacy compatibility (global-key path for migration) ----------
# Used only to read data written by V1. New writes use envelope path.

def legacy_encrypt_text(plaintext: str, key_hex: str) -> tuple[str, str]:
    """V1 format: (ciphertext_b64, iv_b64). Tag embedded in ciphertext."""
    key = bytes.fromhex(key_hex) if len(key_hex) == 64 else hashlib.sha256(key_hex.encode()).digest()
    aes = AESGCM(key)
    iv = secrets.token_bytes(NONCE_SIZE)
    ct = aes.encrypt(iv, plaintext.encode("utf-8"), None)
    return base64.b64encode(ct).decode(), base64.b64encode(iv).decode()


def legacy_decrypt_text(ciphertext_b64: str, iv_b64: str, key_hex: str) -> str:
    key = bytes.fromhex(key_hex) if len(key_hex) == 64 else hashlib.sha256(key_hex.encode()).digest()
    aes = AESGCM(key)
    return aes.decrypt(base64.b64decode(iv_b64), base64.b64decode(ciphertext_b64), None).decode("utf-8")
