"""Regression tests for remaining vulnerability fixes."""
import os
import sys
from pathlib import Path

os.environ.setdefault("JWT_SECRET_KEY", "test-jwt-secret-key-must-be-at-least-32-chars")
os.environ.setdefault(
    "MASTER_KEY_HEX",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
)
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from app.utils.files import (
    validate_upload, sanitize_filename, detect_mime,
    content_disposition_attachment, FileValidationError,
)
from app.core.step_up import create_step_up_token, verify_step_up_token, SCOPE_RELEASE_FINALIZE
from app.core.confirmation_tokens import (
    issue_confirmation_token, verify_confirmation_token,
)


# ---------- File validation ----------

def test_reject_empty_file():
    with pytest.raises(FileValidationError) as e:
        validate_upload(b"", "x.pdf", None, 10_000_000)
    assert e.value.code == "EMPTY_FILE"


def test_reject_oversized():
    with pytest.raises(FileValidationError) as e:
        validate_upload(b"%PDF" + b"x" * 100, "a.pdf", None, max_size=10)
    assert e.value.code == "FILE_TOO_LARGE"


def test_reject_unknown_magic():
    with pytest.raises(FileValidationError) as e:
        validate_upload(b"\x00\x01\x02\x03MALWARE", "evil.exe", None, 10_000_000)
    assert e.value.code in ("MAGIC_DENIED", "EXTENSION_DENIED")


def test_accept_pdf():
    data = b"%PDF-1.4 fake content for test"
    meta = validate_upload(data, "will.pdf", "DOCUMENT", 10_000_000)
    assert meta["mime_type"] == "application/pdf"
    assert meta["media_type"] == "DOCUMENT"
    assert meta["safe_name"] == "will.pdf"


def test_accept_jpeg():
    data = b"\xff\xd8\xff\xe0" + b"\x00" * 20
    meta = validate_upload(data, "photo.jpg", "PHOTO", 10_000_000)
    assert meta["mime_type"] == "image/jpeg"
    assert meta["media_type"] == "PHOTO"


def test_path_traversal_filename():
    assert ".." not in sanitize_filename("../../etc/passwd")
    assert "/" not in sanitize_filename("a/b/c.txt")
    assert sanitize_filename('evil"name.pdf') == "evilname.pdf"


def test_mime_extension_mismatch():
    # JPEG bytes with .pdf extension
    data = b"\xff\xd8\xff\xe0" + b"\x00" * 20
    with pytest.raises(FileValidationError) as e:
        validate_upload(data, "trick.pdf", None, 10_000_000)
    assert e.value.code == "MIME_MISMATCH"


def test_content_disposition_safe():
    h = content_disposition_attachment('a"b\r\nX: 1.pdf')
    assert "\r" not in h and "\n" not in h
    assert "attachment;" in h


# ---------- Step-up ----------

def test_step_up_token_roundtrip():
    token = create_step_up_token("user-1", SCOPE_RELEASE_FINALIZE)
    assert verify_step_up_token(token, "user-1", SCOPE_RELEASE_FINALIZE)
    assert not verify_step_up_token(token, "user-2", SCOPE_RELEASE_FINALIZE)
    assert not verify_step_up_token(token, "user-1", "wrong_scope")


def test_step_up_tampered():
    token = create_step_up_token("user-1", SCOPE_RELEASE_FINALIZE)
    bad = token[:-5] + "xxxxx"
    assert not verify_step_up_token(bad, "user-1", SCOPE_RELEASE_FINALIZE)


# ---------- Confirmation tokens ----------

def test_confirmation_token_valid():
    tok = issue_confirmation_token("msg-1", "tc-1", "VERIFICATION_REQUIRED", ttl_seconds=60)
    claims = verify_confirmation_token(tok, "msg-1", "tc-1", "VERIFICATION_REQUIRED")
    assert claims.message_id == "msg-1"
    assert claims.nonce


def test_confirmation_token_wrong_state():
    tok = issue_confirmation_token("msg-1", "tc-1", "ACTIVE")
    with pytest.raises(ValueError, match="state"):
        verify_confirmation_token(tok, "msg-1", "tc-1", "RELEASED")


def test_confirmation_token_tamper():
    tok = issue_confirmation_token("msg-1", "tc-1", "ACTIVE")
    parts = tok.split(".")
    bad = parts[0] + ".deadbeef"
    with pytest.raises(ValueError, match="signature"):
        verify_confirmation_token(bad, "msg-1", "tc-1", "ACTIVE")


def test_confirmation_token_message_mismatch():
    tok = issue_confirmation_token("msg-1", "tc-1", "ACTIVE")
    with pytest.raises(ValueError, match="message"):
        verify_confirmation_token(tok, "msg-OTHER", "tc-1", "ACTIVE")
