"""
Secure file handling: magic-byte validation, safe filenames, size limits.
Never trust client MIME type or extension alone.
"""
from __future__ import annotations

import re
import uuid
from pathlib import Path

# Magic byte signatures (prefix) → canonical MIME
# Order matters for overlapping prefixes (longer/more specific first where needed)
MAGIC_SIGNATURES: list[tuple[bytes, str, str]] = [
    (b"\xff\xd8\xff", "image/jpeg", "PHOTO"),
    (b"\x89PNG\r\n\x1a\n", "image/png", "PHOTO"),
    (b"GIF87a", "image/gif", "PHOTO"),
    (b"GIF89a", "image/gif", "PHOTO"),
    (b"RIFF", "image/webp", "PHOTO"),  # WebP starts with RIFF....WEBP
    (b"%PDF", "application/pdf", "DOCUMENT"),
    (b"PK\x03\x04", "application/zip", "DOCUMENT"),  # also docx/xlsx
    (b"\xd0\xcf\x11\xe0", "application/msword", "DOCUMENT"),  # OLE
]

ALLOWED_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp",
    ".pdf", ".txt", ".md",
    ".doc", ".docx",
}

# Max decompressed-ish size already enforced by MAX_UPLOAD_SIZE
MAX_FILENAME_LEN = 200


class FileValidationError(Exception):
    def __init__(self, message: str, code: str = "INVALID_FILE"):
        self.message = message
        self.code = code
        super().__init__(message)


def detect_mime(data: bytes) -> tuple[str | None, str | None]:
    """Return (mime, media_category) from magic bytes, or (None, None)."""
    if not data or len(data) < 4:
        return None, None
    for sig, mime, category in MAGIC_SIGNATURES:
        if data.startswith(sig):
            # WebP: RIFF....WEBP
            if sig == b"RIFF" and len(data) >= 12:
                if data[8:12] != b"WEBP":
                    continue
            return mime, category
    # Plain text heuristic (no nulls in first 512, mostly printable)
    sample = data[:512]
    if b"\x00" not in sample:
        try:
            sample.decode("utf-8")
            return "text/plain", "DOCUMENT"
        except UnicodeDecodeError:
            pass
    return None, None


def sanitize_filename(name: str | None) -> str:
    """Strip path components and dangerous characters."""
    if not name:
        return "upload.bin"
    # Path traversal
    name = Path(name).name
    name = name.replace("\x00", "")
    # Remove control chars and quotes used in Content-Disposition
    name = re.sub(r'[\r\n\t"\\\\]', "", name)
    name = re.sub(r"[^\w.\- ()\[\]]+", "_", name)
    name = name.strip(" .")
    if not name or name in (".", ".."):
        name = "upload.bin"
    if len(name) > MAX_FILENAME_LEN:
        stem = Path(name).stem[: MAX_FILENAME_LEN - 10]
        suffix = Path(name).suffix[:10]
        name = stem + suffix
    return name


def validate_upload(
    data: bytes,
    original_name: str | None,
    claimed_type: str | None,
    max_size: int,
) -> dict:
    """
    Validate uploaded bytes. Returns dict with safe metadata.
    Raises FileValidationError on rejection.
    """
    if not data:
        raise FileValidationError("Empty file", "EMPTY_FILE")
    if len(data) > max_size:
        raise FileValidationError(f"File exceeds maximum size of {max_size} bytes", "FILE_TOO_LARGE")

    safe_name = sanitize_filename(original_name)
    ext = Path(safe_name).suffix.lower()
    if ext and ext not in ALLOWED_EXTENSIONS:
        raise FileValidationError(
            f"Extension '{ext}' is not allowed",
            "EXTENSION_DENIED",
        )

    mime, category = detect_mime(data)
    if mime is None:
        raise FileValidationError(
            "Unrecognized or disallowed file content (magic-byte check failed)",
            "MAGIC_DENIED",
        )

    # Extension should roughly match content when both present
    if ext in {".jpg", ".jpeg"} and not mime.startswith("image/jpeg"):
        raise FileValidationError("Extension does not match file content", "MIME_MISMATCH")
    if ext == ".png" and mime != "image/png":
        raise FileValidationError("Extension does not match file content", "MIME_MISMATCH")
    if ext == ".pdf" and mime != "application/pdf":
        raise FileValidationError("Extension does not match file content", "MIME_MISMATCH")

    # claimed_type is advisory only
    media_type = "PHOTO" if category == "PHOTO" else "DOCUMENT"

    return {
        "safe_name": safe_name,
        "mime_type": mime,
        "media_type": media_type,
        "size": len(data),
        "storage_name": str(uuid.uuid4()),
    }


def content_disposition_attachment(filename: str) -> str:
    """RFC 5987-ish safe Content-Disposition header value."""
    safe = sanitize_filename(filename)
    # ASCII fallback
    ascii_name = safe.encode("ascii", "ignore").decode("ascii") or "download"
    ascii_name = ascii_name.replace('"', "")
    return f'attachment; filename="{ascii_name}"'
