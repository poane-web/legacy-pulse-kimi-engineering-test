"""
Audit logging with hash-chain integrity.
Application code must never UPDATE or DELETE audit rows after insert.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.models import AuditLog


def _compute_entry_hash(
    entry_id: str,
    actor_id: str | None,
    action: str,
    resource_type: str | None,
    resource_id: str | None,
    metadata_json: str | None,
    created_at: datetime,
    prev_hash: str | None,
) -> str:
    material = "|".join([
        entry_id,
        actor_id or "",
        action,
        resource_type or "",
        resource_id or "",
        metadata_json or "",
        created_at.isoformat(),
        prev_hash or "GENESIS",
    ])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def log_action(
    db: Session,
    action: str,
    actor_id: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    metadata: dict | None = None,
    commit: bool = True,
) -> AuditLog:
    last = db.query(AuditLog).order_by(desc(AuditLog.created_at)).first()
    prev_hash = last.entry_hash if last else None

    entry_id = str(uuid.uuid4())
    now = datetime.utcnow()
    meta_str = json.dumps(metadata, sort_keys=True) if metadata else None

    entry_hash = _compute_entry_hash(
        entry_id, actor_id, action, resource_type, resource_id, meta_str, now, prev_hash
    )

    entry = AuditLog(
        id=entry_id,
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=ip_address,
        user_agent=user_agent,
        metadata_json=meta_str,
        created_at=now,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
    )
    db.add(entry)
    if commit:
        db.commit()
    return entry


def verify_audit_chain(db: Session, limit: int = 1000) -> tuple[bool, str]:
    rows = (
        db.query(AuditLog)
        .order_by(AuditLog.created_at.asc())
        .limit(limit)
        .all()
    )
    if not rows:
        return True, "empty"

    expected_prev = None
    for row in rows:
        if row.prev_hash != expected_prev:
            return False, f"chain break at {row.id}"
        recomputed = _compute_entry_hash(
            row.id, row.actor_id, row.action, row.resource_type, row.resource_id,
            row.metadata_json, row.created_at, row.prev_hash,
        )
        if recomputed != row.entry_hash:
            return False, f"hash mismatch at {row.id}"
        expected_prev = row.entry_hash
    return True, f"ok ({len(rows)} entries)"


def assert_audit_immutable(db: Session, entry_id: str) -> None:
    """
    Recompute hash for an entry; raise if stored hash does not match
    (detects UPDATE tampering of audited fields).
    """
    entry = db.query(AuditLog).filter(AuditLog.id == entry_id).first()
    if not entry:
        raise ValueError("Audit entry not found")
    recomputed = _compute_entry_hash(
        entry.id,
        entry.actor_id,
        entry.action,
        entry.resource_type,
        entry.resource_id,
        entry.metadata_json,
        entry.created_at,
        entry.prev_hash,
    )
    if recomputed != entry.entry_hash:
        raise ValueError(f"Audit integrity failure at {entry_id}")
