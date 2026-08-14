"""Audit logging service."""
import json
import uuid
from datetime import datetime
from sqlalchemy.orm import Session
from app.models.models import AuditLog


def log_action(
    db: Session,
    action: str,
    actor_id: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    metadata: dict | None = None,
) -> None:
    entry = AuditLog(
        id=str(uuid.uuid4()),
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=ip_address,
        user_agent=user_agent,
        metadata_json=json.dumps(metadata) if metadata else None,
        created_at=datetime.utcnow(),
    )
    db.add(entry)
    db.commit()
