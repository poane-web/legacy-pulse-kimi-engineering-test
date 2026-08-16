"""Authorization guards for media/memory cross-user association."""
from sqlalchemy.orm import Session
from app.models.models import Memory


class MediaAuthError(Exception):
    def __init__(self, message: str = "Not authorized"):
        self.message = message
        super().__init__(message)


def assert_memory_owned_by(db: Session, memory_id: str, user_id: str) -> Memory:
    mem = db.query(Memory).filter(Memory.id == memory_id).first()
    if not mem:
        raise MediaAuthError("Memory not found")
    if mem.owner_id != user_id:
        raise MediaAuthError("Cannot associate media with another user's memory")
    return mem
