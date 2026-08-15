"""
SQLAlchemy models — Legacy Pulse V2.
Release state machine, confirmation records, life-event verification, audit integrity.
"""
from datetime import datetime
from sqlalchemy import (
    String, Boolean, DateTime, Text, Integer, ForeignKey, Enum as SAEnum, UniqueConstraint
)
from sqlalchemy.orm import Mapped, mapped_column, relationship as sa_relationship
import enum
from app.core.database import Base


class Role(str, enum.Enum):
    USER = "USER"
    ADMIN = "ADMIN"


class AccessLevel(str, enum.Enum):
    NONE = "NONE"
    VIEW = "VIEW"
    FULL = "FULL"


class MediaType(str, enum.Enum):
    PHOTO = "PHOTO"
    DOCUMENT = "DOCUMENT"


class ReleaseCondition(str, enum.Enum):
    SCHEDULED = "SCHEDULED"
    MANUAL = "MANUAL"
    ON_DEATH = "ON_DEATH"
    TRUSTED_CONSENSUS = "TRUSTED_CONSENSUS"


class ReleaseState(str, enum.Enum):
    ACTIVE = "ACTIVE"
    INACTIVITY_DETECTED = "INACTIVITY_DETECTED"
    GRACE_PERIOD = "GRACE_PERIOD"
    VERIFICATION_REQUIRED = "VERIFICATION_REQUIRED"
    VERIFIED = "VERIFIED"
    RELEASE_ELIGIBLE = "RELEASE_ELIGIBLE"
    RELEASE_PENDING = "RELEASE_PENDING"
    RELEASED = "RELEASED"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"


RELEASE_TRANSITIONS = {
    ReleaseState.ACTIVE: {ReleaseState.INACTIVITY_DETECTED, ReleaseState.VERIFICATION_REQUIRED, ReleaseState.CANCELLED},
    ReleaseState.INACTIVITY_DETECTED: {ReleaseState.GRACE_PERIOD, ReleaseState.CANCELLED},
    ReleaseState.GRACE_PERIOD: {ReleaseState.VERIFICATION_REQUIRED, ReleaseState.ACTIVE, ReleaseState.CANCELLED},
    ReleaseState.VERIFICATION_REQUIRED: {ReleaseState.VERIFIED, ReleaseState.FAILED, ReleaseState.CANCELLED},
    ReleaseState.VERIFIED: {ReleaseState.RELEASE_ELIGIBLE, ReleaseState.CANCELLED},
    ReleaseState.RELEASE_ELIGIBLE: {ReleaseState.RELEASE_PENDING, ReleaseState.CANCELLED},
    ReleaseState.RELEASE_PENDING: {ReleaseState.RELEASED, ReleaseState.FAILED, ReleaseState.CANCELLED},
    ReleaseState.RELEASED: set(),
    ReleaseState.CANCELLED: {ReleaseState.ACTIVE},
    ReleaseState.FAILED: {ReleaseState.VERIFICATION_REQUIRED, ReleaseState.CANCELLED},
}


class LifeEventCategory(str, enum.Enum):
    BIRTH = "BIRTH"
    MARRIAGE = "MARRIAGE"
    DIVORCE = "DIVORCE"
    DEATH = "DEATH"
    GRADUATION = "GRADUATION"
    CAREER = "CAREER"
    TRAVEL = "TRAVEL"
    ESTATE = "ESTATE"
    RELATIONSHIP_CHANGE = "RELATIONSHIP_CHANGE"
    OTHER = "OTHER"


class LifeEventStatus(str, enum.Enum):
    DECLARED = "DECLARED"
    PENDING_VERIFICATION = "PENDING_VERIFICATION"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"


class ConfirmationType(str, enum.Enum):
    RELEASE_TRIGGER = "RELEASE_TRIGGER"
    IDENTITY = "IDENTITY"
    DEATH = "DEATH"
    INACTIVITY = "INACTIVITY"


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    first_name: Mapped[str] = mapped_column(String(100))
    last_name: Mapped[str] = mapped_column(String(100))
    role: Mapped[Role] = mapped_column(SAEnum(Role), default=Role.USER)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    wrapped_dek: Mapped[str | None] = mapped_column(Text, nullable=True)

    profile = sa_relationship("Profile", back_populates="user", uselist=False, cascade="all, delete-orphan")
    family_members = sa_relationship(
        "FamilyMember", back_populates="owner",
        foreign_keys="FamilyMember.owner_id", cascade="all, delete-orphan"
    )
    memories = sa_relationship("Memory", back_populates="owner", cascade="all, delete-orphan")
    media_assets = sa_relationship("MediaAsset", back_populates="owner", cascade="all, delete-orphan")
    life_events = sa_relationship("LifeEvent", back_populates="owner", cascade="all, delete-orphan")
    legacy_messages = sa_relationship("LegacyMessage", back_populates="owner", cascade="all, delete-orphan")
    notifications = sa_relationship("Notification", back_populates="user", cascade="all, delete-orphan")
    audit_logs = sa_relationship("AuditLog", back_populates="actor")
    refresh_tokens = sa_relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")
    release_policies = sa_relationship("ReleasePolicy", back_populates="owner", cascade="all, delete-orphan")


class Profile(Base):
    __tablename__ = "profiles"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), unique=True)
    bio: Mapped[str | None] = mapped_column(Text, nullable=True)
    date_of_birth: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    location: Mapped[str | None] = mapped_column(String(255), nullable=True)
    avatar_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = sa_relationship("User", back_populates="profile")


class FamilyMember(Base):
    __tablename__ = "family_members"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    related_user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(200))
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    relationship: Mapped[str] = mapped_column(String(100))
    is_beneficiary: Mapped[bool] = mapped_column(Boolean, default=False)
    is_trusted_contact: Mapped[bool] = mapped_column(Boolean, default=False)
    access_level: Mapped[AccessLevel] = mapped_column(SAEnum(AccessLevel), default=AccessLevel.NONE)
    notes_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    notes_iv: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    owner = sa_relationship("User", back_populates="family_members", foreign_keys=[owner_id])
    messages = sa_relationship("LegacyMessage", back_populates="recipient")
    confirmations = sa_relationship("ReleaseConfirmation", back_populates="trusted_contact")


class Memory(Base):
    __tablename__ = "memories"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(300))
    content_encrypted: Mapped[str] = mapped_column(Text)
    content_iv: Mapped[str | None] = mapped_column(String(64), nullable=True)
    encryption_version: Mapped[int] = mapped_column(Integer, default=2)
    memory_date: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    location: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_private: Mapped[bool] = mapped_column(Boolean, default=True)
    tags: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    owner = sa_relationship("User", back_populates="memories")
    media = sa_relationship("MediaAsset", back_populates="memory")


class MediaAsset(Base):
    __tablename__ = "media_assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    memory_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("memories.id"), nullable=True)
    type: Mapped[MediaType] = mapped_column(SAEnum(MediaType))
    original_name: Mapped[str] = mapped_column(String(512))
    mime_type: Mapped[str] = mapped_column(String(128))
    size: Mapped[int] = mapped_column(Integer)
    storage_path: Mapped[str] = mapped_column(String(512))
    encryption_meta: Mapped[str | None] = mapped_column(Text, nullable=True)
    encryption_iv: Mapped[str | None] = mapped_column(String(64), nullable=True)
    encryption_version: Mapped[int] = mapped_column(Integer, default=2)
    is_released: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    owner = sa_relationship("User", back_populates="media_assets")
    memory = sa_relationship("Memory", back_populates="media")


class LifeEvent(Base):
    __tablename__ = "life_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(300))
    description_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    description_iv: Mapped[str | None] = mapped_column(String(64), nullable=True)
    encryption_version: Mapped[int] = mapped_column(Integer, default=2)
    event_date: Mapped[datetime] = mapped_column(DateTime)
    category: Mapped[LifeEventCategory] = mapped_column(SAEnum(LifeEventCategory), default=LifeEventCategory.OTHER)
    status: Mapped[LifeEventStatus] = mapped_column(SAEnum(LifeEventStatus), default=LifeEventStatus.DECLARED)
    source: Mapped[str] = mapped_column(String(50), default="user_declaration")
    verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    verified_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    rejection_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    owner = sa_relationship("User", back_populates="life_events")


class LegacyMessage(Base):
    __tablename__ = "legacy_messages"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(300))
    body_encrypted: Mapped[str] = mapped_column(Text)
    body_iv: Mapped[str | None] = mapped_column(String(64), nullable=True)
    encryption_version: Mapped[int] = mapped_column(Integer, default=2)
    recipient_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("family_members.id"), nullable=True)
    release_condition: Mapped[ReleaseCondition] = mapped_column(SAEnum(ReleaseCondition), default=ReleaseCondition.MANUAL)
    scheduled_release_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    release_state: Mapped[ReleaseState] = mapped_column(SAEnum(ReleaseState), default=ReleaseState.ACTIVE)
    is_released: Mapped[bool] = mapped_column(Boolean, default=False)
    released_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    policy_frozen: Mapped[bool] = mapped_column(Boolean, default=False)
    required_confirmations: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    owner = sa_relationship("User", back_populates="legacy_messages")
    recipient = sa_relationship("FamilyMember", back_populates="messages")
    confirmations = sa_relationship("ReleaseConfirmation", back_populates="legacy_message", cascade="all, delete-orphan")
    state_history = sa_relationship("ReleaseStateTransition", back_populates="legacy_message", cascade="all, delete-orphan")


class ReleasePolicy(Base):
    __tablename__ = "release_policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    condition: Mapped[ReleaseCondition] = mapped_column(SAEnum(ReleaseCondition), default=ReleaseCondition.MANUAL)
    required_confirmations: Mapped[int] = mapped_column(Integer, default=2)
    grace_period_days: Mapped[int] = mapped_column(Integer, default=7)
    inactivity_days: Mapped[int] = mapped_column(Integer, default=90)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    owner = sa_relationship("User", back_populates="release_policies")


class ReleaseConfirmation(Base):
    __tablename__ = "release_confirmations"
    __table_args__ = (
        UniqueConstraint("legacy_message_id", "trusted_contact_id", "confirmation_type", "nonce",
                         name="uq_confirmation_nonce"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    legacy_message_id: Mapped[str] = mapped_column(String(36), ForeignKey("legacy_messages.id", ondelete="CASCADE"), index=True)
    trusted_contact_id: Mapped[str] = mapped_column(String(36), ForeignKey("family_members.id"), index=True)
    confirmation_type: Mapped[ConfirmationType] = mapped_column(SAEnum(ConfirmationType), default=ConfirmationType.RELEASE_TRIGGER)
    state_at_confirmation: Mapped[str] = mapped_column(String(50))
    nonce: Mapped[str] = mapped_column(String(64), unique=True)
    actor_user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    is_valid: Mapped[bool] = mapped_column(Boolean, default=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    legacy_message = sa_relationship("LegacyMessage", back_populates="confirmations")
    trusted_contact = sa_relationship("FamilyMember", back_populates="confirmations")


class ReleaseStateTransition(Base):
    __tablename__ = "release_state_transitions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    legacy_message_id: Mapped[str] = mapped_column(String(36), ForeignKey("legacy_messages.id", ondelete="CASCADE"), index=True)
    from_state: Mapped[str] = mapped_column(String(50))
    to_state: Mapped[str] = mapped_column(String(50))
    actor_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

    legacy_message = sa_relationship("LegacyMessage", back_populates="state_history")


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    type: Mapped[str] = mapped_column(String(50))
    title: Mapped[str] = mapped_column(String(300))
    body: Mapped[str] = mapped_column(Text)
    is_read: Mapped[bool] = mapped_column(Boolean, default=False)
    related_resource_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    related_resource_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    user = sa_relationship("User", back_populates="notifications")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    actor_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(100))
    resource_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    entry_hash: Mapped[str] = mapped_column(String(64))

    actor = sa_relationship("User", back_populates="audit_logs")


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    family_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    replaced_by: Mapped[str | None] = mapped_column(String(36), nullable=True)

    user = sa_relationship("User", back_populates="refresh_tokens")


class LoginAttempt(Base):
    __tablename__ = "login_attempts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    email: Mapped[str] = mapped_column(String(255), index=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), index=True)
    success: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
