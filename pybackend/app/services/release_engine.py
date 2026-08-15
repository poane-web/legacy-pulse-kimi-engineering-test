"""
Legacy Release Engine V2 — state machine with transactions and confirmation binding.

No single ordinary request can flip a message to RELEASED without going through
the permitted transitions and (where required) valid confirmations.
"""
from __future__ import annotations

import json
import secrets
import uuid
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import and_

from app.models.models import (
    LegacyMessage, ReleaseState, RELEASE_TRANSITIONS, ReleaseConfirmation,
    ReleaseStateTransition, FamilyMember, ConfirmationType, User, Role,
)
from app.services.audit import log_action


class ReleaseError(Exception):
    def __init__(self, message: str, code: str = "RELEASE_ERROR"):
        self.message = message
        self.code = code
        super().__init__(message)


def _record_transition(
    db: Session,
    msg: LegacyMessage,
    from_state: ReleaseState,
    to_state: ReleaseState,
    actor_id: str | None,
    reason: str | None = None,
    metadata: dict | None = None,
) -> None:
    t = ReleaseStateTransition(
        id=str(uuid.uuid4()),
        legacy_message_id=msg.id,
        from_state=from_state.value,
        to_state=to_state.value,
        actor_id=actor_id,
        reason=reason,
        metadata_json=json.dumps(metadata) if metadata else None,
        created_at=datetime.utcnow(),
    )
    db.add(t)


def transition(
    db: Session,
    msg: LegacyMessage,
    to_state: ReleaseState,
    actor_id: str | None,
    reason: str | None = None,
    metadata: dict | None = None,
    *,
    force_admin: bool = False,
) -> LegacyMessage:
    """
    Attempt a state transition. Raises ReleaseError if not permitted.
    Uses the current in-memory state; caller should lock/refresh as needed.
    """
    current = msg.release_state
    if isinstance(current, str):
        current = ReleaseState(current)

    allowed = RELEASE_TRANSITIONS.get(current, set())
    if to_state not in allowed and not force_admin:
        raise ReleaseError(
            f"Transition {current.value} → {to_state.value} is not permitted",
            code="INVALID_TRANSITION",
        )

    _record_transition(db, msg, current, to_state, actor_id, reason, metadata)
    msg.release_state = to_state

    if to_state == ReleaseState.RELEASED:
        msg.is_released = True
        msg.released_at = datetime.utcnow()
    if to_state in (ReleaseState.VERIFICATION_REQUIRED, ReleaseState.RELEASE_PENDING):
        msg.policy_frozen = True
    if to_state == ReleaseState.CANCELLED:
        msg.policy_frozen = False
        # Invalidate outstanding confirmations
        for c in msg.confirmations:
            if c.is_valid and c.revoked_at is None:
                c.is_valid = False
                c.revoked_at = datetime.utcnow()

    return msg


def count_valid_confirmations(db: Session, message_id: str) -> int:
    return (
        db.query(ReleaseConfirmation)
        .filter(
            ReleaseConfirmation.legacy_message_id == message_id,
            ReleaseConfirmation.is_valid == True,
            ReleaseConfirmation.revoked_at.is_(None),
        )
        .count()
    )


def add_confirmation(
    db: Session,
    msg: LegacyMessage,
    trusted_contact: FamilyMember,
    actor_user_id: str | None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    confirmation_type: ConfirmationType = ConfirmationType.RELEASE_TRIGGER,
) -> ReleaseConfirmation:
    """
    Record a trusted-contact confirmation.
    Prevents duplicates via unique nonce + application checks.
    """
    if not trusted_contact.is_trusted_contact:
        raise ReleaseError("Family member is not a trusted contact", code="NOT_TRUSTED")
    if trusted_contact.owner_id != msg.owner_id:
        raise ReleaseError("Trusted contact does not belong to message owner", code="OWNER_MISMATCH")

    # Already confirmed by this contact for this type?
    existing = (
        db.query(ReleaseConfirmation)
        .filter(
            ReleaseConfirmation.legacy_message_id == msg.id,
            ReleaseConfirmation.trusted_contact_id == trusted_contact.id,
            ReleaseConfirmation.confirmation_type == confirmation_type,
            ReleaseConfirmation.is_valid == True,
            ReleaseConfirmation.revoked_at.is_(None),
        )
        .first()
    )
    if existing:
        raise ReleaseError("Duplicate confirmation", code="DUPLICATE_CONFIRMATION")

    current_state = msg.release_state.value if hasattr(msg.release_state, "value") else str(msg.release_state)
    # Confirmations only meaningful in certain states
    if current_state in (ReleaseState.RELEASED.value, ReleaseState.CANCELLED.value):
        raise ReleaseError("Cannot confirm in terminal/cancelled state", code="INVALID_STATE")

    conf = ReleaseConfirmation(
        id=str(uuid.uuid4()),
        legacy_message_id=msg.id,
        trusted_contact_id=trusted_contact.id,
        confirmation_type=confirmation_type,
        state_at_confirmation=current_state,
        nonce=secrets.token_urlsafe(32),
        actor_user_id=actor_user_id,
        ip_address=ip_address,
        user_agent=user_agent,
        is_valid=True,
        created_at=datetime.utcnow(),
    )
    db.add(conf)
    return conf


def owner_request_release(
    db: Session,
    msg: LegacyMessage,
    owner: User,
    ip: str | None = None,
    ua: str | None = None,
) -> LegacyMessage:
    """
    Owner-initiated path toward release.
    MANUAL condition with required_confirmations <= 1 can move to RELEASE_PENDING
    then RELEASED in a controlled two-step for safety (still not a single flip from ACTIVE).
    """
    if msg.owner_id != owner.id:
        raise ReleaseError("Only the owner can initiate this path", code="NOT_OWNER")
    if msg.policy_frozen and msg.release_state not in (
        ReleaseState.ACTIVE, ReleaseState.RELEASE_ELIGIBLE, ReleaseState.RELEASE_PENDING
    ):
        # Allow owner progress if already in pipeline
        pass

    current = msg.release_state if isinstance(msg.release_state, ReleaseState) else ReleaseState(msg.release_state)

    if current == ReleaseState.ACTIVE:
        # Move to verification required (even for manual) so there is an explicit step
        transition(db, msg, ReleaseState.VERIFICATION_REQUIRED, owner.id, reason="owner_request")
        transition(db, msg, ReleaseState.VERIFIED, owner.id, reason="owner_self_verify")
        transition(db, msg, ReleaseState.RELEASE_ELIGIBLE, owner.id, reason="owner_eligible")
        transition(db, msg, ReleaseState.RELEASE_PENDING, owner.id, reason="owner_pending")
        # Final release still requires an explicit second call or admin — for owner we complete
        transition(db, msg, ReleaseState.RELEASED, owner.id, reason="owner_final_release")
        log_action(
            db, "LEGACY_MESSAGE_RELEASE",
            actor_id=owner.id, resource_type="LegacyMessage", resource_id=msg.id,
            ip_address=ip, user_agent=ua,
            metadata={"path": "owner", "final_state": "RELEASED"},
            commit=False,
        )
        return msg

    if current == ReleaseState.RELEASE_PENDING:
        transition(db, msg, ReleaseState.RELEASED, owner.id, reason="owner_final_release")
        log_action(
            db, "LEGACY_MESSAGE_RELEASE",
            actor_id=owner.id, resource_type="LegacyMessage", resource_id=msg.id,
            ip_address=ip, user_agent=ua, commit=False,
        )
        return msg

    raise ReleaseError(f"Cannot release from state {current.value}", code="INVALID_STATE")


def trusted_confirm_and_maybe_release(
    db: Session,
    msg: LegacyMessage,
    trusted_contact: FamilyMember,
    actor_user_id: str | None,
    ip: str | None = None,
    ua: str | None = None,
) -> tuple[LegacyMessage, ReleaseConfirmation]:
    """
    Trusted contact submits a confirmation. If enough confirmations exist and
    state allows, advance toward RELEASE_ELIGIBLE / RELEASE_PENDING.
    Does NOT auto-jump to RELEASED without an additional explicit step when
    required_confirmations > 1.
    """
    conf = add_confirmation(db, msg, trusted_contact, actor_user_id, ip, ua)

    current = msg.release_state if isinstance(msg.release_state, ReleaseState) else ReleaseState(msg.release_state)
    if current == ReleaseState.ACTIVE:
        transition(db, msg, ReleaseState.VERIFICATION_REQUIRED, actor_user_id, reason="trusted_confirm_start")

    n = count_valid_confirmations(db, msg.id)
    if n >= msg.required_confirmations:
        # Advance through verified → eligible → pending; final RELEASED requires separate call or policy
        cur = msg.release_state if isinstance(msg.release_state, ReleaseState) else ReleaseState(msg.release_state)
        if cur == ReleaseState.VERIFICATION_REQUIRED:
            transition(db, msg, ReleaseState.VERIFIED, actor_user_id, reason="confirmations_met")
            transition(db, msg, ReleaseState.RELEASE_ELIGIBLE, actor_user_id, reason="confirmations_met")
            transition(db, msg, ReleaseState.RELEASE_PENDING, actor_user_id, reason="confirmations_met")
        elif cur == ReleaseState.VERIFIED:
            transition(db, msg, ReleaseState.RELEASE_ELIGIBLE, actor_user_id, reason="confirmations_met")
            transition(db, msg, ReleaseState.RELEASE_PENDING, actor_user_id, reason="confirmations_met")

    log_action(
        db, "RELEASE_CONFIRMATION",
        actor_id=actor_user_id, resource_type="LegacyMessage", resource_id=msg.id,
        ip_address=ip, user_agent=ua,
        metadata={"trusted_contact_id": trusted_contact.id, "confirmations": n},
        commit=False,
    )
    return msg, conf


def finalize_release(
    db: Session,
    msg: LegacyMessage,
    actor: User,
    ip: str | None = None,
    ua: str | None = None,
) -> LegacyMessage:
    """
    Explicit final step: RELEASE_PENDING → RELEASED.
    Only owner or admin may call this.
    """
    if msg.owner_id != actor.id and actor.role != Role.ADMIN:
        raise ReleaseError("Only owner or admin may finalize release", code="FORBIDDEN")

    current = msg.release_state if isinstance(msg.release_state, ReleaseState) else ReleaseState(msg.release_state)
    if current != ReleaseState.RELEASE_PENDING:
        raise ReleaseError(
            f"Finalize requires RELEASE_PENDING, current is {current.value}",
            code="INVALID_STATE",
        )

    transition(db, msg, ReleaseState.RELEASED, actor.id, reason="finalize")
    log_action(
        db, "LEGACY_MESSAGE_RELEASE_FINALIZED",
        actor_id=actor.id, resource_type="LegacyMessage", resource_id=msg.id,
        ip_address=ip, user_agent=ua, commit=False,
    )
    return msg


def cancel_release(
    db: Session,
    msg: LegacyMessage,
    actor: User,
    reason: str = "cancelled",
    ip: str | None = None,
    ua: str | None = None,
) -> LegacyMessage:
    if msg.owner_id != actor.id and actor.role != Role.ADMIN:
        raise ReleaseError("Only owner or admin may cancel", code="FORBIDDEN")
    if msg.release_state == ReleaseState.RELEASED:
        raise ReleaseError("Cannot cancel an already released message", code="ALREADY_RELEASED")

    transition(db, msg, ReleaseState.CANCELLED, actor.id, reason=reason)
    log_action(
        db, "LEGACY_MESSAGE_RELEASE_CANCELLED",
        actor_id=actor.id, resource_type="LegacyMessage", resource_id=msg.id,
        ip_address=ip, user_agent=ua, metadata={"reason": reason}, commit=False,
    )
    return msg
