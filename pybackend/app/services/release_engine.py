"""
Legacy Release Engine V2.1 — policy-enforcing state machine.

SECURITY INVARIANT:
  No asset reaches RELEASED / is_released=True unless its release_condition
  has been satisfied. force_admin cannot bypass policy checks for RELEASED.

Attacker regressions live in tests/test_attacker_release.py.
"""
from __future__ import annotations

import json
import secrets
import uuid
from datetime import datetime
from sqlalchemy.orm import Session

from app.models.models import (
    LegacyMessage, ReleaseState, RELEASE_TRANSITIONS, ReleaseConfirmation,
    ReleaseStateTransition, FamilyMember, ConfirmationType, User, Role,
    ReleaseCondition, LifeEvent, LifeEventCategory, LifeEventStatus,
)
from app.services.audit import log_action

# Consumed confirmation nonces (in-memory + DB check)
_consumed_nonces: set[str] = set()


class ReleaseError(Exception):
    def __init__(self, message: str, code: str = "RELEASE_ERROR"):
        self.message = message
        self.code = code
        super().__init__(message)


def consume_confirmation_token_nonce(db: Session, nonce: str) -> None:
    """Mark a confirmation token nonce as used. Raises if already consumed."""
    if nonce in _consumed_nonces:
        raise ReleaseError("Confirmation token nonce already used", code="NONCE_REPLAY")
    # Also check DB confirmations table for same nonce
    existing = db.query(ReleaseConfirmation).filter(ReleaseConfirmation.nonce == nonce).first()
    if existing:
        raise ReleaseError("Confirmation token nonce already used", code="NONCE_REPLAY")
    _consumed_nonces.add(nonce)


def assert_policy_mutable(msg: LegacyMessage) -> None:
    if msg.policy_frozen:
        raise ReleaseError("Release policy is frozen and cannot be modified", code="POLICY_FROZEN")


def _policy_satisfied(db: Session, msg: LegacyMessage) -> tuple[bool, str]:
    """
    Evaluate whether the message's release_condition is currently satisfied.
    Returns (ok, reason_code).
    """
    cond = msg.release_condition
    if isinstance(cond, str):
        cond = ReleaseCondition(cond)

    if cond == ReleaseCondition.MANUAL:
        # MANUAL: owner-initiated path is allowed to progress, but still
        # requires explicit multi-step finalize (not single-call RELEASED).
        return True, "MANUAL_OK"

    if cond == ReleaseCondition.SCHEDULED:
        if not msg.scheduled_release_at:
            return False, "SCHEDULE_MISSING"
        if datetime.utcnow() < msg.scheduled_release_at:
            return False, "SCHEDULE_NOT_REACHED"
        return True, "SCHEDULE_OK"

    if cond == ReleaseCondition.ON_DEATH:
        # Require a VERIFIED life event of category DEATH for the owner
        death = (
            db.query(LifeEvent)
            .filter(
                LifeEvent.owner_id == msg.owner_id,
                LifeEvent.category == LifeEventCategory.DEATH,
                LifeEvent.status == LifeEventStatus.VERIFIED,
            )
            .first()
        )
        if not death:
            return False, "ON_DEATH_REQUIRED"
        return True, "ON_DEATH_OK"

    if cond == ReleaseCondition.TRUSTED_CONSENSUS:
        n = count_valid_confirmations(db, msg.id)
        # Exclude self-confirmations (owner as TC)
        # count_valid_confirmations already filters; we also reject self in add_confirmation
        if n < msg.required_confirmations:
            return False, "QUORUM_NOT_MET"
        return True, "QUORUM_OK"

    return False, "UNKNOWN_CONDITION"


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
    current = msg.release_state
    if isinstance(current, str):
        current = ReleaseState(current)

    allowed = RELEASE_TRANSITIONS.get(current, set())
    # force_admin may skip graph ONLY for non-terminal operational states —
    # NEVER for RELEASED without policy satisfaction.
    if to_state not in allowed:
        if not force_admin:
            raise ReleaseError(
                f"Transition {current.value} → {to_state.value} is not permitted",
                code="INVALID_TRANSITION",
            )
        if to_state == ReleaseState.RELEASED:
            raise ReleaseError(
                "force_admin cannot move a message to RELEASED; policy must be satisfied",
                code="FORCE_ADMIN_BLOCKED",
            )

    if to_state == ReleaseState.RELEASED:
        ok, code = _policy_satisfied(db, msg)
        if not ok:
            raise ReleaseError(
                f"Release condition not satisfied: {code}",
                code="POLICY_NOT_SATISFIED",
            )

    _record_transition(db, msg, current, to_state, actor_id, reason, metadata)
    msg.release_state = to_state

    if to_state == ReleaseState.RELEASED:
        msg.is_released = True
        msg.released_at = datetime.utcnow()
    if to_state in (ReleaseState.VERIFICATION_REQUIRED, ReleaseState.RELEASE_PENDING, ReleaseState.VERIFIED):
        msg.policy_frozen = True
    if to_state == ReleaseState.CANCELLED:
        msg.policy_frozen = False
        for c in list(msg.confirmations):
            if c.is_valid and c.revoked_at is None:
                c.is_valid = False
                c.revoked_at = datetime.utcnow()

    return msg


def count_valid_confirmations(db: Session, message_id: str) -> int:
    """Count valid confirmations excluding self-confirmations by the owner."""
    msg = db.query(LegacyMessage).filter(LegacyMessage.id == message_id).first()
    rows = (
        db.query(ReleaseConfirmation)
        .filter(
            ReleaseConfirmation.legacy_message_id == message_id,
            ReleaseConfirmation.is_valid == True,
            ReleaseConfirmation.revoked_at.is_(None),
        )
        .all()
    )
    if not msg:
        return len(rows)
    count = 0
    for c in rows:
        tc = db.query(FamilyMember).filter(FamilyMember.id == c.trusted_contact_id).first()
        if not tc:
            continue
        # Exclude owner self-confirmation
        if tc.related_user_id and tc.related_user_id == msg.owner_id:
            continue
        if c.actor_user_id and c.actor_user_id == msg.owner_id:
            continue
        count += 1
    return count


def add_confirmation(
    db: Session,
    msg: LegacyMessage,
    trusted_contact: FamilyMember,
    actor_user_id: str | None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    confirmation_type: ConfirmationType = ConfirmationType.RELEASE_TRIGGER,
) -> ReleaseConfirmation:
    if not trusted_contact.is_trusted_contact:
        raise ReleaseError("Family member is not a trusted contact", code="NOT_TRUSTED")
    if trusted_contact.owner_id != msg.owner_id:
        raise ReleaseError("Trusted contact does not belong to message owner", code="OWNER_MISMATCH")

    # Owner cannot confirm as their own trusted contact
    if actor_user_id and actor_user_id == msg.owner_id:
        raise ReleaseError(
            "Owner cannot submit confirmation as trusted contact",
            code="OWNER_AS_TC",
        )
    if trusted_contact.related_user_id and trusted_contact.related_user_id == msg.owner_id:
        raise ReleaseError(
            "Owner cannot be their own trusted contact for confirmations",
            code="OWNER_AS_TC",
        )

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
    Owner may advance the release pipeline, but NEVER to RELEASED in this call.
    Final RELEASED requires finalize_release after policy is satisfied.
    """
    if msg.owner_id != owner.id:
        raise ReleaseError("Only the owner can initiate this path", code="NOT_OWNER")

    cond = msg.release_condition
    if isinstance(cond, str):
        cond = ReleaseCondition(cond)

    # Hard blocks: conditions that owner alone can never satisfy via this path
    if cond == ReleaseCondition.ON_DEATH:
        ok, code = _policy_satisfied(db, msg)
        if not ok:
            raise ReleaseError(
                "ON_DEATH requires a verified death life-event before release can proceed",
                code="POLICY_NOT_SATISFIED",
            )
    if cond == ReleaseCondition.SCHEDULED:
        ok, code = _policy_satisfied(db, msg)
        if not ok:
            raise ReleaseError(
                f"Scheduled release not yet reachable: {code}",
                code="POLICY_NOT_SATISFIED",
            )
    if cond == ReleaseCondition.TRUSTED_CONSENSUS:
        ok, code = _policy_satisfied(db, msg)
        if not ok:
            raise ReleaseError(
                f"Trusted consensus not met: {code}",
                code="POLICY_NOT_SATISFIED",
            )

    current = msg.release_state if isinstance(msg.release_state, ReleaseState) else ReleaseState(msg.release_state)

    if current == ReleaseState.ACTIVE:
        # Progress toward pending — stop at RELEASE_PENDING, never RELEASED here
        transition(db, msg, ReleaseState.VERIFICATION_REQUIRED, owner.id, reason="owner_request")
        transition(db, msg, ReleaseState.VERIFIED, owner.id, reason="owner_self_verify")
        transition(db, msg, ReleaseState.RELEASE_ELIGIBLE, owner.id, reason="owner_eligible")
        transition(db, msg, ReleaseState.RELEASE_PENDING, owner.id, reason="owner_pending")
        log_action(
            db, "LEGACY_MESSAGE_RELEASE_REQUESTED",
            actor_id=owner.id, resource_type="LegacyMessage", resource_id=msg.id,
            ip_address=ip, user_agent=ua,
            metadata={"path": "owner", "state": "RELEASE_PENDING"},
            commit=False,
        )
        return msg

    if current == ReleaseState.RELEASE_PENDING:
        # Owner still cannot finalize without going through finalize_release
        # which re-checks policy
        raise ReleaseError(
            "Message is RELEASE_PENDING; call finalize_release explicitly",
            code="USE_FINALIZE",
        )

    raise ReleaseError(f"Cannot request release from state {current.value}", code="INVALID_STATE")


def trusted_confirm_and_maybe_release(
    db: Session,
    msg: LegacyMessage,
    trusted_contact: FamilyMember,
    actor_user_id: str | None,
    ip: str | None = None,
    ua: str | None = None,
) -> tuple[LegacyMessage, ReleaseConfirmation]:
    conf = add_confirmation(db, msg, trusted_contact, actor_user_id, ip, ua)

    current = msg.release_state if isinstance(msg.release_state, ReleaseState) else ReleaseState(msg.release_state)
    if current == ReleaseState.ACTIVE:
        transition(db, msg, ReleaseState.VERIFICATION_REQUIRED, actor_user_id, reason="trusted_confirm_start")

    n = count_valid_confirmations(db, msg.id)
    # Only advance toward pending when quorum met AND condition is TRUSTED_CONSENSUS or allows it
    cond = msg.release_condition
    if isinstance(cond, str):
        cond = ReleaseCondition(cond)

    if n >= msg.required_confirmations and cond in (
        ReleaseCondition.TRUSTED_CONSENSUS, ReleaseCondition.MANUAL
    ):
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
    RELEASE_PENDING → RELEASED only when policy is satisfied.
    Admin cannot bypass policy.
    """
    if msg.owner_id != actor.id and actor.role != Role.ADMIN:
        raise ReleaseError("Only owner or admin may finalize release", code="FORBIDDEN")

    current = msg.release_state if isinstance(msg.release_state, ReleaseState) else ReleaseState(msg.release_state)
    if current != ReleaseState.RELEASE_PENDING:
        raise ReleaseError(
            f"Finalize requires RELEASE_PENDING, current is {current.value}",
            code="INVALID_STATE",
        )

    ok, code = _policy_satisfied(db, msg)
    if not ok:
        raise ReleaseError(
            f"Cannot finalize: release condition not satisfied ({code})",
            code="POLICY_NOT_SATISFIED",
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
    current = msg.release_state if isinstance(msg.release_state, ReleaseState) else ReleaseState(msg.release_state)
    if current == ReleaseState.RELEASED:
        raise ReleaseError("Cannot cancel an already released message", code="ALREADY_RELEASED")

    transition(db, msg, ReleaseState.CANCELLED, actor.id, reason=reason)
    log_action(
        db, "LEGACY_MESSAGE_RELEASE_CANCELLED",
        actor_id=actor.id, resource_type="LegacyMessage", resource_id=msg.id,
        ip_address=ip, user_agent=ua, metadata={"reason": reason}, commit=False,
    )
    return msg
