"""
ATTACKER TESTS — Legacy Pulse release invariants.

Every test models an authenticated attacker. A green suite is not evidence of
security unless these attacker tests pass.

Invariant:
  No Legacy Pulse asset may reach is_released=True / RELEASED unless the
  exact release_condition for that asset has been satisfied.

Run: PYTHONPATH=. pytest tests/test_attacker_release.py -v
"""
from __future__ import annotations

import os
import sys
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock

os.environ.setdefault("JWT_SECRET_KEY", "test-jwt-secret-key-must-be-at-least-32-chars")
os.environ.setdefault(
    "MASTER_KEY_HEX",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
)
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.core.security import hash_password, create_access_token, decode_access_token
from app.core.step_up import create_step_up_token, verify_step_up_token, SCOPE_RELEASE_FINALIZE
from app.core.confirmation_tokens import issue_confirmation_token, verify_confirmation_token
from app.core.crypto import encrypt_user_text, decrypt_user_text
from app.models.models import (
    User, Role, FamilyMember, LegacyMessage, ReleaseState, ReleaseCondition,
    AccessLevel, ReleaseConfirmation, ConfirmationType, Memory, MediaAsset,
    MediaType, AuditLog, RELEASE_TRANSITIONS,
)
from app.services.release_engine import (
    owner_request_release, finalize_release, cancel_release,
    trusted_confirm_and_maybe_release, transition, ReleaseError,
    add_confirmation, count_valid_confirmations,
)


# ---------- Fixtures ----------

@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def make_user(db, email="owner@test.com", role=Role.USER) -> User:
    u = User(
        id=str(uuid.uuid4()),
        email=email,
        password_hash=hash_password("Password1!"),
        first_name="Test",
        last_name="User",
        role=role,
        is_active=True,
    )
    db.add(u)
    db.flush()
    return u


def make_message(
    db,
    owner: User,
    condition: ReleaseCondition = ReleaseCondition.MANUAL,
    required_confirmations: int = 2,
    scheduled_release_at: datetime | None = None,
    state: ReleaseState = ReleaseState.ACTIVE,
) -> LegacyMessage:
    body = encrypt_user_text("classified legacy content", owner.id)
    msg = LegacyMessage(
        id=str(uuid.uuid4()),
        owner_id=owner.id,
        title="Attack surface message",
        body_encrypted=body,
        encryption_version=2,
        release_condition=condition,
        required_confirmations=required_confirmations,
        scheduled_release_at=scheduled_release_at,
        release_state=state,
        is_released=False,
        policy_frozen=False,
    )
    db.add(msg)
    db.flush()
    return msg


def make_trusted_contact(db, owner: User, related_user: User | None = None) -> FamilyMember:
    fm = FamilyMember(
        id=str(uuid.uuid4()),
        owner_id=owner.id,
        related_user_id=related_user.id if related_user else None,
        name="Trusted Contact",
        email="tc@test.com",
        relationship="friend",
        is_trusted_contact=True,
        is_beneficiary=False,
        access_level=AccessLevel.NONE,
    )
    db.add(fm)
    db.flush()
    return fm


# =====================================================================
# ATTACK: Owner-as-trusted-contact
# =====================================================================

def test_attack_owner_cannot_confirm_as_own_trusted_contact(db):
    """Owner must not satisfy TRUSTED_CONSENSUS by confirming as their own TC."""
    owner = make_user(db, "owner@x.com")
    # Owner lists themselves as trusted contact
    self_tc = FamilyMember(
        id=str(uuid.uuid4()),
        owner_id=owner.id,
        related_user_id=owner.id,  # self-link
        name="Myself",
        relationship="self",
        is_trusted_contact=True,
        access_level=AccessLevel.NONE,
    )
    db.add(self_tc)
    msg = make_message(db, owner, ReleaseCondition.TRUSTED_CONSENSUS, required_confirmations=1)
    db.commit()

    with pytest.raises(ReleaseError) as ei:
        trusted_confirm_and_maybe_release(db, msg, self_tc, actor_user_id=owner.id)
    assert ei.value.code in ("SELF_CONFIRM_FORBIDDEN", "NOT_TRUSTED", "FORBIDDEN", "OWNER_AS_TC")
    assert msg.is_released is False
    assert msg.release_state != ReleaseState.RELEASED


# =====================================================================
# ATTACK: Admin bypass from ACTIVE
# =====================================================================

def test_attack_admin_cannot_finalize_from_active(db):
    """Admin must not release a message still in ACTIVE."""
    owner = make_user(db, "owner2@x.com")
    admin = make_user(db, "admin@x.com", role=Role.ADMIN)
    msg = make_message(db, owner, ReleaseCondition.MANUAL, required_confirmations=2)
    db.commit()

    with pytest.raises(ReleaseError):
        finalize_release(db, msg, admin)
    assert msg.is_released is False
    assert msg.release_state == ReleaseState.ACTIVE


def test_attack_admin_cannot_skip_policy_via_force(db):
    """force_admin must not be usable to jump ACTIVE → RELEASED."""
    owner = make_user(db, "owner3@x.com")
    admin = make_user(db, "admin2@x.com", role=Role.ADMIN)
    msg = make_message(db, owner, ReleaseCondition.ON_DEATH, required_confirmations=2)
    db.commit()

    with pytest.raises(ReleaseError):
        transition(db, msg, ReleaseState.RELEASED, admin.id, force_admin=True)
    # Even if transition allows force_admin, higher-level policy must block RELEASED
    # without satisfied condition — force_admin should be removed or policy-gated
    assert msg.is_released is False or msg.release_condition == ReleaseCondition.ON_DEATH and not msg.is_released


# =====================================================================
# ATTACK: Owner single-call full release (condition bypass)
# =====================================================================

def test_attack_owner_cannot_release_on_death_without_death_event(db):
    """ON_DEATH message must not reach RELEASED via owner /release path."""
    owner = make_user(db, "owner4@x.com")
    msg = make_message(db, owner, ReleaseCondition.ON_DEATH, required_confirmations=1)
    db.commit()

    with pytest.raises(ReleaseError) as ei:
        owner_request_release(db, msg, owner)
    assert msg.is_released is False
    assert msg.release_state != ReleaseState.RELEASED
    assert ei.value.code in ("CONDITION_NOT_MET", "ON_DEATH_REQUIRED", "INVALID_CONDITION", "POLICY_NOT_SATISFIED")


def test_attack_owner_cannot_release_scheduled_early(db):
    """SCHEDULED message must not release before scheduled_release_at."""
    owner = make_user(db, "owner5@x.com")
    future = datetime.utcnow() + timedelta(days=30)
    msg = make_message(
        db, owner, ReleaseCondition.SCHEDULED,
        required_confirmations=1, scheduled_release_at=future,
    )
    db.commit()

    with pytest.raises(ReleaseError) as ei:
        owner_request_release(db, msg, owner)
    assert msg.is_released is False
    assert ei.value.code in ("CONDITION_NOT_MET", "SCHEDULE_NOT_REACHED", "POLICY_NOT_SATISFIED")


def test_attack_owner_cannot_bypass_trusted_consensus_quorum(db):
    """TRUSTED_CONSENSUS with required_confirmations=2 must not release with 0 confirms."""
    owner = make_user(db, "owner6@x.com")
    msg = make_message(db, owner, ReleaseCondition.TRUSTED_CONSENSUS, required_confirmations=2)
    db.commit()

    with pytest.raises(ReleaseError) as ei:
        owner_request_release(db, msg, owner)
    assert msg.is_released is False
    assert msg.release_state != ReleaseState.RELEASED


def test_attack_owner_manual_still_cannot_chain_to_released_in_one_call(db):
    """
    Even MANUAL must not go ACTIVE→RELEASED inside a single service call.
    Owner may request release; final RELEASED requires explicit finalize after policy checks.
    """
    owner = make_user(db, "owner7@x.com")
    msg = make_message(db, owner, ReleaseCondition.MANUAL, required_confirmations=1)
    db.commit()

    # After owner_request_release, must NOT be RELEASED yet
    result = owner_request_release(db, msg, owner)
    assert result.is_released is False, (
        "CRITICAL: owner_request_release moved message to RELEASED in one call"
    )
    assert result.release_state != ReleaseState.RELEASED


# =====================================================================
# ATTACK: TRUSTED_CONSENSUS quorum bypass
# =====================================================================

def test_attack_single_confirmation_insufficient_for_quorum_2(db):
    owner = make_user(db, "owner8@x.com")
    tc_user = make_user(db, "tc@x.com")
    tc = make_trusted_contact(db, owner, related_user=tc_user)
    msg = make_message(db, owner, ReleaseCondition.TRUSTED_CONSENSUS, required_confirmations=2)
    db.commit()

    trusted_confirm_and_maybe_release(db, msg, tc, actor_user_id=tc_user.id)
    assert msg.is_released is False
    assert msg.release_state != ReleaseState.RELEASED
    # Must not reach RELEASE_PENDING with only 1 of 2 confirms when condition is TRUSTED_CONSENSUS
    n = count_valid_confirmations(db, msg.id)
    assert n == 1
    assert msg.release_state not in (ReleaseState.RELEASE_PENDING, ReleaseState.RELEASED)


def test_attack_duplicate_confirmation_same_contact(db):
    owner = make_user(db, "owner9@x.com")
    tc_user = make_user(db, "tc2@x.com")
    tc = make_trusted_contact(db, owner, related_user=tc_user)
    msg = make_message(db, owner, ReleaseCondition.TRUSTED_CONSENSUS, required_confirmations=2)
    db.commit()

    trusted_confirm_and_maybe_release(db, msg, tc, actor_user_id=tc_user.id)
    with pytest.raises(ReleaseError) as ei:
        trusted_confirm_and_maybe_release(db, msg, tc, actor_user_id=tc_user.id)
    assert ei.value.code == "DUPLICATE_CONFIRMATION"
    assert count_valid_confirmations(db, msg.id) == 1


# =====================================================================
# ATTACK: Confirmation-token replay
# =====================================================================

def test_attack_confirmation_token_replay_after_use(db):
    """Used confirmation nonce/token must not be reusable."""
    owner = make_user(db, "owner10@x.com")
    tc_user = make_user(db, "tc3@x.com")
    tc = make_trusted_contact(db, owner, related_user=tc_user)
    msg = make_message(db, owner, ReleaseCondition.TRUSTED_CONSENSUS, required_confirmations=2)
    db.commit()

    tok = issue_confirmation_token(msg.id, tc.id, msg.release_state.value, ttl_seconds=3600)
    claims = verify_confirmation_token(tok, msg.id, tc.id, msg.release_state.value)
    # Mark nonce as consumed (engine must support this)
    from app.services.release_engine import consume_confirmation_token_nonce
    consume_confirmation_token_nonce(db, claims.nonce)
    db.commit()

    with pytest.raises((ReleaseError, ValueError)):
        # Second verify/consume must fail
        consume_confirmation_token_nonce(db, claims.nonce)


# =====================================================================
# ATTACK: Step-up-token replay
# =====================================================================

def test_attack_step_up_token_cannot_be_reused():
    """Step-up tokens must be single-use (jti blacklist)."""
    from app.core.step_up import consume_step_up_token

    token = create_step_up_token("user-attack", SCOPE_RELEASE_FINALIZE)
    assert verify_step_up_token(token, "user-attack", SCOPE_RELEASE_FINALIZE)
    consume_step_up_token(token)
    # After consume, same token must fail
    assert verify_step_up_token(token, "user-attack", SCOPE_RELEASE_FINALIZE) is False


# =====================================================================
# ATTACK: Cross-user memory/media association
# =====================================================================

def test_attack_cannot_attach_media_to_other_users_memory(db):
    owner = make_user(db, "owner11@x.com")
    attacker = make_user(db, "attacker@x.com")
    mem = Memory(
        id=str(uuid.uuid4()),
        owner_id=owner.id,
        title="Private",
        content_encrypted=encrypt_user_text("secret", owner.id),
        encryption_version=2,
    )
    db.add(mem)
    db.flush()

    # Attacker tries to associate media with owner's memory
    from app.services.media_guard import assert_memory_owned_by
    with pytest.raises(Exception):
        assert_memory_owned_by(db, mem.id, attacker.id)


# =====================================================================
# ATTACK: Policy mutation during release
# =====================================================================

def test_attack_cannot_change_condition_when_policy_frozen(db):
    owner = make_user(db, "owner12@x.com")
    msg = make_message(db, owner, ReleaseCondition.ON_DEATH, required_confirmations=2)
    msg.policy_frozen = True
    msg.release_state = ReleaseState.VERIFICATION_REQUIRED
    db.commit()

    from app.services.release_engine import assert_policy_mutable
    with pytest.raises(ReleaseError) as ei:
        assert_policy_mutable(msg)
        msg.release_condition = ReleaseCondition.MANUAL  # attacker tries to weaken
    assert ei.value.code in ("POLICY_FROZEN", "IMMUTABLE")


# =====================================================================
# ATTACK: JWT / session abuse
# =====================================================================

def test_attack_refresh_token_reuse_after_rotation(db):
    """After rotation, old refresh token hash must not authenticate."""
    from app.core.security import create_refresh_token, hash_token
    from app.models.models import RefreshToken

    user = make_user(db, "rot@x.com")
    old_raw = create_refresh_token()
    family = str(uuid.uuid4())
    rt = RefreshToken(
        id=str(uuid.uuid4()),
        user_id=user.id,
        token_hash=hash_token(old_raw),
        expires_at=datetime.utcnow() + timedelta(days=7),
        family_id=family,
    )
    db.add(rt)
    db.commit()

    # Simulate rotation: revoke old, issue new
    rt.revoked_at = datetime.utcnow()
    new_raw = create_refresh_token()
    new_rt = RefreshToken(
        id=str(uuid.uuid4()),
        user_id=user.id,
        token_hash=hash_token(new_raw),
        expires_at=datetime.utcnow() + timedelta(days=7),
        family_id=family,
        replaced_by=None,
    )
    db.add(new_rt)
    db.commit()

    # Old token must not be accepted
    found = db.query(RefreshToken).filter(
        RefreshToken.token_hash == hash_token(old_raw),
        RefreshToken.revoked_at.is_(None),
        RefreshToken.expires_at > datetime.utcnow(),
    ).first()
    assert found is None


# =====================================================================
# ATTACK: Audit tampering
# =====================================================================

def test_attack_audit_update_should_be_rejected(db):
    """Application must not allow UPDATE of audit rows."""
    from app.services.audit import log_action, assert_audit_immutable

    owner = make_user(db, "aud@x.com")
    entry = log_action(db, "TEST_ACTION", actor_id=owner.id, commit=True)
    with pytest.raises(Exception):
        assert_audit_immutable(db, entry.id)
        entry.action = "TAMPERED"
        db.commit()
        assert_audit_immutable(db, entry.id)  # should detect hash mismatch


# =====================================================================
# ATTACK: Encryption-key misuse — decrypt other user's envelope
# =====================================================================

def test_attack_cannot_decrypt_other_users_envelope(db):
    owner = make_user(db, "enc-owner@x.com")
    attacker = make_user(db, "enc-attacker@x.com")
    stored = encrypt_user_text("family secret", owner.id)
    with pytest.raises(Exception):
        decrypt_user_text(stored, attacker.id)


# =====================================================================
# ATTACK: Concurrent confirmation race (logical)
# =====================================================================

def test_attack_concurrent_duplicate_confirmations_counted_once(db):
    """Two rapid confirms from same contact must not double-count."""
    owner = make_user(db, "race-owner@x.com")
    tc_user = make_user(db, "race-tc@x.com")
    tc = make_trusted_contact(db, owner, related_user=tc_user)
    msg = make_message(db, owner, ReleaseCondition.TRUSTED_CONSENSUS, required_confirmations=2)
    db.commit()

    trusted_confirm_and_maybe_release(db, msg, tc, actor_user_id=tc_user.id)
    with pytest.raises(ReleaseError):
        trusted_confirm_and_maybe_release(db, msg, tc, actor_user_id=tc_user.id)
    assert count_valid_confirmations(db, msg.id) == 1


# =====================================================================
# ATTACK: RELEASED is terminal — no further transitions
# =====================================================================

def test_attack_cannot_unrelease(db):
    owner = make_user(db, "term@x.com")
    msg = make_message(db, owner, state=ReleaseState.RELEASED)
    msg.is_released = True
    db.commit()
    with pytest.raises(ReleaseError):
        transition(db, msg, ReleaseState.ACTIVE, owner.id)
    with pytest.raises(ReleaseError):
        cancel_release(db, msg, owner)
