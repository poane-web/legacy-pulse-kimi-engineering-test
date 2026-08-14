"""
Legacy Pulse – FastAPI application entry point.
Secure digital legacy platform MVP.
"""
import os
import uuid
import json
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from pathlib import Path

from fastapi import FastAPI, Depends, HTTPException, status, Request, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import StreamingResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.core.config import get_settings
from app.core.database import engine, Base, get_db, SessionLocal
from app.core.security import (
    hash_password, verify_password, create_access_token, create_refresh_token,
    hash_token, decode_access_token, encrypt_text, decrypt_text, encrypt_file, decrypt_file
)
from app.models.models import (
    User, Profile, FamilyMember, Memory, MediaAsset, LifeEvent, LegacyMessage,
    Notification, AuditLog, RefreshToken, Role, AccessLevel, MediaType,
    ReleaseCondition, LifeEventCategory
)
from app.models.schemas import (
    RegisterRequest, LoginRequest, TokenResponse, RefreshRequest,
    ProfileUpdate, UserResponse, FamilyMemberCreate, FamilyMemberUpdate,
    FamilyMemberResponse, MemoryCreate, MemoryUpdate, MemoryResponse,
    LifeEventCreate, LifeEventResponse, LegacyMessageCreate, LegacyMessageResponse,
    MediaResponse, NotificationResponse, AuditLogResponse, MessageResponse
)
from app.services.audit import log_action

settings = get_settings()
security = HTTPBearer(auto_error=False)

app = FastAPI(
    title="Legacy Pulse API",
    description="Secure digital legacy platform – Engineering MVP",
    version="0.1.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS + ["*"] if settings.DEBUG else settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ensure upload dir exists
Path(settings.UPLOAD_DIR).mkdir(parents=True, exist_ok=True)


# ---------- Startup ----------
@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)
    # Seed if empty
    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            _seed_demo_data(db)
    finally:
        db.close()


def _seed_demo_data(db: Session):
    """Create demo accounts and sample data."""
    admin_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    beneficiary_id = str(uuid.uuid4())

    admin = User(
        id=admin_id,
        email="admin@legacypulse.demo",
        password_hash=hash_password("Admin123!"),
        first_name="System",
        last_name="Admin",
        role=Role.ADMIN,
        is_active=True,
    )
    user = User(
        id=user_id,
        email="alex@legacypulse.demo",
        password_hash=hash_password("Legacy123!"),
        first_name="Alex",
        last_name="Morgan",
        role=Role.USER,
        is_active=True,
    )
    db.add_all([admin, user])
    db.flush()

    db.add(Profile(id=str(uuid.uuid4()), user_id=admin_id, bio="Platform administrator"))
    db.add(Profile(id=str(uuid.uuid4()), user_id=user_id, bio="Demo legacy owner", location="Portland, OR"))

    # Family
    spouse = FamilyMember(
        id=str(uuid.uuid4()),
        owner_id=user_id,
        name="Jordan Morgan",
        email="jordan@example.com",
        relationship="Spouse",
        is_beneficiary=True,
        is_trusted_contact=True,
        access_level=AccessLevel.FULL,
    )
    child = FamilyMember(
        id=str(uuid.uuid4()),
        owner_id=user_id,
        name="Sam Morgan",
        email="sam@example.com",
        relationship="Child",
        is_beneficiary=True,
        access_level=AccessLevel.VIEW,
    )
    db.add_all([spouse, child])
    db.flush()

    # Memory
    ct, iv, _ = encrypt_text("The summer we spent at the lake house in 2019. Best days of my life.")
    mem = Memory(
        id=str(uuid.uuid4()),
        owner_id=user_id,
        title="Lake House Summer 2019",
        content_encrypted=ct,
        content_iv=iv,
        memory_date=datetime(2019, 7, 15),
        location="Lake Tahoe",
        tags=json.dumps(["family", "vacation"]),
    )
    db.add(mem)

    # Life event
    ct2, iv2, _ = encrypt_text("Graduated with honors in Computer Science.")
    le = LifeEvent(
        id=str(uuid.uuid4()),
        owner_id=user_id,
        title="University Graduation",
        description_encrypted=ct2,
        description_iv=iv2,
        event_date=datetime(2012, 6, 10),
        category=LifeEventCategory.GRADUATION,
    )
    db.add(le)

    # Legacy message
    ct3, iv3, _ = encrypt_text(
        "My dearest Jordan and Sam,\n\nIf you are reading this, it means the time has come. "
        "I want you to know how much I love you. Take care of each other. "
        "The safe combination is written in the red notebook.\n\nWith all my love,\nAlex"
    )
    lm = LegacyMessage(
        id=str(uuid.uuid4()),
        owner_id=user_id,
        title="Final Words for My Family",
        body_encrypted=ct3,
        body_iv=iv3,
        recipient_id=spouse.id,
        release_condition=ReleaseCondition.MANUAL,
        is_released=False,
    )
    db.add(lm)

    db.commit()
    print("Demo data seeded successfully.")


# ---------- Auth helpers ----------
def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = decode_access_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = db.query(User).filter(User.id == payload["sub"]).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != Role.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def get_client_info(request: Request) -> tuple[str | None, str | None]:
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")
    return ip, ua


# ---------- Auth Routes ----------
@app.post("/api/auth/register", response_model=TokenResponse, status_code=201)
def register(body: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == body.email.lower()).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    user_id = str(uuid.uuid4())
    user = User(
        id=user_id,
        email=body.email.lower(),
        password_hash=hash_password(body.password),
        first_name=body.first_name,
        last_name=body.last_name,
        role=Role.USER,
    )
    db.add(user)
    db.add(Profile(id=str(uuid.uuid4()), user_id=user_id))
    db.commit()

    access = create_access_token(user.id, user.role.value, user.email)
    refresh = create_refresh_token()
    rt = RefreshToken(
        id=str(uuid.uuid4()),
        user_id=user.id,
        token_hash=hash_token(refresh),
        expires_at=datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )
    db.add(rt)
    db.commit()

    ip, ua = get_client_info(request)
    log_action(db, "USER_REGISTER", actor_id=user.id, ip_address=ip, user_agent=ua)

    return TokenResponse(
        access_token=access,
        refresh_token=refresh,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@app.post("/api/auth/login", response_model=TokenResponse)
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.email.lower()).first()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is deactivated")

    user.last_login_at = datetime.utcnow()
    access = create_access_token(user.id, user.role.value, user.email)
    refresh = create_refresh_token()
    rt = RefreshToken(
        id=str(uuid.uuid4()),
        user_id=user.id,
        token_hash=hash_token(refresh),
        expires_at=datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )
    db.add(rt)
    db.commit()

    ip, ua = get_client_info(request)
    log_action(db, "USER_LOGIN", actor_id=user.id, ip_address=ip, user_agent=ua)

    return TokenResponse(
        access_token=access,
        refresh_token=refresh,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@app.post("/api/auth/refresh", response_model=TokenResponse)
def refresh_token(body: RefreshRequest, db: Session = Depends(get_db)):
    token_hash = hash_token(body.refresh_token)
    rt = db.query(RefreshToken).filter(
        RefreshToken.token_hash == token_hash,
        RefreshToken.revoked_at.is_(None),
        RefreshToken.expires_at > datetime.utcnow(),
    ).first()
    if not rt:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    user = db.query(User).filter(User.id == rt.user_id).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User invalid")

    # Rotate
    rt.revoked_at = datetime.utcnow()
    new_refresh = create_refresh_token()
    new_rt = RefreshToken(
        id=str(uuid.uuid4()),
        user_id=user.id,
        token_hash=hash_token(new_refresh),
        expires_at=datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )
    db.add(new_rt)
    db.commit()

    access = create_access_token(user.id, user.role.value, user.email)
    return TokenResponse(
        access_token=access,
        refresh_token=new_refresh,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@app.post("/api/auth/logout", response_model=MessageResponse)
def logout(
    body: RefreshRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    token_hash = hash_token(body.refresh_token)
    rt = db.query(RefreshToken).filter(
        RefreshToken.token_hash == token_hash,
        RefreshToken.user_id == user.id,
    ).first()
    if rt:
        rt.revoked_at = datetime.utcnow()
        db.commit()
    return MessageResponse(message="Logged out")


# ---------- User ----------
@app.get("/api/users/me", response_model=UserResponse)
def get_me(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    profile = db.query(Profile).filter(Profile.user_id == user.id).first()
    return UserResponse(
        id=user.id,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        role=user.role,
        is_active=user.is_active,
        created_at=user.created_at,
        last_login_at=user.last_login_at,
        profile={
            "bio": profile.bio if profile else None,
            "location": profile.location if profile else None,
            "date_of_birth": profile.date_of_birth.isoformat() if profile and profile.date_of_birth else None,
        } if profile else None,
    )


@app.patch("/api/users/me", response_model=UserResponse)
def update_me(
    body: ProfileUpdate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    profile = db.query(Profile).filter(Profile.user_id == user.id).first()
    if not profile:
        profile = Profile(id=str(uuid.uuid4()), user_id=user.id)
        db.add(profile)
    if body.bio is not None:
        profile.bio = body.bio
    if body.location is not None:
        profile.location = body.location
    if body.date_of_birth is not None:
        profile.date_of_birth = body.date_of_birth
    db.commit()
    return get_me(user, db)


# ---------- Family ----------
@app.get("/api/family", response_model=List[FamilyMemberResponse])
def list_family(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    members = db.query(FamilyMember).filter(FamilyMember.owner_id == user.id).all()
    result = []
    for m in members:
        notes = None
        if m.notes_encrypted and m.notes_iv:
            try:
                notes = decrypt_text(m.notes_encrypted, m.notes_iv)
            except Exception:
                notes = None
        result.append(FamilyMemberResponse(
            id=m.id, name=m.name, email=m.email, relationship=m.relationship,
            is_beneficiary=m.is_beneficiary, is_trusted_contact=m.is_trusted_contact,
            access_level=m.access_level, notes=notes, created_at=m.created_at,
        ))
    return result


@app.post("/api/family", response_model=FamilyMemberResponse, status_code=201)
def create_family(
    body: FamilyMemberCreate,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    notes_enc, notes_iv = None, None
    if body.notes:
        notes_enc, notes_iv, _ = encrypt_text(body.notes)
    member = FamilyMember(
        id=str(uuid.uuid4()),
        owner_id=user.id,
        name=body.name,
        email=body.email,
        relationship=body.relationship,
        is_beneficiary=body.is_beneficiary,
        is_trusted_contact=body.is_trusted_contact,
        access_level=body.access_level,
        notes_encrypted=notes_enc,
        notes_iv=notes_iv,
    )
    db.add(member)
    db.commit()
    ip, ua = get_client_info(request)
    log_action(db, "FAMILY_MEMBER_CREATE", actor_id=user.id, resource_type="FamilyMember",
               resource_id=member.id, ip_address=ip, user_agent=ua)
    return FamilyMemberResponse(
        id=member.id, name=member.name, email=member.email, relationship=member.relationship,
        is_beneficiary=member.is_beneficiary, is_trusted_contact=member.is_trusted_contact,
        access_level=member.access_level, notes=body.notes, created_at=member.created_at,
    )


@app.delete("/api/family/{member_id}", response_model=MessageResponse)
def delete_family(
    member_id: str,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    member = db.query(FamilyMember).filter(
        FamilyMember.id == member_id, FamilyMember.owner_id == user.id
    ).first()
    if not member:
        raise HTTPException(status_code=404, detail="Not found")
    db.delete(member)
    db.commit()
    ip, ua = get_client_info(request)
    log_action(db, "FAMILY_MEMBER_DELETE", actor_id=user.id, resource_type="FamilyMember",
               resource_id=member_id, ip_address=ip, user_agent=ua)
    return MessageResponse(message="Deleted")


# ---------- Memories ----------
@app.get("/api/memories", response_model=List[MemoryResponse])
def list_memories(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    memories = db.query(Memory).filter(Memory.owner_id == user.id).order_by(Memory.created_at.desc()).all()
    result = []
    for m in memories:
        content = None
        try:
            content = decrypt_text(m.content_encrypted, m.content_iv)
        except Exception:
            content = "[decryption error]"
        tags = json.loads(m.tags or "[]")
        result.append(MemoryResponse(
            id=m.id, title=m.title, content=content, memory_date=m.memory_date,
            location=m.location, is_private=m.is_private, tags=tags,
            created_at=m.created_at, updated_at=m.updated_at,
        ))
    return result


@app.post("/api/memories", response_model=MemoryResponse, status_code=201)
def create_memory(
    body: MemoryCreate,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    ct, iv, _ = encrypt_text(body.content)
    mem = Memory(
        id=str(uuid.uuid4()),
        owner_id=user.id,
        title=body.title,
        content_encrypted=ct,
        content_iv=iv,
        memory_date=body.memory_date,
        location=body.location,
        is_private=body.is_private,
        tags=json.dumps(body.tags),
    )
    db.add(mem)
    db.commit()
    ip, ua = get_client_info(request)
    log_action(db, "MEMORY_CREATE", actor_id=user.id, resource_type="Memory",
               resource_id=mem.id, ip_address=ip, user_agent=ua)
    return MemoryResponse(
        id=mem.id, title=mem.title, content=body.content, memory_date=mem.memory_date,
        location=mem.location, is_private=mem.is_private, tags=body.tags,
        created_at=mem.created_at, updated_at=mem.updated_at,
    )


@app.delete("/api/memories/{memory_id}", response_model=MessageResponse)
def delete_memory(
    memory_id: str,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    mem = db.query(Memory).filter(Memory.id == memory_id, Memory.owner_id == user.id).first()
    if not mem:
        raise HTTPException(status_code=404, detail="Not found")
    db.delete(mem)
    db.commit()
    ip, ua = get_client_info(request)
    log_action(db, "MEMORY_DELETE", actor_id=user.id, resource_type="Memory",
               resource_id=memory_id, ip_address=ip, user_agent=ua)
    return MessageResponse(message="Deleted")


# ---------- Life Events ----------
@app.get("/api/life-events", response_model=List[LifeEventResponse])
def list_life_events(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    events = db.query(LifeEvent).filter(LifeEvent.owner_id == user.id).order_by(LifeEvent.event_date.desc()).all()
    result = []
    for e in events:
        desc = None
        if e.description_encrypted and e.description_iv:
            try:
                desc = decrypt_text(e.description_encrypted, e.description_iv)
            except Exception:
                pass
        result.append(LifeEventResponse(
            id=e.id, title=e.title, description=desc, event_date=e.event_date,
            category=e.category, created_at=e.created_at,
        ))
    return result


@app.post("/api/life-events", response_model=LifeEventResponse, status_code=201)
def create_life_event(
    body: LifeEventCreate,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    desc_enc, desc_iv = None, None
    if body.description:
        desc_enc, desc_iv, _ = encrypt_text(body.description)
    event = LifeEvent(
        id=str(uuid.uuid4()),
        owner_id=user.id,
        title=body.title,
        description_encrypted=desc_enc,
        description_iv=desc_iv,
        event_date=body.event_date,
        category=body.category,
    )
    db.add(event)
    db.commit()
    ip, ua = get_client_info(request)
    log_action(db, "LIFE_EVENT_CREATE", actor_id=user.id, resource_type="LifeEvent",
               resource_id=event.id, ip_address=ip, user_agent=ua)
    return LifeEventResponse(
        id=event.id, title=event.title, description=body.description,
        event_date=event.event_date, category=event.category, created_at=event.created_at,
    )


# ---------- Legacy Messages ----------
@app.get("/api/legacy-messages", response_model=List[LegacyMessageResponse])
def list_legacy_messages(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    msgs = db.query(LegacyMessage).filter(LegacyMessage.owner_id == user.id).order_by(LegacyMessage.created_at.desc()).all()
    result = []
    for m in msgs:
        body = None
        # Owner always sees content
        try:
            body = decrypt_text(m.body_encrypted, m.body_iv)
        except Exception:
            body = "[decryption error]"
        result.append(LegacyMessageResponse(
            id=m.id, title=m.title, body=body, recipient_id=m.recipient_id,
            release_condition=m.release_condition, scheduled_release_at=m.scheduled_release_at,
            is_released=m.is_released, released_at=m.released_at, created_at=m.created_at,
        ))
    return result


@app.post("/api/legacy-messages", response_model=LegacyMessageResponse, status_code=201)
def create_legacy_message(
    body: LegacyMessageCreate,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    ct, iv, _ = encrypt_text(body.body)
    msg = LegacyMessage(
        id=str(uuid.uuid4()),
        owner_id=user.id,
        title=body.title,
        body_encrypted=ct,
        body_iv=iv,
        recipient_id=body.recipient_id,
        release_condition=body.release_condition,
        scheduled_release_at=body.scheduled_release_at,
    )
    db.add(msg)
    db.commit()
    ip, ua = get_client_info(request)
    log_action(db, "LEGACY_MESSAGE_CREATE", actor_id=user.id, resource_type="LegacyMessage",
               resource_id=msg.id, ip_address=ip, user_agent=ua)
    return LegacyMessageResponse(
        id=msg.id, title=msg.title, body=body.body, recipient_id=msg.recipient_id,
        release_condition=msg.release_condition, scheduled_release_at=msg.scheduled_release_at,
        is_released=False, released_at=None, created_at=msg.created_at,
    )


@app.post("/api/legacy-messages/{msg_id}/release", response_model=LegacyMessageResponse)
def release_legacy_message(
    msg_id: str,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    msg = db.query(LegacyMessage).filter(LegacyMessage.id == msg_id).first()
    if not msg:
        raise HTTPException(status_code=404, detail="Not found")
    # Owner or trusted contact of owner can release
    if msg.owner_id != user.id:
        # Check if current user is a trusted contact of the owner
        trusted = db.query(FamilyMember).filter(
            FamilyMember.owner_id == msg.owner_id,
            FamilyMember.is_trusted_contact == True,
            # In a full system we would link related_user_id; for MVP owner only for simplicity
        ).first()
        if user.role != Role.ADMIN:
            raise HTTPException(status_code=403, detail="Not authorized to release")
    if msg.is_released:
        raise HTTPException(status_code=400, detail="Already released")
    msg.is_released = True
    msg.released_at = datetime.utcnow()
    db.commit()
    ip, ua = get_client_info(request)
    log_action(db, "LEGACY_MESSAGE_RELEASE", actor_id=user.id, resource_type="LegacyMessage",
               resource_id=msg_id, ip_address=ip, user_agent=ua)
    body = decrypt_text(msg.body_encrypted, msg.body_iv)
    return LegacyMessageResponse(
        id=msg.id, title=msg.title, body=body, recipient_id=msg.recipient_id,
        release_condition=msg.release_condition, scheduled_release_at=msg.scheduled_release_at,
        is_released=True, released_at=msg.released_at, created_at=msg.created_at,
    )


# ---------- Media Upload ----------
@app.post("/api/media", response_model=MediaResponse, status_code=201)
async def upload_media(
    request: Request,
    file: UploadFile = File(...),
    type: str = Form("DOCUMENT"),
    memory_id: Optional[str] = Form(None),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if file.size and file.size > settings.MAX_UPLOAD_SIZE:
        raise HTTPException(status_code=400, detail="File too large (max 10MB)")
    content = await file.read()
    if len(content) > settings.MAX_UPLOAD_SIZE:
        raise HTTPException(status_code=400, detail="File too large")

    media_type = MediaType.PHOTO if type.upper() == "PHOTO" else MediaType.DOCUMENT
    ciphertext, iv = encrypt_file(content)
    storage_name = str(uuid.uuid4())
    path = Path(settings.UPLOAD_DIR) / storage_name
    path.write_bytes(ciphertext)

    asset = MediaAsset(
        id=str(uuid.uuid4()),
        owner_id=user.id,
        memory_id=memory_id,
        type=media_type,
        original_name=file.filename or "unknown",
        mime_type=file.content_type or "application/octet-stream",
        size=len(content),
        storage_path=storage_name,
        encryption_iv=iv.hex(),
    )
    db.add(asset)
    db.commit()
    ip, ua = get_client_info(request)
    log_action(db, "MEDIA_UPLOAD", actor_id=user.id, resource_type="MediaAsset",
               resource_id=asset.id, ip_address=ip, user_agent=ua)
    return MediaResponse(
        id=asset.id, type=asset.type, original_name=asset.original_name,
        mime_type=asset.mime_type, size=asset.size, is_released=False,
        created_at=asset.created_at, memory_id=asset.memory_id,
    )


@app.get("/api/media")
def list_media(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    assets = db.query(MediaAsset).filter(MediaAsset.owner_id == user.id).all()
    return [
        MediaResponse(
            id=a.id, type=a.type, original_name=a.original_name, mime_type=a.mime_type,
            size=a.size, is_released=a.is_released, created_at=a.created_at, memory_id=a.memory_id,
        ) for a in assets
    ]


@app.get("/api/media/{asset_id}/download")
def download_media(
    asset_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    asset = db.query(MediaAsset).filter(MediaAsset.id == asset_id, MediaAsset.owner_id == user.id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Not found")
    path = Path(settings.UPLOAD_DIR) / asset.storage_path
    if not path.exists():
        raise HTTPException(status_code=404, detail="File missing")
    ciphertext = path.read_bytes()
    iv = bytes.fromhex(asset.encryption_iv)
    plaintext = decrypt_file(ciphertext, iv)
    return StreamingResponse(
        iter([plaintext]),
        media_type=asset.mime_type,
        headers={"Content-Disposition": f'attachment; filename="{asset.original_name}"'},
    )


# ---------- Notifications ----------
@app.get("/api/notifications", response_model=List[NotificationResponse])
def list_notifications(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    notes = db.query(Notification).filter(Notification.user_id == user.id).order_by(Notification.created_at.desc()).limit(50).all()
    return [NotificationResponse.model_validate(n) for n in notes]


# ---------- Audit ----------
@app.get("/api/audit", response_model=List[AuditLogResponse])
def list_audit(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = db.query(AuditLog)
    if user.role != Role.ADMIN:
        q = q.filter(AuditLog.actor_id == user.id)
    logs = q.order_by(AuditLog.created_at.desc()).limit(100).all()
    return [
        AuditLogResponse(
            id=l.id, action=l.action, resource_type=l.resource_type, resource_id=l.resource_id,
            ip_address=l.ip_address, created_at=l.created_at, actor_id=l.actor_id,
        ) for l in logs
    ]


# ---------- Admin ----------
@app.get("/api/admin/users")
def admin_list_users(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    users = db.query(User).all()
    return [
        {
            "id": u.id, "email": u.email, "first_name": u.first_name, "last_name": u.last_name,
            "role": u.role.value, "is_active": u.is_active, "created_at": u.created_at.isoformat(),
        } for u in users
    ]


@app.get("/api/admin/stats")
def admin_stats(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    return {
        "users": db.query(User).count(),
        "memories": db.query(Memory).count(),
        "legacy_messages": db.query(LegacyMessage).count(),
        "media_assets": db.query(MediaAsset).count(),
        "audit_entries": db.query(AuditLog).count(),
    }


# ---------- Search ----------
@app.get("/api/search")
def search(q: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not q or len(q) < 2:
        return {"memories": [], "life_events": [], "legacy_messages": []}
    # Simple title search (content is encrypted so we cannot search body easily)
    memories = db.query(Memory).filter(
        Memory.owner_id == user.id,
        Memory.title.ilike(f"%{q}%"),
    ).limit(10).all()
    events = db.query(LifeEvent).filter(
        LifeEvent.owner_id == user.id,
        LifeEvent.title.ilike(f"%{q}%"),
    ).limit(10).all()
    msgs = db.query(LegacyMessage).filter(
        LegacyMessage.owner_id == user.id,
        LegacyMessage.title.ilike(f"%{q}%"),
    ).limit(10).all()
    return {
        "memories": [{"id": m.id, "title": m.title} for m in memories],
        "life_events": [{"id": e.id, "title": e.title} for e in events],
        "legacy_messages": [{"id": m.id, "title": m.title} for m in msgs],
    }


# ---------- Health ----------
@app.get("/api/health")
def health():
    return {"status": "ok", "app": settings.APP_NAME, "env": settings.APP_ENV}


# Serve frontend
static_dir = Path(__file__).parent.parent / "static"
if static_dir.exists():
    app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=3001, reload=True)
