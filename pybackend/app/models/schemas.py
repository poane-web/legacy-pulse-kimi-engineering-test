"""
Pydantic schemas for request/response validation.
"""
from datetime import datetime
from typing import Optional, List, Any
from pydantic import BaseModel, EmailStr, Field, field_validator
from enum import Enum


class RoleEnum(str, Enum):
    USER = "USER"
    ADMIN = "ADMIN"


class AccessLevelEnum(str, Enum):
    NONE = "NONE"
    VIEW = "VIEW"
    FULL = "FULL"


class MediaTypeEnum(str, Enum):
    PHOTO = "PHOTO"
    DOCUMENT = "DOCUMENT"


class ReleaseConditionEnum(str, Enum):
    SCHEDULED = "SCHEDULED"
    MANUAL = "MANUAL"
    ON_DEATH = "ON_DEATH"


class LifeEventCategoryEnum(str, Enum):
    BIRTH = "BIRTH"
    MARRIAGE = "MARRIAGE"
    GRADUATION = "GRADUATION"
    CAREER = "CAREER"
    TRAVEL = "TRAVEL"
    OTHER = "OTHER"


# ---------- Auth ----------
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    first_name: str = Field(min_length=1, max_length=100)
    last_name: str = Field(min_length=1, max_length=100)

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    refresh_token: str


# ---------- User / Profile ----------
class ProfileUpdate(BaseModel):
    bio: Optional[str] = None
    date_of_birth: Optional[datetime] = None
    location: Optional[str] = None


class UserResponse(BaseModel):
    id: str
    email: str
    first_name: str
    last_name: str
    role: RoleEnum
    is_active: bool
    created_at: datetime
    last_login_at: Optional[datetime] = None
    profile: Optional[dict] = None

    class Config:
        from_attributes = True


# ---------- Family ----------
class FamilyMemberCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    email: Optional[EmailStr] = None
    relationship: str = Field(min_length=1, max_length=100)
    is_beneficiary: bool = False
    is_trusted_contact: bool = False
    access_level: AccessLevelEnum = AccessLevelEnum.NONE
    notes: Optional[str] = None


class FamilyMemberUpdate(BaseModel):
    name: Optional[str] = None
    email: Optional[EmailStr] = None
    relationship: Optional[str] = None
    is_beneficiary: Optional[bool] = None
    is_trusted_contact: Optional[bool] = None
    access_level: Optional[AccessLevelEnum] = None
    notes: Optional[str] = None


class FamilyMemberResponse(BaseModel):
    id: str
    name: str
    email: Optional[str]
    relationship: str
    is_beneficiary: bool
    is_trusted_contact: bool
    access_level: AccessLevelEnum
    notes: Optional[str] = None  # decrypted when authorized
    created_at: datetime

    class Config:
        from_attributes = True


# ---------- Memory ----------
class MemoryCreate(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    content: str = Field(min_length=1)
    memory_date: Optional[datetime] = None
    location: Optional[str] = None
    is_private: bool = True
    tags: List[str] = []


class MemoryUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None
    memory_date: Optional[datetime] = None
    location: Optional[str] = None
    is_private: Optional[bool] = None
    tags: Optional[List[str]] = None


class MemoryResponse(BaseModel):
    id: str
    title: str
    content: Optional[str] = None  # decrypted when authorized
    memory_date: Optional[datetime]
    location: Optional[str]
    is_private: bool
    tags: List[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# ---------- Life Event ----------
class LifeEventCreate(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    description: Optional[str] = None
    event_date: datetime
    category: LifeEventCategoryEnum = LifeEventCategoryEnum.OTHER


class LifeEventResponse(BaseModel):
    id: str
    title: str
    description: Optional[str] = None
    event_date: datetime
    category: LifeEventCategoryEnum
    created_at: datetime

    class Config:
        from_attributes = True


# ---------- Legacy Message ----------
class LegacyMessageCreate(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    body: str = Field(min_length=1)
    recipient_id: Optional[str] = None
    release_condition: ReleaseConditionEnum = ReleaseConditionEnum.MANUAL
    scheduled_release_at: Optional[datetime] = None


class LegacyMessageResponse(BaseModel):
    id: str
    title: str
    body: Optional[str] = None  # only if released or owner
    recipient_id: Optional[str]
    release_condition: ReleaseConditionEnum
    scheduled_release_at: Optional[datetime]
    is_released: bool
    released_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


# ---------- Media ----------
class MediaResponse(BaseModel):
    id: str
    type: MediaTypeEnum
    original_name: str
    mime_type: str
    size: int
    is_released: bool
    created_at: datetime
    memory_id: Optional[str] = None

    class Config:
        from_attributes = True


# ---------- Notification ----------
class NotificationResponse(BaseModel):
    id: str
    type: str
    title: str
    body: str
    is_read: bool
    created_at: datetime

    class Config:
        from_attributes = True


# ---------- Audit ----------
class AuditLogResponse(BaseModel):
    id: str
    action: str
    resource_type: Optional[str]
    resource_id: Optional[str]
    ip_address: Optional[str]
    created_at: datetime
    actor_id: Optional[str]

    class Config:
        from_attributes = True


# ---------- Generic ----------
class MessageResponse(BaseModel):
    message: str


class ErrorDetail(BaseModel):
    code: str
    message: str
    details: Optional[Any] = None
