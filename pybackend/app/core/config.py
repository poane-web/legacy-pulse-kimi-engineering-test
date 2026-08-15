"""
Application configuration. Secrets MUST come from environment.
No silent generation of encryption keys — startup fails if they are missing or invalid.
"""
from functools import lru_cache
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    APP_NAME: str = "Legacy Pulse"
    APP_ENV: str = "development"
    DEBUG: bool = False  # default safe; enable explicitly for local
    API_PREFIX: str = "/api"

    # Database
    DATABASE_URL: str = "sqlite:///./legacy_pulse.db"

    # JWT — MUST be set in environment
    JWT_SECRET_KEY: str = Field(..., min_length=32)
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Root key material for envelope encryption (exactly 32 bytes as hex = 64 chars).
    # Production: replace with KMS/HSM-backed material via KeyProvider abstraction.
    MASTER_KEY_HEX: str = Field(..., min_length=64, max_length=64)

    # File storage
    UPLOAD_DIR: str = "./uploads"
    MAX_UPLOAD_SIZE: int = 10 * 1024 * 1024  # 10 MB

    # Rate limiting
    RATE_LIMIT_LOGIN_ATTEMPTS: int = 5
    RATE_LIMIT_LOGIN_WINDOW_SECONDS: int = 900  # 15 min

    # CORS — never include "*" when credentials are used
    CORS_ORIGINS: str = "http://localhost:3001,http://127.0.0.1:3001,http://localhost:5173"

    SECURE_COOKIES: bool = False
    COOKIE_SAMESITE: str = "lax"

    @field_validator("MASTER_KEY_HEX")
    @classmethod
    def validate_master_key(cls, v: str) -> str:
        try:
            raw = bytes.fromhex(v)
        except ValueError as e:
            raise ValueError("MASTER_KEY_HEX must be valid hex") from e
        if len(raw) != 32:
            raise ValueError("MASTER_KEY_HEX must decode to exactly 32 bytes")
        return v

    @field_validator("JWT_SECRET_KEY")
    @classmethod
    def validate_jwt_secret(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("JWT_SECRET_KEY must be at least 32 characters")
        return v

    def cors_origin_list(self) -> List[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]


@lru_cache()
def get_settings() -> Settings:
    return Settings()
