"""
Application configuration loaded from environment variables.
Never hard-code secrets.
"""
from functools import lru_cache
from pydantic_settings import BaseSettings
from pydantic import Field
import secrets


class Settings(BaseSettings):
    APP_NAME: str = "Legacy Pulse"
    APP_ENV: str = "development"
    DEBUG: bool = True
    API_PREFIX: str = "/api"

    # Database
    DATABASE_URL: str = "sqlite:///./legacy_pulse.db"

    # JWT
    JWT_SECRET_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Encryption keys (must be 32 bytes when decoded)
    # Generate with: python -c "import secrets; print(secrets.token_hex(32))"
    DATA_ENCRYPTION_KEY: str = Field(default_factory=lambda: secrets.token_hex(32))
    FILE_ENCRYPTION_KEY: str = Field(default_factory=lambda: secrets.token_hex(32))

    # File storage
    UPLOAD_DIR: str = "./uploads"
    MAX_UPLOAD_SIZE: int = 10 * 1024 * 1024  # 10 MB

    # Rate limiting (simple in-memory for MVP)
    RATE_LIMIT_LOGIN: str = "5/minute"

    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173"]

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    return Settings()
