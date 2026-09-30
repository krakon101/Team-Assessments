"""Application Configuration Module.

Loads configuration from environment variables or .env file using Pydantic Settings.
"""
from functools import lru_cache
from typing import Literal
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Application Info
    APP_NAME: str = "EDABIP Authentication API"
    APP_ENV: str = "development"
    DEBUG: bool = True

    # Database
    DATABASE_URL: str = "sqlite:///./edabip.db"

    # Security & OTP Secrets
    SECRET_KEY: str = "edabip-super-secret-key-change-in-production-2026"
    OTP_SECRET: str = "edabip-otp-secret-key-very-secure-2026"

    # OTP Configuration
    OTP_LENGTH: int = 6
    OTP_EXPIRY_MINUTES: int = 10
    OTP_MAX_ATTEMPTS: int = 5
    OTP_RESEND_COOLDOWN_SECONDS: int = 60
    OTP_RESEND_MAX_PER_HOUR: int = 5

    # Email Service Configuration
    EMAIL_BACKEND: Literal["console", "smtp"] = "console"
    SMTP_HOST: str = "localhost"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = "no-reply@edabip.local"
    SMTP_USE_TLS: bool = True

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


@lru_cache()
def get_settings() -> Settings:
    """Return a cached instance of application settings."""
    return Settings()
