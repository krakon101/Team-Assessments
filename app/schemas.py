"""Pydantic v2 Request and Response Schemas.

Enforces strict input validation, email normalization, password complexity rules,
and consistent API response envelopes.
"""
import re
from typing import Any, Generic, Optional, TypeVar
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from app.errors import ErrorCode

T = TypeVar("T")

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


# Generic Envelopes
class ErrorDetail(BaseModel):
    code: str
    message: str
    field: Optional[str] = None


class ErrorResponse(BaseModel):
    success: bool = False
    error: ErrorDetail


class APIResponse(BaseModel, Generic[T]):
    success: bool = True
    message: str
    data: Optional[T] = None


# Request Schemas
class RegisterRequest(BaseModel):
    first_name: str
    last_name: str
    email: str
    password: str
    confirm_password: str

    @field_validator("first_name")
    @classmethod
    def validate_first_name(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError(f"[{ErrorCode.FIRST_NAME_REQUIRED}] First name is required.")
        v_trimmed = v.strip()
        if len(v_trimmed) > 100:
            raise ValueError(f"[{ErrorCode.FIRST_NAME_REQUIRED}] First name cannot exceed 100 characters.")
        return v_trimmed

    @field_validator("last_name")
    @classmethod
    def validate_last_name(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError(f"[{ErrorCode.LAST_NAME_REQUIRED}] Last name is required.")
        v_trimmed = v.strip()
        if len(v_trimmed) > 100:
            raise ValueError(f"[{ErrorCode.LAST_NAME_REQUIRED}] Last name cannot exceed 100 characters.")
        return v_trimmed

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError(f"[{ErrorCode.EMAIL_REQUIRED}] Email is required.")
        v_norm = v.strip().lower()
        if not EMAIL_REGEX.match(v_norm):
            raise ValueError(f"[{ErrorCode.INVALID_EMAIL}] Invalid email address format.")
        return v_norm

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if not v:
            raise ValueError(f"[{ErrorCode.PASSWORD_REQUIRED}] Password is required.")

        failed_rules = []
        if len(v) < 8:
            failed_rules.append("at least 8 characters")
        if len(v) > 128:
            failed_rules.append("at most 128 characters")
        if not re.search(r"[A-Z]", v):
            failed_rules.append("at least 1 uppercase letter")
        if not re.search(r"[a-z]", v):
            failed_rules.append("at least 1 lowercase letter")
        if not re.search(r"\d", v):
            failed_rules.append("at least 1 digit")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>\-_+=\[\]~`/\\]', v):
            failed_rules.append("at least 1 special character")

        if failed_rules:
            raise ValueError(
                f"[{ErrorCode.INVALID_PASSWORD}] Password must satisfy: {', '.join(failed_rules)}."
            )
        return v

    @field_validator("confirm_password")
    @classmethod
    def validate_confirm_password(cls, v: str) -> str:
        if not v:
            raise ValueError(f"[{ErrorCode.CONFIRM_PASSWORD_REQUIRED}] Password confirmation is required.")
        return v

    @model_validator(mode="after")
    def validate_passwords_match(self) -> "RegisterRequest":
        if self.password != self.confirm_password:
            raise ValueError(f"[{ErrorCode.PASSWORD_MISMATCH}] Passwords do not match.")
        return self


class VerifyOtpRequest(BaseModel):
    email: str
    otp: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError(f"[{ErrorCode.EMAIL_REQUIRED}] Email is required.")
        v_norm = v.strip().lower()
        if not EMAIL_REGEX.match(v_norm):
            raise ValueError(f"[{ErrorCode.INVALID_EMAIL}] Invalid email address format.")
        return v_norm

    @field_validator("otp")
    @classmethod
    def validate_otp(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError(f"[{ErrorCode.INVALID_OTP}] OTP is required.")
        v_trimmed = v.strip()
        if not v_trimmed.isdigit() or len(v_trimmed) != 6:
            raise ValueError(f"[{ErrorCode.INVALID_OTP}] OTP must be a 6-digit numeric code.")
        return v_trimmed


class ResendOtpRequest(BaseModel):
    email: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError(f"[{ErrorCode.EMAIL_REQUIRED}] Email is required.")
        v_norm = v.strip().lower()
        if not EMAIL_REGEX.match(v_norm):
            raise ValueError(f"[{ErrorCode.INVALID_EMAIL}] Invalid email address format.")
        return v_norm


class LoginRequest(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError(f"[{ErrorCode.EMAIL_REQUIRED}] Email is required.")
        return v.strip().lower()

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if not v:
            raise ValueError(f"[{ErrorCode.PASSWORD_REQUIRED}] Password is required.")
        return v


# Response Data Models
class RegisterResponseData(BaseModel):
    email: str
    verification_required: bool = True
    otp_expires_in_seconds: int


class VerifyOtpResponseData(BaseModel):
    redirect_to: str = "/login"


class ResendOtpResponseData(BaseModel):
    email: str
    otp_expires_in_seconds: int


class UserResponseData(BaseModel):
    id: int
    first_name: str
    last_name: str
    email: str
    is_email_verified: bool

    model_config = ConfigDict(from_attributes=True)


class LoginResponseData(BaseModel):
    user: UserResponseData
