"""Authentication Service Module.

Encapsulates all business logic for user registration, OTP generation & verification,
rate limiting, password validation, and user authentication.
"""
from datetime import datetime, timedelta, timezone
from typing import Any, Dict
from fastapi import Depends
from sqlalchemy.orm import Session
from starlette.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_401_UNAUTHORIZED,
    HTTP_403_FORBIDDEN,
    HTTP_404_NOT_FOUND,
    HTTP_409_CONFLICT,
    HTTP_429_TOO_MANY_REQUESTS,
    HTTP_502_BAD_GATEWAY
)
from app.config import get_settings
from app.email_service import EmailService, get_email_service
from app.errors import AppException, ErrorCode
from app.models import EmailVerificationOTP, User
from app.schemas import LoginRequest, RegisterRequest, ResendOtpRequest, VerifyOtpRequest
from app.security import (
    generate_otp,
    hash_otp,
    hash_password,
    verify_otp_hash,
    verify_password
)


def _get_utc_now() -> datetime:
    """Return timezone-naive UTC timestamp for consistent DB storage."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class AuthService:
    """Core authentication business logic service."""

    def __init__(self, email_svc: EmailService | None = None):
        self.settings = get_settings()
        self.email_service = email_svc or get_email_service()

    def register(self, db: Session, req: RegisterRequest) -> Dict[str, Any]:
        """
        Register a new user:
        1. Check if email exists:
           - Verified -> 409 EMAIL_ALREADY_REGISTERED
           - Unverified -> 409 EMAIL_NOT_VERIFIED
        2. Hash password.
        3. Save user (is_email_verified = False).
        4. Generate cryptographically secure OTP, hash it, store with expiry.
        5. Send OTP email. Roll back if email fails.
        """
        existing_user = db.query(User).filter(User.email == req.email).first()
        if existing_user:
            if existing_user.is_email_verified:
                raise AppException(
                    status_code=HTTP_409_CONFLICT,
                    code=ErrorCode.EMAIL_ALREADY_REGISTERED,
                    message="An account with this email address is already registered.",
                    field="email"
                )
            else:
                raise AppException(
                    status_code=HTTP_409_CONFLICT,
                    code=ErrorCode.EMAIL_NOT_VERIFIED,
                    message="Account already exists but email is not verified. Please verify your email or request a new OTP.",
                    field="email"
                )

        now = _get_utc_now()
        hashed_pwd = hash_password(req.password)
        new_user = User(
            first_name=req.first_name,
            last_name=req.last_name,
            email=req.email,
            password_hash=hashed_pwd,
            is_email_verified=False,
            created_at=now,
            updated_at=now
        )
        db.add(new_user)
        db.flush()  # Populates new_user.id

        # Generate OTP
        plain_otp = generate_otp(self.settings.OTP_LENGTH)
        otp_hashed = hash_otp(plain_otp, self.settings.OTP_SECRET)
        expires_at = now + timedelta(minutes=self.settings.OTP_EXPIRY_MINUTES)

        otp_record = EmailVerificationOTP(
            user_id=new_user.id,
            email=new_user.email,
            otp_hash=otp_hashed,
            expires_at=expires_at,
            is_used=False,
            used_at=None,
            attempts=0,
            created_at=now
        )
        db.add(otp_record)

        # Dispatch email
        email_sent = self.email_service.send_verification_otp(
            email=new_user.email,
            first_name=new_user.first_name,
            otp=plain_otp,
            expires_in_minutes=self.settings.OTP_EXPIRY_MINUTES
        )

        if not email_sent:
            db.rollback()
            raise AppException(
                status_code=HTTP_502_BAD_GATEWAY,
                code=ErrorCode.EMAIL_SEND_FAILED,
                message="Failed to send verification email. Please try again later."
            )

        db.commit()
        db.refresh(new_user)

        return {
            "email": new_user.email,
            "verification_required": True,
            "otp_expires_in_seconds": self.settings.OTP_EXPIRY_MINUTES * 60
        }

    def verify_otp(self, db: Session, req: VerifyOtpRequest) -> Dict[str, Any]:
        """
        Verify email OTP with checks in strict order:
        1. User exists -> else 404 USER_NOT_FOUND
        2. Already verified -> 400 EMAIL_ALREADY_VERIFIED
        3. Latest OTP exists -> else 404 OTP_NOT_FOUND
        4. OTP already used -> 400 OTP_ALREADY_USED
        5. OTP expired -> 400 OTP_EXPIRED
        6. Too many failed attempts -> 429 OTP_ATTEMPTS_EXCEEDED
        7. OTP incorrect -> increment attempts, 400 INVALID_OTP (or 429 if exceeded)
        Success: Mark user verified & OTP used in single transaction.
        """
        user = db.query(User).filter(User.email == req.email).first()
        if not user:
            raise AppException(
                status_code=HTTP_404_NOT_FOUND,
                code=ErrorCode.USER_NOT_FOUND,
                message="User not found with this email address.",
                field="email"
            )

        if user.is_email_verified:
            raise AppException(
                status_code=HTTP_400_BAD_REQUEST,
                code=ErrorCode.EMAIL_ALREADY_VERIFIED,
                message="Email address is already verified.",
                field="email"
            )

        latest_otp = (
            db.query(EmailVerificationOTP)
            .filter(EmailVerificationOTP.user_id == user.id)
            .order_by(EmailVerificationOTP.created_at.desc())
            .first()
        )

        if not latest_otp:
            raise AppException(
                status_code=HTTP_404_NOT_FOUND,
                code=ErrorCode.OTP_NOT_FOUND,
                message="No verification OTP found for this account. Please request a new OTP.",
                field="otp"
            )

        if latest_otp.is_used:
            raise AppException(
                status_code=HTTP_400_BAD_REQUEST,
                code=ErrorCode.OTP_ALREADY_USED,
                message="This verification code has already been used.",
                field="otp"
            )

        now = _get_utc_now()
        if now > latest_otp.expires_at:
            raise AppException(
                status_code=HTTP_400_BAD_REQUEST,
                code=ErrorCode.OTP_EXPIRED,
                message="This verification code has expired. Please request a new code.",
                field="otp"
            )

        if latest_otp.attempts >= self.settings.OTP_MAX_ATTEMPTS:
            raise AppException(
                status_code=HTTP_429_TOO_MANY_REQUESTS,
                code=ErrorCode.OTP_ATTEMPTS_EXCEEDED,
                message="Maximum verification attempts exceeded. Please request a new code.",
                field="otp"
            )

        # Constant-time comparison
        is_valid = verify_otp_hash(req.otp, latest_otp.otp_hash, self.settings.OTP_SECRET)
        if not is_valid:
            latest_otp.attempts += 1
            db.commit()
            remaining = max(0, self.settings.OTP_MAX_ATTEMPTS - latest_otp.attempts)
            if remaining == 0:
                raise AppException(
                    status_code=HTTP_429_TOO_MANY_REQUESTS,
                    code=ErrorCode.OTP_ATTEMPTS_EXCEEDED,
                    message="Maximum verification attempts exceeded. Please request a new code.",
                    field="otp"
                )
            raise AppException(
                status_code=HTTP_400_BAD_REQUEST,
                code=ErrorCode.INVALID_OTP,
                message=f"Invalid verification code. {remaining} attempt(s) remaining.",
                field="otp"
            )

        # Success - Single transaction
        user.is_email_verified = True
        user.updated_at = now
        latest_otp.is_used = True
        latest_otp.used_at = now
        db.commit()

        return {"redirect_to": "/login"}

    def resend_otp(self, db: Session, req: ResendOtpRequest) -> Dict[str, Any]:
        """
        Resend OTP with rate limiting:
        1. User exists -> 404 USER_NOT_FOUND
        2. Already verified -> 400 EMAIL_ALREADY_VERIFIED
        3. Rate limits:
           - Cooldown (default 60s) -> 429 OTP_RESEND_COOLDOWN
           - Hourly cap (default 5/hr) -> 429 OTP_RESEND_LIMIT
        4. Invalidate all previous unused OTPs.
        5. Generate new OTP, save hash with new expiry, send email.
        """
        user = db.query(User).filter(User.email == req.email).first()
        if not user:
            raise AppException(
                status_code=HTTP_404_NOT_FOUND,
                code=ErrorCode.USER_NOT_FOUND,
                message="User not found with this email address.",
                field="email"
            )

        if user.is_email_verified:
            raise AppException(
                status_code=HTTP_400_BAD_REQUEST,
                code=ErrorCode.EMAIL_ALREADY_VERIFIED,
                message="Email address is already verified.",
                field="email"
            )

        now = _get_utc_now()

        # Cooldown check against latest OTP
        latest_otp = (
            db.query(EmailVerificationOTP)
            .filter(EmailVerificationOTP.user_id == user.id)
            .order_by(EmailVerificationOTP.created_at.desc())
            .first()
        )

        if latest_otp:
            elapsed = (now - latest_otp.created_at).total_seconds()
            if elapsed < self.settings.OTP_RESEND_COOLDOWN_SECONDS:
                retry_after = int(self.settings.OTP_RESEND_COOLDOWN_SECONDS - elapsed)
                raise AppException(
                    status_code=HTTP_429_TOO_MANY_REQUESTS,
                    code=ErrorCode.OTP_RESEND_COOLDOWN,
                    message=f"Please wait {retry_after} seconds before requesting a new code.",
                    field="email",
                    data={"retry_after_seconds": retry_after}
                )

        # Hourly limit check
        one_hour_ago = now - timedelta(hours=1)
        recent_count = (
            db.query(EmailVerificationOTP)
            .filter(
                EmailVerificationOTP.user_id == user.id,
                EmailVerificationOTP.created_at >= one_hour_ago
            )
            .count()
        )

        if recent_count >= self.settings.OTP_RESEND_MAX_PER_HOUR:
            raise AppException(
                status_code=HTTP_429_TOO_MANY_REQUESTS,
                code=ErrorCode.OTP_RESEND_LIMIT,
                message="Hourly OTP request limit exceeded. Please try again later.",
                field="email"
            )

        # Invalidate all prior unused OTPs
        db.query(EmailVerificationOTP).filter(
            EmailVerificationOTP.user_id == user.id,
            EmailVerificationOTP.is_used == False  # noqa: E712
        ).update({"is_used": True})

        # Generate new OTP
        plain_otp = generate_otp(self.settings.OTP_LENGTH)
        otp_hashed = hash_otp(plain_otp, self.settings.OTP_SECRET)
        expires_at = now + timedelta(minutes=self.settings.OTP_EXPIRY_MINUTES)

        new_otp = EmailVerificationOTP(
            user_id=user.id,
            email=user.email,
            otp_hash=otp_hashed,
            expires_at=expires_at,
            is_used=False,
            used_at=None,
            attempts=0,
            created_at=now
        )
        db.add(new_otp)

        # Dispatch email
        email_sent = self.email_service.send_verification_otp(
            email=user.email,
            first_name=user.first_name,
            otp=plain_otp,
            expires_in_minutes=self.settings.OTP_EXPIRY_MINUTES
        )

        if not email_sent:
            db.rollback()
            raise AppException(
                status_code=HTTP_502_BAD_GATEWAY,
                code=ErrorCode.EMAIL_SEND_FAILED,
                message="Failed to send verification email. Please try again later."
            )

        db.commit()

        return {
            "email": user.email,
            "otp_expires_in_seconds": self.settings.OTP_EXPIRY_MINUTES * 60
        }

    def login(self, db: Session, req: LoginRequest) -> Dict[str, Any]:
        """
        Authenticate user:
        1. Verify email & password.
        2. Block if email not verified -> 403 EMAIL_NOT_VERIFIED.
        3. Wrong credentials -> 401 INVALID_CREDENTIALS.
        4. Return user info.
        """
        user = db.query(User).filter(User.email == req.email).first()
        if not user or not verify_password(req.password, user.password_hash):
            raise AppException(
                status_code=HTTP_401_UNAUTHORIZED,
                code=ErrorCode.INVALID_CREDENTIALS,
                message="Invalid email or password."
            )

        if not user.is_email_verified:
            raise AppException(
                status_code=HTTP_403_FORBIDDEN,
                code=ErrorCode.EMAIL_NOT_VERIFIED,
                message="Email is not verified. Please verify your email first.",
                field="email"
            )

        return {"user": user}


def get_auth_service(
    email_svc: EmailService = Depends(get_email_service)
) -> AuthService:
    """Dependency for getting the auth service with injected email service."""
    return AuthService(email_svc=email_svc)
