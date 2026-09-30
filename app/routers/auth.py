"""Authentication Routes Module.

Thin routing layer exposing REST endpoints for registration, OTP verification,
OTP resend, and user login. Delegates all business logic to AuthService.
"""
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.schemas import (
    APIResponse,
    ErrorResponse,
    LoginRequest,
    LoginResponseData,
    RegisterRequest,
    RegisterResponseData,
    ResendOtpRequest,
    ResendOtpResponseData,
    VerifyOtpRequest,
    VerifyOtpResponseData
)
from app.services.auth_service import AuthService, get_auth_service

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
    responses={
        400: {"model": ErrorResponse, "description": "Validation or logic error"},
        401: {"model": ErrorResponse, "description": "Invalid credentials"},
        403: {"model": ErrorResponse, "description": "Email not verified"},
        404: {"model": ErrorResponse, "description": "Resource not found"},
        409: {"model": ErrorResponse, "description": "Conflict (already registered/verified)"},
        429: {"model": ErrorResponse, "description": "Rate limit / attempts exceeded"},
        502: {"model": ErrorResponse, "description": "Email delivery failed"}
    }
)


@router.post(
    "/register",
    response_model=APIResponse[RegisterResponseData],
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account"
)
def register(
    request: RegisterRequest,
    db: Session = Depends(get_db),
    service: AuthService = Depends(get_auth_service)
):
    """
    Register a new user account and dispatch an email verification OTP code.
    Password must satisfy complexity rules. Returns registration status and OTP expiry info.
    """
    result = service.register(db, request)
    return APIResponse(
        success=True,
        message="Account created. Please verify your email.",
        data=result
    )


@router.post(
    "/verify-otp",
    response_model=APIResponse[VerifyOtpResponseData],
    status_code=status.HTTP_200_OK,
    summary="Verify email OTP"
)
def verify_otp(
    request: VerifyOtpRequest,
    db: Session = Depends(get_db),
    service: AuthService = Depends(get_auth_service)
):
    """
    Verify the 6-digit OTP sent to user's email.
    Upon successful verification, activates user account for login.
    """
    result = service.verify_otp(db, request)
    return APIResponse(
        success=True,
        message="Email verified successfully. Please log in.",
        data=result
    )


@router.post(
    "/resend-otp",
    response_model=APIResponse[ResendOtpResponseData],
    status_code=status.HTTP_200_OK,
    summary="Resend email verification OTP"
)
def resend_otp(
    request: ResendOtpRequest,
    db: Session = Depends(get_db),
    service: AuthService = Depends(get_auth_service)
):
    """
    Invalidate previous OTPs and generate a new OTP sent to user's email.
    Enforces a 60-second cooldown and 5 per hour rate limit.
    """
    result = service.resend_otp(db, request)
    return APIResponse(
        success=True,
        message="A new verification code has been sent to your email.",
        data=result
    )


@router.post(
    "/login",
    response_model=APIResponse[LoginResponseData],
    status_code=status.HTTP_200_OK,
    summary="Authenticate user"
)
def login(
    request: LoginRequest,
    db: Session = Depends(get_db),
    service: AuthService = Depends(get_auth_service)
):
    """
    Authenticate user credentials. Blocks unverified accounts with 403 EMAIL_NOT_VERIFIED.
    """
    result = service.login(db, request)
    return APIResponse(
        success=True,
        message="Login successful.",
        data=result
    )
