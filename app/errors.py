"""Application Exceptions and Error Handlers Module.

Defines standardized error codes, custom exception classes, and FastAPI exception handlers
to guarantee consistent error responses:
{
  "success": false,
  "error": {
    "code": "...",
    "message": "...",
    "field": "..."
  }
}
"""
from typing import Any, Dict, Optional
from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.status import HTTP_500_INTERNAL_SERVER_ERROR


# Standardized Error Codes defined in specification
class ErrorCode:
    FIRST_NAME_REQUIRED = "FIRST_NAME_REQUIRED"
    LAST_NAME_REQUIRED = "LAST_NAME_REQUIRED"
    EMAIL_REQUIRED = "EMAIL_REQUIRED"
    INVALID_EMAIL = "INVALID_EMAIL"
    EMAIL_ALREADY_REGISTERED = "EMAIL_ALREADY_REGISTERED"
    PASSWORD_REQUIRED = "PASSWORD_REQUIRED"
    INVALID_PASSWORD = "INVALID_PASSWORD"
    CONFIRM_PASSWORD_REQUIRED = "CONFIRM_PASSWORD_REQUIRED"
    PASSWORD_MISMATCH = "PASSWORD_MISMATCH"
    INVALID_OTP = "INVALID_OTP"
    OTP_EXPIRED = "OTP_EXPIRED"
    OTP_ALREADY_USED = "OTP_ALREADY_USED"
    OTP_NOT_FOUND = "OTP_NOT_FOUND"
    OTP_ATTEMPTS_EXCEEDED = "OTP_ATTEMPTS_EXCEEDED"
    OTP_RESEND_COOLDOWN = "OTP_RESEND_COOLDOWN"
    OTP_RESEND_LIMIT = "OTP_RESEND_LIMIT"
    USER_NOT_FOUND = "USER_NOT_FOUND"
    EMAIL_ALREADY_VERIFIED = "EMAIL_ALREADY_VERIFIED"
    EMAIL_NOT_VERIFIED = "EMAIL_NOT_VERIFIED"
    EMAIL_SEND_FAILED = "EMAIL_SEND_FAILED"
    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class AppException(Exception):
    """Base application exception for business logic and validation errors."""
    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        field: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.field = field
        self.data = data or {}


async def app_exception_handler(request: Request, exc: AppException) -> JSONResponse:
    """Exception handler for custom AppException."""
    content: Dict[str, Any] = {
        "success": False,
        "error": {
            "code": exc.code,
            "message": exc.message,
            "field": exc.field
        }
    }
    if exc.data:
        content["data"] = exc.data
    return JSONResponse(status_code=exc.status_code, content=content)


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """
    Transforms Pydantic validation errors into the consistent EDABIP error shape:
    { "success": false, "error": { "code": "...", "message": "...", "field": "..." } }
    """
    errors = exc.errors()
    if not errors:
        return JSONResponse(
            status_code=422,
            content={
                "success": False,
                "error": {
                    "code": ErrorCode.INTERNAL_ERROR,
                    "message": "Validation failed.",
                    "field": None
                }
            }
        )

    # Inspect the first validation error
    first_error = errors[0]
    loc = first_error.get("loc", ())
    field_name = str(loc[-1]) if loc else None
    error_msg = first_error.get("msg", "Validation error.")
    error_type = first_error.get("type", "")

    # Clean up Pydantic prefix "Value error, " if present
    if error_msg.startswith("Value error, "):
        error_msg = error_msg[len("Value error, "):]

    # Map error type and field to standardized ErrorCode
    code = ErrorCode.INTERNAL_ERROR
    custom_field = field_name

    # Check for custom embedded error codes like "[CODE:MESSAGE]"
    if error_msg.startswith("[") and "]" in error_msg:
        code_part, _, msg_part = error_msg[1:].partition("]")
        code = code_part.strip()
        error_msg = msg_part.strip()
    elif field_name == "first_name":
        code = ErrorCode.FIRST_NAME_REQUIRED
    elif field_name == "last_name":
        code = ErrorCode.LAST_NAME_REQUIRED
    elif field_name == "email":
        if "missing" in error_type:
            code = ErrorCode.EMAIL_REQUIRED
        else:
            code = ErrorCode.INVALID_EMAIL
    elif field_name == "password":
        if "missing" in error_type:
            code = ErrorCode.PASSWORD_REQUIRED
        else:
            code = ErrorCode.INVALID_PASSWORD
    elif field_name == "confirm_password":
        if "missing" in error_type:
            code = ErrorCode.CONFIRM_PASSWORD_REQUIRED
        elif "mismatch" in error_msg.lower() or "equal" in error_msg.lower():
            code = ErrorCode.PASSWORD_MISMATCH
        else:
            code = ErrorCode.CONFIRM_PASSWORD_REQUIRED
    elif field_name == "otp":
        code = ErrorCode.INVALID_OTP
    else:
        code = ErrorCode.INTERNAL_ERROR

    return JSONResponse(
        status_code=400,
        content={
            "success": False,
            "error": {
                "code": code,
                "message": error_msg,
                "field": custom_field
            }
        }
    )


async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all unhandled exception handler."""
    return JSONResponse(
        status_code=HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "success": False,
            "error": {
                "code": ErrorCode.INTERNAL_ERROR,
                "message": "An unexpected internal server error occurred.",
                "field": None
            }
        }
    )
