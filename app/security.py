"""Cryptographic and Security Utilities Module.

Provides secure password hashing (bcrypt), constant-time OTP verification (HMAC-SHA256),
and cryptographically secure OTP generation using python secrets.
"""
import hashlib
import hmac
import secrets
import bcrypt


def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8")
        )
    except Exception:
        return False


def generate_otp(length: int = 6) -> str:
    """Generate a cryptographically secure numeric OTP string of specified length."""
    return "".join(secrets.choice("0123456789") for _ in range(length))


def hash_otp(otp: str, secret: str) -> str:
    """Hash an OTP code using HMAC-SHA256 with the server-side secret."""
    return hmac.new(
        secret.encode("utf-8"),
        otp.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def verify_otp_hash(provided_otp: str, stored_hash: str, secret: str) -> bool:
    """Verify an OTP using constant-time comparison against the stored HMAC hash."""
    calculated_hash = hash_otp(provided_otp, secret)
    return hmac.compare_digest(calculated_hash, stored_hash)
