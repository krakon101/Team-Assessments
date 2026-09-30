"""SQLAlchemy Database Models.
"""
from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship
from app.database import Base


def utc_now() -> datetime:
    """Return current UTC datetime without tzinfo for consistent DB storage."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(Base):
    """User account model."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    is_email_verified = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    # Relationships
    otps = relationship(
        "EmailVerificationOTP",
        back_populates="user",
        cascade="all, delete-orphan",
        order_by="desc(EmailVerificationOTP.created_at)"
    )

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email} verified={self.is_email_verified}>"


class EmailVerificationOTP(Base):
    """Email OTP verification record model."""
    __tablename__ = "email_verification_otps"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    email = Column(String(255), nullable=False)
    otp_hash = Column(String(255), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    is_used = Column(Boolean, default=False, nullable=False)
    used_at = Column(DateTime, nullable=True)
    attempts = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationships
    user = relationship("User", back_populates="otps")

    def __repr__(self) -> str:
        return (
            f"<EmailVerificationOTP id={self.id} user_id={self.user_id} "
            f"is_used={self.is_used} attempts={self.attempts}>"
        )
