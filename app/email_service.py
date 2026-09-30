"""Email Service Module.

Supports console printing (for local dev and testing) and standard SMTP dispatch.
"""
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional
from app.config import Settings, get_settings

logger = logging.getLogger("edabip.email")


class EmailService:
    """Service handling transactional email delivery."""

    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()

    def send_verification_otp(
        self,
        email: str,
        first_name: str,
        otp: str,
        expires_in_minutes: int
    ) -> bool:
        """
        Send verification OTP to the user's email.
        Returns True on success, False or raises on failure.
        """
        subject = "EDABIP - Verify Your Email Address"
        text_body = (
            f"Hi {first_name},\n\n"
            f"Thank you for registering with EDABIP!\n\n"
            f"Your verification code is: {otp}\n\n"
            f"This code will expire in {expires_in_minutes} minutes.\n\n"
            f"If you did not sign up for an account, please ignore this email.\n"
        )
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="background-color: #2563eb; color: #ffffff; padding: 20px; border-radius: 8px 8px 0 0; text-align: center;">
                <h1 style="margin: 0; font-size: 24px;">EDABIP Verification</h1>
            </div>
            <div style="border: 1px solid #e5e7eb; border-top: none; padding: 30px; border-radius: 0 0 8px 8px; background-color: #ffffff;">
                <p style="font-size: 16px;">Hi <strong>{first_name}</strong>,</p>
                <p>Welcome to EDABIP! Please use the verification code below to verify your email address:</p>
                <div style="text-align: center; margin: 30px 0;">
                    <span style="display: inline-block; font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #1e40af; background: #eff6ff; padding: 12px 28px; border-radius: 8px; border: 1px dashed #3b82f6;">
                        {otp}
                    </span>
                </div>
                <p style="font-size: 14px; color: #6b7280;">This verification code will expire in <strong>{expires_in_minutes} minutes</strong>.</p>
                <p style="font-size: 14px; color: #9ca3af; margin-top: 30px; border-top: 1px solid #f3f4f6; padding-top: 15px;">
                    If you did not sign up for an account, please ignore this email.
                </p>
            </div>
        </body>
        </html>
        """

        if self.settings.EMAIL_BACKEND == "console":
            self._log_to_console(email, subject, first_name, otp, expires_in_minutes)
            return True

        if self.settings.EMAIL_BACKEND == "smtp":
            return self._send_smtp(email, subject, text_body, html_body)

        logger.error("Unknown EMAIL_BACKEND: %s", self.settings.EMAIL_BACKEND)
        return False

    def _log_to_console(
        self,
        email: str,
        subject: str,
        first_name: str,
        otp: str,
        expires_in_minutes: int
    ) -> None:
        """Log the OTP verification message clearly to server console."""
        banner = "=" * 70
        log_message = (
            f"\n{banner}\n"
            f"[EMAIL - CONSOLE BACKEND]\n"
            f"To: {email}\n"
            f"From: {self.settings.SMTP_FROM}\n"
            f"Subject: {subject}\n\n"
            f"Hi {first_name},\n\n"
            f"Your verification code is: >>> {otp} <<<\n"
            f"This code will expire in {expires_in_minutes} minutes.\n"
            f"If you did not sign up, please ignore this message.\n"
            f"{banner}\n"
        )
        print(log_message, flush=True)
        logger.info("Sent verification OTP to %s via console backend.", email)

    def _send_smtp(self, email: str, subject: str, text_body: str, html_body: str) -> bool:
        """Send email through configured SMTP server."""
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.settings.SMTP_FROM
            msg["To"] = email

            part1 = MIMEText(text_body, "plain", "utf-8")
            part2 = MIMEText(html_body, "html", "utf-8")
            msg.attach(part1)
            msg.attach(part2)

            with smtplib.SMTP(self.settings.SMTP_HOST, self.settings.SMTP_PORT, timeout=10) as server:
                if self.settings.SMTP_USE_TLS:
                    server.starttls()
                if self.settings.SMTP_USER and self.settings.SMTP_PASSWORD:
                    server.login(self.settings.SMTP_USER, self.settings.SMTP_PASSWORD)
                server.send_message(msg)

            logger.info("Sent verification email to %s via SMTP.", email)
            return True
        except Exception as e:
            logger.error("Failed to deliver email to %s via SMTP: %s", email, str(e), exc_info=True)
            return False


email_service = EmailService()


def get_email_service() -> EmailService:
    """Dependency for obtaining the email service."""
    return email_service
