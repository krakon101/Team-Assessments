"""Automated Test Suite for EDABIP Authentication API.

Covers all 18+ assessment scenarios:
- Successful registration
- Validation errors (each field, trimmed whitespace, password rules, mismatch)
- Duplicate emails (verified vs unverified)
- Password hashing verification
- User unverified default state
- OTP verification (correct, wrong, expired, reused, attempts exceeded)
- OTP resend (invalidation of old OTP, 60s cooldown, 5/hr limit)
- Transaction rollback on email delivery failure
- Login verification gating and credential checking
"""
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from app.errors import ErrorCode
from app.models import EmailVerificationOTP, User
from app.security import verify_password
from tests.conftest import MockEmailService


def test_successful_registration(client, email_mock: MockEmailService, db_session: Session):
    """Test standard valid user registration flow."""
    payload = {
        "first_name": "  Bharath  ",
        "last_name": "  Teja  ",
        "email": "  Bharath.Teja@Example.COM  ",
        "password": "Password123!",
        "confirm_password": "Password123!"
    }
    response = client.post("/auth/register", json=payload)
    assert response.status_code == 201

    body = response.json()
    assert body["success"] is True
    assert body["message"] == "Account created. Please verify your email."
    assert body["data"]["email"] == "bharath.teja@example.com"
    assert body["data"]["verification_required"] is True
    assert body["data"]["otp_expires_in_seconds"] == 600

    # Ensure password and OTP are NOT leaked in response
    assert "password" not in str(body)
    assert "password_hash" not in str(body)

    # Verify email was dispatched
    assert len(email_mock.sent_emails) == 1
    sent = email_mock.sent_emails[0]
    assert sent["email"] == "bharath.teja@example.com"
    assert sent["first_name"] == "Bharath"
    assert len(sent["otp"]) == 6


def test_validation_errors(client):
    """Test validation errors for all fields individually with correct error codes."""
    base = {
        "first_name": "John",
        "last_name": "Doe",
        "email": "john.doe@example.com",
        "password": "Password123!",
        "confirm_password": "Password123!"
    }

    # 1. First name missing or blank
    p = dict(base, first_name="   ")
    res = client.post("/auth/register", json=p)
    assert res.status_code == 400
    assert res.json()["error"]["code"] == ErrorCode.FIRST_NAME_REQUIRED
    assert res.json()["error"]["field"] == "first_name"

    # 2. Last name missing or blank
    p = dict(base, last_name="")
    res = client.post("/auth/register", json=p)
    assert res.status_code == 400
    assert res.json()["error"]["code"] == ErrorCode.LAST_NAME_REQUIRED
    assert res.json()["error"]["field"] == "last_name"

    # 3. Email invalid
    p = dict(base, email="not-an-email")
    res = client.post("/auth/register", json=p)
    assert res.status_code == 400
    assert res.json()["error"]["code"] == ErrorCode.INVALID_EMAIL
    assert res.json()["error"]["field"] == "email"

    # 4. Password too short (<8)
    p = dict(base, password="Aa1!", confirm_password="Aa1!")
    res = client.post("/auth/register", json=p)
    assert res.status_code == 400
    assert res.json()["error"]["code"] == ErrorCode.INVALID_PASSWORD
    assert "8 characters" in res.json()["error"]["message"]

    # 5. Password missing uppercase
    p = dict(base, password="password123!", confirm_password="password123!")
    res = client.post("/auth/register", json=p)
    assert res.status_code == 400
    assert res.json()["error"]["code"] == ErrorCode.INVALID_PASSWORD
    assert "uppercase" in res.json()["error"]["message"]

    # 6. Password missing digit
    p = dict(base, password="Password!", confirm_password="Password!")
    res = client.post("/auth/register", json=p)
    assert res.status_code == 400
    assert res.json()["error"]["code"] == ErrorCode.INVALID_PASSWORD
    assert "digit" in res.json()["error"]["message"]

    # 7. Password missing special char
    p = dict(base, password="Password123", confirm_password="Password123")
    res = client.post("/auth/register", json=p)
    assert res.status_code == 400
    assert res.json()["error"]["code"] == ErrorCode.INVALID_PASSWORD
    assert "special character" in res.json()["error"]["message"]

    # 8. Password mismatch
    p = dict(base, confirm_password="DifferentPassword123!")
    res = client.post("/auth/register", json=p)
    assert res.status_code == 400
    assert res.json()["error"]["code"] == ErrorCode.PASSWORD_MISMATCH


def test_password_is_hashed_and_user_starts_unverified(client, db_session: Session):
    """Verify password is stored as bcrypt hash and user starts with is_email_verified=False."""
    payload = {
        "first_name": "Alice",
        "last_name": "Smith",
        "email": "alice@example.com",
        "password": "SecurePassword1!",
        "confirm_password": "SecurePassword1!"
    }
    client.post("/auth/register", json=payload)

    user = db_session.query(User).filter(User.email == "alice@example.com").first()
    assert user is not None
    assert user.is_email_verified is False
    assert user.password_hash != "SecurePassword1!"
    assert user.password_hash.startswith("$2b$")
    assert verify_password("SecurePassword1!", user.password_hash) is True


def test_duplicate_email_handling(client, email_mock: MockEmailService):
    """Test duplicate registration for unverified vs verified user."""
    payload = {
        "first_name": "Bob",
        "last_name": "Ross",
        "email": "bob@example.com",
        "password": "Password123!",
        "confirm_password": "Password123!"
    }
    res1 = client.post("/auth/register", json=payload)
    assert res1.status_code == 201

    # 1. Unverified duplicate -> 409 EMAIL_NOT_VERIFIED
    res2 = client.post("/auth/register", json=payload)
    assert res2.status_code == 409
    assert res2.json()["error"]["code"] == ErrorCode.EMAIL_NOT_VERIFIED

    # Verify user
    otp = email_mock.sent_emails[0]["otp"]
    client.post("/auth/verify-otp", json={"email": "bob@example.com", "otp": otp})

    # 2. Verified duplicate -> 409 EMAIL_ALREADY_REGISTERED
    res3 = client.post("/auth/register", json=payload)
    assert res3.status_code == 409
    assert res3.json()["error"]["code"] == ErrorCode.EMAIL_ALREADY_REGISTERED


def test_correct_otp_verifies_user(client, email_mock: MockEmailService, db_session: Session):
    """Test successful OTP verification updates user and OTP records."""
    client.post("/auth/register", json={
        "first_name": "Charlie",
        "last_name": "Brown",
        "email": "charlie@example.com",
        "password": "Password123!",
        "confirm_password": "Password123!"
    })

    otp = email_mock.sent_emails[0]["otp"]
    verify_res = client.post("/auth/verify-otp", json={
        "email": "charlie@example.com",
        "otp": otp
    })
    assert verify_res.status_code == 200
    assert verify_res.json()["success"] is True
    assert verify_res.json()["data"]["redirect_to"] == "/login"

    # Check DB state
    user = db_session.query(User).filter(User.email == "charlie@example.com").first()
    assert user.is_email_verified is True

    otp_record = db_session.query(EmailVerificationOTP).filter(
        EmailVerificationOTP.user_id == user.id
    ).first()
    assert otp_record.is_used is True
    assert otp_record.used_at is not None


def test_wrong_otp_increments_attempts(client, email_mock: MockEmailService, db_session: Session):
    """Test wrong OTP returns 400 INVALID_OTP with remaining attempts and increments attempts counter."""
    client.post("/auth/register", json={
        "first_name": "Dave",
        "last_name": "Miller",
        "email": "dave@example.com",
        "password": "Password123!",
        "confirm_password": "Password123!"
    })

    res = client.post("/auth/verify-otp", json={
        "email": "dave@example.com",
        "otp": "999999"
    })
    assert res.status_code == 400
    body = res.json()
    assert body["error"]["code"] == ErrorCode.INVALID_OTP
    assert "4 attempt(s) remaining" in body["error"]["message"]

    # Check database attempt count
    otp_record = db_session.query(EmailVerificationOTP).first()
    assert otp_record.attempts == 1


def test_expired_otp(client, email_mock: MockEmailService, db_session: Session):
    """Test expired OTP returns 400 OTP_EXPIRED."""
    client.post("/auth/register", json={
        "first_name": "Eve",
        "last_name": "Taylor",
        "email": "eve@example.com",
        "password": "Password123!",
        "confirm_password": "Password123!"
    })

    otp = email_mock.sent_emails[0]["otp"]

    # Manipulate expiry in DB to 10 minutes ago
    otp_record = db_session.query(EmailVerificationOTP).first()
    otp_record.expires_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=10)
    db_session.commit()

    res = client.post("/auth/verify-otp", json={
        "email": "eve@example.com",
        "otp": otp
    })
    assert res.status_code == 400
    assert res.json()["error"]["code"] == ErrorCode.OTP_EXPIRED


def test_reused_otp(client, email_mock: MockEmailService):
    """Test that a previously used OTP cannot be verified again."""
    client.post("/auth/register", json={
        "first_name": "Frank",
        "last_name": "Wright",
        "email": "frank@example.com",
        "password": "Password123!",
        "confirm_password": "Password123!"
    })

    otp = email_mock.sent_emails[0]["otp"]

    # First verification succeeds
    res1 = client.post("/auth/verify-otp", json={"email": "frank@example.com", "otp": otp})
    assert res1.status_code == 200

    # Second verification fails (user already verified)
    res2 = client.post("/auth/verify-otp", json={"email": "frank@example.com", "otp": otp})
    assert res2.status_code == 400
    assert res2.json()["error"]["code"] == ErrorCode.EMAIL_ALREADY_VERIFIED


def test_otp_attempts_exceeded(client, db_session: Session):
    """Test reaching max failed attempts locks out verification with 429 OTP_ATTEMPTS_EXCEEDED."""
    client.post("/auth/register", json={
        "first_name": "Grace",
        "last_name": "Hopper",
        "email": "grace@example.com",
        "password": "Password123!",
        "confirm_password": "Password123!"
    })

    # Fail 4 times (returns 400 with remaining attempts)
    for _ in range(4):
        res = client.post("/auth/verify-otp", json={"email": "grace@example.com", "otp": "000000"})
        assert res.status_code == 400

    # 5th failed attempt triggers 429
    res5 = client.post("/auth/verify-otp", json={"email": "grace@example.com", "otp": "000000"})
    assert res5.status_code == 429
    assert res5.json()["error"]["code"] == ErrorCode.OTP_ATTEMPTS_EXCEEDED


def test_resend_cooldown_and_invalidation(client, email_mock: MockEmailService, db_session: Session):
    """Test resend cooldown (60s), invalidation of previous OTP, and successful verification with new OTP."""
    client.post("/auth/register", json={
        "first_name": "Hank",
        "last_name": "Pym",
        "email": "hank@example.com",
        "password": "Password123!",
        "confirm_password": "Password123!"
    })

    old_otp = email_mock.sent_emails[0]["otp"]

    # 1. Immediate resend fails due to 60s cooldown
    res_cooldown = client.post("/auth/resend-otp", json={"email": "hank@example.com"})
    assert res_cooldown.status_code == 429
    assert res_cooldown.json()["error"]["code"] == ErrorCode.OTP_RESEND_COOLDOWN

    # 2. Fast forward time beyond 60s
    first_otp = db_session.query(EmailVerificationOTP).first()
    first_otp.created_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=65)
    db_session.commit()

    # 3. Resend succeeds
    res_resend = client.post("/auth/resend-otp", json={"email": "hank@example.com"})
    assert res_resend.status_code == 200
    assert len(email_mock.sent_emails) == 2
    new_otp = email_mock.sent_emails[1]["otp"]

    # 4. Old OTP is marked used/invalidated
    db_session.refresh(first_otp)
    assert first_otp.is_used is True

    # 5. Old OTP cannot be verified
    res_old = client.post("/auth/verify-otp", json={"email": "hank@example.com", "otp": old_otp})
    assert res_old.status_code == 400

    # 6. New OTP successfully verifies
    res_new = client.post("/auth/verify-otp", json={"email": "hank@example.com", "otp": new_otp})
    assert res_new.status_code == 200


def test_resend_hourly_cap(client, email_mock: MockEmailService, db_session: Session):
    """Test that requesting more than 5 OTPs within 1 hour triggers 429 OTP_RESEND_LIMIT."""
    client.post("/auth/register", json={
        "first_name": "Iris",
        "last_name": "West",
        "email": "iris@example.com",
        "password": "Password123!",
        "confirm_password": "Password123!"
    })

    user = db_session.query(User).filter(User.email == "iris@example.com").first()

    # Set the registered OTP created_at to older than 60s so cooldown check passes
    initial_otp = db_session.query(EmailVerificationOTP).filter(EmailVerificationOTP.user_id == user.id).first()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    initial_otp.created_at = now - timedelta(seconds=70)

    # Create 4 more OTPs within past hour (spaced out)
    for i in range(1, 5):
        db_session.add(EmailVerificationOTP(
            user_id=user.id,
            email=user.email,
            otp_hash="dummyhash",
            expires_at=now + timedelta(minutes=10),
            is_used=True,
            created_at=now - timedelta(minutes=10 * i)
        ))
    db_session.commit()

    # Now there are 5 OTPs in the last hour.
    # Attempting to resend should hit hourly limit
    res = client.post("/auth/resend-otp", json={"email": "iris@example.com"})
    assert res.status_code == 429
    assert res.json()["error"]["code"] == ErrorCode.OTP_RESEND_LIMIT


def test_email_failure_rolls_back_user_and_otp(client, email_mock: MockEmailService, db_session: Session):
    """Test transactional rollback: if email fails, user and OTP records are completely rolled back."""
    email_mock.should_fail = True

    payload = {
        "first_name": "Jack",
        "last_name": "Bauer",
        "email": "jack@example.com",
        "password": "Password123!",
        "confirm_password": "Password123!"
    }
    res = client.post("/auth/register", json=payload)
    assert res.status_code == 502
    assert res.json()["error"]["code"] == ErrorCode.EMAIL_SEND_FAILED

    # Check database: user and OTP must not exist
    user = db_session.query(User).filter(User.email == "jack@example.com").first()
    assert user is None

    otp = db_session.query(EmailVerificationOTP).filter(EmailVerificationOTP.email == "jack@example.com").first()
    assert otp is None


def test_login_flow(client, email_mock: MockEmailService):
    """Test login blocked before verification and allowed after verification with correct credentials."""
    payload = {
        "first_name": "Karen",
        "last_name": "Page",
        "email": "karen@example.com",
        "password": "SecretPassword1!",
        "confirm_password": "SecretPassword1!"
    }
    client.post("/auth/register", json=payload)
    otp = email_mock.sent_emails[0]["otp"]

    # 1. Login before verification -> 403 EMAIL_NOT_VERIFIED
    res_block = client.post("/auth/login", json={"email": "karen@example.com", "password": "SecretPassword1!"})
    assert res_block.status_code == 403
    assert res_block.json()["error"]["code"] == ErrorCode.EMAIL_NOT_VERIFIED

    # 2. Login with wrong password -> 401 INVALID_CREDENTIALS
    res_wrong = client.post("/auth/login", json={"email": "karen@example.com", "password": "WrongPassword1!"})
    assert res_wrong.status_code == 401
    assert res_wrong.json()["error"]["code"] == ErrorCode.INVALID_CREDENTIALS

    # 3. Verify OTP
    client.post("/auth/verify-otp", json={"email": "karen@example.com", "otp": otp})

    # 4. Login after verification with correct password -> 200 OK
    res_ok = client.post("/auth/login", json={"email": "karen@example.com", "password": "SecretPassword1!"})
    assert res_ok.status_code == 200
    assert res_ok.json()["success"] is True
    assert res_ok.json()["data"]["user"]["email"] == "karen@example.com"
    assert res_ok.json()["data"]["user"]["is_email_verified"] is True


def test_user_not_found_on_verify_and_resend(client):
    """Test 404 USER_NOT_FOUND when attempting to verify or resend for non-existent email."""
    # Verify non-existent user
    res_verify = client.post("/auth/verify-otp", json={
        "email": "ghost@example.com",
        "otp": "123456"
    })
    assert res_verify.status_code == 404
    assert res_verify.json()["error"]["code"] == ErrorCode.USER_NOT_FOUND

    # Resend for non-existent user
    res_resend = client.post("/auth/resend-otp", json={
        "email": "ghost@example.com"
    })
    assert res_resend.status_code == 404
    assert res_resend.json()["error"]["code"] == ErrorCode.USER_NOT_FOUND


def test_resend_when_already_verified(client, email_mock: MockEmailService):
    """Test resend returns 400 EMAIL_ALREADY_VERIFIED if user is already verified."""
    client.post("/auth/register", json={
        "first_name": "Leo",
        "last_name": "Fitz",
        "email": "leo@example.com",
        "password": "Password123!",
        "confirm_password": "Password123!"
    })
    otp = email_mock.sent_emails[0]["otp"]
    client.post("/auth/verify-otp", json={"email": "leo@example.com", "otp": otp})

    # Now attempt to resend
    res = client.post("/auth/resend-otp", json={"email": "leo@example.com"})
    assert res.status_code == 400
    assert res.json()["error"]["code"] == ErrorCode.EMAIL_ALREADY_VERIFIED


def test_max_length_validations(client):
    """Test length boundary constraints (first_name > 100, last_name > 100, password > 128)."""
    base = {
        "first_name": "A" * 101,
        "last_name": "Valid",
        "email": "length@example.com",
        "password": "Password123!",
        "confirm_password": "Password123!"
    }
    res_fn = client.post("/auth/register", json=base)
    assert res_fn.status_code == 400
    assert res_fn.json()["error"]["code"] == ErrorCode.FIRST_NAME_REQUIRED

    base["first_name"] = "Valid"
    base["last_name"] = "B" * 101
    res_ln = client.post("/auth/register", json=base)
    assert res_ln.status_code == 400
    assert res_ln.json()["error"]["code"] == ErrorCode.LAST_NAME_REQUIRED

    base["last_name"] = "Valid"
    long_pwd = "P1!" + ("a" * 130)
    base["password"] = long_pwd
    base["confirm_password"] = long_pwd
    res_pwd = client.post("/auth/register", json=base)
    assert res_pwd.status_code == 400
    assert res_pwd.json()["error"]["code"] == ErrorCode.INVALID_PASSWORD
