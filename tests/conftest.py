"""Pytest Configuration and Fixtures Module.

Sets up an isolated in-memory SQLite database, FastAPI TestClient, and email service mock.
"""
from typing import Generator
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from app.database import Base, get_db
from app.email_service import EmailService, get_email_service
from app.main import app

# In-memory SQLite for testing with StaticPool to share connection across threads
TEST_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class MockEmailService(EmailService):
    """Mock email service capturing sent emails and allowing simulated failures."""
    def __init__(self):
        self.sent_emails = []
        self.should_fail = False

    def send_verification_otp(
        self,
        email: str,
        first_name: str,
        otp: str,
        expires_in_minutes: int
    ) -> bool:
        if self.should_fail:
            return False
        self.sent_emails.append({
            "email": email,
            "first_name": first_name,
            "otp": otp,
            "expires_in_minutes": expires_in_minutes
        })
        return True


mock_email = MockEmailService()


@pytest.fixture(autouse=True)
def setup_database():
    """Create all tables before each test and drop after test."""
    Base.metadata.create_all(bind=engine)
    mock_email.sent_emails.clear()
    mock_email.should_fail = False
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db_session() -> Generator[Session, None, None]:
    """Provide transactional test database session."""
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client(db_session: Session) -> Generator[TestClient, None, None]:
    """Provide FastAPI test client wired with test DB and mock email service."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    def override_get_email():
        return mock_email

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_email_service] = override_get_email

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


@pytest.fixture
def email_mock() -> MockEmailService:
    """Fixture to inspect or configure the mock email service."""
    return mock_email
