"""Phase 1 auth tests: signup, login, logout, verify, reset, OAuth (mocked),
CSRF, rate limits, session revocation.

Uses SQLite in-memory DB. Email sending is stubbed (no RESEND_API_KEY).
HIBP check is mocked to avoid network calls.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Set DATABASE_URL before importing app modules
os.environ["DATABASE_URL"] = "sqlite://"

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import auth as auth_helpers
from app.db import Base, get_db
from app.main import app
from app.models import EmailVerification, PasswordReset, User

# Use in-memory SQLite with StaticPool (shared connection)
engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)


def override_get_db():
    db = TestingSession()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app, raise_server_exceptions=False)

TEST_PASSWORD = "SecurePass123!"
WEAK_PASSWORD = "weak"


def _clear_db():
    db = TestingSession()
    for table in reversed(Base.metadata.sorted_tables):
        db.execute(table.delete())
    db.commit()
    db.close()
    auth_helpers.auth_limiter._attempts.clear()


@pytest.fixture(autouse=True)
def clean_db():
    _clear_db()
    yield
    _clear_db()


@pytest.fixture(autouse=True)
def mock_hibp():
    with patch("app.auth.check_password_breached", return_value=False):
        yield


@pytest.fixture(autouse=True)
def mock_email():
    with patch("app.email.send_email", return_value=True):
        yield


def _signup(email="test@example.com", password=TEST_PASSWORD):
    return client.post("/auth/signup", data={"email": email, "password": password})


def _verify_email(email):
    db = TestingSession()
    user = db.query(User).filter(User.email == email).first()
    ver = db.query(EmailVerification).filter(EmailVerification.user_id == user.id).first()
    db.close()
    # Get raw token from DB is hashed — we need to re-create a verification
    # Instead, directly mark verified for test setup
    db2 = TestingSession()
    u = db2.query(User).filter(User.email == email).first()
    u.email_verified = True
    db2.commit()
    db2.close()


def _login(email="test@example.com", password=TEST_PASSWORD):
    return client.post("/auth/login", data={"email": email, "password": password})


def _authenticated_client(email="test@example.com"):
    _signup(email)
    _verify_email(email)
    resp = _login(email)
    assert resp.status_code == 200, resp.text
    csrf = resp.json()["csrf_token"]
    # Extract session cookie
    cookies = resp.cookies
    c = TestClient(app, raise_server_exceptions=False, cookies=dict(cookies))
    return c, csrf


# --- Signup ---

def test_signup_success():
    resp = _signup()
    assert resp.status_code == 201
    assert "verification" in resp.json()["message"].lower()

    db = TestingSession()
    user = db.query(User).filter(User.email == "test@example.com").first()
    assert user is not None
    assert user.email_verified is False
    assert user.password_hash != TEST_PASSWORD  # Hashed
    db.close()


def test_signup_weak_password():
    resp = _signup(password=WEAK_PASSWORD)
    assert resp.status_code == 400
    assert "password" in resp.json()["error"].lower()


def test_signup_short_password():
    resp = _signup(password="Short1!")
    assert resp.status_code == 400


def test_signup_no_uppercase():
    resp = _signup(password="lowercase123!")
    assert resp.status_code == 400


def test_signup_no_special():
    resp = _signup(password="NoSpecial123")
    assert resp.status_code == 400


def test_signup_duplicate_email_returns_generic():
    _signup()
    resp = _signup()
    # Should NOT reveal that email exists — same generic message
    assert resp.status_code == 200
    assert "verification" in resp.json()["message"].lower()


def test_signup_breached_password():
    with patch("app.auth.check_password_breached", return_value=True):
        resp = _signup()
        assert resp.status_code == 400
        assert "breach" in resp.json()["error"].lower()


# --- Email verification ---

def test_verify_email_success():
    _signup()
    db = TestingSession()
    user = db.query(User).filter(User.email == "test@example.com").first()
    assert user.email_verified is False
    db.close()

    # Get the token — in real flow it's emailed; here we generate one directly
    # by querying the DB for the hash and using a known token
    token = auth_helpers.generate_token()
    db2 = TestingSession()
    u = db2.query(User).filter(User.email == "test@example.com").first()
    ver = EmailVerification(
        user_id=u.id,
        token_hash=auth_helpers.hash_token(token),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
    )
    db2.add(ver)
    db2.commit()
    db2.close()

    resp = client.get(f"/verify?token={token}")
    assert resp.status_code == 200
    assert "verified" in resp.text.lower()

    db3 = TestingSession()
    u3 = db3.query(User).filter(User.email == "test@example.com").first()
    assert u3.email_verified is True
    db3.close()


def test_verify_invalid_token():
    resp = client.get("/verify?token=invalid-token-123")
    assert resp.status_code == 200
    assert "failed" in resp.text.lower()


def test_verify_token_single_use():
    token = auth_helpers.generate_token()
    _signup()
    db = TestingSession()
    u = db.query(User).filter(User.email == "test@example.com").first()
    ver = EmailVerification(
        user_id=u.id,
        token_hash=auth_helpers.hash_token(token),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
    )
    db.add(ver)
    db.commit()
    db.close()

    resp1 = client.get(f"/verify?token={token}")
    assert "verified" in resp1.text.lower()
    resp2 = client.get(f"/verify?token={token}")
    assert "failed" in resp2.text.lower()


# --- Login / Logout ---

def test_login_success():
    _signup()
    _verify_email("test@example.com")
    resp = _login()
    assert resp.status_code == 200
    assert "csrf_token" in resp.json()
    assert "stacksift_session" in resp.cookies


def test_login_unverified_email():
    _signup()
    # Don't verify
    resp = _login()
    assert resp.status_code == 403
    assert "verify" in resp.json()["error"].lower()


def test_login_wrong_password():
    _signup()
    _verify_email("test@example.com")
    resp = _login(password="WrongPass123!")
    assert resp.status_code == 401
    assert "invalid" in resp.json()["error"].lower()


def test_login_nonexistent_email():
    resp = _login(email="nonexistent@example.com")
    assert resp.status_code == 401
    # Same message as wrong password — no enumeration
    assert "invalid" in resp.json()["error"].lower()


def test_login_oauth_only_account():
    # OAuth user has no password_hash
    db = TestingSession()
    user = User(email="oauth@example.com", email_verified=True, password_hash=None)
    db.add(user)
    db.commit()
    db.close()
    resp = _login(email="oauth@example.com")
    assert resp.status_code == 401


def test_logout():
    c, csrf = _authenticated_client()
    resp = c.post("/auth/logout", headers={"X-CSRF-Token": csrf})
    assert resp.status_code == 200
    # Session cookie should be cleared
    assert "stacksift_session" not in resp.cookies or resp.cookies["stacksift_session"] == ""


def test_logout_requires_csrf():
    c, csrf = _authenticated_client()
    resp = c.post("/auth/logout")  # No CSRF header
    assert resp.status_code == 403


def test_me_authenticated():
    c, csrf = _authenticated_client()
    resp = c.get("/auth/me")
    assert resp.status_code == 200
    assert resp.json()["email"] == "test@example.com"


def test_me_unauthenticated():
    resp = client.get("/auth/me")
    assert resp.status_code == 401


# --- Password reset ---

def test_forgot_generic_success():
    resp = client.post("/auth/forgot", data={"email": "test@example.com"})
    assert resp.status_code == 200
    assert "reset" in resp.json()["message"].lower()


def test_forgot_nonexistent_email_generic():
    resp = client.post("/auth/forgot", data={"email": "nobody@example.com"})
    assert resp.status_code == 200
    # Same message — no enumeration
    assert "reset" in resp.json()["message"].lower()


def test_reset_password_success():
    _signup()
    _verify_email("test@example.com")
    token = auth_helpers.generate_token()
    db = TestingSession()
    u = db.query(User).filter(User.email == "test@example.com").first()
    reset = PasswordReset(
        user_id=u.id,
        token_hash=auth_helpers.hash_token(token),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    db.add(reset)
    db.commit()
    db.close()

    resp = client.post("/auth/reset", data={"token": token, "new_password": "NewSecurePass456!"})
    assert resp.status_code == 200

    # Old password should fail, new should work
    resp_old = _login(password=TEST_PASSWORD)
    assert resp_old.status_code == 401
    resp_new = _login(password="NewSecurePass456!")
    assert resp_new.status_code == 200


def test_reset_invalid_token():
    resp = client.post("/auth/reset", data={"token": "bad-token", "new_password": "NewSecurePass456!"})
    assert resp.status_code == 400


def test_reset_token_single_use():
    _signup()
    token = auth_helpers.generate_token()
    db = TestingSession()
    u = db.query(User).filter(User.email == "test@example.com").first()
    reset = PasswordReset(
        user_id=u.id,
        token_hash=auth_helpers.hash_token(token),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    db.add(reset)
    db.commit()
    db.close()

    resp1 = client.post("/auth/reset", data={"token": token, "new_password": "NewSecurePass456!"})
    assert resp1.status_code == 200
    resp2 = client.post("/auth/reset", data={"token": token, "new_password": "AnotherPass789!"})
    assert resp2.status_code == 400


def test_reset_revokes_all_sessions():
    c, csrf = _authenticated_client()
    # Create second session (another login)
    resp2 = _login()
    assert resp2.status_code == 200

    # Reset password
    token = auth_helpers.generate_token()
    db = TestingSession()
    u = db.query(User).filter(User.email == "test@example.com").first()
    reset = PasswordReset(
        user_id=u.id,
        token_hash=auth_helpers.hash_token(token),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    db.add(reset)
    db.commit()
    db.close()

    client.post("/auth/reset", data={"token": token, "new_password": "NewSecurePass456!"})

    # Old session should be revoked
    resp = c.get("/auth/me")
    assert resp.status_code == 401


# --- Sessions ---

def test_list_sessions():
    c, csrf = _authenticated_client()
    resp = c.get("/auth/sessions")
    assert resp.status_code == 200
    assert len(resp.json()["sessions"]) == 1
    assert resp.json()["sessions"][0]["is_current"] is True


def test_revoke_session():
    c, csrf = _authenticated_client()
    # Create second session
    resp2 = _login()
    cookies2 = resp2.cookies
    c2 = TestClient(app, raise_server_exceptions=False, cookies=dict(cookies2))

    # List sessions from first client
    resp = c.get("/auth/sessions")
    sessions = resp.json()["sessions"]
    assert len(sessions) == 2
    other = [s for s in sessions if not s["is_current"]][0]

    # Revoke other session
    resp = c.post(f"/auth/sessions/{other['id']}/revoke", headers={"X-CSRF-Token": csrf})
    assert resp.status_code == 200

    # Other session should now be invalid
    resp = c2.get("/auth/me")
    assert resp.status_code == 401


def test_cannot_revoke_current_session():
    c, csrf = _authenticated_client()
    resp = c.get("/auth/sessions")
    current_id = resp.json()["current_session_id"]
    resp = c.post(f"/auth/sessions/{current_id}/revoke", headers={"X-CSRF-Token": csrf})
    assert resp.status_code == 400


def test_revoke_all_sessions():
    c, csrf = _authenticated_client()
    _login()  # Second session
    resp = c.post("/auth/sessions/revoke-all", headers={"X-CSRF-Token": csrf})
    assert resp.status_code == 200
    # Current session still valid
    resp = c.get("/auth/me")
    assert resp.status_code == 200
    # Only 1 session remains
    resp = c.get("/auth/sessions")
    assert len(resp.json()["sessions"]) == 1


# --- CSRF ---

def test_csrf_missing_on_logout():
    c, csrf = _authenticated_client()
    resp = c.post("/auth/logout")
    assert resp.status_code == 403


def test_csrf_wrong_token():
    c, csrf = _authenticated_client()
    resp = c.post("/auth/logout", headers={"X-CSRF-Token": "wrong-token"})
    assert resp.status_code == 403


# --- Rate limits ---

def test_login_rate_limit():
    # 5 attempts allowed, 6th blocked
    for _ in range(5):
        client.post("/auth/login", data={"email": "x@example.com", "password": "Wrong123!"})
    resp = client.post("/auth/login", data={"email": "x@example.com", "password": "Wrong123!"})
    assert resp.status_code == 429


def test_signup_rate_limit():
    for i in range(3):
        client.post("/auth/signup", data={"email": f"user{i}@example.com", "password": TEST_PASSWORD})
    resp = client.post("/auth/signup", data={"email": "user4@example.com", "password": TEST_PASSWORD})
    assert resp.status_code == 429


# --- OAuth (mocked) ---

def test_oauth_no_auto_link_by_email():
    """OAuth with same email as existing user must NOT link — creates separate account."""
    # Create email/password user
    _signup(email="same@example.com")
    _verify_email("same@example.com")

    # OAuth creates a NEW user even with same email (no auto-link)
    db = TestingSession()
    from app import oauth as oauth_helpers

    user1 = db.query(User).filter(User.email == "same@example.com").first()
    user1_id = str(user1.id)
    db.close()

    db2 = TestingSession()
    user2, created = oauth_helpers.find_or_create_oauth_user(
        db2, "google", "google-123", "same@example.com", "Test User"
    )
    assert created is True
    assert str(user2.id) != user1_id  # Different user!
    db2.close()


def test_oauth_link_requires_explicit():
    """Linking OAuth to existing account requires explicit call with logged-in user."""
    db = TestingSession()
    user = User(email="user@example.com", email_verified=True, password_hash="hash")
    db.add(user)
    db.commit()
    db.refresh(user)
    user_id = user.id
    db.close()

    db2 = TestingSession()
    from app import oauth as oauth_helpers

    u = db2.query(User).filter(User.id == user_id).first()
    oauth = oauth_helpers.link_oauth_to_user(db2, u, "github", "gh-123", "user@example.com")
    assert oauth.provider == "github"
    assert oauth.user_id == user_id
    db2.close()


def test_oauth_link_duplicate_rejected():
    """Same OAuth identity linked to another user → rejected."""
    db = TestingSession()
    from app import oauth as oauth_helpers

    user1 = User(email="u1@example.com", email_verified=True, password_hash="hash")
    user2 = User(email="u2@example.com", email_verified=True, password_hash="hash")
    db.add_all([user1, user2])
    db.commit()
    db.refresh(user1)
    db.refresh(user2)
    u1_id, u2_id = user1.id, user2.id
    db.close()

    db2 = TestingSession()
    u1 = db2.query(User).filter(User.id == u1_id).first()
    oauth_helpers.link_oauth_to_user(db2, u1, "google", "google-999", "u1@example.com")
    db2.close()

    db3 = TestingSession()
    u2 = db3.query(User).filter(User.id == u2_id).first()
    with pytest.raises(ValueError, match="already linked"):
        oauth_helpers.link_oauth_to_user(db3, u2, "google", "google-999", "u2@example.com")
    db3.close()


def test_github_primary_verified_email():
    """GitHub helper returns only primary+verified email."""
    import asyncio

    async def mock_get(*args, **kwargs):
        class Resp:
            def raise_for_status(self):
                pass

            def json(self):
                return [
                    {"email": "unverified@example.com", "primary": True, "verified": False},
                    {"email": "verified@example.com", "primary": False, "verified": True},
                    {"email": "primary-verified@example.com", "primary": True, "verified": True},
                ]

        return Resp()

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        from app import oauth as oauth_helpers

        result = asyncio.run(oauth_helpers.get_github_primary_verified_email("fake-token"))
        assert result == "primary-verified@example.com"


# --- Password helpers ---

def test_password_hashing():
    h = auth_helpers.hash_password(TEST_PASSWORD)
    assert auth_helpers.verify_password(TEST_PASSWORD, h) is True
    assert auth_helpers.verify_password("WrongPass123!", h) is False


def test_password_strength():
    assert auth_helpers.validate_password_strength("short") is not None
    assert auth_helpers.validate_password_strength("alllowercase123!") is not None
    assert auth_helpers.validate_password_strength("ALLUPPERCASE123!") is not None
    assert auth_helpers.validate_password_strength("NoNumbers!") is not None
    assert auth_helpers.validate_password_strength("NoSpecial123") is not None
    assert auth_helpers.validate_password_strength(TEST_PASSWORD) is None


def test_email_normalization():
    assert auth_helpers.normalize_email("  TEST@Example.COM  ") == "test@example.com"


def test_session_token_hash():
    token = auth_helpers.generate_token()
    h1 = auth_helpers.hash_token(token)
    h2 = auth_helpers.hash_token(token)
    assert h1 == h2
    assert h1 != token
    assert len(h1) == 64
