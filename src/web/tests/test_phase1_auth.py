"""Accounts regression tests using function-scoped database and dependency fixtures."""
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from app import auth as auth_helpers
from app.main import app
from app.models import EmailVerification, PasswordReset, User

TEST_PASSWORD = "SecurePass123!"
WEAK_PASSWORD = "weak"


def _signup(auth_env, email="test@example.com", password=TEST_PASSWORD):
    return auth_env.client.post("/auth/signup", data={"email": email, "password": password})


def _verify_email(auth_env, email):
    db = auth_env.sessions()
    user = db.query(User).filter(User.email == email).first()
    ver = db.query(EmailVerification).filter(EmailVerification.user_id == user.id).first()
    db.close()
    # Get raw token from DB is hashed — we need to re-create a verification
    # Instead, directly mark verified for test setup
    db2 = auth_env.sessions()
    u = db2.query(User).filter(User.email == email).first()
    u.email_verified = True
    db2.commit()
    db2.close()


def _login(auth_env, email="test@example.com", password=TEST_PASSWORD):
    auth_env.client.headers["X-CSRF-Token"] = auth_env.client.get("/auth/csrf").json()["csrf_token"]
    response = auth_env.client.post("/auth/login", data={"email": email, "password": password})
    if response.status_code == 200:
        auth_env.client.headers["X-CSRF-Token"] = response.json()["csrf_token"]
    return response


def _authenticated_client(auth_env, email="test@example.com"):
    _signup(auth_env, email)
    _verify_email(auth_env, email)
    resp = _login(auth_env, email)
    assert resp.status_code == 200, resp.text
    csrf = resp.json()["csrf_token"]
    # Extract session cookie
    cookies = resp.cookies
    c = TestClient(app, base_url="https://testserver", cookies=dict(cookies))
    auth_env.client.cookies.clear()
    auth_env.client.headers["X-CSRF-Token"] = auth_env.client.get("/auth/csrf").json()["csrf_token"]
    return c, csrf


# --- Signup ---

def test_signup_success(auth_env):
    resp = _signup(auth_env)
    assert resp.status_code == 200
    assert "verification" in resp.json()["message"].lower()

    db = auth_env.sessions()
    user = db.query(User).filter(User.email == "test@example.com").first()
    assert user is not None
    assert user.email_verified is False
    assert user.password_hash != TEST_PASSWORD  # Hashed
    db.close()


def test_signup_weak_password(auth_env):
    resp = _signup(auth_env, password=WEAK_PASSWORD)
    assert resp.status_code == 400
    assert "password" in resp.json()["error"].lower()


def test_signup_short_password(auth_env):
    resp = _signup(auth_env, password="Short1!")
    assert resp.status_code == 400


def test_signup_no_uppercase(auth_env):
    resp = _signup(auth_env, password="lowercase123!")
    assert resp.status_code == 400


def test_signup_no_special(auth_env):
    resp = _signup(auth_env, password="NoSpecial123")
    assert resp.status_code == 400


def test_signup_duplicate_email_returns_generic(auth_env):
    _signup(auth_env)
    resp = _signup(auth_env)
    # Should NOT reveal that email exists — same generic message
    assert resp.status_code == 200
    assert "verification" in resp.json()["message"].lower()


def test_signup_breached_password(auth_env):
    with patch("app.auth.check_password_breached", return_value=True):
        resp = _signup(auth_env)
        assert resp.status_code == 400
        assert "breach" in resp.json()["error"].lower()


# --- Email verification ---

def test_verify_email_success(auth_env):
    _signup(auth_env)
    db = auth_env.sessions()
    user = db.query(User).filter(User.email == "test@example.com").first()
    assert user.email_verified is False
    db.close()

    # Get the token — in real flow it's emailed; here we generate one directly
    # by querying the DB for the hash and using a known token
    token = auth_helpers.generate_token()
    db2 = auth_env.sessions()
    u = db2.query(User).filter(User.email == "test@example.com").first()
    ver = EmailVerification(
        user_id=u.id,
        token_hash=auth_helpers.hash_token(token),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
    )
    db2.add(ver)
    db2.commit()
    db2.close()

    resp = auth_env.client.post("/auth/verify", data={"token": token})
    assert resp.status_code == 200
    assert "verified" in resp.text.lower()

    db3 = auth_env.sessions()
    u3 = db3.query(User).filter(User.email == "test@example.com").first()
    assert u3.email_verified is True
    db3.close()


def test_verify_invalid_token(auth_env):
    resp = auth_env.client.post("/auth/verify", data={"token": "invalid-token-123"})
    assert resp.status_code == 400


def test_verify_token_single_use(auth_env):
    token = auth_helpers.generate_token()
    _signup(auth_env)
    db = auth_env.sessions()
    u = db.query(User).filter(User.email == "test@example.com").first()
    ver = EmailVerification(
        user_id=u.id,
        token_hash=auth_helpers.hash_token(token),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
    )
    db.add(ver)
    db.commit()
    db.close()

    resp1 = auth_env.client.post("/auth/verify", data={"token": token})
    assert "verified" in resp1.text.lower()
    resp2 = auth_env.client.post("/auth/verify", data={"token": token})
    assert resp2.status_code == 400


# --- Login / Logout ---

def test_login_success(auth_env):
    _signup(auth_env)
    _verify_email(auth_env, "test@example.com")
    resp = _login(auth_env)
    assert resp.status_code == 200
    assert "csrf_token" in resp.json()
    assert auth_helpers.SESSION_COOKIE in resp.cookies


def test_login_unverified_email(auth_env):
    _signup(auth_env)
    # Don't verify
    resp = _login(auth_env)
    assert resp.status_code == 403
    assert "verify" in resp.json()["error"].lower()


def test_login_wrong_password(auth_env):
    _signup(auth_env)
    _verify_email(auth_env, "test@example.com")
    resp = _login(auth_env, password="WrongPass123!")
    assert resp.status_code == 401
    assert "invalid" in resp.json()["error"].lower()


def test_login_nonexistent_email(auth_env):
    resp = _login(auth_env, email="nonexistent@example.com")
    assert resp.status_code == 401
    # Same message as wrong password — no enumeration
    assert "invalid" in resp.json()["error"].lower()


def test_login_oauth_only_account(auth_env):
    # OAuth user has no password_hash
    db = auth_env.sessions()
    user = User(email="oauth@example.com", email_verified=True, password_hash=None)
    db.add(user)
    db.commit()
    db.close()
    resp = _login(auth_env, email="oauth@example.com")
    assert resp.status_code == 401


def test_logout(auth_env):
    c, csrf = _authenticated_client(auth_env)
    resp = c.post("/auth/logout", headers={"X-CSRF-Token": csrf})
    assert resp.status_code == 200
    # Session cookie should be cleared
    assert auth_helpers.SESSION_COOKIE not in resp.cookies or resp.cookies[auth_helpers.SESSION_COOKIE] == ""


def test_logout_requires_csrf(auth_env):
    c, csrf = _authenticated_client(auth_env)
    resp = c.post("/auth/logout")  # No CSRF header
    assert resp.status_code == 403


def test_me_authenticated(auth_env):
    c, csrf = _authenticated_client(auth_env)
    resp = c.get("/auth/me")
    assert resp.status_code == 200
    assert resp.json()["email"] == "test@example.com"


def test_me_unauthenticated(auth_env):
    resp = auth_env.client.get("/auth/me")
    assert resp.status_code == 401


# --- Password reset ---

def test_forgot_generic_success(auth_env):
    resp = auth_env.client.post("/auth/forgot", data={"email": "test@example.com"})
    assert resp.status_code == 200
    assert "reset" in resp.json()["message"].lower()


def test_forgot_nonexistent_email_generic(auth_env):
    resp = auth_env.client.post("/auth/forgot", data={"email": "nobody@example.com"})
    assert resp.status_code == 200
    # Same message — no enumeration
    assert "reset" in resp.json()["message"].lower()


def test_reset_password_success(auth_env):
    _signup(auth_env)
    _verify_email(auth_env, "test@example.com")
    token = auth_helpers.generate_token()
    db = auth_env.sessions()
    u = db.query(User).filter(User.email == "test@example.com").first()
    reset = PasswordReset(
        user_id=u.id,
        token_hash=auth_helpers.hash_token(token),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    db.add(reset)
    db.commit()
    db.close()

    resp = auth_env.client.post("/auth/reset", data={"token": token, "new_password": "NewSecurePass456!"})
    assert resp.status_code == 200

    # Old password should fail, new should work
    resp_old = _login(auth_env, password=TEST_PASSWORD)
    assert resp_old.status_code == 401
    resp_new = _login(auth_env, password="NewSecurePass456!")
    assert resp_new.status_code == 200


def test_reset_invalid_token(auth_env):
    resp = auth_env.client.post("/auth/reset", data={"token": "bad-token", "new_password": "NewSecurePass456!"})
    assert resp.status_code == 400


def test_reset_token_single_use(auth_env):
    _signup(auth_env)
    token = auth_helpers.generate_token()
    db = auth_env.sessions()
    u = db.query(User).filter(User.email == "test@example.com").first()
    reset = PasswordReset(
        user_id=u.id,
        token_hash=auth_helpers.hash_token(token),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    db.add(reset)
    db.commit()
    db.close()

    resp1 = auth_env.client.post("/auth/reset", data={"token": token, "new_password": "NewSecurePass456!"})
    assert resp1.status_code == 200
    resp2 = auth_env.client.post("/auth/reset", data={"token": token, "new_password": "AnotherPass789!"})
    assert resp2.status_code == 400


def test_reset_revokes_all_sessions(auth_env):
    c, csrf = _authenticated_client(auth_env)
    # Create second session (another login)
    resp2 = _login(auth_env)
    assert resp2.status_code == 200

    # Reset password
    token = auth_helpers.generate_token()
    db = auth_env.sessions()
    u = db.query(User).filter(User.email == "test@example.com").first()
    reset = PasswordReset(
        user_id=u.id,
        token_hash=auth_helpers.hash_token(token),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    db.add(reset)
    db.commit()
    db.close()

    auth_env.client.post("/auth/reset", data={"token": token, "new_password": "NewSecurePass456!"})

    # Old session should be revoked
    resp = c.get("/auth/me")
    assert resp.status_code == 401


# --- Sessions ---

def test_list_sessions(auth_env):
    c, csrf = _authenticated_client(auth_env)
    resp = c.get("/auth/sessions")
    assert resp.status_code == 200
    assert len(resp.json()["sessions"]) == 1
    assert resp.json()["sessions"][0]["is_current"] is True


def test_revoke_session(auth_env):
    c, csrf = _authenticated_client(auth_env)
    # Create second session
    resp2 = _login(auth_env)
    cookies2 = resp2.cookies
    c2 = TestClient(app, base_url="https://testserver", cookies=dict(cookies2))

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


def test_cannot_revoke_current_session(auth_env):
    c, csrf = _authenticated_client(auth_env)
    resp = c.get("/auth/sessions")
    current_id = resp.json()["current_session_id"]
    resp = c.post(f"/auth/sessions/{current_id}/revoke", headers={"X-CSRF-Token": csrf})
    assert resp.status_code == 400


def test_revoke_all_sessions(auth_env):
    c, csrf = _authenticated_client(auth_env)
    _login(auth_env)  # Second session
    resp = c.post("/auth/sessions/revoke-all", headers={"X-CSRF-Token": csrf})
    assert resp.status_code == 200
    # Current session still valid
    resp = c.get("/auth/me")
    assert resp.status_code == 200
    # Only 1 session remains
    resp = c.get("/auth/sessions")
    assert len(resp.json()["sessions"]) == 1


# --- CSRF ---

def test_csrf_missing_on_logout(auth_env):
    c, csrf = _authenticated_client(auth_env)
    resp = c.post("/auth/logout")
    assert resp.status_code == 403


def test_csrf_wrong_token(auth_env):
    c, csrf = _authenticated_client(auth_env)
    resp = c.post("/auth/logout", headers={"X-CSRF-Token": "wrong-token"})
    assert resp.status_code == 403


# --- Rate limits ---

def test_login_rate_limit(auth_env):
    # 5 attempts allowed, 6th blocked
    for _ in range(5):
        auth_env.client.post("/auth/login", data={"email": "x@example.com", "password": "Wrong123!"})
    resp = auth_env.client.post("/auth/login", data={"email": "x@example.com", "password": "Wrong123!"})
    assert resp.status_code == 429


def test_signup_rate_limit(auth_env):
    for i in range(3):
        auth_env.client.post("/auth/signup", data={"email": f"user{i}@example.com", "password": TEST_PASSWORD})
    resp = auth_env.client.post("/auth/signup", data={"email": "user4@example.com", "password": TEST_PASSWORD})
    assert resp.status_code == 429


# --- OAuth (mocked) ---

@pytest.mark.parametrize("provider", ["google", "github"])
def test_oauth_no_auto_link_by_email(auth_env, provider):
    from app import oauth
    from app.models import OAuthAccount
    _signup(auth_env, email="same@example.com")
    with auth_env.sessions() as db:
        with pytest.raises(oauth.OAuthConflict, match="Account settings"):
            oauth.find_or_create_oauth_user(db, provider, "123", "SAME@example.com", "Test")
        assert db.query(User).count() == 1
        assert db.query(OAuthAccount).count() == 0


def test_oauth_link_requires_explicit(auth_env):
    """Linking OAuth to existing account requires explicit call with logged-in user."""
    db = auth_env.sessions()
    user = User(email="user@example.com", email_verified=True, password_hash="hash")
    db.add(user)
    db.commit()
    db.refresh(user)
    user_id = user.id
    db.close()

    db2 = auth_env.sessions()
    from app import oauth as oauth_helpers

    u = db2.query(User).filter(User.id == user_id).first()
    oauth = oauth_helpers.link_oauth_to_user(db2, u, "github", "gh-123", "user@example.com")
    assert oauth.provider == "github"
    assert oauth.user_id == user_id
    db2.close()


def test_oauth_link_duplicate_rejected(auth_env):
    """Same OAuth identity linked to another user → rejected."""
    db = auth_env.sessions()
    from app import oauth as oauth_helpers

    user1 = User(email="u1@example.com", email_verified=True, password_hash="hash")
    user2 = User(email="u2@example.com", email_verified=True, password_hash="hash")
    db.add_all([user1, user2])
    db.commit()
    db.refresh(user1)
    db.refresh(user2)
    u1_id, u2_id = user1.id, user2.id
    db.close()

    db2 = auth_env.sessions()
    u1 = db2.query(User).filter(User.id == u1_id).first()
    oauth_helpers.link_oauth_to_user(db2, u1, "google", "google-999", "u1@example.com")
    db2.close()

    db3 = auth_env.sessions()
    u2 = db3.query(User).filter(User.id == u2_id).first()
    with pytest.raises(ValueError, match="already linked"):
        oauth_helpers.link_oauth_to_user(db3, u2, "google", "google-999", "u2@example.com")
    db3.close()


def test_github_primary_verified_email(auth_env):
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

def test_password_hashing(auth_env):
    h = auth_helpers.hash_password(TEST_PASSWORD)
    assert auth_helpers.verify_password(TEST_PASSWORD, h) is True
    assert auth_helpers.verify_password("WrongPass123!", h) is False


def test_password_strength(auth_env):
    assert auth_helpers.validate_password_strength("short") is not None
    assert auth_helpers.validate_password_strength("alllowercase123!") is not None
    assert auth_helpers.validate_password_strength("ALLUPPERCASE123!") is not None
    assert auth_helpers.validate_password_strength("NoNumbers!") is not None
    assert auth_helpers.validate_password_strength("NoSpecial123") is not None
    assert auth_helpers.validate_password_strength(TEST_PASSWORD) is None


def test_email_normalization(auth_env):
    assert auth_helpers.normalize_email("  TEST@Example.COM  ") == "test@example.com"


def test_session_token_hash(auth_env):
    token = auth_helpers.generate_token()
    h1 = auth_helpers.hash_token(token)
    h2 = auth_helpers.hash_token(token)
    assert h1 == h2
    assert h1 != token
    assert len(h1) == 64
