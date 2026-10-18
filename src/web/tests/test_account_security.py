"""Boundary tests for browser CSRF, OAuth, signed identities and enumeration."""
import asyncio
import json
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse
from unittest.mock import AsyncMock

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import update

from app import auth, oauth
from app.auth_routes import OAUTH_COOKIE
from app.models import User, OAuthAccount, OAuthState, Session, EmailVerification, PasswordReset

PASSWORD = "SecurePass123!"


def user_session(env, email="owner@example.com"):
    with env.sessions() as db:
        user = User(email=email, email_verified=True, password_hash=auth.hash_password(PASSWORD))
        db.add(user)
        db.commit()
        session, raw = auth.create_session(db, user.id)
        csrf, ident = session.csrf_token, user.id
    env.client.cookies.set(auth.SESSION_COOKIE, raw, domain="testserver.local", path="/")
    env.client.headers["X-CSRF-Token"] = csrf
    return ident


@pytest.fixture(params=["google", "github"])
def provider(request, monkeypatch):
    for setting in ("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET"):
        monkeypatch.setattr(oauth, setting, "test-only")
    monkeypatch.setattr(oauth, "exchange_google_code", AsyncMock(return_value={"id_token": "mock"}))
    monkeypatch.setattr(oauth, "get_google_identity", AsyncMock(return_value={"sub": "123", "email": "provider@example.com", "email_verified": True}))
    monkeypatch.setattr(oauth, "exchange_github_code", AsyncMock(return_value="mock"))
    monkeypatch.setattr(oauth, "get_github_user", AsyncMock(return_value={"id": 123, "login": "provider"}))
    monkeypatch.setattr(oauth, "get_github_primary_verified_email", AsyncMock(return_value="provider@example.com"))
    return request.param


def start(env, provider, link=False):
    response = env.client.post(f"/auth/link/{provider}", follow_redirects=False) if link else env.client.get(f"/auth/{provider}", follow_redirects=False)
    assert response.status_code == 303, response.text
    return parse_qs(urlparse(response.headers["location"]).query)["state"][0]


def callback(env, provider, state):
    return env.client.get(f"/auth/{provider}/callback", params={"state": state, "code": "test"}, follow_redirects=False)


@pytest.mark.parametrize("fault", ["missing", "invalid", "expired", "binding", "provider", "session_switch"])
def test_oauth_rejects_invalid_attempt(auth_env, provider, fault):
    state = start(auth_env, provider)
    if fault == "missing":
        state = ""
    elif fault == "invalid":
        state = "not-a-state"
    elif fault == "expired":
        with auth_env.sessions() as db:
            db.execute(update(OAuthState).values(expires_at=datetime.now(timezone.utc)-timedelta(seconds=1)))
            db.commit()
    elif fault == "binding":
        auth_env.client.cookies.clear()
    elif fault == "provider":
        provider = "github" if provider == "google" else "google"
    elif fault == "session_switch":
        user_session(auth_env)
    assert callback(auth_env, provider, state).status_code == 400
    with auth_env.sessions() as db:
        assert db.query(OAuthAccount).count() == 0


def test_unsolicited_callback(auth_env, provider):
    assert callback(auth_env, provider, "unsolicited").status_code == 400


def test_oauth_success_and_replay(auth_env, provider):
    state = start(auth_env, provider)
    original_binding = auth_env.client.cookies.get(OAUTH_COOKIE)
    with auth_env.sessions() as db:
        attempt = db.query(OAuthState).one()
        assert attempt.state_hash == auth.hash_token(state)
        assert attempt.binding_hash == auth.hash_token(original_binding)
        assert attempt.state_hash != state
    assert callback(auth_env, provider, state).status_code == 303
    auth_env.client.cookies.clear()
    auth_env.client.cookies.set(OAUTH_COOKIE, original_binding)
    assert callback(auth_env, provider, state).status_code == 400
    with auth_env.sessions() as db:
        assert db.query(User).count() == db.query(OAuthAccount).count() == 1
        assert db.query(OAuthState).one().used_at is not None


def test_email_collision_has_safe_link_path(auth_env, provider):
    with auth_env.sessions() as db:
        db.add(User(email="provider@example.com", password_hash="unchanged", email_verified=True))
        db.commit()
    state = start(auth_env, provider)
    response = callback(auth_env, provider, state)
    assert response.status_code == 409
    assert '/settings' in response.text and '/login' in response.text
    assert auth.SESSION_COOKIE not in response.cookies
    with auth_env.sessions() as db:
        assert db.query(User).one().password_hash == "unchanged"
        assert db.query(OAuthAccount).count() == 0


def test_link_requires_authenticated_post_and_csrf(auth_env, provider):
    assert auth_env.client.post(f"/auth/link/{provider}", follow_redirects=False).status_code == 401
    owner = user_session(auth_env)
    assert auth_env.client.get(f"/auth/link/{provider}", follow_redirects=False).status_code == 405
    valid = auth_env.client.headers.pop("X-CSRF-Token")
    assert auth_env.client.post(f"/auth/link/{provider}", follow_redirects=False).status_code == 403
    auth_env.client.headers["X-CSRF-Token"] = valid
    state = start(auth_env, provider, link=True)
    assert callback(auth_env, provider, state).status_code == 303
    with auth_env.sessions() as db:
        assert db.query(OAuthAccount).one().user_id == owner
        assert db.query(User).count() == 1


@pytest.mark.parametrize("change", ["logout", "switch", "expired", "during_exchange"])
def test_link_binds_initiating_session(auth_env, provider, change, monkeypatch):
    owner = user_session(auth_env)
    state = start(auth_env, provider, link=True)
    if change == "logout":
        auth_env.client.post("/auth/logout")
    elif change == "switch":
        auth_env.client.cookies.delete(auth.SESSION_COOKIE)
        user_session(auth_env, "second@example.com")
    elif change == "expired":
        with auth_env.sessions() as db:
            db.execute(update(Session).values(expires_at=datetime.now(timezone.utc)-timedelta(seconds=1)))
            db.commit()
    else:
        async def exchange(*args):
            with auth_env.sessions() as db:
                db.execute(update(Session).values(revoked_at=datetime.now(timezone.utc)))
                db.commit()
            return {"id_token": "mock"} if provider == "google" else "mock"
        monkeypatch.setattr(oauth, f"exchange_{provider}_code", exchange)
    assert callback(auth_env, provider, state).status_code == 400
    with auth_env.sessions() as db:
        assert db.query(OAuthAccount).count() == 0
        assert db.get(User, owner) is not None


def test_failed_exchange_consumes_state(auth_env, provider, monkeypatch):
    state = start(auth_env, provider)
    exchange = AsyncMock(side_effect=ValueError("do-not-expose-secret"))
    monkeypatch.setattr(oauth, f"exchange_{provider}_code", exchange)
    response = callback(auth_env, provider, state)
    assert response.status_code == 400 and "do-not-expose-secret" not in response.text
    assert callback(auth_env, provider, state).status_code == 400
    assert exchange.await_count == 1


@pytest.mark.parametrize("identity", [None, "", "None", True, 0, -1])
def test_github_missing_identity(auth_env, monkeypatch, identity):
    monkeypatch.setattr(oauth, "GITHUB_CLIENT_ID", "test")
    monkeypatch.setattr(oauth, "GITHUB_CLIENT_SECRET", "test")
    monkeypatch.setattr(oauth, "exchange_github_code", AsyncMock(return_value="mock"))
    monkeypatch.setattr(oauth, "get_github_user", AsyncMock(return_value={"id": identity}))
    assert callback(auth_env, "github", start(auth_env, "github")).status_code == 400


@pytest.mark.parametrize("path", ["signup", "login", "forgot", "reset", "verify", "logout"])
def test_all_auth_posts_require_csrf(auth_env, path):
    auth_env.client.headers.pop("X-CSRF-Token")
    response = auth_env.client.post(f"/auth/{path}", data={"email": "x@example.com", "password": PASSWORD, "new_password": PASSWORD, "token": "unknown"})
    assert response.status_code == 403


def test_signup_and_forgot_responses_indistinguishable(auth_env):
    data = {"email": "new@example.com", "password": PASSWORD}
    first = auth_env.client.post("/auth/signup", data=data)
    duplicate = auth_env.client.post("/auth/signup", data=data)
    # New vs unverified-duplicate remain indistinguishable (generic message)
    assert [(r.status_code, r.content) for r in [first, duplicate]] == [(200, first.content)] * 2
    with auth_env.sessions() as db:
        db.query(User).one().email_verified = True
        db.commit()
    verified = auth_env.client.post("/auth/signup", data=data)
    # Founder decision 2026-10-18: verified emails get explicit "already registered"
    # (409) for UX clarity, accepting enumeration tradeoff on signup only.
    assert verified.status_code == 409
    assert "already registered" in verified.json()["error"].lower()
    known = auth_env.client.post("/auth/forgot", data={"email": "new@example.com"})
    unknown = auth_env.client.post("/auth/forgot", data={"email": "unknown@example.com"})
    assert (known.status_code, known.content) == (unknown.status_code, unknown.content)


def test_email_links_point_to_real_pages(monkeypatch):
    from app import email
    captures = []
    monkeypatch.setattr(email, "send_email", lambda to, subject, html: captures.append(html))
    email.send_verification_email("x@example.com", "verification-secret")
    email.send_password_reset_email("x@example.com", "reset-secret")
    assert '/verify?token=verification-secret' in captures[0]
    assert '/reset?token=reset-secret' in captures[1]


def test_forms_secure_cookies_and_token_storage(auth_env):
    auth_env.client.post("/auth/signup", data={"email": "new@example.com", "password": PASSWORD})
    token = auth_env.sent[0][2]
    page = auth_env.client.get("/verify", params={"token": token})
    assert page.headers["Cache-Control"] == "no-store"
    assert page.headers["Referrer-Policy"] == "no-referrer"
    assert 'action="/auth/verify"' in page.text
    with auth_env.sessions() as db:
        verification = db.query(EmailVerification).one()
        assert verification.token_hash == auth.hash_token(token)
        assert verification.used_at is None
    assert auth_env.client.post("/auth/verify", data={"token": token}).status_code == 200
    response = auth_env.client.post("/auth/login", data={"email": "new@example.com", "password": PASSWORD})
    cookie = response.headers["set-cookie"]
    assert all(word in cookie for word in ["Secure", "HttpOnly", "SameSite=lax", "Path=/", "__Host-"])
    page = auth_env.client.get("/settings")
    assert 'method="post" action="/auth/link/google"' in page.text
    assert 'method="post" action="/auth/link/github"' in page.text
    assert 'action="/auth/logout"' in page.text
    assert 'name="csrf_token"' in page.text


def test_email_does_not_log_secrets_or_claim_delivery(caplog, monkeypatch):
    from app import email
    monkeypatch.setattr(email, "RESEND_API_KEY", "")
    assert email.send_email("private@example.com", "subject", "secret-token") is False
    assert "private@example.com" not in caplog.text and "secret-token" not in caplog.text


@pytest.fixture
def signed_google(monkeypatch):
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk["kid"] = "test-key"
    class Response:
        def raise_for_status(self): pass
        def json(self): return {"keys": [jwk]}
    monkeypatch.setattr(oauth, "GOOGLE_CLIENT_ID", "client")
    monkeypatch.setattr(oauth.httpx.AsyncClient, "get", AsyncMock(return_value=Response()))
    now = datetime.now(timezone.utc).timestamp()
    claims = {"iss": "https://accounts.google.com", "aud": "client", "iat": now, "exp": now+300,
              "sub": "123", "nonce": "nonce", "email": "verified@example.com", "email_verified": True}
    return key, claims


@pytest.mark.parametrize("fault", [None, "issuer", "audience", "expiry", "nonce", "signature", "unverified", "truthy_verified", "missing_sub", "azp", "multi_audience", "algorithm"])
def test_google_signed_identity_validation(signed_google, fault):
    key, claims = signed_google
    if fault == "issuer": claims["iss"] = "https://evil.example"
    if fault == "audience": claims["aud"] = "other-client"
    if fault == "expiry": claims["exp"] = claims["iat"] - 1
    if fault == "nonce": claims["nonce"] = "other-nonce"
    if fault == "unverified": claims["email_verified"] = False
    if fault == "truthy_verified": claims["email_verified"] = "true"
    if fault == "missing_sub": del claims["sub"]
    if fault == "azp": claims["azp"] = "other-client"
    if fault == "multi_audience": claims["aud"] = ["client", "other-client"]
    if fault == "signature":
        from cryptography.hazmat.primitives.asymmetric import rsa
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    encoded = jwt.encode(claims, "invalid-key-long-enough-for-hs256!!!" if fault == "algorithm" else key,
                         algorithm="HS256" if fault == "algorithm" else "RS256", headers={"kid": "test-key"})
    if fault is None:
        assert asyncio.run(oauth.get_google_identity({"id_token": encoded}, "nonce"))["sub"] == "123"
    else:
        with pytest.raises((ValueError, jwt.PyJWTError)):
            asyncio.run(oauth.get_google_identity({"id_token": encoded}, "nonce"))


def test_oauth_concurrent_callbacks_only_one_claim(auth_env, provider):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    state = start(auth_env, provider)
    binding = auth_env.client.cookies.get(OAUTH_COOKIE)
    barrier = Barrier(2)
    def attempt(_):
        with TestClient(auth_env.app, base_url="https://testserver", cookies={OAUTH_COOKIE: binding}) as client:
            barrier.wait(timeout=10)
            return client.get(f"/auth/{provider}/callback", params={"code": "test", "state": state}, follow_redirects=False).status_code
    with ThreadPoolExecutor(2) as pool:
        assert sorted(pool.map(attempt, range(2))) == [303, 400]
    with auth_env.sessions() as db:
        assert db.query(OAuthAccount).count() == 1
        assert db.query(Session).count() == 1


def test_expired_cookie_can_restart_oauth(auth_env, provider):
    user_session(auth_env)
    with auth_env.sessions() as db:
        db.execute(update(Session).values(expires_at=datetime.now(timezone.utc)-timedelta(seconds=1)))
        db.commit()
    state = start(auth_env, provider)
    assert auth.SESSION_COOKIE not in auth_env.client.cookies
    assert callback(auth_env, provider, state).status_code == 303


def test_login_rotates_current_session_and_rejects_old_csrf(auth_env):
    user_session(auth_env)
    old_raw = auth_env.client.cookies.get(auth.SESSION_COOKIE)
    old_csrf = auth_env.client.headers["X-CSRF-Token"]
    response = auth_env.client.post("/auth/login", data={"email": "owner@example.com", "password": PASSWORD})
    assert response.status_code == 200
    assert response.json()["csrf_token"] != old_csrf
    assert auth_env.client.post("/auth/logout").status_code == 403
    with TestClient(auth_env.app, base_url="https://testserver", cookies={auth.SESSION_COOKIE: old_raw}) as client:
        assert client.get("/auth/me").status_code == 401


@pytest.mark.parametrize("password", ["A1!" + "x"*70, "A1!" + "é"*35])
def test_password_byte_limit_returns_validation_error(auth_env, password):
    response = auth_env.client.post("/auth/signup", data={"email": "long@example.com", "password": password})
    assert response.status_code == 400
    assert "72 bytes" in response.json()["error"]


def test_missing_and_oauth_login_use_dummy_hash(auth_env, monkeypatch):
    checks = []
    monkeypatch.setattr(auth, "verify_password", lambda password, digest: checks.append(digest) or False)
    with auth_env.sessions() as db:
        db.add(User(email="oauth@example.com", email_verified=True))
        db.commit()
    responses = [auth_env.client.post("/auth/login", data={"email": email, "password": PASSWORD}) for email in ["missing@example.com", "oauth@example.com"]]
    assert checks == [auth.DUMMY_PASSWORD_HASH] * 2
    assert responses[0].content == responses[1].content
    assert responses[0].status_code == responses[1].status_code == 401


@pytest.mark.parametrize("primary,verified", [(True, "true"), ("true", True), (False, True), (True, False)])
def test_github_requires_boolean_primary_and_verified(monkeypatch, primary, verified):
    class Response:
        def raise_for_status(self): pass
        def json(self): return [{"email": "x@example.com", "primary": primary, "verified": verified}]
    monkeypatch.setattr(oauth.httpx.AsyncClient, "get", AsyncMock(return_value=Response()))
    assert asyncio.run(oauth.get_github_primary_verified_email("mock")) is None


@pytest.mark.parametrize("payload", [{"error": "unavailable"}, [None], "invalid"])
def test_malformed_github_email_response_is_rejected(monkeypatch, payload):
    class Response:
        def raise_for_status(self): pass
        def json(self): return payload
    monkeypatch.setattr(oauth.httpx.AsyncClient, "get", AsyncMock(return_value=Response()))
    with pytest.raises(ValueError, match="Invalid GitHub"):
        asyncio.run(oauth.get_github_primary_verified_email("mock"))
