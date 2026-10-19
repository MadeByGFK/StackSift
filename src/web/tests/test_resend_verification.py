"""Security tests for /auth/resend-verification (GFD 2026-10-18).

The previous client-side dummy-password approach (ResendOnly123!) could
create accounts with a predictable password. The dedicated endpoint
never creates accounts and never accepts a password.
"""

import re


def _signup(auth_env, email="resend@example.com", password="TestPass123!x"):
    return auth_env.client.post("/auth/signup", data={
        "email": email, "password": password,
    })


def test_resend_verification_unverified_sends(auth_env):
    """Existing unverified account → verification email queued."""
    _signup(auth_env)
    # Clear the signup email
    auth_env.sent.clear()
    resp = auth_env.client.post("/auth/resend-verification", data={
        "email": "resend@example.com",
    })
    assert resp.status_code == 200
    assert "verification" in resp.json()["message"].lower()
    # Email was queued
    assert len(auth_env.sent) == 1
    assert auth_env.sent[0][0] == "verify"
    assert auth_env.sent[0][1] == "resend@example.com"


def test_resend_verification_unknown_email_generic(auth_env):
    """Unknown email → generic response, no email sent (no enumeration)."""
    resp = auth_env.client.post("/auth/resend-verification", data={
        "email": "nobody@example.com",
    })
    assert resp.status_code == 200
    assert "verification" in resp.json()["message"].lower()
    assert auth_env.sent == []


def test_resend_verification_verified_no_email(auth_env):
    """Verified account → generic response, no email sent."""
    _signup(auth_env)
    # Verify the account
    from app import auth as auth_helpers
    from app.models import User, EmailVerification
    with auth_env.sessions() as db:
        user = db.query(User).filter(User.email == "resend@example.com").one()
        # Mark verified directly
        user.email_verified = True
        db.commit()
    auth_env.sent.clear()
    resp = auth_env.client.post("/auth/resend-verification", data={
        "email": "resend@example.com",
    })
    assert resp.status_code == 200
    assert auth_env.sent == []


def test_resend_verification_never_creates_account(auth_env):
    """Resend endpoint must NEVER create an account (the old bug)."""
    from app.models import User
    resp = auth_env.client.post("/auth/resend-verification", data={
        "email": "brand-new@example.com",
    })
    assert resp.status_code == 200
    with auth_env.sessions() as db:
        assert db.query(User).filter(User.email == "brand-new@example.com").count() == 0


def test_resend_verification_requires_csrf(auth_env):
    """CSRF protection applies (via router-level require_csrf)."""
    # Temporarily remove CSRF header
    old = auth_env.client.headers.pop("X-CSRF-Token", None)
    try:
        resp = auth_env.client.post("/auth/resend-verification", data={
            "email": "resend@example.com",
        })
        # Should be 403 without CSRF token
        assert resp.status_code == 403
    finally:
        if old:
            auth_env.client.headers["X-CSRF-Token"] = old


def test_signup_template_no_dummy_password(auth_env):
    """The signup page must not contain the predictable dummy password."""
    resp = auth_env.client.get("/signup")
    assert resp.status_code == 200
    assert "ResendOnly123!" not in resp.text
    # Resend button uses the dedicated endpoint
    assert "/auth/resend-verification" in resp.text
