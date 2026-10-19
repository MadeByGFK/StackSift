"""Security tests for /auth/resend-verification (GFD 2026-10-18).

The previous client-side dummy-password approach (ResendOnly123!) could
create accounts with a predictable password. The dedicated endpoint
never creates accounts and never accepts a password.

Rate limits (GFD 2026-10-18 round 2):
- verify_resend: 3/hour per email (prevents targeted harassment)
- resend_ip: 10/hour per IP (prevents distributed abuse)
"""

import pytest


def _signup(auth_env, email="resend@example.com", password="TestPass123!x"):
    return auth_env.client.post("/auth/signup", data={
        "email": email, "password": password,
    })


@pytest.fixture(autouse=True)
def _reset_auth_limiter():
    """Clear in-memory auth rate limiter so tests are isolated."""
    from app import auth as auth_module
    if hasattr(auth_module, "auth_limiter") and hasattr(auth_module.auth_limiter, "_hits"):
        auth_module.auth_limiter._hits.clear()


def test_resend_verification_unverified_sends(auth_env):
    """Existing unverified account → verification email queued."""
    _signup(auth_env)
    auth_env.sent.clear()
    resp = auth_env.client.post("/auth/resend-verification", data={
        "email": "resend@example.com",
    })
    assert resp.status_code == 200
    assert "verification" in resp.json()["message"].lower()
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
    from app.models import User
    with auth_env.sessions() as db:
        user = db.query(User).filter(User.email == "resend@example.com").one()
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
    old = auth_env.client.headers.pop("X-CSRF-Token", None)
    try:
        resp = auth_env.client.post("/auth/resend-verification", data={
            "email": "resend@example.com",
        })
        assert resp.status_code == 403
    finally:
        if old:
            auth_env.client.headers["X-CSRF-Token"] = old


def test_signup_template_no_dummy_password(auth_env):
    """The signup page must not contain the predictable dummy password."""
    resp = auth_env.client.get("/signup")
    assert resp.status_code == 200
    assert "ResendOnly123!" not in resp.text
    assert "/auth/resend-verification" in resp.text


# --- Regression tests: repeated requests and rate-limit exhaustion ---

def test_resend_repeated_requests_same_email(auth_env):
    """Up to 3 resends per hour per email succeed; 4th is rate-limited."""
    _signup(auth_env)
    auth_env.sent.clear()
    for i in range(3):
        resp = auth_env.client.post("/auth/resend-verification", data={
            "email": "resend@example.com",
        })
        assert resp.status_code == 200, f"Request {i+1} should succeed"
    # 4th request → 429
    resp = auth_env.client.post("/auth/resend-verification", data={
        "email": "resend@example.com",
    })
    assert resp.status_code == 429


def test_resend_per_email_limit_independent(auth_env):
    """Per-email limit: exhausting one email doesn't block another."""
    _signup(auth_env, email="alice@example.com")
    _signup(auth_env, email="bob@example.com")
    # Exhaust Alice's limit
    for _ in range(3):
        auth_env.client.post("/auth/resend-verification", data={"email": "alice@example.com"})
    resp = auth_env.client.post("/auth/resend-verification", data={"email": "alice@example.com"})
    assert resp.status_code == 429
    # Bob's email still works
    resp = auth_env.client.post("/auth/resend-verification", data={"email": "bob@example.com"})
    assert resp.status_code == 200


def test_resend_unknown_email_rate_limited(auth_env):
    """Unknown emails are also rate-limited per-email (no bypass)."""
    for _ in range(3):
        resp = auth_env.client.post("/auth/resend-verification", data={
            "email": "ghost@example.com",
        })
        assert resp.status_code == 200
    resp = auth_env.client.post("/auth/resend-verification", data={
        "email": "ghost@example.com",
    })
    assert resp.status_code == 429


def test_resend_per_ip_limit(auth_env):
    """Per-IP limit: 10/hour across different emails from same IP."""
    # Use 10 different emails to avoid hitting per-email limit first
    for i in range(10):
        resp = auth_env.client.post("/auth/resend-verification", data={
            f"email": f"user{i}@example.com",
        })
        assert resp.status_code == 200, f"Request {i+1} should succeed"
    # 11th request from same IP → 429
    resp = auth_env.client.post("/auth/resend-verification", data={
        "email": "user10@example.com",
    })
    assert resp.status_code == 429
