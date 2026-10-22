"""Notify-me capture on the credits page (issue #67).

Short bridge until checkout ships (#68): an email capture form on /credits
for anonymous visitors, stored durably in our own database (no third-party
list tool), with the source page recorded. Counts are intent only — never
demand evidence (GFK-013 §5.12).
"""
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker


@pytest.fixture
def notify_env(tmp_path, monkeypatch):
    from app import auth
    from app.db import Base, get_db
    from app.main import app

    engine = create_engine(
        f"sqlite:///{tmp_path / 'notify.db'}",
        connect_args={"check_same_thread": False, "timeout": 20},
    )

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, _):
        connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)

    def override():
        with sessions() as db:
            yield db

    monkeypatch.setitem(app.dependency_overrides, get_db, override)
    monkeypatch.setattr(auth, "auth_limiter", auth.AuthRateLimiter())
    try:
        with TestClient(app, base_url="https://testserver") as client:
            yield SimpleNamespace(client=client, sessions=sessions, engine=engine, app=app)
    finally:
        engine.dispose()


def _csrf_from_cookie(notify_env):
    token = notify_env.client.cookies.get("__Host-stacksift_csrf")
    assert token, "GET /credits must set the CSRF cookie for anonymous visitors"
    return token


def _signup(notify_env, email):
    notify_env.client.get("/credits")  # sets the CSRF cookie for anonymous visitors
    csrf = _csrf_from_cookie(notify_env)
    resp = notify_env.client.post(
        "/credits/notify", data={"email": email, "csrf_token": csrf}
    )
    return resp


def test_credits_page_shows_notify_form_to_anonymous(notify_env):
    resp = notify_env.client.get("/credits")
    assert resp.status_code == 200
    assert 'action="/credits/notify"' in resp.text
    assert "Notify me" in resp.text
    # Acceptance: clear copy — purchases coming, no date promised.
    assert "coming soon" in resp.text.lower()
    assert "one email" in resp.text.lower()
    # The hidden field carries the same token the cookie holds.
    csrf = _csrf_from_cookie(notify_env)
    assert f'name="csrf_token" value="{csrf}"' in resp.text


def test_notify_captures_email_normalized(notify_env):
    from app.models import NotifySignup

    resp = _signup(notify_env, "  User@Example.COM ")
    assert resp.status_code == 200
    assert "on the list" in resp.json()["message"]
    with notify_env.sessions() as db:
        rows = db.query(NotifySignup).all()
        assert len(rows) == 1
        assert rows[0].email == "user@example.com"
        assert rows[0].source == "credits"
        assert rows[0].created_at is not None


def test_notify_duplicate_email_is_idempotent_success(notify_env):
    from app.models import NotifySignup

    assert _signup(notify_env, "dup@example.com").status_code == 200
    # Second submit with the same address still succeeds but stores one row.
    assert _signup(notify_env, "DUP@example.com").status_code == 200
    with notify_env.sessions() as db:
        assert db.query(NotifySignup).count() == 1


def test_notify_rejects_invalid_email(notify_env):
    from app.models import NotifySignup

    for bad in ("not-an-email", "a@b@c.com", "x@ ", "@example.com", "x" * 250 + "@example.com"):
        resp = _signup(notify_env, bad)
        assert resp.status_code == 400, bad
        assert "valid email" in resp.json()["error"].lower()
    with notify_env.sessions() as db:
        assert db.query(NotifySignup).count() == 0


def test_notify_rejects_bad_csrf(notify_env):
    from app.models import NotifySignup

    notify_env.client.get("/credits")  # sets the real cookie
    resp = notify_env.client.post(
        "/credits/notify", data={"email": "evil@example.com", "csrf_token": "wrong"}
    )
    assert resp.status_code == 403
    with notify_env.sessions() as db:
        assert db.query(NotifySignup).count() == 0


def test_notify_rejects_missing_csrf_cookie(notify_env):
    from app.models import NotifySignup

    notify_env.client.cookies.clear()
    resp = notify_env.client.post(
        "/credits/notify", data={"email": "nocookie@example.com", "csrf_token": "anything"}
    )
    assert resp.status_code == 403
    with notify_env.sessions() as db:
        assert db.query(NotifySignup).count() == 0


def test_notify_rate_limited(notify_env):
    from app.models import NotifySignup

    notify_env.client.get("/credits")  # sets the CSRF cookie for anonymous visitors
    csrf = _csrf_from_cookie(notify_env)
    statuses = set()
    for i in range(12):
        resp = notify_env.client.post(
            "/credits/notify",
            data={"email": f"rl{i}@example.com", "csrf_token": csrf},
        )
        statuses.add(resp.status_code)
    assert 429 in statuses
    with notify_env.sessions() as db:
        # Only the requests inside the limit were stored.
        assert db.query(NotifySignup).count() <= 10


def test_notify_uses_shared_limiter_when_database_configured(notify_env, monkeypatch):
    """With DATABASE_URL set, /credits/notify enforces through the shared
    Postgres-backed limiter (PR #28): admissions are recorded in
    rate_limit_hits under the notify bucket, and a bucket already at the
    10/hour cap blocks further signups. The fixture's in-memory auth limiter
    starts empty, so only the shared store can produce the 429.
    """
    from datetime import datetime, timezone

    import app.main as main_mod
    from app.models import RateLimitHit

    monkeypatch.setenv("DATABASE_URL", "sqlite://")
    monkeypatch.setattr(main_mod, "_db_session", lambda: notify_env.sessions())

    # A first signup is admitted and recorded in the shared table.
    assert _signup(notify_env, "shared@example.com").status_code == 200
    with notify_env.sessions() as db:
        hits = db.query(RateLimitHit).all()
        assert len(hits) == 1
        bucket = hits[0].trusted_ip
        assert bucket.startswith("n:")
        # Fill the rest of the hourly bucket directly in the shared store.
        for _ in range(9):
            db.add(
                RateLimitHit(
                    trusted_ip=bucket, hit_at=datetime.now(timezone.utc)
                )
            )
        db.commit()

    # The next signup exceeds the shared 10/hour cap -> 429.
    resp = _signup(notify_env, "over@example.com")
    assert resp.status_code == 429
    with notify_env.sessions() as db:
        assert db.query(RateLimitHit).count() == 10


def test_credits_page_hides_notify_form_when_logged_in(notify_env, monkeypatch):
    import app.main as main_mod

    monkeypatch.setattr(
        main_mod, "_get_current_user_optional", lambda request: (object(), "tok")
    )
    resp = notify_env.client.get("/credits")
    assert resp.status_code == 200
    assert 'action="/credits/notify"' not in resp.text
    # Logged-in users keep the existing "we'll notify you at launch" message.
    assert "notify you at launch" in resp.text
