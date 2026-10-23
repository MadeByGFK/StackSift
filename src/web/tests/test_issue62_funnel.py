"""Activation and purchase funnel instrumentation (issue #62).

- Events defined and implemented: analysis_first, email_verified,
  export_intent, purchase_start, purchase_success, credit_spend,
  repeat_purchase.
- Privacy: events join by user_id or random anon_id only; log text, tokens,
  filenames, IPs and contact PII are never recorded (enforced in code).
- Weekly-readable summary: counts + step conversion, with a named reviewer.
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app import credits as C
from app import funnel
from app import models
from app.db import Base


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    @event.listens_for(engine, "connect")
    def _fk(conn, _):
        conn.execute("PRAGMA foreign_keys=ON")
    Base.metadata.create_all(engine)
    S = sessionmaker(bind=engine)
    session = S()
    yield session
    session.close()
    engine.dispose()


@pytest.fixture
def user(db):
    uid = uuid.uuid4()
    db.add(models.User(id=uid, email=f"{uid.hex[:8]}@test.com", email_verified=True))
    db.commit()
    return uid


def _events(db, event_name, user_id=None):
    q = db.query(models.FunnelEvent).filter(models.FunnelEvent.event == event_name)
    if user_id is not None:
        q = q.filter(models.FunnelEvent.user_id == user_id)
    return q.all()


def test_record_requires_known_event_and_identity(db, user):
    with pytest.raises(ValueError):
        funnel.record(db, "bogus_event", user_id=user)
    with pytest.raises(ValueError):
        funnel.record(db, funnel.ANALYSIS_FIRST)


def test_record_rejects_banned_meta_keys(db, user):
    # Log text, tokens, filenames, IPs, contact PII: never recorded.
    for banned in ("log_text", "filename", "token", "ip_address", "email",
                   "csrf_token", "LOG_TEXT", "FileName"):
        with pytest.raises(ValueError):
            funnel.record(db, funnel.EXPORT_INTENT, user_id=user, meta={banned: "x"})
    assert _events(db, funnel.EXPORT_INTENT, user) == []
    # Non-scalar meta values are rejected too.
    with pytest.raises(ValueError):
        funnel.record(db, funnel.EXPORT_INTENT, user_id=user, meta={"nested": {"a": 1}})


def test_record_accepts_scalar_meta(db, user):
    row = funnel.record(db, funnel.PURCHASE_START, user_id=user, meta={"pack_id": "starter"})
    assert row.meta == {"pack_id": "starter"}
    row2 = funnel.record(db, funnel.CREDIT_SPEND, user_id=user, meta={"credits": 2, "op_type": "pdf"})
    assert row2.meta == {"credits": 2, "op_type": "pdf"}


def test_anonymous_identity_joins_without_pii(db):
    anon = uuid.uuid4().hex
    funnel.record(db, funnel.ANALYSIS_FIRST, anon_id=anon, once_per_identity=True)
    rows = db.query(models.FunnelEvent).filter(models.FunnelEvent.event == funnel.ANALYSIS_FIRST).all()
    assert len(rows) == 1
    assert rows[0].anon_id == anon
    assert rows[0].user_id is None


def test_analysis_first_dedupes_per_identity(db, user):
    assert funnel.record(db, funnel.ANALYSIS_FIRST, user_id=user, once_per_identity=True) is not None
    assert funnel.record(db, funnel.ANALYSIS_FIRST, user_id=user, once_per_identity=True) is None
    assert len(_events(db, funnel.ANALYSIS_FIRST, user)) == 1


def test_emit_never_raises(db):
    # Telemetry must not break call sites: emit swallows everything.
    funnel.emit(db, "bogus_event", user_id=uuid.uuid4())
    funnel.emit(db, funnel.PURCHASE_START)  # no identity
    db.rollback()  # nothing partial should linger


def test_purchase_success_fires_on_purchase_grant_only(db, user):
    C.grant_credits(db, user, "signup", "reward", 3)
    assert _events(db, funnel.PURCHASE_SUCCESS, user) == []
    C.grant_credits(db, user, "purchase", "cp-1", 10)
    rows = _events(db, funnel.PURCHASE_SUCCESS, user)
    assert len(rows) == 1
    assert rows[0].meta == {"credits": 10}
    # First purchase is not a repeat.
    assert _events(db, funnel.REPEAT_PURCHASE, user) == []


def test_repeat_purchase_on_second_purchase_grant(db, user):
    C.grant_credits(db, user, "purchase", "cp-1", 10)
    C.grant_credits(db, user, "purchase", "cp-2", 25)
    assert len(_events(db, funnel.PURCHASE_SUCCESS, user)) == 2
    repeats = _events(db, funnel.REPEAT_PURCHASE, user)
    assert len(repeats) == 1
    assert repeats[0].meta == {"credits": 25}


def _admit_and_complete(db, user_id, cost=1, op_type="additional_analysis"):
    C.grant_credits(db, user_id, "admin", f"g-{uuid.uuid4().hex[:8]}", 10)
    consent = C.create_consent(db, user_id, op_type, "hash", cost)
    db.commit()
    op = C.admit_paid_operation(db, user_id, op_type, f"k-{uuid.uuid4().hex[:8]}",
                                "hash", cost, consent.id, "w1")
    db.commit()
    r = models.Result(
        user_id=user_id, operation_id=op.id, type="analysis",
        storage_manifest='{"test": true}', integrity_digest=C.hash_input(b'{"test": true}'),
        byte_count=14, ready_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
    )
    db.add(r)
    db.flush()
    C.complete_operation(db, op.id, "w1", result_id=r.id)
    db.commit()
    return op


def test_credit_spend_fires_on_settlement(db, user):
    _admit_and_complete(db, user, cost=2, op_type="pdf")
    rows = _events(db, funnel.CREDIT_SPEND, user)
    assert len(rows) == 1
    assert rows[0].meta == {"credits": 2, "op_type": "pdf"}


def test_summary_counts_and_conversion(db, user):
    other = uuid.uuid4()
    db.add(models.User(id=other, email="o@test.com", email_verified=True))
    db.commit()
    funnel.record(db, funnel.ANALYSIS_FIRST, user_id=user, once_per_identity=True)
    funnel.record(db, funnel.ANALYSIS_FIRST, user_id=other, once_per_identity=True)
    funnel.record(db, funnel.EMAIL_VERIFIED, user_id=user, once_per_identity=True)
    funnel.record(db, funnel.PURCHASE_START, user_id=user, meta={"pack_id": "starter"})
    report = funnel.summary(db, days=7)
    assert report["counts"][funnel.ANALYSIS_FIRST] == 2
    assert report["counts"][funnel.EMAIL_VERIFIED] == 1
    ladder = {s["event"]: s for s in report["ladder"]}
    assert ladder[funnel.EMAIL_VERIFIED]["conversion_from_prev"] == pytest.approx(0.5)
    assert ladder[funnel.ANALYSIS_FIRST]["conversion_from_prev"] is None
    assert report["reviewer"] == funnel.FUNNEL_REVIEWER


def test_summary_credits_spent(db, user):
    _admit_and_complete(db, user, cost=2, op_type="pdf")
    _admit_and_complete(db, user, cost=1, op_type="additional_analysis")
    report = funnel.summary(db, days=7)
    assert report["credit_spend_events"] == 2
    assert report["credits_spent"] == 3


def test_summary_window_excludes_old_events(db, user):
    funnel.record(db, funnel.EXPORT_INTENT, user_id=user)
    old = _events(db, funnel.EXPORT_INTENT, user)[0]
    old.occurred_at = datetime.now(timezone.utc) - timedelta(days=30)
    db.commit()
    report = funnel.summary(db, days=7)
    assert report["counts"][funnel.EXPORT_INTENT] == 0


def test_render_text_names_reviewer(db, user):
    funnel.record(db, funnel.ANALYSIS_FIRST, user_id=user, once_per_identity=True)
    text = funnel.render_text(funnel.summary(db, days=7))
    assert "Sunny" in text
    assert "analysis_first" in text


# --- route-level wiring -----------------------------------------------------

TEST_PASSWORD = "Correct Horse Battery Staple 9!"

PACK_PRICES = {
    "starter": "price_test_starter",
    "growth": "price_test_growth",
    "power": "price_test_power",
}


@pytest.fixture
def route_env(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from fastapi.testclient import TestClient
    from sqlalchemy import event as sa_event
    from app import auth, email
    from app.db import Base, get_db
    import app.db as db_module
    from app.main import app

    engine = create_engine(
        f"sqlite:///{tmp_path / 'funnel62.db'}",
        connect_args={"check_same_thread": False, "timeout": 20},
    )

    @sa_event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, _):
        connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)

    def override():
        with sessions() as db:
            yield db

    monkeypatch.setitem(app.dependency_overrides, get_db, override)
    monkeypatch.setattr(auth, "auth_limiter", auth.AuthRateLimiter())
    monkeypatch.setattr(auth, "check_password_breached", lambda _: False)
    monkeypatch.setattr(db_module, "SessionLocal", sessions)
    monkeypatch.setenv("DATABASE_URL", "sqlite://")
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_route_fixture")
    for pack_id, price in PACK_PRICES.items():
        monkeypatch.setenv(f"STRIPE_PRICE_{pack_id.upper()}", price)
    sent = []
    monkeypatch.setattr(email, "send_verification_email",
                        lambda address, token: sent.append(("verify", address, token)))
    try:
        with TestClient(app, base_url="https://testserver") as client:
            client.headers["X-CSRF-Token"] = client.get("/auth/csrf").json()["csrf_token"]
            yield SimpleNamespace(client=client, sessions=sessions, sent=sent, app=app)
    finally:
        engine.dispose()


def _login(route_env, email="funnelbuyer@example.com"):
    from app.models import User

    c = route_env.client
    assert c.post("/auth/signup", data={"email": email, "password": TEST_PASSWORD}).status_code == 200
    with route_env.sessions() as db:
        u = db.query(User).filter(User.email == email).first()
        u.email_verified = True
        db.commit()
        user_id = u.id
    c.headers["X-CSRF-Token"] = c.get("/auth/csrf").json()["csrf_token"]
    resp = c.post("/auth/login", data={"email": email, "password": TEST_PASSWORD})
    assert resp.status_code == 200, resp.text
    return user_id, resp.json()["csrf_token"]


def test_checkout_route_emits_purchase_start(route_env, monkeypatch):
    from app import stripe_billing

    user_id, csrf = _login(route_env)
    captured = []

    class _FakeResp:
        status_code = 200

        def json(self):
            # The merged checkout path (#84) requires the session id as well
            # as the URL — it records pending purchases before the call.
            return {"id": "cs_test_123", "url": "https://checkout.stripe.com/pay/cs_test_123"}

    monkeypatch.setattr(stripe_billing.httpx, "post",
                        lambda url, data=None, auth=None, headers=None, timeout=None: (
                            captured.append(url) or _FakeResp()))
    resp = route_env.client.post("/credits/checkout", data={"pack_id": "growth", "csrf_token": csrf})
    assert resp.status_code == 200, resp.text
    rows = _events_from_sessions(route_env, funnel.PURCHASE_START, user_id)
    assert len(rows) == 1
    assert rows[0].meta == {"pack_id": "growth"}


def _events_from_sessions(route_env, event_name, user_id):
    with route_env.sessions() as db:
        return (
            db.query(models.FunnelEvent)
            .filter(models.FunnelEvent.event == event_name,
                    models.FunnelEvent.user_id == user_id)
            .all()
        )


def test_verify_route_emits_email_verified(route_env):
    c = route_env.client
    assert c.post("/auth/signup",
                  data={"email": "verifier@example.com", "password": TEST_PASSWORD}).status_code == 200
    assert route_env.sent, "verification email should have been captured"
    token = route_env.sent[0][2]
    resp = c.post("/auth/verify", data={"token": token})
    assert resp.status_code == 200, resp.text
    with route_env.sessions() as db:
        u = db.query(models.User).filter(models.User.email == "verifier@example.com").first()
        rows = _events(db, funnel.EMAIL_VERIFIED, u.id)
    assert len(rows) == 1
