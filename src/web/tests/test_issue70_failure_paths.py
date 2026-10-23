"""Phase 3 purchase failure paths — nothing granted on failure (issue #70).

Covers the failure behavior of the purchase lifecycle end to end:

- Declined card (``payment_intent.payment_failed``): no credits, no ledger
  grant; the purchase deliberately stays pending because the customer can
  retry inside the still-open Checkout session — a later
  ``checkout.session.completed`` for the same session still settles once.
- Abandoned checkout (``checkout.session.expired``) and failed async
  payment (``checkout.session.async_payment_failed``): terminal — the
  purchase is marked failed, no credits, no ledger grant, and a late
  completion for the same session grants nothing.
- Abandoned without any event: ``expire_stale_pending_purchases`` marks
  pending purchases older than the cutoff failed, so no row sticks pending
  forever (runs in the credit-maintenance loop, ~every minute).
- Webhook delivery failure and retry: a crash between the idempotency gate
  and settlement leaves no event row (rolled back), so Stripe's retry
  settles exactly once.

Evidence database: ``TEST_POSTGRES_URL`` (Postgres 16, the CI service) when
set, otherwise a local SQLite file. Name the environment and the commit
under test when reporting results::

    TEST_POSTGRES_URL=postgresql+psycopg2://stacksift_test:local_test_only@localhost:5432/stacksift_test \
        python -m pytest src/web/tests/test_issue70_failure_paths.py -v  # commit: $(git rev-parse --short HEAD)

Stripe is faked at the event-construction boundary exactly as in
test_issue69_webhook.py: events are HMAC-signed the way Stripe signs them.
Live sandbox API access was unavailable in this environment (Stripe
connector needs reauthorization), so sandbox end-to-end with test cards
remains the documented remaining unlock, not part of this change.
"""
import hashlib
import hmac
import json
import os
import time
import uuid
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, select, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

TEST_PASSWORD = "CorrectHorseBatteryStaple99!"
WEBHOOK_SECRET = "whsec_test_failure_paths"

PACK_CREDITS = {"starter": 10, "growth": 25, "power": 75}
PACK_AMOUNTS = {"starter": 500, "growth": 1000, "power": 2500}


def _engine_for(tmp_path):
    """Real Postgres (CI) when TEST_POSTGRES_URL is set, else local SQLite."""
    pg_url = os.environ.get("TEST_POSTGRES_URL")
    if pg_url:
        schema = "fp70_" + uuid.uuid4().hex
        admin = create_engine(pg_url, poolclass=NullPool)
        with admin.begin() as conn:
            conn.execute(text(f'CREATE SCHEMA "{schema}"'))
        admin.dispose()
        engine = create_engine(
            pg_url,
            connect_args={"options": f"-csearch_path={schema}"},
            poolclass=NullPool,
        )
        return engine, schema, pg_url
    path = tmp_path / f"failure70_{uuid.uuid4().hex[:8]}.db"
    engine = create_engine(
        f"sqlite:///{path}",
        connect_args={"check_same_thread": False, "timeout": 20},
    )

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, _):
        connection.execute("PRAGMA foreign_keys=ON")

    return engine, None, f"sqlite:///{path}"


@pytest.fixture
def failure_env(tmp_path, monkeypatch):
    from app import auth, email
    from app.db import Base, get_db
    import app.db as db_module
    from app.main import app

    engine, schema, db_url = _engine_for(tmp_path)
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)

    def override():
        with sessions() as db:
            yield db

    monkeypatch.setitem(app.dependency_overrides, get_db, override)
    monkeypatch.setattr(auth, "auth_limiter", auth.AuthRateLimiter())
    monkeypatch.setattr(auth, "check_password_breached", lambda _: False)
    monkeypatch.setattr(db_module, "SessionLocal", sessions)
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("STRIPE_PRICE_STARTER", "price_test_starter")
    monkeypatch.setenv("STRIPE_PRICE_GROWTH", "price_test_growth")
    monkeypatch.setenv("STRIPE_PRICE_POWER", "price_test_power")
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_cycle_fixture")
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", WEBHOOK_SECRET)
    sent = []
    monkeypatch.setattr(email, "send_verification_email", lambda address, token: sent.append((address, token)))
    try:
        with TestClient(app, base_url="https://testserver") as client:
            client.headers["X-CSRF-Token"] = client.get("/auth/csrf").json()["csrf_token"]
            yield SimpleNamespace(client=client, sessions=sessions, app=app)
    finally:
        engine.dispose()
        if schema:
            admin = create_engine(os.environ["TEST_POSTGRES_URL"], poolclass=NullPool)
            with admin.begin() as conn:
                conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
            admin.dispose()


def _login(failure_env, email="buyer70@example.com"):
    from app.models import User

    c = failure_env.client
    assert c.post("/auth/signup", data={"email": email, "password": TEST_PASSWORD}).status_code == 200
    with failure_env.sessions() as db:
        u = db.query(User).filter(User.email == email).first()
        u.email_verified = True
        db.commit()
        user_id = str(u.id)
    resp = c.post("/auth/login", data={"email": email, "password": TEST_PASSWORD})
    assert resp.status_code == 200, resp.text
    return user_id, resp.json()["csrf_token"]


def _sign(payload: bytes, secret=WEBHOOK_SECRET, ts=None):
    ts = ts if ts is not None else int(time.time())
    sig = hmac.new(secret.encode(), f"{ts}.".encode() + payload,
                   hashlib.sha256).hexdigest()
    return f"t={ts},v1={sig}"


def _post_event(failure_env, evt, secret=WEBHOOK_SECRET):
    payload = json.dumps(evt).encode()
    return failure_env.client.post(
        "/credits/webhook", content=payload,
        headers={"Stripe-Signature": _sign(payload, secret),
                 "Content-Type": "application/json"})


def _metadata(purchase_id, user_id, pack_id="starter", pricing_version=1):
    return {
        "purchase_id": str(purchase_id),
        "user_id": str(user_id),
        "pack_id": pack_id,
        "credits": str(PACK_CREDITS[pack_id]),
        "pricing_version": str(pricing_version),
    }


def _completed_event(event_id, session_id, purchase_id, user_id,
                     pack_id="starter", payment_intent="pi_test_70_ok"):
    return {
        "id": event_id,
        "type": "checkout.session.completed",
        "data": {"object": {
            "id": session_id,
            "object": "checkout.session",
            "amount_total": PACK_AMOUNTS[pack_id],
            "currency": "usd",
            "payment_intent": payment_intent,
            "client_reference_id": str(user_id),
            "metadata": _metadata(purchase_id, user_id, pack_id),
        }},
    }


def _payment_failed_event(event_id, purchase_id, user_id, pack_id="starter"):
    # Shape mirrors a real Stripe payment_intent.payment_failed: the object
    # is a PaymentIntent carrying the decline in last_payment_error.
    return {
        "id": event_id,
        "type": "payment_intent.payment_failed",
        "data": {"object": {
            "id": "pi_test_70_declined",
            "object": "payment_intent",
            "amount": PACK_AMOUNTS[pack_id],
            "currency": "usd",
            "status": "requires_payment_method",
            "last_payment_error": {
                "code": "card_declined",
                "decline_code": "generic_decline",
                "message": "Your card was declined.",
                "type": "card_error",
            },
            "metadata": _metadata(purchase_id, user_id, pack_id),
        }},
    }


def _session_failed_event(event_id, session_id, purchase_id, user_id,
                          event_type, pack_id="starter"):
    assert event_type in ("checkout.session.expired",
                          "checkout.session.async_payment_failed")
    return {
        "id": event_id,
        "type": event_type,
        "data": {"object": {
            "id": session_id,
            "object": "checkout.session",
            "payment_status": "unpaid",
            "status": "expired" if event_type == "checkout.session.expired" else "open",
            "metadata": _metadata(purchase_id, user_id, pack_id),
        }},
    }


def _make_pending(failure_env, user_id, session_id, pack_id="starter"):
    from app import credits as credits_helpers

    with failure_env.sessions() as db:
        purchase = credits_helpers.create_pending_purchase(
            db, uuid.UUID(user_id), pack_id)
        purchase.stripe_session_id = session_id
        db.commit()
        return str(purchase.id)


def _purchase_state(failure_env, purchase_id):
    from app import credits as credits_helpers
    from app import models

    with failure_env.sessions() as db:
        p = db.get(models.CreditPurchase, purchase_id)
        status = p.status
        grants = db.query(models.CreditGrant).filter(
            models.CreditGrant.source == "purchase").count()
        ledger = db.query(models.CreditLedger).count()
    return status, grants, ledger


# --- declined card --------------------------------------------------------

def test_declined_card_grants_nothing_and_leaves_pending_for_retry(failure_env):
    from app import credits as credits_helpers
    from app import models

    user_id, _ = _login(failure_env)
    purchase_id = _make_pending(failure_env, user_id, "cs_test_70_decline")

    resp = _post_event(
        failure_env,
        _payment_failed_event("evt_70_decline_1", purchase_id, user_id))
    assert resp.status_code == 200
    assert resp.json()["status"] == "processed"

    status, grants, ledger = _purchase_state(failure_env, purchase_id)
    assert status == "pending"  # still open: the customer retries in Checkout
    assert grants == 0 and ledger == 0
    with failure_env.sessions() as db:
        summary = credits_helpers.get_balance_summary(db, uuid.UUID(user_id))
        assert summary["balance"] == 0
        wrow = db.get(models.StripeWebhookEvent, "evt_70_decline_1")
        assert wrow.outcome == "processed"
        assert "declined" in (wrow.note or "")

    # The in-session retry succeeds: the same session completes and the
    # purchase settles exactly once — the decline did not poison it.
    resp = _post_event(
        failure_env,
        _completed_event("evt_70_decline_retry_ok", "cs_test_70_decline",
                         purchase_id, user_id))
    assert resp.json()["status"] == "processed"
    status, grants, ledger = _purchase_state(failure_env, purchase_id)
    assert status == "completed"
    assert grants == 1 and ledger == 1
    with failure_env.sessions() as db:
        summary = credits_helpers.get_balance_summary(db, uuid.UUID(user_id))
        assert summary["balance"] == 10


def test_declined_card_for_unknown_purchase_ignored(failure_env):
    from app import models

    evt = _payment_failed_event(
        "evt_70_decline_unknown", str(uuid.uuid4()), str(uuid.uuid4()))
    resp = _post_event(failure_env, evt)
    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"
    with failure_env.sessions() as db:
        assert db.get(models.StripeWebhookEvent,
                      "evt_70_decline_unknown").outcome == "ignored"
        assert db.query(models.CreditGrant).count() == 0


# --- expired / async-failed sessions --------------------------------------

def test_expired_session_fails_purchase_grants_nothing(failure_env):
    from app import credits as credits_helpers
    from app import models

    user_id, _ = _login(failure_env)
    purchase_id = _make_pending(failure_env, user_id, "cs_test_70_expired")

    resp = _post_event(
        failure_env,
        _session_failed_event("evt_70_expired_1", "cs_test_70_expired",
                              purchase_id, user_id,
                              "checkout.session.expired"))
    assert resp.status_code == 200
    assert resp.json()["status"] == "processed"

    status, grants, ledger = _purchase_state(failure_env, purchase_id)
    assert status == "failed"
    assert grants == 0 and ledger == 0
    with failure_env.sessions() as db:
        p = db.get(models.CreditPurchase, purchase_id)
        assert p.stripe_event_id == "evt_70_expired_1"
        assert p.completed_at is None
        summary = credits_helpers.get_balance_summary(db, uuid.UUID(user_id))
        assert summary["balance"] == 0
        wrow = db.get(models.StripeWebhookEvent, "evt_70_expired_1")
        assert wrow.outcome == "processed"
        assert "expired" in (wrow.note or "")

    # A completion arriving after expiry can never settle: the purchase is
    # terminal and grants nothing (Stripe itself never sends completed for
    # an expired session; this asserts our fail-closed ordering anyway).
    resp = _post_event(
        failure_env,
        _completed_event("evt_70_expired_late", "cs_test_70_expired",
                         purchase_id, user_id))
    assert resp.json()["status"] == "duplicate"
    _, grants, ledger = _purchase_state(failure_env, purchase_id)
    assert grants == 0 and ledger == 0


def test_async_payment_failed_fails_purchase(failure_env):
    user_id, _ = _login(failure_env)
    purchase_id = _make_pending(failure_env, user_id, "cs_test_70_asyncfail")

    resp = _post_event(
        failure_env,
        _session_failed_event("evt_70_asyncfail_1", "cs_test_70_asyncfail",
                              purchase_id, user_id,
                              "checkout.session.async_payment_failed"))
    assert resp.status_code == 200
    assert resp.json()["status"] == "processed"

    status, grants, ledger = _purchase_state(failure_env, purchase_id)
    assert status == "failed"
    assert grants == 0 and ledger == 0


# --- abandoned without any event: stale cleanup ----------------------------

def test_abandoned_pending_purchases_expire(failure_env):
    from app import credits as credits_helpers
    from app import models

    user_id, _ = _login(failure_env)
    old_id = _make_pending(failure_env, user_id, "cs_test_70_stale")
    fresh_id = _make_pending(failure_env, user_id, "cs_test_70_fresh")

    with failure_env.sessions() as db:
        old = db.get(models.CreditPurchase, old_id)
        old.created_at = old.created_at - timedelta(hours=25)
        db.commit()

    with failure_env.sessions() as db:
        expired = credits_helpers.expire_stale_pending_purchases(db)
        db.commit()
    assert expired == 1

    with failure_env.sessions() as db:
        assert db.get(models.CreditPurchase, old_id).status == "failed"
        assert db.get(models.CreditPurchase, fresh_id).status == "pending"
        assert db.query(models.CreditGrant).count() == 0
        assert db.query(models.CreditLedger).count() == 0


def test_expire_stale_pending_is_idempotent(failure_env):
    from app import credits as credits_helpers
    from app import models

    user_id, _ = _login(failure_env)
    with failure_env.sessions() as db:
        assert credits_helpers.expire_stale_pending_purchases(db) == 0
        db.commit()


def test_fail_purchase_never_double_fails_or_touches_settled(failure_env):
    from app import credits as credits_helpers
    from app import models

    user_id, _ = _login(failure_env)
    purchase_id = _make_pending(failure_env, user_id, "cs_test_70_failidem")

    with failure_env.sessions() as db:
        p = db.get(models.CreditPurchase, purchase_id)
        assert credits_helpers.fail_purchase(
            db, p, reason="test", stripe_event_id="evt_70_x") is True
        assert credits_helpers.fail_purchase(
            db, p, reason="test", stripe_event_id="evt_70_y") is False
        db.commit()
        assert db.get(models.CreditPurchase, purchase_id).status == "failed"
        assert db.get(models.CreditPurchase,
                      purchase_id).stripe_event_id == "evt_70_x"

    # A completed purchase is terminal: a late failure signal changes nothing.
    purchase2 = _make_pending(failure_env, user_id, "cs_test_70_faildone")
    resp = _post_event(
        failure_env,
        _completed_event("evt_70_faildone_ok", "cs_test_70_faildone",
                         purchase2, user_id))
    assert resp.json()["status"] == "processed"
    with failure_env.sessions() as db:
        p2 = db.get(models.CreditPurchase, purchase2)
        assert credits_helpers.fail_purchase(
            db, p2, reason="late", stripe_event_id="evt_70_late") is False
        db.commit()
        p2 = db.get(models.CreditPurchase, purchase2)
        assert p2.status == "completed"
        assert p2.stripe_event_id == "evt_70_faildone_ok"


# --- webhook delivery failure and retry ------------------------------------

def test_webhook_crash_then_retry_settles_exactly_once(failure_env):
    from app import credits as credits_helpers
    from app import models

    user_id, _ = _login(failure_env)
    purchase_id = _make_pending(failure_env, user_id, "cs_test_70_crash")
    evt = _completed_event("evt_70_crash_1", "cs_test_70_crash",
                           purchase_id, user_id)

    # First delivery: the handler crashes after the idempotency gate flushed.
    # Nothing is committed, so no event row survives the rollback.
    with patch.object(credits_helpers, "settle_purchase",
                      side_effect=RuntimeError("boom")):
        with pytest.raises(RuntimeError):
            _post_event(failure_env, evt)
    with failure_env.sessions() as db:
        assert db.get(models.StripeWebhookEvent, "evt_70_crash_1") is None
        assert db.get(models.CreditPurchase, purchase_id).status == "pending"
        assert db.query(models.CreditGrant).count() == 0

    # Stripe retries the same event: it settles exactly once.
    resp = _post_event(failure_env, evt)
    assert resp.status_code == 200
    assert resp.json()["status"] == "processed"
    status, grants, ledger = _purchase_state(failure_env, purchase_id)
    assert status == "completed"
    assert grants == 1 and ledger == 1

    # And a duplicate redelivery after that still grants nothing.
    resp = _post_event(failure_env, evt)
    assert resp.json()["status"] == "duplicate"
    _, grants, ledger = _purchase_state(failure_env, purchase_id)
    assert grants == 1 and ledger == 1


# --- user-facing failure state ---------------------------------------------

def test_cancelled_banner_names_failure_and_retry_path(failure_env):
    _login(failure_env)
    resp = failure_env.client.get("/credits?checkout=cancelled")
    assert resp.status_code == 200
    body = resp.text
    assert "Payment didn&#x27;t go through" in body or "Payment didn't go through" in body
    assert "no charge was made" in body
    assert "try again below" in body
