"""Phase 3 webhook settlement — idempotent credit granting (issue #69).

- POST /credits/webhook verifies the Stripe-Signature HMAC before touching
  the database; unsigned/mis-signed deliveries are 400 with no rows written.
- checkout.session.completed settles the pending CreditPurchase exactly once:
  pending -> completed, credits granted through the standard GRANT path with
  a full ledger entry, money side (amount/currency/payment intent) recorded
  on the purchase for reconciliation to the cent (#72).
- Idempotency: redelivered events collide on stripe_webhook_events PK;
  second event ids for an already-settled purchase grant nothing;
  unknown purchases are ignored and logged; metadata mismatches fail closed.
- Test mode only: live keys refused, unset webhook secret fails closed.

Stripe is faked at the httpx boundary for checkout; webhook events are
constructed locally and HMAC-signed exactly the way Stripe signs them.
"""
import hashlib
import hmac
import json
import time
import uuid
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

TEST_PASSWORD = "Test Password 123!"
WEBHOOK_SECRET = "whsec_test_cycle_secret_69"

PACK_PRICES = {
    "starter": "price_test_starter",
    "growth": "price_test_growth",
    "power": "price_test_power",
}
PACK_CREDITS = {"starter": 10, "growth": 25, "power": 75}
PACK_AMOUNTS = {"starter": 500, "growth": 1000, "power": 2500}


@pytest.fixture
def webhook_env(tmp_path, monkeypatch):
    from app import auth, email
    from app.db import Base, get_db
    import app.db as db_module
    from app.main import app

    engine = create_engine(
        f"sqlite:///{tmp_path / 'webhook69.db'}",
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
    monkeypatch.setattr(auth, "check_password_breached", lambda _: False)
    monkeypatch.setattr(db_module, "SessionLocal", sessions)
    monkeypatch.setenv("DATABASE_URL", "sqlite:///webhook69.db")
    for pack_id, price in PACK_PRICES.items():
        monkeypatch.setenv(f"STRIPE_PRICE_{pack_id.upper()}", price)
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


def _login(webhook_env, email="buyer69@example.com"):
    from app.models import User

    c = webhook_env.client
    assert c.post("/auth/signup", data={"email": email, "password": TEST_PASSWORD}).status_code == 200
    with webhook_env.sessions() as db:
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


def _checkout_event(event_id, session_id, purchase_id, user_id,
                    pack_id="starter", credits=None, amount_total=None,
                    event_type="checkout.session.completed",
                    pricing_version=1, payment_intent="pi_test_123",
                    currency="usd"):
    credits = PACK_CREDITS[pack_id] if credits is None else credits
    amount_total = PACK_AMOUNTS[pack_id] if amount_total is None else amount_total
    return {
        "id": event_id,
        "type": event_type,
        "data": {"object": {
            "id": session_id,
            "object": "checkout.session",
            "amount_total": amount_total,
            "currency": currency,
            "payment_intent": payment_intent,
            "client_reference_id": str(user_id),
            "metadata": {
                "purchase_id": str(purchase_id),
                "user_id": str(user_id),
                "pack_id": pack_id,
                "credits": str(credits),
                "pricing_version": str(pricing_version),
            },
        }},
    }


def _post_event(webhook_env, event, secret=WEBHOOK_SECRET, ts=None,
                raw_header=None):
    payload = json.dumps(event).encode()
    header = raw_header if raw_header is not None else _sign(payload, secret, ts)
    return webhook_env.client.post(
        "/credits/webhook", content=payload,
        headers={"Stripe-Signature": header,
                 "Content-Type": "application/json"})


def _make_pending(webhook_env, user_id, pack_id="starter"):
    from app import credits as credits_helpers
    from app import models

    with webhook_env.sessions() as db:
        purchase = credits_helpers.create_pending_purchase(
            db, uuid.UUID(user_id), pack_id)
        purchase.stripe_session_id = "cs_test_pending_1"
        db.commit()
        return str(purchase.id)


# --- signature verification (unit) ----------------------------------------

def test_signature_valid(webhook_env):
    from app import stripe_billing

    payload = b'{"id":"evt_1"}'
    assert stripe_billing.verify_stripe_signature(
        payload, _sign(payload), WEBHOOK_SECRET) is True


def test_signature_wrong_secret(webhook_env):
    from app import stripe_billing

    payload = b'{"id":"evt_1"}'
    assert stripe_billing.verify_stripe_signature(
        payload, _sign(payload, secret="whsec_wrong"), WEBHOOK_SECRET) is False


def test_signature_stale_timestamp(webhook_env):
    from app import stripe_billing

    payload = b'{"id":"evt_1"}'
    old = int(time.time()) - 3600
    assert stripe_billing.verify_stripe_signature(
        payload, _sign(payload, ts=old), WEBHOOK_SECRET) is False


def test_signature_tampered_payload(webhook_env):
    from app import stripe_billing

    header = _sign(b'{"id":"evt_1"}')
    assert stripe_billing.verify_stripe_signature(
        b'{"id":"evt_2"}', header, WEBHOOK_SECRET) is False


def test_signature_malformed_header(webhook_env):
    from app import stripe_billing

    payload = b'{"id":"evt_1"}'
    for bad in (None, "", "t=abc", "v1=deadbeef", "t=123"):
        assert stripe_billing.verify_stripe_signature(
            payload, bad, WEBHOOK_SECRET) is False


# --- webhook route: configuration gates ------------------------------------

def test_webhook_secret_unset_503(webhook_env, monkeypatch):
    monkeypatch.delenv("STRIPE_WEBHOOK_SECRET", raising=False)
    resp = webhook_env.client.post("/credits/webhook", content=b"{}")
    assert resp.status_code == 503


def test_webhook_refuses_live_key(webhook_env, monkeypatch):
    from app import stripe_billing

    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_live_abc123")
    payload = json.dumps({"id": "evt_x", "type": "ping"}).encode()
    resp = webhook_env.client.post(
        "/credits/webhook", content=payload,
        headers={"Stripe-Signature": _sign(payload)})
    assert resp.status_code == 500


def test_webhook_bad_signature_400_writes_nothing(webhook_env):
    from app import models

    user_id, _ = _login(webhook_env)
    purchase_id = _make_pending(webhook_env, user_id)
    evt = _checkout_event("evt_bad_1", "cs_test_pending_1", purchase_id, user_id)
    payload = json.dumps(evt).encode()
    resp = webhook_env.client.post(
        "/credits/webhook", content=payload,
        headers={"Stripe-Signature": _sign(payload, secret="whsec_wrong")})
    assert resp.status_code == 400
    with webhook_env.sessions() as db:
        assert db.query(models.StripeWebhookEvent).count() == 0
        p = db.get(models.CreditPurchase, purchase_id)
        assert p.status == "pending"


# --- webhook route: event handling -----------------------------------------

def test_webhook_ignores_unhandled_event_type(webhook_env):
    from app import models

    evt = {"id": "evt_other_1", "type": "payment_intent.succeeded",
           "data": {"object": {}}}
    resp = _post_event(webhook_env, evt)
    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"
    with webhook_env.sessions() as db:
        row = db.get(models.StripeWebhookEvent, "evt_other_1")
        assert row is not None and row.outcome == "ignored"


def test_settlement_happy_path(webhook_env):
    from app import credits as credits_helpers
    from app import models

    user_id, _ = _login(webhook_env)
    purchase_id = _make_pending(webhook_env, user_id)
    evt = _checkout_event("evt_ok_1", "cs_test_pending_1", purchase_id, user_id)
    resp = _post_event(webhook_env, evt)
    assert resp.status_code == 200
    assert resp.json()["status"] == "processed"

    with webhook_env.sessions() as db:
        p = db.get(models.CreditPurchase, purchase_id)
        assert p.status == "completed"
        assert p.amount_cents == 500
        assert p.currency == "usd"
        assert p.stripe_payment_intent_id == "pi_test_123"
        assert p.stripe_event_id == "evt_ok_1"
        assert p.completed_at is not None

        summary = credits_helpers.get_balance_summary(db, uuid.UUID(user_id))
        assert summary["balance"] == 10

        grant = db.execute(
            select(models.CreditGrant).where(
                models.CreditGrant.user_id == uuid.UUID(user_id))
        ).scalar_one()
        assert grant.source == "purchase"
        assert grant.source_key == purchase_id
        assert grant.purchase_id == uuid.UUID(purchase_id)
        assert grant.issued == 10 and grant.remaining == 10

        # Ledger entry reconciles: one grant entry, delta == credits, and the
        # purchase row carries the Stripe money side to the cent.
        entries = db.execute(
            select(models.CreditLedger).where(
                models.CreditLedger.user_id == uuid.UUID(user_id))
        ).scalars().all()
        assert len(entries) == 1
        assert entries[0].delta == 10
        assert entries[0].event_key == f"grant:{grant.id}"
        assert entries[0].balance_after == 10
        assert p.amount_cents == 500  # Stripe amount_total, cents

        wrow = db.get(models.StripeWebhookEvent, "evt_ok_1")
        assert wrow.outcome == "processed"
        assert str(wrow.purchase_id) == purchase_id


def test_settlement_replay_same_event_grants_once(webhook_env):
    from app import credits as credits_helpers
    from app import models

    user_id, _ = _login(webhook_env)
    purchase_id = _make_pending(webhook_env, user_id)
    evt = _checkout_event("evt_replay_1", "cs_test_pending_1", purchase_id, user_id)
    assert _post_event(webhook_env, evt).json()["status"] == "processed"
    resp = _post_event(webhook_env, evt)
    assert resp.status_code == 200
    assert resp.json()["status"] == "duplicate"

    with webhook_env.sessions() as db:
        summary = credits_helpers.get_balance_summary(db, uuid.UUID(user_id))
        assert summary["balance"] == 10
        assert db.query(models.CreditGrant).count() == 1
        assert db.query(models.CreditLedger).count() == 1


def test_settlement_second_event_id_for_settled_purchase_grants_nothing(webhook_env):
    from app import credits as credits_helpers
    from app import models

    user_id, _ = _login(webhook_env)
    purchase_id = _make_pending(webhook_env, user_id)
    evt1 = _checkout_event("evt_multi_a", "cs_test_pending_1", purchase_id, user_id)
    evt2 = _checkout_event("evt_multi_b", "cs_test_pending_1", purchase_id, user_id)
    assert _post_event(webhook_env, evt1).json()["status"] == "processed"
    # Out-of-order / async duplicate with a different event id.
    resp = _post_event(webhook_env, evt2)
    assert resp.status_code == 200
    assert resp.json()["status"] == "duplicate"
    with webhook_env.sessions() as db:
        summary = credits_helpers.get_balance_summary(db, uuid.UUID(user_id))
        assert summary["balance"] == 10
        assert db.query(models.CreditGrant).count() == 1
        wrow = db.get(models.StripeWebhookEvent, "evt_multi_b")
        assert wrow.outcome == "duplicate"


def test_settlement_unknown_purchase_ignored(webhook_env):
    from app import credits as credits_helpers
    from app import models

    user_id, _ = _login(webhook_env)
    ghost = str(uuid.uuid4())
    evt = _checkout_event("evt_ghost_1", "cs_test_ghost", ghost, user_id)
    resp = _post_event(webhook_env, evt)
    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"
    with webhook_env.sessions() as db:
        summary = credits_helpers.get_balance_summary(db, uuid.UUID(user_id))
        assert summary["balance"] == 0
        assert db.query(models.CreditGrant).count() == 0
        wrow = db.get(models.StripeWebhookEvent, "evt_ghost_1")
        assert wrow.outcome == "ignored"


def test_settlement_metadata_mismatch_fails_closed(webhook_env):
    from app import credits as credits_helpers
    from app import models

    user_id, _ = _login(webhook_env)
    purchase_id = _make_pending(webhook_env, user_id)
    # Tampered metadata: claims 999 credits for a 10-credit pack.
    evt = _checkout_event("evt_tamper_1", "cs_test_pending_1", purchase_id,
                          user_id, credits=999)
    resp = _post_event(webhook_env, evt)
    assert resp.status_code == 200
    assert resp.json()["status"] == "failed"
    with webhook_env.sessions() as db:
        p = db.get(models.CreditPurchase, purchase_id)
        assert p.status == "failed"
        summary = credits_helpers.get_balance_summary(db, uuid.UUID(user_id))
        assert summary["balance"] == 0
        assert db.query(models.CreditGrant).count() == 0
        assert db.query(models.CreditLedger).count() == 0
        wrow = db.get(models.StripeWebhookEvent, "evt_tamper_1")
        assert wrow.outcome == "failed"


def test_settlement_backfills_missing_session_id(webhook_env):
    from app import credits as credits_helpers
    from app import models

    # Pending row with NULL stripe_session_id (checkout route recorded the
    # purchase but could not store the session id); metadata still joins.
    user_id, _ = _login(webhook_env)
    with webhook_env.sessions() as db:
        purchase = credits_helpers.create_pending_purchase(
            db, uuid.UUID(user_id), "growth")
        db.commit()
        purchase_id = str(purchase.id)
    evt = _checkout_event("evt_backfill_1", "cs_test_backfill", purchase_id,
                          user_id, pack_id="growth")
    resp = _post_event(webhook_env, evt)
    assert resp.json()["status"] == "processed"
    with webhook_env.sessions() as db:
        p = db.get(models.CreditPurchase, purchase_id)
        assert p.stripe_session_id == "cs_test_backfill"
        assert p.status == "completed"
        assert p.amount_cents == 1000
        summary = credits_helpers.get_balance_summary(db, uuid.UUID(user_id))
        assert summary["balance"] == 25


# --- checkout route now records the pending purchase ------------------------

class _FakeStripeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {
            "url": "https://checkout.stripe.com/pay/cs_test_123",
            "id": "cs_test_123",
        }

    def json(self):
        return self._payload


def test_checkout_creates_pending_purchase_with_session_id(webhook_env, monkeypatch):
    from app import stripe_billing
    from app import models

    user_id, csrf = _login(webhook_env)
    captured = []

    def _post(url, data=None, auth=None, headers=None, timeout=None):
        captured.append({"url": url, "data": data})
        return _FakeStripeResponse()

    monkeypatch.setattr(stripe_billing.httpx, "post", _post)
    resp = webhook_env.client.post(
        "/credits/checkout", data={"pack_id": "starter", "csrf_token": csrf})
    assert resp.status_code == 200, resp.text
    assert resp.json()["checkout_url"] == "https://checkout.stripe.com/pay/cs_test_123"

    sent_meta = captured[0]["data"]
    with webhook_env.sessions() as db:
        purchases = db.query(models.CreditPurchase).all()
        assert len(purchases) == 1
        p = purchases[0]
        assert str(p.user_id) == user_id
        assert p.pack_id == "starter"
        assert p.credits == 10
        assert p.status == "pending"
        assert p.stripe_session_id == "cs_test_123"
        # The settlement join key rode in the session metadata.
        assert sent_meta["metadata[purchase_id]"] == str(p.id)


def test_checkout_stripe_failure_keeps_pending_attempt(webhook_env, monkeypatch):
    from app import stripe_billing
    from app import models

    user_id, csrf = _login(webhook_env)

    def _boom(*a, **k):
        return _FakeStripeResponse(status_code=500, payload={"error": {}})

    monkeypatch.setattr(stripe_billing.httpx, "post", _boom)
    resp = webhook_env.client.post(
        "/credits/checkout", data={"pack_id": "starter", "csrf_token": csrf})
    assert resp.status_code == 503
    with webhook_env.sessions() as db:
        purchases = db.query(models.CreditPurchase).all()
        assert len(purchases) == 1
        assert purchases[0].status == "pending"
        assert purchases[0].stripe_session_id is None


def test_checkout_unconfigured_creates_no_purchase_row(webhook_env, monkeypatch):
    from app import models

    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    _, csrf = _login(webhook_env)
    resp = webhook_env.client.post(
        "/credits/checkout", data={"pack_id": "starter", "csrf_token": csrf})
    assert resp.status_code == 503
    with webhook_env.sessions() as db:
        assert db.query(models.CreditPurchase).count() == 0
