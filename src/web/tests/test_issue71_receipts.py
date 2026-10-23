"""Receipts and post-purchase balance display (issue #71).

- The Checkout Session creation sends ``payment_intent_data[receipt_email]``
  with the buyer's account email, so Stripe emails the payment receipt.
- After settlement, /credits and /settings render the ledger-derived
  balance (no display-only numbers) and the success return self-updates
  the balance via polling instead of asking the user to hit refresh.
- The account view shows purchase history: pack, date, credits granted.

Stripe's HTTP API and webhook deliveries are faked at the httpx/HMAC
boundary — no network, no keys. Sandbox evidence of an actual receipt
email is deferred to the founder's Stripe sandbox setup (issue #69).
"""
import hashlib
import hmac
import json
import time
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import sessionmaker

TEST_PASSWORD = "Correct horse battery staple 7!"
WEBHOOK_SECRET = "whsec_test_cycle_fixture"

PACK_PRICES = {
    "starter": "price_test_starter",
    "growth": "price_test_growth",
    "power": "price_test_power",
}
PACK_CREDITS = {"starter": 10, "growth": 25, "power": 75}
PACK_AMOUNTS = {"starter": 500, "growth": 1000, "power": 2500}


@pytest.fixture
def receipts_env(tmp_path, monkeypatch):
    from app import auth, email
    from app.db import Base, get_db
    import app.db as db_module
    from app.main import app

    engine = create_engine(
        f"sqlite:///{tmp_path / 'receipts71.db'}",
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
    monkeypatch.setenv("DATABASE_URL", "sqlite://cycle-fixture")
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


def _fresh_client(receipts_env):
    """A second browser: no session cookie, its own CSRF token."""
    c = TestClient(receipts_env.app, base_url="https://testserver")
    c.headers["X-CSRF-Token"] = c.get("/auth/csrf").json()["csrf_token"]
    return c


def _login(receipts_env, email="buyer71@example.com", client=None):
    from app.models import User

    c = client or receipts_env.client
    assert c.post("/auth/signup", data={"email": email, "password": TEST_PASSWORD}).status_code == 200
    with receipts_env.sessions() as db:
        u = db.query(User).filter(User.email == email).first()
        u.email_verified = True
        db.commit()
        user_id = str(u.id)
    resp = c.post("/auth/login", data={"email": email, "password": TEST_PASSWORD})
    assert resp.status_code == 200, resp.text
    return user_id, resp.json()["csrf_token"]


def _history_section(html):
    """The purchase-history card only — page chrome may name packs elsewhere."""
    start = html.index('id="purchase-history"')
    return html[start:start + 2000]


class _FakeStripeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {
            "url": "https://checkout.stripe.com/pay/cs_test_123",
            "id": "cs_test_123",
        }

    def json(self):
        return self._payload


def _fake_post(captured):
    def _post(url, data=None, auth=None, headers=None, timeout=None):
        captured.append({"url": url, "data": data, "auth": auth, "headers": headers})
        return _FakeStripeResponse()

    return _post


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


def _settle_purchase(receipts_env, user_id, pack_id="starter"):
    """Create a pending purchase and settle it through the signed webhook."""
    import uuid
    from app import credits as credits_helpers

    with receipts_env.sessions() as db:
        purchase = credits_helpers.create_pending_purchase(
            db, uuid.UUID(user_id), pack_id)
        purchase.stripe_session_id = f"cs_test_{pack_id}_71"
        db.commit()
        purchase_id = str(purchase.id)
    event = _checkout_event(
        f"evt_71_{pack_id}", f"cs_test_{pack_id}_71", purchase_id, user_id,
        pack_id=pack_id)
    payload = json.dumps(event).encode()
    resp = receipts_env.client.post(
        "/credits/webhook", content=payload,
        headers={"Stripe-Signature": _sign(payload),
                 "Content-Type": "application/json"})
    assert resp.status_code == 200, resp.text
    return purchase_id


# --- receipt email -----------------------------------------------------------

def test_receipt_email_sent_with_checkout(receipts_env, monkeypatch):
    from app import stripe_billing

    email = "buyer71@example.com"
    _, csrf = _login(receipts_env, email=email)
    captured = []
    monkeypatch.setattr(stripe_billing.httpx, "post", _fake_post(captured))
    resp = receipts_env.client.post(
        "/credits/checkout", data={"pack_id": "starter", "csrf_token": csrf})
    assert resp.status_code == 200, resp.text
    data = captured[-1]["data"]
    # Issue #71: Stripe emails the payment receipt to the buyer's account email.
    assert data["payment_intent_data[receipt_email]"] == email


def test_receipt_email_omitted_when_not_provided(receipts_env, monkeypatch):
    from app import stripe_billing

    captured = []
    monkeypatch.setattr(stripe_billing.httpx, "post", _fake_post(captured))
    url, session_id = stripe_billing.create_checkout_session(
        user_id="u-1", pack_id="starter", purchase_id="p-1",
        success_url="https://x/s", cancel_url="https://x/c")
    assert url and session_id
    assert "payment_intent_data[receipt_email]" not in captured[-1]["data"]


# --- balance rendering: ledger-derived everywhere ------------------------------

def test_credits_page_shows_ledger_balance(receipts_env):
    _login(receipts_env)
    page = receipts_env.client.get("/credits")
    assert page.status_code == 200
    api = receipts_env.client.get("/credits/balance")
    assert api.status_code == 200
    balance = api.json()["balance"]
    # The page renders the exact JSON balance inside the balance strip.
    assert f'id="credit-balance" data-initial="{balance}">{balance}' in page.text


def test_credits_page_hides_balance_when_anonymous(receipts_env):
    page = receipts_env.client.get("/credits")
    assert page.status_code == 200
    assert "credit-balance" not in page.text


def test_success_return_self_updates_balance(receipts_env):
    """The success page polls /credits/balance so settlement shows without
    the user hitting refresh (issue #71 acceptance: no manual refresh)."""
    _login(receipts_env)
    page = receipts_env.client.get("/credits?checkout=success")
    assert page.status_code == 200
    assert 'id="credit-balance"' in page.text
    assert 'fetch("/credits/balance"' in page.text
    # Anonymous visitors never get the polling script.
    anon = TestClient(receipts_env.app, base_url="https://testserver")
    anon_page = anon.get("/credits?checkout=success")
    assert 'fetch("/credits/balance"' not in anon_page.text


def test_balance_matches_ledger_after_settlement(receipts_env):
    """Every displayed balance equals the ledger — no display-only numbers."""
    from app import models

    user_id, _ = _login(receipts_env)
    _settle_purchase(receipts_env, user_id, "starter")

    with receipts_env.sessions() as db:
        ledger_total = db.execute(
            select(func.coalesce(func.sum(models.CreditLedger.delta), 0))
            .where(models.CreditLedger.user_id == user_id)
        ).scalar()

    api = receipts_env.client.get("/credits/balance")
    assert api.status_code == 200
    assert api.json()["balance"] == ledger_total

    page = receipts_env.client.get("/credits")
    assert f'id="credit-balance" data-initial="{ledger_total}">{ledger_total}' in page.text

    settings = receipts_env.client.get("/settings")
    assert settings.status_code == 200
    assert f"{ledger_total} credits" in settings.text


# --- purchase history ----------------------------------------------------------

def test_purchase_history_on_account(receipts_env):
    from app import credits as credits_helpers
    import uuid

    user_id, _ = _login(receipts_env)
    _settle_purchase(receipts_env, user_id, "starter")
    _settle_purchase(receipts_env, user_id, "growth")

    # A pending purchase is reconciliation internals, not history.
    with receipts_env.sessions() as db:
        pending = credits_helpers.create_pending_purchase(
            db, uuid.UUID(user_id), "power")
        db.commit()

    page = receipts_env.client.get("/settings")
    assert page.status_code == 200
    history = _history_section(page.text)
    assert "Purchase history" in history
    assert "Starter" in history and "10 credits" in history
    assert "Growth" in history and "25 credits" in history
    # The pending Power purchase is reconciliation internals, not history.
    assert "Power" not in history
    # A date is shown for each completed purchase.
    assert history.count("session-meta") >= 2


def test_purchase_history_newest_first(receipts_env):
    user_id, _ = _login(receipts_env)
    _settle_purchase(receipts_env, user_id, "starter")
    _settle_purchase(receipts_env, user_id, "growth")
    page = receipts_env.client.get("/settings")
    history = _history_section(page.text)
    assert history.index("Growth") < history.index("Starter")


def test_purchase_history_is_private(receipts_env):
    user_id, _ = _login(receipts_env, email="buyer71@example.com")
    _settle_purchase(receipts_env, user_id, "power")
    # A second user (fresh browser) with no purchases sees an empty history.
    other = _fresh_client(receipts_env)
    _login(receipts_env, email="other71@example.com", client=other)
    page = other.get("/settings")
    assert page.status_code == 200
    history = _history_section(page.text)
    assert "No credit purchases yet." in history
    assert "Power" not in history
