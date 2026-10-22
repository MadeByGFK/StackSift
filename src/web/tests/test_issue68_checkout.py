"""Stripe Checkout entry points (issue #68).

- Packs start Checkout sessions for the correct price and pack identity;
  session metadata carries user + pack for settlement (issue #69).
- Entry points: credits page buy forms (signed-in only) + insufficient-credits
  flow (402 page CTA, PDF 402 JSON purchase_url, badge/modal links).
- Anonymous users are routed to signup/login, never to Stripe.
- Test mode enforced: live keys refused before any network call; nothing
  here enables live mode.

Stripe's HTTP API is faked at the httpx boundary — no network, no keys.
"""
import os
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

TEST_PASSWORD = "CorrectHorseBatteryStaple99!"

PACK_PRICES = {
    "starter": "price_test_starter",
    "growth": "price_test_growth",
    "power": "price_test_power",
}


@pytest.fixture
def checkout_env(tmp_path, monkeypatch):
    from app import auth, email
    from app.db import Base, get_db
    import app.db as db_module
    from app.main import app

    engine = create_engine(
        f"sqlite:///{tmp_path / 'checkout68.db'}",
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
    monkeypatch.setenv("DATABASE_URL", "sqlite://")
    for pack_id, price in PACK_PRICES.items():
        monkeypatch.setenv(f"STRIPE_PRICE_{pack_id.upper()}", price)
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_cycle_fixture")
    sent = []
    monkeypatch.setattr(email, "send_verification_email", lambda address, token: sent.append((address, token)))
    try:
        with TestClient(app, base_url="https://testserver") as client:
            client.headers["X-CSRF-Token"] = client.get("/auth/csrf").json()["csrf_token"]
            yield SimpleNamespace(client=client, sessions=sessions, app=app)
    finally:
        engine.dispose()


def _login(checkout_env, email="buyer@example.com"):
    from app.models import User

    c = checkout_env.client
    assert c.post("/auth/signup", data={"email": email, "password": TEST_PASSWORD}).status_code == 200
    with checkout_env.sessions() as db:
        u = db.query(User).filter(User.email == email).first()
        u.email_verified = True
        db.commit()
        user_id = str(u.id)
    c.headers["X-CSRF-Token"] = c.get("/auth/csrf").json()["csrf_token"]
    resp = c.post("/auth/login", data={"email": email, "password": TEST_PASSWORD})
    assert resp.status_code == 200, resp.text
    return user_id, resp.json()["csrf_token"]


class _FakeStripeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {"url": "https://checkout.stripe.com/pay/cs_test_123"}

    def json(self):
        return self._payload


def _fake_post(captured):
    def _post(url, data=None, auth=None, headers=None, timeout=None):
        captured.append({"url": url, "data": data, "auth": auth, "headers": headers})
        return _FakeStripeResponse()

    return _post


# --- billing module unit tests -------------------------------------------

def test_pack_catalog_matches_v111():
    from app import stripe_billing

    assert stripe_billing.get_pack("starter")["credits"] == 10
    assert stripe_billing.get_pack("growth")["credits"] == 25
    assert stripe_billing.get_pack("power")["credits"] == 75
    assert stripe_billing.get_pack("nope") is None


def test_secret_key_missing_refuses(checkout_env, monkeypatch):
    from app import stripe_billing

    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    with pytest.raises(stripe_billing.CheckoutNotConfigured):
        stripe_billing._secret_key()


def test_live_key_refused_without_network(checkout_env, monkeypatch):
    from app import stripe_billing

    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_live_abc123")
    captured = []
    monkeypatch.setattr(stripe_billing.httpx, "post", _fake_post(captured))
    with pytest.raises(stripe_billing.LiveKeyRefused):
        stripe_billing.create_checkout_session(
            user_id="u1", pack_id="starter",
            success_url="https://x/s", cancel_url="https://x/c")
    assert captured == [], "live key must never reach the network"


def test_unrecognized_key_format_refused(checkout_env, monkeypatch):
    from app import stripe_billing

    monkeypatch.setenv("STRIPE_SECRET_KEY", "rk_test_whatever")
    with pytest.raises(stripe_billing.CheckoutError):
        stripe_billing._secret_key()


def test_each_pack_sends_correct_price_and_metadata(checkout_env, monkeypatch):
    from app import stripe_billing

    for pack_id, price_id in PACK_PRICES.items():
        captured = []
        monkeypatch.setattr(stripe_billing.httpx, "post", _fake_post(captured))
        url = stripe_billing.create_checkout_session(
            user_id="user-9", pack_id=pack_id,
            success_url="https://x/s", cancel_url="https://x/c")
        assert url == "https://checkout.stripe.com/pay/cs_test_123"
        call = captured[0]
        assert call["url"] == "https://api.stripe.com/v1/checkout/sessions"
        assert call["data"]["mode"] == "payment"
        assert call["data"]["line_items[0][price]"] == price_id, pack_id
        assert call["data"]["line_items[0][quantity]"] == "1"
        assert call["data"]["success_url"] == "https://x/s"
        assert call["data"]["cancel_url"] == "https://x/c"
        # Settlement contract (issue #69): user + pack identity on the session.
        assert call["data"]["metadata[user_id]"] == "user-9"
        assert call["data"]["metadata[pack_id]"] == pack_id
        assert call["data"]["metadata[credits]"] == str(stripe_billing.PACKS[pack_id]["credits"])
        assert call["data"]["metadata[pricing_version]"] == "1"
        assert call["data"]["client_reference_id"] == "user-9"
        # Test key used as the basic-auth username.
        assert call["auth"][0] == "sk_test_cycle_fixture"
        assert "Idempotency-Key" in call["headers"]


def test_unconfigured_pack_fails_closed(checkout_env, monkeypatch):
    from app import stripe_billing

    monkeypatch.delenv("STRIPE_PRICE_GROWTH", raising=False)
    captured = []
    monkeypatch.setattr(stripe_billing.httpx, "post", _fake_post(captured))
    with pytest.raises(stripe_billing.CheckoutNotConfigured):
        stripe_billing.create_checkout_session(
            user_id="u1", pack_id="growth",
            success_url="https://x/s", cancel_url="https://x/c")
    assert captured == []


def test_stripe_error_fails_closed(checkout_env, monkeypatch):
    from app import stripe_billing

    def _boom(*a, **k):
        return _FakeStripeResponse(status_code=500, payload={"error": {"message": "nope"}})

    monkeypatch.setattr(stripe_billing.httpx, "post", _boom)
    with pytest.raises(stripe_billing.CheckoutError):
        stripe_billing.create_checkout_session(
            user_id="u1", pack_id="starter",
            success_url="https://x/s", cancel_url="https://x/c")


# --- credits page entry point --------------------------------------------

def test_credits_page_anonymous_sees_packs_not_buy_forms(checkout_env):
    resp = checkout_env.client.get("/credits")
    assert resp.status_code == 200
    assert "Starter" in resp.text and "Growth" in resp.text and "Power" in resp.text
    assert 'action="/credits/checkout"' not in resp.text
    assert "Sign up to buy" in resp.text
    # The issue-67 notify bridge is gone with checkout.
    assert "/credits/notify" not in resp.text
    assert "notify-capture" not in resp.text


def test_credits_page_logged_in_shows_buy_forms(checkout_env):
    user_id, csrf = _login(checkout_env)
    resp = checkout_env.client.get("/credits")
    assert resp.status_code == 200
    for pack_id in ("starter", "growth", "power"):
        assert f'name="pack_id" value="{pack_id}"' in resp.text, pack_id
    assert f'name="csrf_token" value="{csrf}"' in resp.text
    assert "data-checkout-form" in resp.text


def test_credits_page_unconfigured_pack_shows_coming_soon(checkout_env, monkeypatch):
    monkeypatch.delenv("STRIPE_PRICE_POWER", raising=False)
    _login(checkout_env)
    resp = checkout_env.client.get("/credits")
    assert resp.status_code == 200
    assert 'name="pack_id" value="power"' not in resp.text
    assert "Coming soon" in resp.text


def test_credits_page_checkout_banners(checkout_env):
    assert "Payment complete" in checkout_env.client.get("/credits?checkout=success").text
    assert "no charge was made" in checkout_env.client.get("/credits?checkout=cancelled").text
    assert "Payment complete" not in checkout_env.client.get("/credits").text


# --- checkout route --------------------------------------------------------

def test_checkout_anonymous_routed_to_signup(checkout_env):
    resp = checkout_env.client.post(
        "/credits/checkout", data={"pack_id": "starter", "csrf_token": "x"})
    assert resp.status_code == 401
    assert "sign up" in resp.json()["error"].lower()


def test_checkout_rejects_unknown_pack(checkout_env):
    _, csrf = _login(checkout_env)
    resp = checkout_env.client.post(
        "/credits/checkout", data={"pack_id": "platinum", "csrf_token": csrf})
    assert resp.status_code == 400


def test_checkout_rejects_bad_csrf(checkout_env):
    _login(checkout_env)
    resp = checkout_env.client.post(
        "/credits/checkout", data={"pack_id": "starter", "csrf_token": "wrong"})
    assert resp.status_code == 403


def test_checkout_creates_session_for_each_pack(checkout_env, monkeypatch):
    from app import stripe_billing

    user_id, csrf = _login(checkout_env)
    for pack_id, price_id in PACK_PRICES.items():
        captured = []
        monkeypatch.setattr(stripe_billing.httpx, "post", _fake_post(captured))
        resp = checkout_env.client.post(
            "/credits/checkout", data={"pack_id": pack_id, "csrf_token": csrf})
        assert resp.status_code == 200, (pack_id, resp.text)
        assert resp.json()["checkout_url"] == "https://checkout.stripe.com/pay/cs_test_123"
        call = captured[0]
        assert call["data"]["line_items[0][price]"] == price_id
        assert call["data"]["metadata[user_id]"] == user_id
        assert call["data"]["metadata[pack_id]"] == pack_id


def test_checkout_503_when_stripe_unconfigured(checkout_env, monkeypatch):
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    _, csrf = _login(checkout_env)
    resp = checkout_env.client.post(
        "/credits/checkout", data={"pack_id": "starter", "csrf_token": csrf})
    assert resp.status_code == 503
    assert "not available yet" in resp.json()["error"]


def test_checkout_refuses_live_key(checkout_env, monkeypatch):
    from app import stripe_billing

    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_live_abc123")
    captured = []
    monkeypatch.setattr(stripe_billing.httpx, "post", _fake_post(captured))
    _, csrf = _login(checkout_env)
    resp = checkout_env.client.post(
        "/credits/checkout", data={"pack_id": "starter", "csrf_token": csrf})
    assert resp.status_code == 500
    assert captured == [], "live key must never reach the network"


def test_checkout_rate_limited(checkout_env, monkeypatch):
    from app import stripe_billing

    _, csrf = _login(checkout_env, email="ratelimit@example.com")
    captured = []
    monkeypatch.setattr(stripe_billing.httpx, "post", _fake_post(captured))
    statuses = [
        checkout_env.client.post(
            "/credits/checkout", data={"pack_id": "starter", "csrf_token": csrf}).status_code
        for _ in range(6)
    ]
    assert statuses[:5] == [200] * 5
    assert statuses[5] == 429


# --- notify bridge removal -------------------------------------------------

def test_notify_endpoint_removed(checkout_env):
    assert checkout_env.client.post(
        "/credits/notify", data={"email": "x@y.z", "csrf_token": "x"}).status_code == 404


# --- insufficient-credits entry points -------------------------------------

def test_402_page_carries_buy_credits_cta(checkout_env):
    from starlette.requests import Request
    from app.main import _analysis_response

    scope = {
        "type": "http", "http_version": "1.1", "method": "GET",
        "scheme": "https", "path": "/", "query_string": b"",
        "headers": [], "server": ("testserver", 443),
    }
    request = Request(scope)
    response = _analysis_response(
        request, 402, message="Insufficient Power-Up credits.", buy_credits=True)
    assert response.status_code == 402
    body = response.body.decode()
    assert "Insufficient Power-Up credits." in body
    assert 'href="/credits"' in body and "Buy credits" in body


def test_non_402_page_has_no_buy_cta(checkout_env):
    from starlette.requests import Request
    from app.main import _analysis_response

    scope = {
        "type": "http", "http_version": "1.1", "method": "GET",
        "scheme": "https", "path": "/", "query_string": b"",
        "headers": [], "server": ("testserver", 443),
    }
    response = _analysis_response(Request(scope), 503, message="Down for a moment.")
    assert '<a href="/credits" class="buy-credits-cta">' not in response.body.decode()
