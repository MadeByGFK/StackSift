"""In-modal quick buy for the credit-pack modal (issue #68 follow-up).

Founder request 2026-10-23: the nav credit-badge modal dead-ended — pack
rows were static and "Buy credits" just linked to /credits. Now:

- /auth/balance (already fetched by the badge script on every page) also
  returns the session CSRF token and per-pack checkout readiness for
  logged-in users — and neither field for anonymous callers.
- The modal renders selectable pack rows (radio semantics, Growth the
  default) and a real buy form posting the selected pack to the existing
  /credits/checkout contract via the shared data-checkout-form handler.
- With no pack ready the modal keeps its coming-soon state (production
  parity — Stripe unconfigured there), and the insufficient-credits PDF
  modal hands off to the pack modal instead of linking away.

Stripe's HTTP API is faked at the httpx boundary — no network, no keys.
"""
from pathlib import Path
from types import SimpleNamespace

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

SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "app" / "templates" / "auth_form_script.html"
).read_text()


@pytest.fixture
def modal_env(tmp_path, monkeypatch):
    from app import auth, email
    from app.db import Base, get_db
    import app.db as db_module
    from app.main import app

    engine = create_engine(
        f"sqlite:///{tmp_path / 'modal68.db'}",
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


def _login(modal_env, email="modalbuyer@example.com"):
    from app.models import User

    c = modal_env.client
    assert c.post("/auth/signup", data={"email": email, "password": TEST_PASSWORD}).status_code == 200
    with modal_env.sessions() as db:
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


# --- /auth/balance contract -------------------------------------------------

def test_balance_logged_in_includes_csrf_and_readiness(modal_env):
    _, csrf = _login(modal_env)
    resp = modal_env.client.get("/auth/balance")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data["balance"], int)
    # The token is the session token — the same one the page forms use.
    assert data["csrf_token"] == csrf
    assert data["packs"] == {"starter": True, "growth": True, "power": True}


def test_balance_anonymous_omits_csrf_and_readiness(modal_env):
    resp = modal_env.client.get("/auth/balance")
    assert resp.status_code == 200
    data = resp.json()
    assert data == {"balance": None}
    assert "csrf_token" not in data
    assert "packs" not in data


def test_balance_readiness_reflects_unconfigured_pack(modal_env, monkeypatch):
    _login(modal_env)
    monkeypatch.delenv("STRIPE_PRICE_POWER")
    data = modal_env.client.get("/auth/balance").json()
    assert data["packs"] == {"starter": True, "growth": True, "power": False}


def test_balance_csrf_token_authorizes_checkout(modal_env, monkeypatch):
    # End to end: the token the modal receives from /auth/balance is the
    # token /credits/checkout accepts — no page-form token involved.
    from app import stripe_billing

    _login(modal_env)
    captured = []
    monkeypatch.setattr(stripe_billing.httpx, "post", _fake_post(captured))
    balance = modal_env.client.get("/auth/balance").json()
    resp = modal_env.client.post(
        "/credits/checkout",
        data={"pack_id": "power", "csrf_token": balance["csrf_token"]},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["checkout_url"].startswith("https://checkout.stripe.com/")
    assert captured[0]["data"]["line_items[0][price]"] == PACK_PRICES["power"]


# --- modal template: selectable packs + quick-buy form ----------------------

def test_modal_pack_rows_are_selectable_radios():
    assert 'type="radio"' in SCRIPT
    assert 'name="credit-pack"' in SCRIPT
    assert 'role="radiogroup"' in SCRIPT
    assert "data-pack-row" in SCRIPT
    # Selected row gold, unselected default — the modal's existing palette.
    assert "BORDER_SELECTED = '#ecc94b'" in SCRIPT
    assert "BORDER_DEFAULT = '#2d3d6b'" in SCRIPT


def test_modal_default_selection_is_growth():
    # Growth preselected when purchasable; first ready pack otherwise.
    assert "readyIds.indexOf('growth') !== -1 ? 'growth' : readyIds[0]" in SCRIPT
    # The hidden pack_id starts at the default and follows selection changes.
    assert 'name="pack_id" id="credit-modal-pack-id"' in SCRIPT
    assert "packIdInput.value = radio.value" in SCRIPT


def test_modal_buy_form_posts_to_existing_checkout_contract():
    # The form is built with the DOM API inside the modal builder — it
    # never exists in rendered page markup.
    assert "buyForm.action = '/credits/checkout'" in SCRIPT
    assert "buyForm.method = 'post'" in SCRIPT
    assert "buyForm.setAttribute('data-auth-form', '')" in SCRIPT
    assert "buyForm.setAttribute('data-checkout-form', '')" in SCRIPT
    assert "buyForm.id = 'credit-modal-form'" in SCRIPT
    assert 'name="csrf_token"' in SCRIPT
    # Errors surface inline in the form's status element.
    assert '<p role="status"' in SCRIPT
    # The dynamically created form is wired with the shared submit handler.
    assert "wireAuthForm(buyForm)" in SCRIPT


def test_modal_keeps_pack_copy_and_popular_badge():
    for copy in ("name: 'Starter'", "credits: 10", "price: '$5'",
                 "name: 'Growth'", "credits: 25", "price: '$10'",
                 "name: 'Power'", "credits: 75", "price: '$25'", "POPULAR"):
        assert copy in SCRIPT, copy


def test_modal_coming_soon_state_when_nothing_ready():
    # Production parity: no live buy form, details live on /credits.
    assert "Purchasing coming soon." in SCRIPT
    assert "View details" in SCRIPT
    # The quick-buy form only renders in the quickBuy branch.
    assert "const quickBuy = Boolean(checkoutState.csrfToken) && readyIds.length > 0" in SCRIPT


# --- insufficient-credits PDF modal handoff ---------------------------------

def test_pdf_modal_buy_button_opens_pack_modal():
    assert "window.showCreditModal = showCreditModal" in SCRIPT
    assert "window.showCreditModal()" in SCRIPT
    # The old dead-end anchor out of the PDF modal is gone.
    assert "buy.href = '/credits'" not in SCRIPT


def test_pdf_modal_ruled_copy_unchanged():
    assert "Insufficient Credits" in SCRIPT
    assert "PDF export costs 2 credits." in SCRIPT
