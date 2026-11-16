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

Issue #164 Phase C re-base (C3): the header badge and the quick-buy
pack modal are REMOVED, and /auth/balance is retired (410) along with
its CSRF-for-modal provision. Every test below keeps its subject —
the balance contract, the modal markup, the PDF-modal handoff — and
asserts the retirement with the same strength: the endpoint serves no
balance/CSRF/readiness to anyone, the shared script contains no badge,
no pack rows, no modal buy form and no pack copy, and the PDF error
modal has no insufficient-credits state and no buy handoff (exports
are free). The shared script's non-credit duties (wireAuthForm, the
data-checkout-form redirect used by PRODUCT checkout forms, the PDF
error modal itself) are asserted preserved.
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
    # Phase C premise: /auth/balance is retired — a logged-in caller
    # gets 410 and NONE of the old fields: no balance value, no session
    # CSRF token for the modal, no per-pack readiness map.
    _, csrf = _login(modal_env)
    resp = modal_env.client.get("/auth/balance")
    assert resp.status_code == 410
    data = resp.json()
    assert data.get("balance") is None
    assert "csrf_token" not in data
    assert "packs" not in data


def test_balance_anonymous_omits_csrf_and_readiness(modal_env):
    # Phase C premise: anonymous callers get the same honest 410 (the
    # old contract answered 200 with {"balance": None} and omitted the
    # modal fields; nothing is served to anyone now).
    resp = modal_env.client.get("/auth/balance")
    assert resp.status_code == 410
    data = resp.json()
    assert data.get("balance") is None
    assert "csrf_token" not in data
    assert "packs" not in data


def test_balance_readiness_reflects_unconfigured_pack(modal_env, monkeypatch):
    # Phase C premise: pack readiness no longer exists as a concept —
    # unconfiguring a pack price changes nothing; the endpoint stays
    # retired and serves no readiness map.
    _login(modal_env)
    monkeypatch.delenv("STRIPE_PRICE_POWER")
    resp = modal_env.client.get("/auth/balance")
    assert resp.status_code == 410
    assert "packs" not in resp.json()


def test_balance_csrf_token_authorizes_checkout(modal_env, monkeypatch):
    # Phase C premise: there is no balance-endpoint token to authorize
    # anything (the endpoint is 410), and even the real session CSRF
    # token cannot buy a pack — /credits/checkout answers the 410
    # retirement with zero Stripe calls and zero purchase rows.
    from app import models, stripe_billing

    _, csrf = _login(modal_env)
    captured = []
    monkeypatch.setattr(stripe_billing.httpx, "post", _fake_post(captured))
    balance = modal_env.client.get("/auth/balance")
    assert balance.status_code == 410
    assert "csrf_token" not in balance.json()
    resp = modal_env.client.post(
        "/credits/checkout",
        data={"pack_id": "power", "csrf_token": csrf},
    )
    assert resp.status_code == 410, resp.text
    assert "retired" in resp.json()["error"].lower()
    assert captured == []
    with modal_env.sessions() as db:
        assert db.query(models.CreditPurchase).count() == 0


# --- modal template: selectable packs + quick-buy form ----------------------

def test_modal_pack_rows_are_selectable_radios():
    # Phase C premise: the modal is gone — no pack radio rows, no
    # radiogroup, no selected/default border logic in the shared script.
    assert 'name="credit-pack"' not in SCRIPT
    assert 'role="radiogroup"' not in SCRIPT
    assert "data-pack-row" not in SCRIPT
    assert "BORDER_SELECTED" not in SCRIPT
    assert "BORDER_DEFAULT" not in SCRIPT
    # The badge that opened the modal is gone too.
    assert "credit-badge" not in SCRIPT
    assert "/auth/balance" not in SCRIPT


def test_modal_default_selection_is_growth():
    # Phase C premise: no default selection exists — no ready-pack
    # computation, no hidden pack_id input following a selection.
    assert "readyIds" not in SCRIPT
    assert 'name="pack_id" id="credit-modal-pack-id"' not in SCRIPT
    assert "packIdInput" not in SCRIPT
    assert "MODAL_PACKS" not in SCRIPT


def test_modal_buy_form_posts_to_existing_checkout_contract():
    # Phase C premise: no modal buy form is ever built — no form posting
    # to the retired checkout route, no modal form id, no wire-up.
    assert "buyForm" not in SCRIPT
    assert "'/credits/checkout'" not in SCRIPT
    assert '"/credits/checkout"' not in SCRIPT
    assert "credit-modal-form" not in SCRIPT
    assert "wireAuthForm(buyForm)" not in SCRIPT
    # Preserved: the shared script's non-credit duties remain — the
    # auth-form wiring and the data-checkout-form redirect that PRODUCT
    # checkout forms (Phase A/B) still rely on.
    assert "wireAuthForm" in SCRIPT
    assert "data-checkout-form" in SCRIPT


def test_modal_keeps_pack_copy_and_popular_badge():
    # Phase C premise: none of the modal's pack copy survives — no pack
    # names, credit counts, pack prices, or POPULAR badge in the script.
    for copy in ("name: 'Starter'", "credits: 10", "price: '$5'",
                 "name: 'Growth'", "credits: 25", "price: '$10'",
                 "name: 'Power'", "credits: 75", "price: '$25'", "POPULAR"):
        assert copy not in SCRIPT, copy


def test_modal_coming_soon_state_when_nothing_ready():
    # Phase C premise: there is no coming-soon state because there is
    # no modal — the copy and the quickBuy branch condition are gone.
    assert "Purchasing coming soon." not in SCRIPT
    assert "quickBuy" not in SCRIPT
    assert "checkoutState" not in SCRIPT


# --- insufficient-credits PDF modal handoff ---------------------------------

def test_pdf_modal_buy_button_opens_pack_modal():
    # Phase C premise: the PDF error modal no longer hands off anywhere
    # — no showCreditModal export or call, and no /credits buy anchor;
    # the modal itself (a preserved shared-script duty) just reports
    # the error with a Close button, because exports are free.
    assert "showCreditModal" not in SCRIPT
    assert "buy.href = '/credits'" not in SCRIPT
    assert "error-modal" in SCRIPT
    assert "Close" in SCRIPT


def test_pdf_modal_ruled_copy_unchanged():
    # Phase C premise: the old ruled copy is retired with the charge —
    # exports are free, so the script carries no insufficient-credits
    # heading and no per-export credit price anywhere.
    assert "Insufficient Credits" not in SCRIPT
    assert "PDF export costs 2 credits." not in SCRIPT
    assert "costs 2 credits" not in SCRIPT
