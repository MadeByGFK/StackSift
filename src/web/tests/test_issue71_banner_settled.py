"""Credits-page success banner vs. settlement state (issue #71).

When the latest purchase is already 'completed' the server renders the
"credits added" banner and must NOT ship the /credits/balance polling
script. When it is still 'pending' the "on their way" banner and the
polling script are both present. Cancelled returns are unchanged.

Real route (GET /credits), real TestClient, real seeded SQLite DB.
"""
import uuid
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

TEST_PASSWORD = "Correct horse battery staple 7!"
PACK_PRICES = {
    "starter": "price_test_starter",
    "growth": "price_test_growth",
    "power": "price_test_power",
}
PACK_CREDITS = {"starter": 10, "growth": 25, "power": 75}
PACK_AMOUNTS = {"starter": 500, "growth": 1000, "power": 2500}

POLL_MARKER = 'fetch("/credits/balance"'
EM_DASH = "\u2014"


@pytest.fixture
def banner_env(tmp_path, monkeypatch):
    from app import auth, email
    from app.db import Base, get_db
    import app.db as db_module
    from app.main import app

    engine = create_engine(
        f"sqlite:///{tmp_path / 'banner71.db'}",
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
    sent = []
    monkeypatch.setattr(email, "send_verification_email", lambda address, token: sent.append((address, token)))
    try:
        with TestClient(app, base_url="https://testserver") as client:
            client.headers["X-CSRF-Token"] = client.get("/auth/csrf").json()["csrf_token"]
            yield SimpleNamespace(client=client, sessions=sessions, app=app)
    finally:
        engine.dispose()


def _login(banner_env, email="banner71@example.com"):
    from app.models import User

    c = banner_env.client
    assert c.post("/auth/signup", data={"email": email, "password": TEST_PASSWORD}).status_code == 200
    with banner_env.sessions() as db:
        u = db.query(User).filter(User.email == email).first()
        u.email_verified = True
        db.commit()
        user_id = str(u.id)
    resp = c.post("/auth/login", data={"email": email, "password": TEST_PASSWORD})
    assert resp.status_code == 200, resp.text
    return user_id


def _seed_purchase(banner_env, user_id, status, pack_id="growth"):
    """Insert one CreditPurchase row directly.

    A 'completed' row must carry amount_cents > 0 (CHECK
    ck_purchase_completed_has_amount); we also set the Stripe ids,
    currency and completed_at that settlement would have written.
    """
    from datetime import datetime, timezone
    from app.models import CreditPurchase

    fields = dict(
        id=uuid.uuid4(),
        user_id=uuid.UUID(user_id),
        stripe_session_id=f"cs_test_banner71_{uuid.uuid4().hex[:8]}",
        pack_id=pack_id,
        credits=PACK_CREDITS[pack_id],
        pricing_version=1,
        status=status,
    )
    if status == "completed":
        fields.update(
            stripe_payment_intent_id=f"pi_test_{uuid.uuid4().hex[:8]}",
            amount_cents=PACK_AMOUNTS[pack_id],
            currency="usd",
            stripe_event_id=f"evt_test_{uuid.uuid4().hex[:8]}",
            completed_at=datetime.now(timezone.utc),
        )
    with banner_env.sessions() as db:
        db.add(CreditPurchase(**fields))
        db.commit()


def _banner(html):
    """Only the first checkout banner element.

    The polling script also contains the text 'credits added to your
    balance', so page-wide text assertions on it would be wrong.
    """
    start = html.index('class="checkout-banner')
    end = html.index("</div>", start)
    return html[start:end]


def test_completed_purchase_renders_credits_added_banner(banner_env):
    user_id = _login(banner_env)
    _seed_purchase(banner_env, user_id, "completed", pack_id="growth")
    page = banner_env.client.get("/credits?checkout=success")
    assert page.status_code == 200
    banner = _banner(page.text)
    assert f"Payment complete {EM_DASH} 25 credits added to your balance." in banner
    assert "on their way" not in banner
    assert "on their way" not in page.text


def test_pending_purchase_renders_on_their_way_banner(banner_env):
    user_id = _login(banner_env)
    _seed_purchase(banner_env, user_id, "pending", pack_id="growth")
    page = banner_env.client.get("/credits?checkout=success")
    assert page.status_code == 200
    banner = _banner(page.text)
    assert "on their way" in banner
    assert "credits added to your balance" not in banner


def test_polling_script_absent_when_completed(banner_env):
    user_id = _login(banner_env)
    _seed_purchase(banner_env, user_id, "completed", pack_id="starter")
    page = banner_env.client.get("/credits?checkout=success")
    assert page.status_code == 200
    assert POLL_MARKER not in page.text
    # The balance strip itself is still rendered.
    assert 'id="credit-balance"' in page.text


def test_polling_script_present_when_pending(banner_env):
    user_id = _login(banner_env)
    _seed_purchase(banner_env, user_id, "pending", pack_id="starter")
    page = banner_env.client.get("/credits?checkout=success")
    assert page.status_code == 200
    assert POLL_MARKER in page.text


def test_cancelled_return_unchanged(banner_env):
    user_id = _login(banner_env)
    _seed_purchase(banner_env, user_id, "completed", pack_id="growth")
    page = banner_env.client.get("/credits?checkout=cancelled")
    assert page.status_code == 200
    banner = _banner(page.text)
    assert "no charge was made and no credits were added" in banner
    assert "on their way" not in page.text
    assert "credits added to your balance" not in page.text
    assert POLL_MARKER not in page.text
