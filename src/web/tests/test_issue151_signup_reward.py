"""Issue #151: signup reward is 10 credits (founder ruling 2026-11-01).

Production granted 3 after Release #4 because the /pricing correction
never landed in code. This file pins the ruled amount, the one-grant
idempotency (existing 3-credit accounts keep 3 — no top-up, founder
ruling 2026-11-05), and the user-facing copy on the pricing/signup
surfaces plus the pack framing (per-report unlock of ALL formats,
not PDF-only).
"""

import pathlib
import uuid

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app import credits as C
from app import models
from app.db import Base

APP_DIR = pathlib.Path(__file__).resolve().parents[1] / "app"


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


def test_signup_reward_constant_is_ruled_10():
    assert C.SIGNUP_REWARD_CREDITS == 10


def test_signup_reward_grants_10_once(db, user):
    email = f"{user.hex[:8]}@test.com"
    g = C.grant_signup_reward(db, user, email)
    db.commit()
    assert g is not None and g.issued == 10
    assert C.get_balance_summary(db, user)["balance"] == 10
    # Idempotent: a second grant for the same email issues nothing.
    assert C.grant_signup_reward(db, user, email) is None
    db.commit()
    assert C.get_balance_summary(db, user)["balance"] == 10


def test_pricing_and_signup_copy_say_10_not_3():
    pricing = (APP_DIR / "templates" / "pricing.html").read_text()
    signup = (APP_DIR / "templates" / "signup.html").read_text()
    assert "10 free credits" in pricing
    assert "10 free credits" in signup
    assert "3 free credits" not in pricing
    assert "3 free credits" not in signup


def test_pack_framing_is_all_format_unlock_not_pdf_only():
    billing = (APP_DIR / "stripe_billing.py").read_text()
    assert "PDF exports" not in billing
    assert "report unlocks (all formats)" in billing
    pricing = (APP_DIR / "templates" / "pricing.html").read_text()
    assert "2 credits per report unlocks all formats" in pricing
