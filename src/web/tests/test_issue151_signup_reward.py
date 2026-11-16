"""Issue #151: signup reward is 10 credits (founder ruling 2026-11-01).

Production granted 3 after Release #4 because the /pricing correction
never landed in code. This file pins the ruled amount, the one-grant
idempotency (existing 3-credit accounts keep 3 — no top-up, founder
ruling 2026-11-05), and the user-facing copy on the pricing/signup
surfaces plus the pack framing (per-report unlock of ALL formats,
not PDF-only).

PREMISE CHANGED (#164 Phase C, Decision 3 + amendment C4): the
signup grant is REMOVED. `grant_signup_reward` is disabled
deliberately (early return before any eligibility/account/grant/
ledger write; the SIGNUP_REWARD_CREDITS constant and the
`grant_credits` quantity>0 invariant stay, per C4), and every
free-signup-credit claim is gone from pricing/signup copy. Exports
are framed as FREE for all reports, not as a credit unlock. The
tests below pin the retirement with the same strength as the
original grant pins.
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


def test_signup_reward_disabled_grants_nothing(db, user):
    # Phase C / C4: the helper returns None BEFORE any write, on the
    # first and on a repeat call (the old one-grant idempotency pin,
    # re-based: zero grants, not exactly one).
    email = f"{user.hex[:8]}@test.com"
    assert C.grant_signup_reward(db, user, email) is None
    db.commit()
    assert C.grant_signup_reward(db, user, email) is None
    db.commit()
    assert C.get_balance_summary(db, user)["balance"] == 0
    assert db.query(models.CreditGrant).filter(
        models.CreditGrant.user_id == user).count() == 0
    assert db.query(models.CreditAccount).filter(
        models.CreditAccount.user_id == user).count() == 0
    assert db.query(models.CreditLedger).filter(
        models.CreditLedger.user_id == user).count() == 0
    assert db.query(models.SignupEligibility).filter(
        models.SignupEligibility.email_normalized == email).count() == 0


def test_pricing_and_signup_copy_have_no_free_credit_claim():
    pricing = (APP_DIR / "templates" / "pricing.html").read_text()
    signup = (APP_DIR / "templates" / "signup.html").read_text()
    for page in (pricing, signup):
        assert "10 free credits" not in page
        assert "3 free credits" not in page
        assert "free credits" not in page.lower()
    # The retirement is stated honestly on the Pricing page (FAQ).
    assert "new accounts no longer receive signup credits" in pricing


def test_pricing_exports_free_framing_not_credit_unlock():
    pricing = (APP_DIR / "templates" / "pricing.html").read_text()
    # Exports are free for all reports — no unlock is sold or priced.
    assert "Exports are free" in pricing
    assert "Nothing. Exports are free for all reports" in pricing
    assert "2 credits per report unlocks all formats" not in pricing
    assert "unlock" not in pricing.lower()
    assert "unlock" not in (APP_DIR / "templates" / "signup.html") \
        .read_text().lower()
