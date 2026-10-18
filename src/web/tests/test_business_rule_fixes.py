"""Regression tests for Codex business-rule findings on PR #17.

BR-01: zero eligible credits must return HTTP 402 (credit limit), not 503.
BR-02: verified OAuth signups must receive the 3-credit signup reward.
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from test_phase2a_regressions import env, quota
from app import auth as auth_helpers
from app import credits as C
from app import models as M
from app import oauth as oauth_helpers
from app.sample_data import SAMPLE_LOG


def test_zero_eligible_credits_returns_402(env):
    """BR-01: exhausted credits -> 402 credit-limit, not a 503 retry loop."""
    quota(env)
    with env.sessions() as db:
        for grant in db.query(M.CreditGrant).filter(M.CreditGrant.user_id == env.uid):
            grant.revoked_at = C._utcnow()
        db.commit()
    r = env.client.post(
        "/analyze",
        files={"file": ("test.log", SAMPLE_LOG.encode())},
        data={"request_id": uuid.uuid4().hex},
    )
    assert r.status_code == 402, f"expected 402, got {r.status_code}: {r.text[:300]}"


def test_oauth_signup_grants_three_credits(env, monkeypatch):
    """BR-02: a verified OAuth signup receives the 3-credit reward."""
    from app import auth_routes

    async def fake_exchange(code):
        return "fake-access-token"

    async def fake_get_user(access):
        return {"id": 987654321, "login": "br02user", "name": "BR02 User"}

    async def fake_get_email(access):
        return "br02-oauth@example.com"

    monkeypatch.setattr(oauth_helpers, "exchange_github_code", fake_exchange)
    monkeypatch.setattr(oauth_helpers, "get_github_user", fake_get_user)
    monkeypatch.setattr(
        oauth_helpers, "get_github_primary_verified_email", fake_get_email
    )

    state = auth_helpers.generate_token()
    binding = auth_helpers.generate_token()
    with env.sessions() as db:
        db.add(
            M.OAuthState(
                state_hash=auth_helpers.hash_token(state),
                binding_hash=auth_helpers.hash_token(binding),
                provider="github",
                action="login",
                session_id=None,
                nonce=auth_helpers.generate_token(),
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
            )
        )
        db.commit()

    env.client.cookies.set(auth_routes.OAUTH_COOKIE, binding)
    r = env.client.get(
        "/auth/github/callback", params={"code": "fake", "state": state}
    )
    assert r.status_code == 303, f"expected 303, got {r.status_code}: {r.text[:300]}"

    with env.sessions() as db:
        user = db.query(M.User).filter_by(email="br02-oauth@example.com").first()
        assert user is not None and user.email_verified
        assert C.get_balance_summary(db, user.id)["balance"] == 3


def test_oauth_repeat_login_grants_no_second_reward(env, monkeypatch):
    """BR-02: repeat OAuth logins and re-signups never double-grant."""
    from app import auth_routes

    async def fake_exchange(code):
        return "fake-access-token"

    async def fake_get_user(access):
        return {"id": 123456789, "login": "br02repeat", "name": "Repeat User"}

    async def fake_get_email(access):
        return "br02-repeat@example.com"

    monkeypatch.setattr(oauth_helpers, "exchange_github_code", fake_exchange)
    monkeypatch.setattr(oauth_helpers, "get_github_user", fake_get_user)
    monkeypatch.setattr(
        oauth_helpers, "get_github_primary_verified_email", fake_get_email
    )

    def do_callback():
        state = auth_helpers.generate_token()
        binding = auth_helpers.generate_token()
        with env.sessions() as db:
            db.add(
                M.OAuthState(
                    state_hash=auth_helpers.hash_token(state),
                    binding_hash=auth_helpers.hash_token(binding),
                    provider="github",
                    action="login",
                    session_id=None,
                    nonce=auth_helpers.generate_token(),
                    expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
                )
            )
            db.commit()
        env.client.cookies.set(auth_routes.OAUTH_COOKIE, binding)
        return env.client.get(
            "/auth/github/callback", params={"code": "fake", "state": state}
        )

    r1 = do_callback()
    assert r1.status_code == 303, r1.text[:200]
    # Second login with the same provider identity: no new reward.
    env.client.cookies.clear()
    r2 = do_callback()
    assert r2.status_code == 303, r2.text[:200]

    with env.sessions() as db:
        user = db.query(M.User).filter_by(email="br02-repeat@example.com").first()
        assert C.get_balance_summary(db, user.id)["balance"] == 3
# ci-trigger
