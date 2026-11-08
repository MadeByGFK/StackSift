"""Issue #156: D2 attribution instrumentation (MVP).

Sunny spec (2026-11-05): extend the #62 funnel with offer_viewed /
analysis_run / premium_intent (NOT in FUNNEL_LADDER), a first-party
d2_visitor_id cookie + first-touch d2_attribution cookie, a
POST /events/d2 beacon endpoint (analysis_run is server-only), an
identity merge into d2_visitor_links on signup/login/OAuth, server-side
premium_intent at checkout / export / Analysis Report attempt entry,
analysis_run at successful single-file + paid completions, and the
d2_summary report. Observe-only: no charge, balance, ledger, or
status-code behaviour changes anywhere.

Teeth: these tests FAIL on the pre-build tree (no d2_attribution
module, no D2VisitorLink model, no /events/d2 route, no cookies, no
new funnel events) and PASS on the built tree. The observe-only group
pins the pre-build money behaviour explicitly.
"""

import json
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlparse

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app import credits as C
from app import d2_attribution as d2
from app import funnel
from app import models
from app.db import Base

TEST_PASSWORD = "Correct Horse Battery Staple 9!"

PACK_PRICES = {
    "starter": "price_test_starter",
    "growth": "price_test_growth",
    "power": "price_test_power",
}


# --- fixtures ---------------------------------------------------------------

@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:",
                           connect_args={"check_same_thread": False})

    @event.listens_for(engine, "connect")
    def _fk(conn, _):
        conn.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)
    session = sessions()
    yield session
    session.close()
    engine.dispose()


@pytest.fixture
def user(db):
    uid = uuid.uuid4()
    db.add(models.User(id=uid, email=f"{uid.hex[:8]}@test.com",
                       email_verified=True))
    db.commit()
    return uid


def _make_user(db, email=None):
    uid = uuid.uuid4()
    db.add(models.User(id=uid, email=email or f"{uid.hex[:8]}@test.com",
                       email_verified=True))
    db.commit()
    return uid


@pytest.fixture
def route_env(tmp_path, monkeypatch):
    """HTTP env in the test_issue62_funnel.route_env mould, plus the
    SessionLocal patch emit_standalone needs and Stripe pack prices."""
    from fastapi.testclient import TestClient
    from sqlalchemy import event as sa_event

    import app.db as db_module
    from app import auth, email
    from app.db import Base as DbBase, get_db
    from app.main import app

    engine = create_engine(
        f"sqlite:///{tmp_path / 'd2.db'}",
        connect_args={"check_same_thread": False, "timeout": 20},
    )

    @sa_event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, _):
        connection.execute("PRAGMA foreign_keys=ON")

    DbBase.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)

    def override():
        with sessions() as session:
            yield session

    monkeypatch.setitem(app.dependency_overrides, get_db, override)
    monkeypatch.setattr(auth, "auth_limiter", auth.AuthRateLimiter())
    monkeypatch.setattr(auth, "check_password_breached", lambda _: False)
    monkeypatch.setattr(db_module, "SessionLocal", sessions)
    monkeypatch.setenv("DATABASE_URL", "sqlite://")
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_route_fixture")
    for pack_id, price in PACK_PRICES.items():
        monkeypatch.setenv(f"STRIPE_PRICE_{pack_id.upper()}", price)
    sent = []
    monkeypatch.setattr(
        email, "send_verification_email",
        lambda address, token: sent.append(("verify", address, token)))
    monkeypatch.setattr(
        email, "send_password_reset_email",
        lambda address, token: sent.append(("reset", address, token)))
    try:
        with TestClient(app, base_url="https://testserver") as client:
            client.headers["X-CSRF-Token"] = \
                client.get("/auth/csrf").json()["csrf_token"]
            yield SimpleNamespace(client=client, sessions=sessions,
                                  sent=sent, app=app, engine=engine)
    finally:
        engine.dispose()


# --- helpers ------------------------------------------------------------------

def _set_cookies(resp):
    return resp.headers.get_list("set-cookie")


def _cookie_header(resp, name):
    for header in _set_cookies(resp):
        if header.startswith(name + "="):
            return header
    return None


def _events_from_sessions(env, event_name, user_id=None, anon_id=None):
    with env.sessions() as session:
        q = session.query(models.FunnelEvent).filter(
            models.FunnelEvent.event == event_name)
        if user_id is not None:
            q = q.filter(models.FunnelEvent.user_id == user_id)
        if anon_id is not None:
            q = q.filter(models.FunnelEvent.anon_id == anon_id)
        rows = q.all()
        for row in rows:
            session.expunge(row)
        return rows


def _links(env):
    with env.sessions() as session:
        rows = session.query(models.D2VisitorLink).all()
        for row in rows:
            session.expunge(row)
        return rows


def _balance(env, user_id):
    with env.sessions() as session:
        return C.get_balance_summary(session, user_id)["balance"]


def _counts(env, user_id):
    """(ledger rows, purchase rows, operation rows) for a user."""
    with env.sessions() as session:
        ledger = session.query(models.CreditLedger).filter(
            models.CreditLedger.user_id == user_id).count()
        purchases = session.query(models.CreditPurchase).filter(
            models.CreditPurchase.user_id == user_id).count()
        ops = session.query(models.Operation).filter(
            models.Operation.user_id == user_id).count()
        return ledger, purchases, ops


def _set_visitor(client, visitor_id):
    client.cookies.set(d2.VISITOR_COOKIE, visitor_id)


# --- group 1: cookies ---------------------------------------------------------

def test_cookie_set_on_utm_landing(route_env):
    resp = route_env.client.get("/credits?utm_source=devto&utm_medium=post")
    assert resp.status_code == 200
    header = _cookie_header(resp, "d2_visitor_id")
    assert header is not None
    value = header.split(";", 1)[0].split("=", 1)[1]
    assert d2.valid_visitor_id(value) is not None
    assert "HttpOnly" in header
    assert "SameSite=lax" in header
    assert "Max-Age=15552000" in header  # 180 days
    assert _cookie_header(resp, "d2_attribution") is not None


def test_cookie_set_on_plain_landing_pages(route_env):
    for path in ("/", "/credits"):
        route_env.client.cookies.clear()
        resp = route_env.client.get(path)
        assert resp.status_code == 200
        assert _cookie_header(resp, "d2_visitor_id") is not None, path
        # No utm params -> no attribution cookie.
        assert _cookie_header(resp, "d2_attribution") is None, path


def test_cookie_persists_when_valid(route_env):
    vid = str(uuid.uuid4())
    _set_visitor(route_env.client, vid)
    resp = route_env.client.get("/credits?utm_source=devto")
    assert _cookie_header(resp, "d2_visitor_id") is None  # never overwritten
    assert route_env.client.cookies.get("d2_visitor_id") == vid


def test_cookie_malformed_value_replaced(route_env):
    _set_visitor(route_env.client, "not-a-uuid")
    resp = route_env.client.get("/credits")
    header = _cookie_header(resp, "d2_visitor_id")
    assert header is not None
    value = header.split(";", 1)[0].split("=", 1)[1]
    assert value != "not-a-uuid"
    assert d2.valid_visitor_id(value) is not None


def test_cookie_not_set_on_non_landing_or_api_requests(route_env):
    # HTML GET, but not a landing path and no utm params.
    resp = route_env.client.get("/login")
    assert resp.status_code == 200
    assert _cookie_header(resp, "d2_visitor_id") is None
    resp = route_env.client.get("/privacy")
    assert _cookie_header(resp, "d2_visitor_id") is None
    # Non-HTML (JSON) response.
    resp = route_env.client.get("/auth/csrf")
    assert _cookie_header(resp, "d2_visitor_id") is None
    # POST responses never set it either.
    resp = route_env.client.post("/events/d2", json={"event": "offer_viewed"})
    assert _cookie_header(resp, "d2_visitor_id") is None


def test_pricing_page_carries_offer_viewed_beacon(route_env):
    resp = route_env.client.get("/credits")
    assert resp.status_code == 200
    assert 'id="packs"' in resp.text
    assert "IntersectionObserver" in resp.text
    assert "offer_viewed" in resp.text
    assert "/events/d2" in resp.text
    assert "sendBeacon" in resp.text
    # Codex P2 remediation (PR #157): the observer must watch the
    # individual pack cards, not the #packs grid — at <=800px the grid
    # stacks taller than the viewport, so its ratio can never reach
    # 0.5 and offer_viewed would never fire on mobile.
    assert 'querySelectorAll(".pack")' in resp.text
    assert "observer.observe(card)" in resp.text
    assert "observer.observe(packs)" not in resp.text
    # Codex P2 remediation round 2 (PR #157): the >=1s continuous
    # visibility interval is tracked PER CARD (_d2timer on the card
    # element). A shared timer/counter would keep running while any
    # card qualifies, firing the beacon although no single card was
    # >=50% visible continuously for 1s.
    assert "_d2timer" in resp.text
    assert "qualifying" not in resp.text


# --- group 10 (cookie half): attribution caps ---------------------------------

def test_attribution_truncation_and_referrer_host_only():
    long_value = "x" * 300
    params = {"utm_source": long_value, "utm_medium": "post",
              "utm_campaign": long_value}
    attribution = d2.build_attribution(
        params, "https://dev.to/some/article?ref=secret")
    assert attribution["utm_source"] == "x" * 128
    assert attribution["utm_campaign"] == "x" * 128
    assert attribution["referrer_host"] == "dev.to"
    assert "secret" not in json.dumps(attribution)
    assert "/some/article" not in json.dumps(attribution)
    # The cookie parser re-truncates server-side too.
    raw = json.dumps({"utm_source": long_value, "email": "a@b.c",
                      "referrer_host": "dev.to"})
    parsed = d2.parse_attribution_cookie(raw)
    assert parsed == {"utm_source": "x" * 128, "referrer_host": "dev.to"}
    assert d2.parse_attribution_cookie("not json") == {}
    assert d2.parse_attribution_cookie('{"utm_source": 5}') == {}


def test_attribution_cookie_route_level_and_first_touch_wins(route_env):
    from http.cookies import SimpleCookie

    resp = route_env.client.get(
        "/credits?utm_source=" + "y" * 200,
        headers={"Referer": "https://dev.to/post/123"})
    header = _cookie_header(resp, "d2_attribution")
    assert header is not None
    jar = SimpleCookie()
    jar.load(header)
    raw = jar["d2_attribution"].value  # unquoted by the cookie parser
    parsed = json.loads(raw)
    assert parsed["utm_source"] == "y" * 128
    assert parsed["referrer_host"] == "dev.to"
    # First touch wins: a later landing with different utm params does
    # not rewrite the attribution cookie.
    route_env.client.cookies.clear()
    route_env.client.cookies.set("d2_attribution", raw)
    resp2 = route_env.client.get("/credits?utm_source=other")
    assert _cookie_header(resp2, "d2_attribution") is None


# --- group 2: /events/d2 records offer_viewed ---------------------------------

def _post_event(client, payload):
    return client.post("/events/d2", json=payload)


def test_endpoint_records_offer_viewed_with_server_side_meta(route_env):
    vid = str(uuid.uuid4())
    _set_visitor(route_env.client, vid)
    route_env.client.cookies.set(
        "d2_attribution",
        json.dumps({"utm_source": "devto", "utm_medium": "post"}))
    resp = _post_event(route_env.client, {
        "event": "offer_viewed",
        # Client-supplied attribution / meta must never be trusted.
        "utm_source": "FORGED", "email": "victim@example.com",
        "meta": {"utm_source": "FORGED", "log_text": "secret log"},
    })
    assert resp.status_code == 204
    rows = _events_from_sessions(route_env, funnel.OFFER_VIEWED, anon_id=vid)
    assert len(rows) == 1
    assert rows[0].user_id is None
    assert rows[0].meta == {"utm_source": "devto", "utm_medium": "post"}


def test_endpoint_records_once_per_post(route_env):
    vid = str(uuid.uuid4())
    _set_visitor(route_env.client, vid)
    for _ in range(2):
        assert _post_event(route_env.client,
                           {"event": "offer_viewed"}).status_code == 204
    rows = _events_from_sessions(route_env, funnel.OFFER_VIEWED, anon_id=vid)
    assert len(rows) == 2


def test_endpoint_client_premium_intent_kind_allowlist(route_env):
    vid = str(uuid.uuid4())
    _set_visitor(route_env.client, vid)
    assert _post_event(route_env.client, {
        "event": "premium_intent", "kind": "checkout_start"}).status_code == 204
    assert _post_event(route_env.client, {
        "event": "premium_intent", "kind": "bogus_kind"}).status_code == 204
    rows = _events_from_sessions(route_env, funnel.PREMIUM_INTENT, anon_id=vid)
    assert len(rows) == 2
    kinds = [(row.meta or {}).get("kind") for row in rows]
    assert "checkout_start" in kinds
    assert "bogus_kind" not in kinds


# --- group 3: endpoint ignores forgery / identity-less -------------------------

def test_endpoint_ignores_client_claimed_analysis_run(route_env):
    vid = str(uuid.uuid4())
    _set_visitor(route_env.client, vid)
    resp = _post_event(route_env.client, {"event": "analysis_run"})
    assert resp.status_code == 204
    assert _events_from_sessions(route_env, funnel.ANALYSIS_RUN) == []
    # Unknown events are ignored the same way (no oracle).
    resp = _post_event(route_env.client, {"event": "purchase_success"})
    assert resp.status_code == 204
    assert _events_from_sessions(route_env, funnel.PURCHASE_SUCCESS) == []


def test_endpoint_ignores_identityless_posts(route_env):
    route_env.client.cookies.clear()
    resp = _post_event(route_env.client, {"event": "offer_viewed"})
    assert resp.status_code == 204
    assert _events_from_sessions(route_env, funnel.OFFER_VIEWED) == []


def test_endpoint_malformed_json_is_204_no_row(route_env):
    vid = str(uuid.uuid4())
    _set_visitor(route_env.client, vid)
    resp = route_env.client.post(
        "/events/d2", content=b"{not json",
        headers={"Content-Type": "application/json"})
    assert resp.status_code == 204
    assert _events_from_sessions(route_env, funnel.OFFER_VIEWED) == []


# --- group 4: identity merge ----------------------------------------------------

def test_link_visitor_first_merge_wins_unit(db, user):
    other = _make_user(db)
    vid = str(uuid.uuid4())
    assert d2.link_visitor(db, vid, user) is True
    db.commit()
    assert d2.link_visitor(db, vid, user) is True  # same-user idempotent
    db.commit()
    assert d2.link_visitor(db, vid, other) is False  # never stolen
    db.commit()
    rows = db.query(models.D2VisitorLink).all()
    assert len(rows) == 1
    assert str(rows[0].user_id) == str(user)
    assert rows[0].visitor_id == vid
    assert d2.link_visitor(db, "not-a-uuid", user) is False
    assert d2.link_visitor(db, str(uuid.uuid4()), None) is False


def test_signup_with_cookie_creates_exactly_one_link(route_env):
    from app.models import User

    vid = str(uuid.uuid4())
    _set_visitor(route_env.client, vid)
    resp = route_env.client.post(
        "/auth/signup",
        data={"email": "d2signup@example.com", "password": TEST_PASSWORD})
    assert resp.status_code == 200, resp.text
    links = _links(route_env)
    assert len(links) == 1
    assert links[0].visitor_id == vid
    with route_env.sessions() as session:
        created = session.query(User).filter(
            User.email == "d2signup@example.com").one()
        assert str(links[0].user_id) == str(created.id)


def test_signup_existing_unverified_account_does_not_link_visitor(route_env):
    """Codex P2 remediation (PR #157): the existing-unverified signup
    path never checks the submitted password against the stored hash,
    so it must NOT merge the caller's visitor cookie — otherwise anyone
    who knows an unverified account's email could permanently attach
    their visitor history to it (first-merge-wins would also block the
    real owner's later merge). Response behaviour is unchanged."""
    # Owner signs up (no visitor cookie): creates an UNVERIFIED account.
    resp = route_env.client.post(
        "/auth/signup",
        data={"email": "d2owner@example.com", "password": TEST_PASSWORD})
    assert resp.status_code == 200, resp.text
    assert _links(route_env) == []
    # Attacker re-submits signup for the same email with THEIR visitor
    # cookie and a different (never verified) password.
    attacker_vid = str(uuid.uuid4())
    _set_visitor(route_env.client, attacker_vid)
    resp = route_env.client.post(
        "/auth/signup",
        data={"email": "d2owner@example.com",
              "password": "An0ther!Passw0rd"})
    assert resp.status_code == 200, resp.text  # generic response unchanged
    assert _links(route_env) == []  # no link created for the attacker


def test_login_remerge_idempotent(route_env):
    from test_phase2b_reports_pdf import _login, _signup_and_verify

    vid = str(uuid.uuid4())
    _set_visitor(route_env.client, vid)
    email, user_id = _signup_and_verify(route_env)
    assert len(_links(route_env)) == 1  # merged at signup
    resp = _login(route_env, email)
    assert resp.status_code == 200, resp.text
    links = _links(route_env)
    assert len(links) == 1
    assert str(links[0].user_id) == str(user_id)


def test_different_user_login_does_not_steal_link(route_env):
    from test_phase2b_reports_pdf import _login, _signup_and_verify

    vid = str(uuid.uuid4())
    _set_visitor(route_env.client, vid)
    email_a, user_a = _signup_and_verify(route_env)
    assert len(_links(route_env)) == 1
    # Second user logs in presenting the SAME visitor cookie.
    email_b, user_b = _signup_and_verify(route_env)
    resp = _login(route_env, email_b)
    assert resp.status_code == 200, resp.text
    links = _links(route_env)
    assert len(links) == 1
    assert str(links[0].user_id) == str(user_a)


def test_oauth_callback_links_visitor(route_env, monkeypatch):
    from app import oauth

    for setting in ("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"):
        monkeypatch.setattr(oauth, setting, "test-only")
    monkeypatch.setattr(oauth, "exchange_google_code",
                        AsyncMock(return_value={"id_token": "mock"}))
    monkeypatch.setattr(oauth, "get_google_identity", AsyncMock(
        return_value={"sub": "123", "email": "d2oauth@example.com",
                      "email_verified": True}))
    vid = str(uuid.uuid4())
    _set_visitor(route_env.client, vid)
    start = route_env.client.get("/auth/google", follow_redirects=False)
    assert start.status_code == 303, start.text
    state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
    resp = route_env.client.get(
        "/auth/google/callback", params={"state": state, "code": "test"},
        follow_redirects=False)
    assert resp.status_code == 303, resp.text
    links = _links(route_env)
    assert len(links) == 1
    assert links[0].visitor_id == vid
    with route_env.sessions() as session:
        created = session.query(models.User).filter(
            models.User.email == "d2oauth@example.com").one()
        assert str(links[0].user_id) == str(created.id)


# --- groups 5+6: premium_intent hooks, observe-only -----------------------------

def _login62(env, email="d2buyer@example.com"):
    """test_issue62_funnel._login pattern: signup, verify, login."""
    from app.models import User

    c = env.client
    assert c.post("/auth/signup", data={
        "email": email, "password": TEST_PASSWORD}).status_code == 200
    with env.sessions() as session:
        u = session.query(User).filter(User.email == email).first()
        u.email_verified = True
        session.commit()
        user_id = u.id
    c.headers["X-CSRF-Token"] = c.get("/auth/csrf").json()["csrf_token"]
    resp = c.post("/auth/login", data={"email": email, "password": TEST_PASSWORD})
    assert resp.status_code == 200, resp.text
    return user_id, resp.json()["csrf_token"]


def _mock_stripe_ok(monkeypatch, captured=None):
    from app import stripe_billing

    class _FakeResp:
        status_code = 200

        def json(self):
            return {"id": "cs_test_123",
                    "url": "https://checkout.stripe.com/pay/cs_test_123"}

    monkeypatch.setattr(
        stripe_billing.httpx, "post",
        lambda url, data=None, auth=None, headers=None, timeout=None: (
            (captured.append(url) if captured is not None else None)
            or _FakeResp()))


def test_premium_intent_checkout_attempt(route_env, monkeypatch):
    user_id, csrf = _login62(route_env)
    vid = str(uuid.uuid4())
    _set_visitor(route_env.client, vid)
    _mock_stripe_ok(monkeypatch)
    before = _counts(route_env, user_id)
    balance_before = _balance(route_env, user_id)
    resp = route_env.client.post(
        "/credits/checkout", data={"pack_id": "growth", "csrf_token": csrf})
    assert resp.status_code == 200, resp.text
    rows = _events_from_sessions(
        route_env, funnel.PREMIUM_INTENT, user_id=user_id)
    assert len(rows) == 1
    assert rows[0].meta["kind"] == "checkout_start"
    assert rows[0].anon_id == vid
    # Pre-existing behaviour unchanged: PURCHASE_START still fires and
    # the only new money row is the checkout's own pending purchase.
    assert len(_events_from_sessions(
        route_env, funnel.PURCHASE_START, user_id=user_id)) == 1
    ledger, purchases, ops = _counts(route_env, user_id)
    assert (ledger, ops) == (before[0], before[2])
    assert purchases == before[1] + 1
    assert _balance(route_env, user_id) == balance_before


def test_premium_intent_checkout_failure_observe_only(route_env, monkeypatch):
    from app import stripe_billing

    user_id, csrf = _login62(route_env, "d2fail@example.com")
    balance_before = _balance(route_env, user_id)
    ledger_before, _, _ = _counts(route_env, user_id)

    def _boom(url, data=None, auth=None, headers=None, timeout=None):
        raise stripe_billing.CheckoutError("stripe down")

    monkeypatch.setattr(stripe_billing.httpx, "post", _boom)
    resp = route_env.client.post(
        "/credits/checkout", data={"pack_id": "growth", "csrf_token": csrf})
    # Pre-build behaviour for a Stripe failure is a 503 — unchanged.
    assert resp.status_code == 503, resp.text
    rows = _events_from_sessions(
        route_env, funnel.PREMIUM_INTENT, user_id=user_id)
    assert len(rows) == 1 and rows[0].meta["kind"] == "checkout_start"
    assert _balance(route_env, user_id) == balance_before
    ledger_after, purchases_after, _ = _counts(route_env, user_id)
    assert ledger_after == ledger_before
    # The pending purchase row is the checkout's own pre-build record.
    assert purchases_after == 1
    with route_env.sessions() as session:
        purchase = session.query(models.CreditPurchase).filter(
            models.CreditPurchase.user_id == user_id).one()
        assert purchase.status == "pending"


def test_premium_intent_export_and_observe_only(route_env):
    from test_structured_export_e2e import _setup

    _, user_id, rid, csrf = _setup(route_env)
    before_balance = _balance(route_env, user_id)
    resp = route_env.client.post(
        f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert resp.status_code == 200, resp.text[:300]
    rows = _events_from_sessions(
        route_env, funnel.PREMIUM_INTENT, user_id=user_id)
    assert len(rows) == 1 and rows[0].meta["kind"] == "export_unlock"
    # Observe-only: the export's own ruled charge is the ONLY change.
    assert _balance(route_env, user_id) == before_balance - 2
    ledger1, purchases1, ops1 = _counts(route_env, user_id)
    assert purchases1 == 0
    # Second export of the unlocked report: free re-download, no new
    # operation or ledger rows — but premium_intent still records.
    resp2 = route_env.client.post(
        f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert resp2.status_code == 200
    assert _balance(route_env, user_id) == before_balance - 2
    assert _counts(route_env, user_id) == (ledger1, purchases1, ops1)
    rows = _events_from_sessions(
        route_env, funnel.PREMIUM_INTENT, user_id=user_id)
    assert len(rows) == 2


def test_premium_intent_export_insufficient_balance_402(route_env):
    from test_structured_export_e2e import _drain_signup, _setup

    _, user_id, rid, csrf = _setup(route_env, extra_credits=0)
    _drain_signup(route_env, user_id, 10)
    assert _balance(route_env, user_id) == 0
    before = _counts(route_env, user_id)
    resp = route_env.client.post(
        f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert resp.status_code == 402, resp.text[:300]
    rows = _events_from_sessions(
        route_env, funnel.PREMIUM_INTENT, user_id=user_id)
    assert len(rows) == 1 and rows[0].meta["kind"] == "export_unlock"
    # Observe-only on the blocked attempt: nothing charged or reserved.
    assert _balance(route_env, user_id) == 0
    assert _counts(route_env, user_id) == before


def test_premium_intent_structured_export_and_observe_only(route_env):
    # Codex P2 (PR #157 round 2): CSV/JSON first exports perform the
    # same paid per-report unlock as PDF, so they must record the
    # same premium_intent — otherwise the funnel depends on format.
    from test_structured_export_e2e import _setup

    _, user_id, rid, csrf = _setup(route_env)
    before_balance = _balance(route_env, user_id)
    resp = route_env.client.post(
        f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    assert resp.status_code == 200, resp.text[:300]
    rows = _events_from_sessions(
        route_env, funnel.PREMIUM_INTENT, user_id=user_id)
    assert len(rows) == 1 and rows[0].meta["kind"] == "export_unlock"
    # Observe-only: the export's own ruled charge is the ONLY change.
    assert _balance(route_env, user_id) == before_balance - 2
    ledger1, purchases1, ops1 = _counts(route_env, user_id)
    assert purchases1 == 0
    # Second format of the unlocked report: free, no new money rows —
    # but premium_intent still records.
    resp2 = route_env.client.post(
        f"/reports/{rid}/exports/json", data={"csrf_token": csrf})
    assert resp2.status_code == 200, resp2.text[:300]
    assert _balance(route_env, user_id) == before_balance - 2
    assert _counts(route_env, user_id) == (ledger1, purchases1, ops1)
    rows = _events_from_sessions(
        route_env, funnel.PREMIUM_INTENT, user_id=user_id)
    assert len(rows) == 2


def test_premium_intent_structured_export_insufficient_balance_402(route_env):
    from test_structured_export_e2e import _drain_signup, _setup

    _, user_id, rid, csrf = _setup(route_env, extra_credits=0)
    _drain_signup(route_env, user_id, 10)
    assert _balance(route_env, user_id) == 0
    before = _counts(route_env, user_id)
    resp = route_env.client.post(
        f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    assert resp.status_code == 402, resp.text[:300]
    rows = _events_from_sessions(
        route_env, funnel.PREMIUM_INTENT, user_id=user_id)
    assert len(rows) == 1 and rows[0].meta["kind"] == "export_unlock"
    # Observe-only on the blocked attempt: nothing charged or reserved.
    assert _balance(route_env, user_id) == 0
    assert _counts(route_env, user_id) == before


def test_premium_intent_analysis_report_success_and_402(route_env):
    from test_deep_dive_paid import _custom_result, _eligible_payload
    from test_structured_export_e2e import (
        _drain_signup, _session_csrf, _setup)

    # PREMISE CHANGED (#164 Phase A, A10: dollar-product): the
    # success path redeems a $9 entitlement — premium_intent still
    # fires exactly once at attempt entry and NO credit state moves
    # (the event is observe-only; the dollar charge is not a credit
    # charge). The blocked path is now "no entitlement" (402 to the
    # product checkout), independent of the credit balance.
    from product_seed import seed_entitlement_for_source
    _, user_id, rid, csrf = _setup(route_env)
    before = _balance(route_env, user_id)
    seed_entitlement_for_source(route_env.sessions, rid)
    resp = route_env.client.post(
        f"/reports/{rid}/deep-dive", data={"csrf_token": csrf})
    assert resp.status_code == 200, resp.text[:300]
    assert _balance(route_env, user_id) == before  # no credit movement
    rows = _events_from_sessions(
        route_env, funnel.PREMIUM_INTENT, user_id=user_id)
    assert len(rows) == 1 and rows[0].meta["kind"] == "analysis_report"

    # Blocked (402) path on a second eligible report: no entitlement
    # held (the drained 0 balance is incidental — credits no longer
    # gate this route at any balance).
    _, user2, rid2, csrf2 = _setup(route_env, extra_credits=0)
    _drain_signup(route_env, user2, 10)
    assert _balance(route_env, user2) == 0
    rid3 = _custom_result(route_env, user2, _eligible_payload())
    csrf3 = _session_csrf(route_env)
    before_counts = _counts(route_env, user2)
    resp = route_env.client.post(
        f"/reports/{rid3}/deep-dive", data={"csrf_token": csrf3})
    assert resp.status_code == 402, resp.text[:300]
    rows = _events_from_sessions(
        route_env, funnel.PREMIUM_INTENT, user_id=user2)
    assert len(rows) == 1 and rows[0].meta["kind"] == "analysis_report"
    assert _balance(route_env, user2) == 0
    assert _counts(route_env, user2) == before_counts


# --- group 7: analysis_run -------------------------------------------------------
# Uses the migrated-DB env from test_phase2a_regressions (real analyze
# stubbed to a deep copy of a real report, like the paid e2e suite).

from test_account_migrations import migrated_engine  # noqa: F401,E402
from test_phase2a_regressions import env, quota, quote  # noqa: F401,E402
from app import main  # noqa: E402
from app.sample_data import SAMPLE_LOG  # noqa: E402


def _analysis_rows(env, event_name, user_id=None):
    with env.sessions() as session:
        q = session.query(models.FunnelEvent).filter(
            models.FunnelEvent.event == event_name)
        if user_id is not None:
            q = q.filter(models.FunnelEvent.user_id == user_id)
        rows = q.all()
        for row in rows:
            session.expunge(row)
        return rows


def _fresh_upload(env, content, filename="test.log"):
    return env.client.post(
        "/analyze",
        files={"file": (filename, content)},
        data={"request_id": uuid.uuid4().hex, "output": "html"})


def test_analysis_run_free_success_and_analysis_first_unchanged(env):
    resp = _fresh_upload(env, SAMPLE_LOG.encode())
    assert resp.status_code == 200, resp.text[:300]
    rows = _analysis_rows(env, funnel.ANALYSIS_RUN, env.uid)
    assert len(rows) == 1
    assert rows[0].meta["kind"] == "free"
    # A second, distinct successful upload: analysis_run counts EVERY
    # completion, while ANALYSIS_FIRST stays once-per-identity.
    resp2 = _fresh_upload(env, SAMPLE_LOG.encode(), filename="second.log")
    assert resp2.status_code == 200, resp2.text[:300]
    assert len(_analysis_rows(env, funnel.ANALYSIS_RUN, env.uid)) == 2
    assert len(_analysis_rows(env, funnel.ANALYSIS_FIRST, env.uid)) == 1


def test_analysis_run_paid_success(env):
    quota(env)
    form = quote(env)
    resp = env.client.post("/analyze/paid", data=form)
    assert resp.status_code == 200, resp.text[:300]
    rows = _analysis_rows(env, funnel.ANALYSIS_RUN, env.uid)
    assert len(rows) == 1
    assert rows[0].meta["kind"] == "paid"


def test_analysis_run_none_on_failed_analysis(env, monkeypatch):
    quota(env)
    form = quote(env)
    monkeypatch.setattr(
        main, "analyze_upload",
        lambda *a: {"error": True, "message": "bad log"})
    resp = env.client.post("/analyze/paid", data=form)
    assert resp.status_code == 400, resp.text[:300]
    assert _analysis_rows(env, funnel.ANALYSIS_RUN, env.uid) == []
    assert _analysis_rows(env, funnel.ANALYSIS_FIRST, env.uid) == []


# --- group 8: d2_summary ------------------------------------------------------------

def _purchase(db, user_id, status, *, completed_at=None, created_at=None):
    now = datetime.now(timezone.utc)
    row = models.CreditPurchase(
        user_id=user_id, pack_id="starter", credits=10,
        amount_cents=500 if status == "completed" else None,
        currency="usd" if status == "completed" else None,
        pricing_version=1, status=status,
        created_at=created_at or now,
        completed_at=completed_at if completed_at is not None
        else (now if status == "completed" else None),
    )
    db.add(row)
    db.commit()
    return row


def test_d2_summary_dedup_and_buyers(db, user):
    other = _make_user(db)
    third = _make_user(db)
    v1, v2 = str(uuid.uuid4()), str(uuid.uuid4())
    # One visitor views three times (two pre-merge anon, one merged),
    # a second visitor once.
    funnel.record(db, funnel.OFFER_VIEWED, anon_id=v1)
    funnel.record(db, funnel.OFFER_VIEWED, anon_id=v1)
    funnel.record(db, funnel.OFFER_VIEWED, anon_id=v2)
    assert d2.link_visitor(db, v1, user)
    db.commit()
    funnel.record(db, funnel.OFFER_VIEWED, user_id=user, anon_id=v1)
    funnel.record(db, funnel.ANALYSIS_RUN, user_id=user)
    funnel.record(db, funnel.ANALYSIS_RUN, user_id=user)
    funnel.record(db, funnel.PREMIUM_INTENT, anon_id=v1,
                  meta={"kind": "checkout_start"})
    funnel.record(db, funnel.PREMIUM_INTENT, anon_id=v1,
                  meta={"kind": "checkout_start"})
    funnel.record(db, funnel.PREMIUM_INTENT, user_id=other,
                  meta={"kind": "export_unlock"})
    db.commit()
    # The linked+exposed buyer: their view precedes completion.
    view = db.query(models.FunnelEvent).filter(
        models.FunnelEvent.event == funnel.OFFER_VIEWED,
        models.FunnelEvent.anon_id == v1).first()
    view.occurred_at = datetime.now(timezone.utc) - timedelta(hours=2)
    db.commit()
    _purchase(db, user, "completed")
    _purchase(db, other, "completed")       # unlinked buyer
    _purchase(db, third, "pending")         # never counts
    _purchase(db, third, "failed")          # never counts

    report = d2.d2_summary(db, days=30)
    assert report["offer_viewed"] == {"total": 4, "uniques": 2}
    assert report["analysis_run"] == {"total": 2, "uniques": 1}
    assert report["premium_intent"]["total"] == 3
    assert report["premium_intent"]["uniques"] == 2
    assert report["premium_intent"]["kinds"] == {
        "checkout_start": 2, "export_unlock": 1}
    assert report["buyers_total"] == 2
    assert report["buyers_from_exposed"] == 1


def test_d2_summary_authenticated_identity_wins_over_visitor_link(db, user):
    # Codex P2 (PR #157 round 2): two accounts share one browser.
    # The visitor is linked to `user` (first account); the second
    # account's events carry their own authenticated user_id alongside
    # the same anon_id. Those events are the SECOND account's — they
    # must not collapse into the first account's uniques, and must not
    # qualify the first account's purchase as exposed.
    other = _make_user(db)
    v = str(uuid.uuid4())
    assert d2.link_visitor(db, v, user)
    db.commit()
    funnel.record(db, funnel.OFFER_VIEWED, user_id=other, anon_id=v)
    funnel.record(db, funnel.PREMIUM_INTENT, user_id=other, anon_id=v,
                  meta={"kind": "export_unlock"})
    funnel.record(db, funnel.OFFER_VIEWED, anon_id=v)  # anonymous: link applies
    db.commit()
    for row in db.query(models.FunnelEvent).all():
        row.occurred_at = datetime.now(timezone.utc) - timedelta(hours=2)
    db.commit()
    _purchase(db, user, "completed")

    report = d2.d2_summary(db, days=30)
    # Uniques: the anonymous event keys to `user` via the link; the
    # authenticated event keys to `other` — two distinct people.
    assert report["offer_viewed"] == {"total": 2, "uniques": 2}
    assert report["premium_intent"]["uniques"] == 1
    # Exposure: only the anonymous/linked view can qualify `user`;
    # delete it in a second pass below would change this — here the
    # anonymous view DOES qualify, so exposed == 1 via the anon event.
    assert report["buyers_from_exposed"] == 1
    # Remove the anonymous view: now only `other`'s authenticated view
    # remains on this visitor, and it must NOT expose `user`.
    db.query(models.FunnelEvent).filter(
        models.FunnelEvent.event == funnel.OFFER_VIEWED,
        models.FunnelEvent.user_id.is_(None)).delete()
    db.commit()
    report = d2.d2_summary(db, days=30)
    assert report["offer_viewed"] == {"total": 1, "uniques": 1}
    assert report["buyers_from_exposed"] == 0


def test_d2_summary_view_after_purchase_is_not_exposure(db, user):
    v = str(uuid.uuid4())
    assert d2.link_visitor(db, v, user)
    completed = datetime.now(timezone.utc) - timedelta(hours=1)
    _purchase(db, user, "completed", completed_at=completed)
    funnel.record(db, funnel.OFFER_VIEWED, anon_id=v)  # viewed AFTER buying
    db.commit()
    report = d2.d2_summary(db, days=30)
    assert report["buyers_total"] == 1
    assert report["buyers_from_exposed"] == 0


def test_d2_summary_window_excludes_old_events(db, user):
    funnel.record(db, funnel.OFFER_VIEWED, user_id=user)
    row = db.query(models.FunnelEvent).one()
    row.occurred_at = datetime.now(timezone.utc) - timedelta(days=90)
    db.commit()
    report = d2.d2_summary(db, days=30)
    assert report["offer_viewed"] == {"total": 0, "uniques": 0}
    assert report["buyers_total"] == 0


# --- group 9: failure isolation ------------------------------------------------------

def test_failure_isolation_credits_checkout_and_endpoint(route_env, monkeypatch):
    def _boom(*args, **kwargs):
        raise RuntimeError("funnel store down")

    monkeypatch.setattr(funnel, "record", _boom)
    # The offer page still renders.
    resp = route_env.client.get("/credits")
    assert resp.status_code == 200
    # The beacon endpoint still answers 204.
    vid = str(uuid.uuid4())
    _set_visitor(route_env.client, vid)
    assert _post_event(route_env.client,
                       {"event": "offer_viewed"}).status_code == 204
    # Checkout still succeeds end to end.
    user_id, csrf = _login62(route_env, "d2iso@example.com")
    _mock_stripe_ok(monkeypatch)
    resp = route_env.client.post(
        "/credits/checkout", data={"pack_id": "growth", "csrf_token": csrf})
    assert resp.status_code == 200, resp.text


def test_failure_isolation_analysis(env, monkeypatch):
    def _boom(*args, **kwargs):
        raise RuntimeError("funnel store down")

    monkeypatch.setattr(funnel, "record", _boom)
    resp = _fresh_upload(env, SAMPLE_LOG.encode())
    assert resp.status_code == 200, resp.text[:300]


# --- migration -------------------------------------------------------------------------

def test_migration_creates_d2_visitor_links(migrated_engine):
    from sqlalchemy import inspect

    engine, _ = migrated_engine
    names = inspect(engine).get_table_names()
    assert "d2_visitor_links" in names
    columns = {c["name"] for c in
               inspect(engine).get_columns("d2_visitor_links")}
    assert columns == {"visitor_id", "user_id", "first_seen_at", "merged_at"}
