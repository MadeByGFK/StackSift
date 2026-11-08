"""Issue #164 Phase A: per-product dollar purchase/entitlement engine.

Spec v1 as amended by spec v2 (A1-A11) + founder rulings F1-F5.
Groups mirror the spec's Tests section:
 1 SKU catalog + fail-closed    2 checkout creation (A7/F1)
 3 webhook settlement (A3/A4)   4 redemption (A1/F2)
 5 replay (A2/A6)               6 retention (90d)
 7 exports free (A9c)           8 expiry edges (F5)
 9 branding (#163 on dollar)    10 reconciliation (A8)
 11 no-credit invariant sweep
Plus A5/F3 refund-dispute machinery and A1 recovery races.

These tests FAIL on the base tree (no product tables, no product
routes, credit-only deep-dive) and PASS on the built tree. PostgreSQL
concurrency legs skip without TEST_POSTGRES_URL, mirroring
test_batch_postgres_concurrency.
"""
import hashlib
import hmac
import json
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

TEST_PASSWORD = "TestPass123!x"
WEBHOOK_SECRET = "whsec_test_164"
PRICE_ID = "price_test_investigation"


@pytest.fixture
def p164_env(tmp_path, monkeypatch):
    from app import auth, email
    from app.db import Base, get_db
    import app.db as db_module
    from app.main import app
    engine = create_engine(
        f"sqlite:///{tmp_path / 'p164.db'}",
        connect_args={"check_same_thread": False, "timeout": 20})

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
    monkeypatch.setenv("DATABASE_URL", "sqlite:///test")
    monkeypatch.setenv("STRIPE_PRICE_INVESTIGATION_REPORT", PRICE_ID)
    monkeypatch.setenv("STRIPE_PRICE_STARTER", "price_test_starter")
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_164_fixture")
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", WEBHOOK_SECRET)
    sent = []
    monkeypatch.setattr(email, "send_verification_email",
                        lambda a, t: sent.append(("verify", a, t)))
    monkeypatch.setattr(email, "send_password_reset_email",
                        lambda a, t: sent.append(("reset", a, t)))
    try:
        with TestClient(app, base_url="https://testserver") as client:
            client.headers["X-CSRF-Token"] = client.get("/auth/csrf").json()["csrf_token"]
            yield SimpleNamespace(client=client, sessions=sessions, sent=sent,
                                  engine=engine, app=app)
    finally:
        engine.dispose()


def _make_user(p164_env, email=None):
    from app.models import User
    email = email or f"u{uuid.uuid4().hex[:8]}@example.com"
    c = p164_env.client
    c.post("/auth/logout")
    c.headers["X-CSRF-Token"] = c.get("/auth/csrf").json()["csrf_token"]
    assert c.post("/auth/signup", data={"email": email, "password": TEST_PASSWORD}).status_code == 200
    with p164_env.sessions() as db:
        u = db.query(User).filter(User.email == email).first()
        u.email_verified = True
        db.commit()
        user_id = u.id
    c.headers["X-CSRF-Token"] = c.get("/auth/csrf").json()["csrf_token"]
    resp = c.post("/auth/login", data={"email": email, "password": TEST_PASSWORD})
    assert resp.status_code == 200, resp.text
    return email, user_id, resp.json()["csrf_token"]


def _source(p164_env, user_id):
    from test_phase2b_reports_pdf import _create_result
    return _create_result(p164_env, user_id)


def _fake_stripe(monkeypatch, captured):
    import httpx
    state = {"n": 0}

    class Resp:
        def __init__(self, payload):
            self.status_code = 200
            self._payload = payload

        def json(self):
            return self._payload

    def _post(url, data=None, auth=None, headers=None, timeout=None):
        captured.append({"url": url, "data": data, "headers": headers})
        state["n"] += 1
        sid = f"cs_test_{state['n']}"
        return Resp({"url": f"https://checkout.stripe.com/pay/{sid}", "id": sid})

    monkeypatch.setattr(httpx, "post", _post)
    return state


def _sign(payload: bytes, secret=WEBHOOK_SECRET, ts=None):
    ts = ts if ts is not None else int(time.time())
    sig = hmac.new(secret.encode(), f"{ts}.".encode() + payload, hashlib.sha256).hexdigest()
    return f"t={ts},v1={sig}"


def _post_event(p164_env, event_dict):
    raw = json.dumps(event_dict).encode()
    return p164_env.client.post(
        "/credits/webhook", content=raw,
        headers={"stripe-signature": _sign(raw), "content-type": "application/json"})


# P1-1 remediation: a REAL checkout.session.completed event carries
# NEITHER line_items NOR a price id on the session object. The event
# builder below therefore has no line_items; the Price ID reaches
# settlement only through the stubbed Stripe API retrieval
# (GET /checkout/sessions/{id}/line_items), whose returned price is
# controlled via _LINE_PRICE.
_LINE_PRICE = {"id": PRICE_ID}


@pytest.fixture(autouse=True)
def _stub_line_item_retrieval(monkeypatch):
    import httpx
    _LINE_PRICE["id"] = PRICE_ID

    class Resp:
        status_code = 200

        def json(self):
            if _LINE_PRICE["id"] is None:
                return {"data": []}
            return {"data": [{"price": {"id": _LINE_PRICE["id"]}}]}

    def _get(url, params=None, auth=None, headers=None, timeout=None):
        assert "/checkout/sessions/" in url and url.endswith("/line_items"), url
        return Resp()

    monkeypatch.setattr(httpx, "get", _get)


def _product_completed_event(event_id, purchase, *, session_id="cs_test_1",
                             amount=900, currency="usd", pi="pi_test_1",
                             payment_status="paid", status="complete",
                             mode="payment", price_id=PRICE_ID, kind="product",
                             sku="investigation_report", version=1):
    # price_id is accepted for call-site compatibility but is NO
    # LONGER placed in the event (Stripe does not send it); tests
    # steer the API-retrieved price via _LINE_PRICE instead.
    meta = {"purchase_id": str(purchase.id), "user_id": str(purchase.user_id),
            "sku": sku, "pricing_version": str(version)}
    if kind is not None:
        meta["kind"] = kind
    return {
        "id": event_id, "type": "checkout.session.completed", "livemode": False,
        "data": {"object": {
            "id": session_id, "payment_status": payment_status,
            "status": status, "mode": mode, "amount_total": amount,
            "currency": currency, "payment_intent": pi,
            "metadata": meta,
        }},
    }


def _seed_purchase(p164_env, user_id, rid, *, status="pending", session_id=None, pi=None):
    from app import models
    with p164_env.sessions() as db:
        p = models.ProductPurchase(
            user_id=user_id, sku="investigation_report", source_result_id=rid,
            stripe_session_id=session_id, stripe_payment_intent_id=pi,
            amount_cents=900, currency="usd", stripe_price_id=PRICE_ID,
            pricing_version=1, status=status)
        db.add(p)
        db.commit()
        db.refresh(p)
        return p.id


def _seed_entitlement(p164_env, user_id, rid, *, status="available", deadline=None):
    from app import models
    pid = _seed_purchase(p164_env, user_id, rid, status="completed")
    with p164_env.sessions() as db:
        purchase = db.get(models.ProductPurchase, pid)
        purchase.completed_at = datetime.now(timezone.utc)
        source = db.get(models.Result, rid)
        dl = deadline or (source.expires_at + timedelta(days=30))
        ent = models.Entitlement(
            user_id=user_id, product_purchase_id=pid,
            sku="investigation_report", source_result_id=rid,
            status=status, redemption_deadline=dl)
        db.add(ent)
        db.commit()
        db.refresh(ent)
        return ent.id


def _counts(p164_env, user_id):
    from app import models
    with p164_env.sessions() as db:
        return {
            "ledger": db.query(models.CreditLedger).filter(models.CreditLedger.user_id == user_id).count(),
            "consents": db.query(models.Consent).filter(models.Consent.user_id == user_id).count(),
            "operations": db.query(models.Operation).filter(models.Operation.user_id == user_id).count(),
            "accounts": db.query(models.CreditAccount).filter(models.CreditAccount.user_id == user_id).count(),
            "balance": (db.query(models.CreditAccount).filter(models.CreditAccount.user_id == user_id).first() or SimpleNamespace(balance=0)).balance,
        }


def _checkout(p164_env, rid, csrf):
    return p164_env.client.post(f"/reports/{rid}/investigation-checkout",
                                data={"csrf_token": csrf})


def _deep_dive(p164_env, rid, csrf):
    return p164_env.client.post(f"/reports/{rid}/deep-dive", data={"csrf_token": csrf})


# --- Group 1/2: catalog, fail-closed, checkout creation --------------------

def test_checkout_fail_closed_when_price_unset(p164_env, monkeypatch):
    monkeypatch.delenv("STRIPE_PRICE_INVESTIGATION_REPORT", raising=False)
    _, user_id, csrf = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    captured = []
    _fake_stripe(monkeypatch, captured)
    r = _checkout(p164_env, rid, csrf)
    assert r.status_code == 503
    assert captured == []  # zero Stripe calls
    from app import models
    with p164_env.sessions() as db:
        assert db.query(models.ProductPurchase).count() == 0  # zero rows


def test_checkout_creation_pending_first_metadata_and_key(p164_env, monkeypatch):
    _, user_id, csrf = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    captured = []
    _fake_stripe(monkeypatch, captured)
    r = _checkout(p164_env, rid, csrf)
    assert r.status_code == 200, r.text[:300]
    body = r.json()
    assert body["checkout_url"].startswith("https://checkout.stripe.com/pay/")
    assert len(captured) == 1
    data = captured[0]["data"]
    from app import models
    with p164_env.sessions() as db:
        purchase = db.query(models.ProductPurchase).one()
        assert str(purchase.id) == body["purchase_id"]
        assert purchase.status == "pending"
        assert purchase.stripe_session_id is not None
        assert purchase.amount_cents == 900 and purchase.currency == "usd"
        assert purchase.stripe_price_id == PRICE_ID
        source = db.get(models.Result, rid)
        expected_deadline = source.expires_at + timedelta(days=30)
    assert data["metadata[purchase_id]"] == body["purchase_id"]
    assert data["metadata[kind]"] == "product"
    assert data["metadata[sku]"] == "investigation_report"
    assert data["payment_intent_data[metadata][kind]"] == "product"
    assert captured[0]["headers"]["Idempotency-Key"] == f"checkout:product:{body['purchase_id']}"
    from app.credits import _as_aware
    assert datetime.fromisoformat(body["redemption_deadline"]) == _as_aware(expected_deadline)


def test_checkout_retry_reuses_pending_purchase(p164_env, monkeypatch):
    _, user_id, csrf = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    captured = []
    _fake_stripe(monkeypatch, captured)
    first = _checkout(p164_env, rid, csrf)
    second = _checkout(p164_env, rid, csrf)
    assert first.status_code == second.status_code == 200
    assert first.json()["purchase_id"] == second.json()["purchase_id"]
    from app import models
    with p164_env.sessions() as db:
        assert db.query(models.ProductPurchase).count() == 1


def test_checkout_two_sources_same_minute_do_not_collide(p164_env, monkeypatch):
    _, user_id, csrf = _make_user(p164_env)
    rid1 = _source(p164_env, user_id)
    rid2 = _source(p164_env, user_id)
    captured = []
    _fake_stripe(monkeypatch, captured)
    assert _checkout(p164_env, rid1, csrf).status_code == 200
    assert _checkout(p164_env, rid2, csrf).status_code == 200
    keys = [c["headers"]["Idempotency-Key"] for c in captured]
    assert keys[0] != keys[1]


def test_checkout_blocked_while_entitlement_available_f1(p164_env, monkeypatch):
    _, user_id, csrf = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    ent_id = _seed_entitlement(p164_env, user_id, rid, status="available")
    captured = []
    _fake_stripe(monkeypatch, captured)
    r = _checkout(p164_env, rid, csrf)
    assert r.status_code == 409
    assert r.json()["existing_entitlement_id"] == str(ent_id)
    assert captured == []  # zero new Stripe sessions


def test_checkout_blocked_while_entitlement_reserved_f1(p164_env, monkeypatch):
    _, user_id, csrf = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    _seed_entitlement(p164_env, user_id, rid, status="reserved")
    captured = []
    _fake_stripe(monkeypatch, captured)
    assert _checkout(p164_env, rid, csrf).status_code == 409
    assert captured == []


def test_checkout_expired_source_refused_410(p164_env, monkeypatch):
    _, user_id, csrf = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    from app import models
    with p164_env.sessions() as db:
        src = db.get(models.Result, rid)
        src.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        db.commit()
    captured = []
    _fake_stripe(monkeypatch, captured)
    assert _checkout(p164_env, rid, csrf).status_code == 410
    assert captured == []
    with p164_env.sessions() as db:
        assert db.query(models.ProductPurchase).count() == 0


def test_checkout_success_url_grants_nothing(p164_env, monkeypatch):
    _, user_id, csrf = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    _fake_stripe(monkeypatch, [])
    assert _checkout(p164_env, rid, csrf).status_code == 200
    r = p164_env.client.get(f"/reports/{rid}?checkout=success")
    assert r.status_code == 200
    from app import models
    with p164_env.sessions() as db:
        assert db.query(models.Entitlement).count() == 0


# --- Group 3: webhook settlement -------------------------------------------

def _pending_with_session(p164_env, user_id, rid):
    pid = _seed_purchase(p164_env, user_id, rid, session_id="cs_test_1")
    with p164_env.sessions() as db:
        return db.get(__import__("app.models", fromlist=["ProductPurchase"]).ProductPurchase, pid)


def test_webhook_settlement_grants_exactly_one_entitlement(p164_env):
    _, user_id, csrf = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    purchase = _pending_with_session(p164_env, user_id, rid)
    before = _counts(p164_env, user_id)
    r = _post_event(p164_env, _product_completed_event("evt_1", purchase))
    assert r.json()["status"] == "processed"
    from app import models
    with p164_env.sessions() as db:
        p = db.get(models.ProductPurchase, purchase.id)
        assert p.status == "completed" and p.amount_cents == 900
        ents = db.query(models.Entitlement).all()
        assert len(ents) == 1 and ents[0].status == "available"
        source = db.get(models.Result, rid)
        from app.credits import _as_aware
        assert _as_aware(ents[0].redemption_deadline) == _as_aware(source.expires_at) + timedelta(days=30)
    assert _counts(p164_env, user_id) == before  # no credits/ledger/consents


def test_webhook_redelivery_and_dual_event_grant_nothing_twice(p164_env):
    _, user_id, _ = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    purchase = _pending_with_session(p164_env, user_id, rid)
    assert _post_event(p164_env, _product_completed_event("evt_1", purchase)).json()["status"] == "processed"
    assert _post_event(p164_env, _product_completed_event("evt_1", purchase)).json()["status"] == "duplicate"
    assert _post_event(p164_env, _product_completed_event("evt_2", purchase)).json()["status"] == "duplicate"
    from app import models
    with p164_env.sessions() as db:
        assert db.query(models.Entitlement).count() == 1


@pytest.mark.parametrize("mutate", ["sku", "currency", "amount", "unpaid", "price", "version", "session", "pi"])
def test_webhook_strict_facts_fail_closed(p164_env, mutate):
    _, user_id, _ = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    purchase = _pending_with_session(p164_env, user_id, rid)
    ev = _product_completed_event(f"evt_{mutate}", purchase)
    obj = ev["data"]["object"]
    if mutate == "sku":
        obj["metadata"]["sku"] = "compare"
    elif mutate == "currency":
        obj["currency"] = "eur"
    elif mutate == "amount":
        obj["amount_total"] = 100
    elif mutate == "unpaid":
        obj["payment_status"] = "unpaid"
    elif mutate == "price":
        # The Price ID now arrives via the API retrieval stub (P1-1),
        # not from the event payload.
        _LINE_PRICE["id"] = "price_other_900"
    elif mutate == "version":
        obj["metadata"]["pricing_version"] = "99"
    elif mutate == "session":
        obj["id"] = "cs_test_other"
    elif mutate == "pi":
        with p164_env.sessions() as db:
            from app import models
            p = db.get(models.ProductPurchase, purchase.id)
            p.stripe_payment_intent_id = "pi_real"
            db.commit()
        obj["payment_intent"] = "pi_substituted"
    r = _post_event(p164_env, ev)
    assert r.json()["status"] == "failed"
    from app import models
    with p164_env.sessions() as db:
        assert db.query(models.Entitlement).count() == 0
        assert db.get(models.ProductPurchase, purchase.id).status == "failed"


def test_webhook_unknown_purchase_ignored_200(p164_env):
    _, user_id, _ = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    purchase = _pending_with_session(p164_env, user_id, rid)
    ev = _product_completed_event("evt_unknown", purchase)
    ev["data"]["object"]["metadata"]["purchase_id"] = str(uuid.uuid4())
    ev["data"]["object"]["id"] = "cs_nope"
    r = _post_event(p164_env, ev)
    assert r.status_code == 200 and r.json()["status"] == "ignored"


def test_webhook_contradictory_kind_fails_closed(p164_env):
    _, user_id, _ = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    purchase = _pending_with_session(p164_env, user_id, rid)
    ev = _product_completed_event("evt_contra", purchase, kind="pack")
    r = _post_event(p164_env, ev)
    assert r.json()["status"] == "failed"
    from app import models
    with p164_env.sessions() as db:
        assert db.query(models.Entitlement).count() == 0


def test_webhook_unknown_kind_fails_closed(p164_env):
    _, user_id, _ = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    purchase = _pending_with_session(p164_env, user_id, rid)
    ev = _product_completed_event("evt_kind", purchase, kind="mystery")
    assert _post_event(p164_env, ev).json()["status"] == "failed"


def test_webhook_async_success_grants_nothing_f4(p164_env):
    _, user_id, _ = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    purchase = _pending_with_session(p164_env, user_id, rid)
    ev = _product_completed_event("evt_async", purchase)
    ev["type"] = "checkout.session.async_payment_succeeded"
    assert _post_event(p164_env, ev).json()["status"] == "ignored"
    from app import models
    with p164_env.sessions() as db:
        assert db.query(models.Entitlement).count() == 0
        assert db.get(models.ProductPurchase, purchase.id).status == "pending"


def test_webhook_expired_session_fails_product_purchase(p164_env):
    _, user_id, _ = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    purchase = _pending_with_session(p164_env, user_id, rid)
    ev = _product_completed_event("evt_exp", purchase)
    ev["type"] = "checkout.session.expired"
    assert _post_event(p164_env, ev).json()["status"] == "processed"
    from app import models
    with p164_env.sessions() as db:
        assert db.get(models.ProductPurchase, purchase.id).status == "failed"
        assert db.query(models.Entitlement).count() == 0


def test_webhook_legacy_pack_without_kind_still_settles(p164_env):
    from app import credits as C
    from app import models
    _, user_id, _ = _make_user(p164_env)
    with p164_env.sessions() as db:
        purchase = C.create_pending_purchase(db, user_id, "starter")
        purchase.stripe_session_id = "cs_pack_1"
        db.commit()
        pid = purchase.id
    ev = {
        "id": "evt_pack_legacy", "type": "checkout.session.completed", "livemode": False,
        "data": {"object": {
            "id": "cs_pack_1", "amount_total": 500, "currency": "usd",
            "payment_intent": "pi_pack_1",
            "metadata": {"purchase_id": str(pid), "user_id": str(user_id),
                         "pack_id": "starter", "credits": "10", "pricing_version": "1"},
        }},
    }
    r = _post_event(p164_env, ev)
    assert r.json()["status"] == "processed"
    with p164_env.sessions() as db:
        assert db.get(models.CreditPurchase, pid).status == "completed"


# --- Group 4/5/6: redemption, replay, retention ------------------------------

def test_redemption_success_90d_no_credit_movement(p164_env):
    _, user_id, csrf = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    ent_id = _seed_entitlement(p164_env, user_id, rid)
    before = _counts(p164_env, user_id)
    r = _deep_dive(p164_env, rid, csrf)
    assert r.status_code == 200, r.text[:300]
    body = r.json()
    assert body["status"] == "completed" and body["price_cents"] == 900
    from app import models
    from app.credits import _as_aware
    with p164_env.sessions() as db:
        ent = db.get(models.Entitlement, ent_id)
        assert ent.status == "redeemed"
        assert str(ent.redeemed_result_id) == body["analysis_result_id"]
        artifact = db.get(models.Result, uuid.UUID(body["analysis_result_id"]))
        assert artifact.type == "deep_dive"
        assert artifact.product_redemption_id is not None
        assert artifact.operation_id is None and artifact.free_request_id is None
        assert (_as_aware(artifact.expires_at) - _as_aware(artifact.ready_at)).days == 90
    assert _counts(p164_env, user_id) == before


def test_redemption_failure_releases_entitlement_f2(p164_env, monkeypatch):
    from app import deep_dive as dd
    _, user_id, csrf = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    ent_id = _seed_entitlement(p164_env, user_id, rid)

    _orig_build = dd.build_deep_dive

    def boom(*a, **k):
        raise RuntimeError("generation exploded")
    monkeypatch.setattr(dd, "build_deep_dive", boom)
    r = _deep_dive(p164_env, rid, csrf)
    assert r.status_code == 500
    from app import models
    with p164_env.sessions() as db:
        assert db.get(models.Entitlement, ent_id).status == "available"
        reds = db.query(models.EntitlementRedemption).all()
        assert len(reds) == 1 and reds[0].status == "released"
    monkeypatch.setattr(dd, "build_deep_dive", _orig_build)
    r2 = _deep_dive(p164_env, rid, csrf)
    assert r2.status_code == 200  # retry succeeds on the same purchase


def test_no_entitlement_402_directs_to_checkout_even_with_credits(p164_env):
    from app import credits as C
    _, user_id, csrf = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    with p164_env.sessions() as db:
        C.grant_credits(db, user_id, "admin", "test-grant", 10)
        db.commit()
    before = _counts(p164_env, user_id)
    r = _deep_dive(p164_env, rid, csrf)
    assert r.status_code == 402
    assert r.json()["checkout_url"] == f"/reports/{rid}/investigation-checkout"
    assert _counts(p164_env, user_id) == before  # credits untouched


def test_redemption_non_owner_404(p164_env):
    _, user_id, csrf = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    _seed_entitlement(p164_env, user_id, rid)
    _, other_id, other_csrf = _make_user(p164_env)
    r = _deep_dive(p164_env, rid, other_csrf)
    assert r.status_code == 404


def test_redemption_in_flight_409(p164_env):
    from app import product_billing as pb
    _, user_id, csrf = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    ent_id = _seed_entitlement(p164_env, user_id, rid)
    with p164_env.sessions() as db:
        from app import models
        ent = db.get(models.Entitlement, ent_id)
        pb.reserve_redemption(db, ent, request_hash="x" * 64, worker_id="w1")
        db.commit()
    r = _deep_dive(p164_env, rid, csrf)
    assert r.status_code == 409


def test_replay_free_and_second_entitlement_not_consumed(p164_env):
    _, user_id, csrf = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    _seed_entitlement(p164_env, user_id, rid)
    first = _deep_dive(p164_env, rid, csrf)
    assert first.status_code == 200
    second_ent = _seed_entitlement(p164_env, user_id, rid)
    again = _deep_dive(p164_env, rid, csrf)
    assert again.status_code == 200
    assert again.json()["replayed"] is True
    assert again.json()["analysis_result_id"] == first.json()["analysis_result_id"]
    from app import models
    with p164_env.sessions() as db:
        assert db.get(models.Entitlement, second_ent).status == "available"


def test_legacy_credit_artifact_replays_with_entitlement_present(p164_env):
    import json as _json
    from app import credits as C
    from app import deep_dive as dd
    from app import models
    _, user_id, csrf = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    ent_id = _seed_entitlement(p164_env, user_id, rid)
    with p164_env.sessions() as db:
        source = db.get(models.Result, rid)
        payload = C.result_payload(source, user_id=user_id,
                                   operation_id=source.operation_id,
                                   free_request_id=source.free_request_id)
        req_hash = dd.analysis_request_hash(source, payload)
        artifact_data = dd.build_deep_dive(payload, source_result_id=rid,
                                           source_integrity_digest=source.integrity_digest)
        raw = _json.dumps(artifact_data, default=str)
        now = datetime.now(timezone.utc)
        op = models.Operation(
            user_id=user_id, type="deep_dive",
            idempotency_key=f"analysis-{rid}-v1", request_hash=req_hash,
            cost=3, pricing_version=1, status="completed",
            worker_id="legacy", lease_generation=1,
            lease_expires_at=now + timedelta(minutes=5), completed_at=now)
        db.add(op)
        db.flush()
        artifact = models.Result(
            user_id=user_id, operation_id=op.id, type="deep_dive",
            storage_manifest=raw,
            integrity_digest=C.hash_input(raw.encode()),
            byte_count=len(raw.encode()), ready_at=now,
            expires_at=now + timedelta(days=7))
        db.add(artifact)
        db.flush()
        op.result_id = artifact.id
        db.commit()
        legacy_id = str(artifact.id)
    r = _deep_dive(p164_env, rid, csrf)
    assert r.status_code == 200 and r.json()["replayed"] is True
    assert r.json()["analysis_result_id"] == legacy_id
    with p164_env.sessions() as db:
        assert db.get(models.Entitlement, ent_id).status == "available"


# --- Group 7/9: exports free + branding -------------------------------------

def _redeem(p164_env, user_id, rid, csrf):
    _seed_entitlement(p164_env, user_id, rid)
    r = _deep_dive(p164_env, rid, csrf)
    assert r.status_code == 200, r.text[:300]
    return r.json()["analysis_result_id"]


def test_exports_free_for_dollar_paid_report(p164_env):
    _, user_id, csrf = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    artifact_id = _redeem(p164_env, user_id, rid, csrf)
    before = _counts(p164_env, user_id)
    pdf = p164_env.client.post(f"/reports/{artifact_id}/pdf", data={"csrf_token": csrf})
    assert pdf.status_code == 200, pdf.text[:200]
    for fmt in ("csv", "json"):
        r = p164_env.client.post(f"/reports/{artifact_id}/exports/{fmt}",
                                 data={"csrf_token": csrf})
        assert r.status_code == 200, (fmt, r.text[:200])
    assert _counts(p164_env, user_id) == before  # zero unlock charge/consents


def test_source_exports_still_legacy_unlock(p164_env):
    _, user_id, csrf = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    _redeem(p164_env, user_id, rid, csrf)
    # The SOURCE report was never export-unlocked and the user holds no
    # credits in this fixture: its PDF export still 402s (legacy terms).
    r = p164_env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert r.status_code == 402


def test_branding_on_dollar_paid_report(p164_env):
    _, user_id, csrf = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    artifact_id = _redeem(p164_env, user_id, rid, csrf)
    r = p164_env.client.post(
        f"/reports/{artifact_id}/branding",
        data={"csrf_token": csrf, "business_name": "Acme Consulting",
              "client_name": "", "report_title": "", "accent": ""})
    assert r.status_code in (200, 303), r.text[:300]
    page = p164_env.client.get(f"/reports/{artifact_id}")
    assert page.status_code == 200 and "Acme Consulting" in page.text
    pdf = p164_env.client.post(f"/reports/{artifact_id}/pdf", data={"csrf_token": csrf})
    assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"


# --- Group 8 / F5: redemption window -----------------------------------------

def test_redemption_after_source_expiry_within_window_succeeds(p164_env):
    _, user_id, csrf = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    ent_id = _seed_entitlement(p164_env, user_id, rid)
    from app import models
    with p164_env.sessions() as db:
        src = db.get(models.Result, rid)
        src.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        db.commit()
    r = _deep_dive(p164_env, rid, csrf)
    assert r.status_code == 200, r.text[:300]
    with p164_env.sessions() as db:
        assert db.get(models.Entitlement, ent_id).status == "redeemed"


def test_redemption_past_deadline_refused_and_refund_eligible(p164_env):
    _, user_id, csrf = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    from app import models
    with p164_env.sessions() as db:
        src = db.get(models.Result, rid)
        src.expires_at = datetime.now(timezone.utc) - timedelta(days=40)
    ent_id = _seed_entitlement(p164_env, user_id, rid,
                               deadline=datetime.now(timezone.utc) - timedelta(days=1))
    r = _deep_dive(p164_env, rid, csrf)
    assert r.status_code == 410
    assert r.json().get("refund_eligible") is True
    with p164_env.sessions() as db:
        assert db.get(models.Entitlement, ent_id).status == "refund_eligible"


def test_cleanup_preserves_redemption_prerequisites_f5(p164_env):
    from app import credit_maintenance
    from app import models
    _, user_id, csrf = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    _seed_entitlement(p164_env, user_id, rid)
    with p164_env.sessions() as db:
        src = db.get(models.Result, rid)
        manifest_before = src.storage_manifest
        src.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        db.commit()
    with p164_env.sessions() as db:
        credit_maintenance.cleanup_results(db)
    with p164_env.sessions() as db:
        src = db.get(models.Result, rid)
        assert src.deleted_at is None and src.storage_manifest == manifest_before
    # Redemption still succeeds on the preserved prerequisites.
    r = _deep_dive(p164_env, rid, csrf)
    assert r.status_code == 200


# --- A5/F3: refunds and disputes ----------------------------------------------

def _charge_event(event_id, purchase, *, etype, amount=900, refunded=900, status=None):
    """Real Stripe payload shapes (P3-7).

    Refunds arrive as a Charge object whose own metadata does NOT
    carry the PaymentIntent metadata — the join must fall back to the
    purchase row's snapshotted PaymentIntent id. Disputes arrive as a
    Dispute object (charge + payment_intent + status), not a Charge.
    """
    pi = purchase.stripe_payment_intent_id or "pi_test_1"
    if etype.startswith("charge.dispute"):
        obj = {"id": "dp_test_1", "object": "dispute", "charge": "ch_test_1",
               "amount": amount, "payment_intent": pi, "metadata": {}}
        if status is not None:
            obj["status"] = status
        return {"id": event_id, "type": etype, "livemode": False,
                "data": {"object": obj}}
    obj = {"id": "ch_test_1", "amount": amount, "amount_refunded": refunded,
           "payment_intent": pi, "metadata": {}}
    return {"id": event_id, "type": etype, "livemode": False, "data": {"object": obj}}


def _settled_purchase(p164_env, user_id, rid):
    purchase = _pending_with_session(p164_env, user_id, rid)
    with p164_env.sessions() as db:
        from app import models
        p = db.get(models.ProductPurchase, purchase.id)
        p.stripe_payment_intent_id = "pi_test_1"
        db.commit()
    assert _post_event(p164_env, _product_completed_event("evt_settle", purchase)).json()["status"] == "processed"
    with p164_env.sessions() as db:
        from app import models
        return db.get(models.ProductPurchase, purchase.id)


def test_full_refund_revokes_available_entitlement(p164_env):
    _, user_id, _ = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    purchase = _settled_purchase(p164_env, user_id, rid)
    r = _post_event(p164_env, _charge_event("evt_refund", purchase, etype="charge.refunded"))
    assert r.json()["status"] == "processed"
    from app import models
    with p164_env.sessions() as db:
        assert db.get(models.ProductPurchase, purchase.id).status == "refunded"
        assert db.query(models.Entitlement).one().status == "revoked"


def test_partial_refund_leaves_entitlement_intact_f3(p164_env):
    _, user_id, csrf = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    purchase = _settled_purchase(p164_env, user_id, rid)
    _post_event(p164_env, _charge_event("evt_partial", purchase, etype="charge.refunded",
                                        amount=900, refunded=300))
    from app import models
    with p164_env.sessions() as db:
        p = db.get(models.ProductPurchase, purchase.id)
        assert p.status == "completed" and p.reversal_kind == "refund"
        assert db.query(models.Entitlement).one().status == "available"
    r = _deep_dive(p164_env, rid, csrf)  # still redeems
    assert r.status_code == 200


def test_refund_after_redeem_no_clawback_flags_review(p164_env):
    _, user_id, csrf = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    purchase = _settled_purchase(p164_env, user_id, rid)
    redeemed = _deep_dive(p164_env, rid, csrf)
    assert redeemed.status_code == 200
    artifact_id = redeemed.json()["analysis_result_id"]
    _post_event(p164_env, _charge_event("evt_refund2", purchase, etype="charge.refunded"))
    from app import models
    with p164_env.sessions() as db:
        assert db.get(models.ProductPurchase, purchase.id).needs_manual_review is True
    page = p164_env.client.get(f"/reports/{artifact_id}")
    assert page.status_code == 200  # artifact NOT clawed back


def test_dispute_lost_revokes_and_won_never_auto_restores_f3(p164_env):
    _, user_id, _ = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    purchase = _settled_purchase(p164_env, user_id, rid)
    _post_event(p164_env, _charge_event("evt_disp_open", purchase, etype="charge.dispute.created"))
    from app import models
    with p164_env.sessions() as db:
        assert db.query(models.Entitlement).one().status == "available"  # open != final
    _post_event(p164_env, _charge_event("evt_disp_lost", purchase, etype="charge.dispute.closed", status="lost"))
    with p164_env.sessions() as db:
        assert db.query(models.Entitlement).one().status == "revoked"
    _post_event(p164_env, _charge_event("evt_disp_won", purchase, etype="charge.dispute.closed", status="won"))
    with p164_env.sessions() as db:
        ent = db.query(models.Entitlement).one()
        assert ent.status == "revoked"  # founder-manual only
        assert db.get(models.ProductPurchase, purchase.id).needs_manual_review is True


def test_refund_of_pending_purchase_is_terminal(p164_env):
    _, user_id, _ = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    purchase = _pending_with_session(p164_env, user_id, rid)
    with p164_env.sessions() as db:
        from app import models
        p = db.get(models.ProductPurchase, purchase.id)
        p.stripe_payment_intent_id = "pi_test_1"
        db.commit()
    _post_event(p164_env, _charge_event("evt_refund_pending", purchase, etype="charge.refunded"))
    from app import models
    with p164_env.sessions() as db:
        assert db.get(models.ProductPurchase, purchase.id).status == "refunded"
    r = _post_event(p164_env, _product_completed_event("evt_late_complete", purchase))
    assert r.json()["status"] == "duplicate"
    with p164_env.sessions() as db:
        assert db.query(models.Entitlement).count() == 0


# --- A1: recovery, fencing, revocation races (service level) -------------------

def test_recovery_stopped_then_retry_with_evidence(p164_env):
    from app import product_billing as pb
    from app import models
    _, user_id, _ = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    ent_id = _seed_entitlement(p164_env, user_id, rid)
    with p164_env.sessions() as db:
        ent = db.get(models.Entitlement, ent_id)
        red = pb.reserve_redemption(db, ent, request_hash="y" * 64, worker_id="w-dead")
        red.lease_expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.commit()
        red_id = red.id
    with p164_env.sessions() as db:
        pb.recover_expired_redemptions(db)  # no evidence -> stopped
    with p164_env.sessions() as db:
        red = db.get(models.EntitlementRedemption, red_id)
        assert red.status == "stopped"
        assert db.get(models.Entitlement, ent_id).status == "reserved"
        assert pb.retry_stopped_redemption(db, red_id, executor_stopped=lambda *a: False) is False
        db.rollback()
        assert pb.retry_stopped_redemption(db, red_id, executor_stopped=lambda *a: True) is True
        db.commit()
        assert db.get(models.Entitlement, ent_id).status == "available"


def test_late_worker_cannot_complete_after_release(p164_env):
    from app import product_billing as pb
    from app import credits as C
    from app import models
    _, user_id, _ = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    ent_id = _seed_entitlement(p164_env, user_id, rid)
    with p164_env.sessions() as db:
        ent = db.get(models.Entitlement, ent_id)
        red = pb.reserve_redemption(db, ent, request_hash="z" * 64, worker_id="w1")
        db.commit()
        red_id = red.id
        pb.release_redemption(db, red_id, "w1", "generation_failed")
        db.commit()
        with pytest.raises(C.AdmissionError):
            pb.complete_redemption(db, red_id, "w1", result_id=None)
        db.rollback()


def test_revoke_during_generation_wins_over_complete(p164_env):
    from app import product_billing as pb
    from app import credits as C
    from app import models
    _, user_id, _ = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    ent_id = _seed_entitlement(p164_env, user_id, rid)
    with p164_env.sessions() as db:
        ent = db.get(models.Entitlement, ent_id)
        red = pb.reserve_redemption(db, ent, request_hash="w" * 64, worker_id="w1")
        db.commit()
        red_id = red.id
        assert pb.revoke_entitlement(db, db.get(models.Entitlement, ent_id)) is True
        db.commit()
        with pytest.raises(C.AdmissionError):
            pb.complete_redemption(db, red_id, "w1", result_id=None)
        db.rollback()
        # Release after revoke must not revive the entitlement.
        with pytest.raises(C.AdmissionError):
            pb.release_redemption(db, red_id, "w1", "late")
        db.rollback()
        assert db.get(models.Entitlement, ent_id).status == "revoked"


def test_same_entitlement_second_reserve_rejected(p164_env):
    from app import product_billing as pb
    from app import credits as C
    from app import models
    _, user_id, _ = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    ent_id = _seed_entitlement(p164_env, user_id, rid)
    with p164_env.sessions() as db:
        ent = db.get(models.Entitlement, ent_id)
        pb.reserve_redemption(db, ent, request_hash="a" * 64, worker_id="w1")
        db.commit()
        with pytest.raises(C.AdmissionError):
            pb.reserve_redemption(db, db.get(models.Entitlement, ent_id),
                                  request_hash="a" * 64, worker_id="w2")
        db.rollback()


# --- Group 10: reconciliation ---------------------------------------------------

def test_reconciliation_product_only_day_clean_and_mismatch(p164_env):
    from app import payment_reconcile as PR
    _, user_id, _ = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    purchase = _settled_purchase(p164_env, user_id, rid)
    from app import models
    with p164_env.sessions() as db:
        completed_day = db.get(models.ProductPurchase, purchase.id).completed_at.date()
        session = {
            "id": purchase.stripe_session_id or "cs_test_1",
            "amount_total": 900, "payment_intent": "pi_test_1",
            "metadata": {"kind": "product", "purchase_id": str(purchase.id),
                         "sku": "investigation_report"},
        }
        # _settled_purchase settles via webhook, which backfills the
        # session id from the event (cs_test_1).
        result = PR.compute_reconciliation(db, completed_day, [session], [])
        fams = result["per_family"]
        assert fams["product"]["stripe_gross_cents"] == 900
        assert fams["product"]["ledger_gross_cents"] == 900
        assert not [d for d in result["differences"] if d.get("family") == "product"]
        doctored = dict(session, amount_total=1000)
        result2 = PR.compute_reconciliation(db, completed_day, [doctored], [])
        assert any(d["kind"] == "family_total_mismatch" for d in result2["differences"])


def test_reconciliation_missing_entitlement_alerts(p164_env):
    from app import payment_reconcile as PR
    from app import models
    _, user_id, _ = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    pid = _seed_purchase(p164_env, user_id, rid, status="completed", session_id="cs_orphan")
    with p164_env.sessions() as db:
        p = db.get(models.ProductPurchase, pid)
        p.completed_at = datetime.now(timezone.utc)
        db.commit()
        day = p.completed_at.date()
        session = {"id": "cs_orphan", "amount_total": 900, "payment_intent": "pi_x",
                   "metadata": {"kind": "product", "purchase_id": str(pid),
                                "sku": "investigation_report"}}
        result = PR.compute_reconciliation(db, day, [session], [])
        assert any(d["kind"] == "product_purchase_entitlement_mismatch"
                   for d in result["differences"])


# --- Group 11 / A2: invariants ---------------------------------------------------

def test_full_flow_no_credit_invariant(p164_env, monkeypatch):
    _, user_id, csrf = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    before = _counts(p164_env, user_id)
    captured = []
    _fake_stripe(monkeypatch, captured)
    r = _checkout(p164_env, rid, csrf)
    assert r.status_code == 200
    from app import models
    with p164_env.sessions() as db:
        purchase = db.query(models.ProductPurchase).one()
    ev = _product_completed_event("evt_full", purchase,
                                  session_id=purchase.stripe_session_id)
    assert _post_event(p164_env, ev).json()["status"] == "processed"
    redeemed = _deep_dive(p164_env, rid, csrf)
    assert redeemed.status_code == 200
    artifact_id = redeemed.json()["analysis_result_id"]
    pdf = p164_env.client.post(f"/reports/{artifact_id}/pdf", data={"csrf_token": csrf})
    assert pdf.status_code == 200
    assert _counts(p164_env, user_id) == before


def test_result_origin_exactly_one_of_three(p164_env):
    from app import models
    from sqlalchemy.exc import IntegrityError
    _, user_id, _ = _make_user(p164_env)
    now = datetime.now(timezone.utc)
    with p164_env.sessions() as db:
        bad = models.Result(
            user_id=user_id, type="analysis", storage_manifest="{}",
            integrity_digest="x" * 64, byte_count=2, ready_at=now,
            expires_at=now + timedelta(days=7))
        db.add(bad)
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()


# --- Remediation round (Sunny review P1-1/P2-1..P2-4, P3) --------------------

def test_settlement_uses_api_retrieved_price_not_event_payload(p164_env):
    # The event carries no line_items/price at all; settlement must
    # retrieve the price from the Stripe API. With the retrieval
    # returning a DIFFERENT price than the snapshot, it fails closed.
    _, user_id, _ = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    purchase = _pending_with_session(p164_env, user_id, rid)
    ev = _product_completed_event("evt_api_price", purchase)
    assert "line_items" not in ev["data"]["object"]
    _LINE_PRICE["id"] = "price_someone_else"
    r = _post_event(p164_env, ev)
    assert r.json()["status"] == "failed"
    _LINE_PRICE["id"] = PRICE_ID
    pid2 = _seed_purchase(p164_env, user_id, rid, session_id="cs_test_2")
    with p164_env.sessions() as db:
        from app import models as _m
        purchase2 = db.get(_m.ProductPurchase, pid2)
    r2 = _post_event(p164_env, _product_completed_event(
        "evt_api_price_ok", purchase2, session_id="cs_test_2"))
    assert r2.json()["status"] == "processed"


def test_settlement_missing_price_snapshot_fails_closed_p3_4(p164_env):
    # A4(e) unconditional: a purchase row with NO snapshotted price
    # must not settle even when every other fact matches.
    _, user_id, _ = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    pid = _seed_purchase(p164_env, user_id, rid, session_id="cs_test_1")
    from app import models
    with p164_env.sessions() as db:
        p = db.get(models.ProductPurchase, pid)
        p.stripe_price_id = None
        db.commit()
    purchase = SimpleNamespace(id=pid, user_id=user_id)
    r = _post_event(p164_env, _product_completed_event("evt_nosnap", purchase))
    assert r.json()["status"] == "failed"
    with p164_env.sessions() as db:
        assert db.query(models.Entitlement).count() == 0


def test_checkout_reuses_pending_row_without_session_id_p2_1(p164_env, monkeypatch):
    # A7 timeout case: Stripe may have created the session but the
    # local pending row has NO stripe_session_id. The retry must
    # reuse the SAME purchase row (and its idempotency key) — never
    # a second purchase row + second session.
    _, user_id, csrf = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    pid = _seed_purchase(p164_env, user_id, rid, status="pending", session_id=None)
    captured = []
    _fake_stripe(monkeypatch, captured)
    r = _checkout(p164_env, rid, csrf)
    assert r.status_code == 200, r.text[:300]
    assert r.json()["purchase_id"] == str(pid)
    assert r.json()["promise"]  # reused path carries the F2 promise too
    assert captured[0]["headers"]["Idempotency-Key"] == f"checkout:product:{pid}"
    from app import models
    with p164_env.sessions() as db:
        assert db.query(models.ProductPurchase).count() == 1
        assert db.get(models.ProductPurchase, pid).stripe_session_id is not None


def test_second_live_entitlement_insert_rejected_p2_1(p164_env):
    # DB-level F1 guarantee: a second live entitlement for the same
    # (buyer, source, sku) cannot be inserted, even bypassing the
    # checkout route's SELECT-then-act check.
    from app import models
    from sqlalchemy.exc import IntegrityError
    _, user_id, _ = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    _seed_entitlement(p164_env, user_id, rid, status="available")
    pid2 = _seed_purchase(p164_env, user_id, rid, status="completed")
    with p164_env.sessions() as db:
        source = db.get(models.Result, rid)
        ent2 = models.Entitlement(
            user_id=user_id, product_purchase_id=pid2,
            sku="investigation_report", source_result_id=rid,
            status="available",
            redemption_deadline=source.expires_at + timedelta(days=30))
        db.add(ent2)
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()


def test_pricing_and_report_coming_soon_when_price_unset_p2_3(p164_env, monkeypatch):
    # Spec test group 1, display leg: with the product Price env
    # unset, surfaces render the pack-pattern "Coming soon" state
    # instead of a live-looking $9 buy action.
    monkeypatch.delenv("STRIPE_PRICE_INVESTIGATION_REPORT", raising=False)
    _, user_id, csrf = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    pricing = p164_env.client.get("/credits")
    assert pricing.status_code == 200
    seg = pricing.text[pricing.text.index('data-product="investigation_report"'):]
    seg = seg[:800]
    assert "Coming soon" in seg
    assert "$9" not in seg
    page = p164_env.client.get(f"/reports/{rid}")
    assert page.status_code == 200
    assert "Coming soon" in page.text
    # The rendered purchase copy (modal + premium card) must not
    # present the live $9 terms; a JS error-fallback string is not
    # rendered copy and is out of scope for this assertion.
    assert "Investigation Report costs $9, paid by card at checkout" not in page.text
    listing = p164_env.client.get("/reports")
    assert listing.status_code == 200
    assert "Coming soon" in listing.text
    assert "__productReady = false" in listing.text


def test_investigation_status_endpoint_reflects_settlement_p3_2(p164_env, monkeypatch):
    _, user_id, csrf = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    _fake_stripe(monkeypatch, [])
    r = _checkout(p164_env, rid, csrf)
    assert r.status_code == 200
    st = p164_env.client.get(f"/reports/{rid}/investigation-status")
    assert st.status_code == 200
    assert st.json()["purchase_status"] == "pending"
    assert st.json()["entitlement_status"] is None
    from app import models
    with p164_env.sessions() as db:
        purchase = db.query(models.ProductPurchase).one()
    ev = _product_completed_event("evt_status", purchase,
                                  session_id=purchase.stripe_session_id)
    assert _post_event(p164_env, ev).json()["status"] == "processed"
    st2 = p164_env.client.get(f"/reports/{rid}/investigation-status")
    assert st2.json()["entitlement_status"] == "available"
    assert st2.json()["redemption_deadline"]


def test_full_refund_after_dispute_open_refunds_status_p3_5(p164_env):
    _, user_id, _ = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    purchase = _settled_purchase(p164_env, user_id, rid)
    _post_event(p164_env, _charge_event(
        "evt_disp_open2", purchase, etype="charge.dispute.created"))
    from app import models
    with p164_env.sessions() as db:
        assert db.get(models.ProductPurchase, purchase.id).status == "disputed"
    _post_event(p164_env, _charge_event(
        "evt_refund_after_disp", purchase, etype="charge.refunded"))
    with p164_env.sessions() as db:
        assert db.get(models.ProductPurchase, purchase.id).status == "refunded"
        assert db.query(models.Entitlement).one().status == "revoked"


def test_reconciliation_product_refund_day_via_pi_join_p2_2(p164_env):
    from app import payment_reconcile as PR
    from app import models
    _, user_id, _ = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    purchase = _settled_purchase(p164_env, user_id, rid)
    with p164_env.sessions() as db:
        p = db.get(models.ProductPurchase, purchase.id)
        p.status = "refunded"
        p.reversal_kind = "refund"
        p.reversed_at = p.completed_at
        db.commit()
        day = p.completed_at.date()
        session = {"id": p.stripe_session_id or "cs_test_1",
                   "amount_total": 900, "payment_intent": "pi_test_1",
                   "metadata": {"kind": "product", "purchase_id": str(p.id),
                                "sku": "investigation_report"}}
        # Real charge shape: NO kind/purchase metadata on the charge;
        # attribution must join via the PaymentIntent.
        charge = {"id": "ch_prod_refund", "amount": 900,
                  "amount_refunded": 900, "payment_intent": "pi_test_1",
                  "metadata": {}, "disputed": False}
        result = PR.compute_reconciliation(db, day, [session], [charge])
    fam = result["per_family"]["product"]
    assert fam["stripe_refund_cents"] == 900
    assert fam["ledger_refund_cents"] == 900
    assert fam["stripe_net_cents"] == fam["ledger_net_cents"] == 0
    assert result["stripe_refund_cents"] == 900  # headline includes product
    assert not any(d["kind"] == "family_total_mismatch"
                   for d in result["differences"])
    # The product charge must NOT pollute the pack UNKNOWN buckets.
    assert all(pp["stripe_refund_cents"] == 0
               for pp in result["per_pack"].values())
    assert not any(d.get("pack") == "unknown" and d["kind"] == "stripe_refund"
                   for d in result["differences"])


def test_reconciliation_product_dispute_day_via_pi_join_p2_2(p164_env):
    from app import payment_reconcile as PR
    from app import models
    _, user_id, _ = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    purchase = _settled_purchase(p164_env, user_id, rid)
    with p164_env.sessions() as db:
        p = db.get(models.ProductPurchase, purchase.id)
        p.status = "disputed"
        p.reversal_kind = "dispute_lost"
        p.reversed_at = p.completed_at
        db.commit()
        day = p.completed_at.date()
        session = {"id": p.stripe_session_id or "cs_test_1",
                   "amount_total": 900, "payment_intent": "pi_test_1",
                   "metadata": {"kind": "product", "purchase_id": str(p.id),
                                "sku": "investigation_report"}}
        charge = {"id": "ch_prod_disp", "amount": 900,
                  "amount_refunded": 0, "payment_intent": "pi_test_1",
                  "metadata": {}, "disputed": True,
                  "dispute": {"status": "lost", "amount": 900}}
        result = PR.compute_reconciliation(db, day, [session], [charge])
    fam = result["per_family"]["product"]
    assert fam["stripe_dispute_cents"] == 900
    assert fam["ledger_dispute_cents"] == 900
    assert fam["stripe_net_cents"] == fam["ledger_net_cents"] == 0
    assert result["stripe_dispute_cents"] == 900  # headline includes product
    assert not any(d["kind"] == "family_total_mismatch"
                   for d in result["differences"])
    assert all(pp["stripe_dispute_cents"] == 0
               for pp in result["per_pack"].values())


def test_cleanup_after_window_lapse_proceeds_normally_p3_10(p164_env):
    # F5 coverage gap: once the window lapses (entitlement ->
    # refund_eligible), cleanup is no longer blocked from removing
    # the source's redemption prerequisites.
    from app import credit_maintenance
    from app import product_billing as pb
    from app import models
    _, user_id, csrf = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    ent_id = _seed_entitlement(
        p164_env, user_id, rid,
        deadline=datetime.now(timezone.utc) - timedelta(days=1))
    with p164_env.sessions() as db:
        src = db.get(models.Result, rid)
        src.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        db.commit()
    with p164_env.sessions() as db:
        assert pb.lapse_expired_entitlements(db) == 1
        db.commit()
    with p164_env.sessions() as db:
        credit_maintenance.cleanup_results(db)
    with p164_env.sessions() as db:
        src = db.get(models.Result, rid)
        assert src.deleted_at is not None
        assert src.storage_manifest == "{}"
        assert db.get(models.Entitlement, ent_id).status == "refund_eligible"


# --- Remediation round 2 (Codex PR #172: P1-A..P1-D, P2-A..P2-D) -----------

_PI_META = {"value": {}}


def _stub_stripe_get_combined(monkeypatch):
    """httpx.get stub serving PI-metadata + line-items + session GETs.

    Replaces the autouse line-items-only stub for tests whose code
    path also resolves PaymentIntents (P1-A) or Checkout Sessions
    (P1-B) through the Stripe API.
    """
    import httpx
    _PI_META["value"] = {}

    class Resp:
        status_code = 200

        def __init__(self, payload):
            self._payload = payload

        def json(self):
            return self._payload

    def _get(url, params=None, auth=None, headers=None, timeout=None):
        if "/payment_intents/" in url:
            return Resp({"metadata": dict(_PI_META["value"])})
        if url.endswith("/line_items"):
            if _LINE_PRICE["id"] is None:
                return Resp({"data": []})
            return Resp({"data": [{"price": {"id": _LINE_PRICE["id"]}}]})
        raise AssertionError(url)

    monkeypatch.setattr(httpx, "get", _get)
    return _get


def _stub_session_get(monkeypatch, status_by_id):
    """httpx.get stub for GET /checkout/sessions/{id} (P1-B)."""
    import httpx

    class Resp:
        status_code = 200

        def __init__(self, payload):
            self._payload = payload

        def json(self):
            return self._payload

    def _get(url, params=None, auth=None, headers=None, timeout=None):
        sid = url.rsplit("/", 1)[-1]
        assert sid in status_by_id, url
        return Resp({"id": sid, "status": status_by_id[sid]})

    monkeypatch.setattr(httpx, "get", _get)


def _backdate_purchase(p164_env, pid, *, hours):
    from app import models
    with p164_env.sessions() as db:
        p = db.get(models.ProductPurchase, pid)
        p.created_at = datetime.now(timezone.utc) - timedelta(hours=hours)
        db.commit()


def test_refund_before_completion_via_pi_resolution_grants_nothing_p1a(p164_env, monkeypatch):
    # The reversal arrives BEFORE checkout.session.completed: the
    # charge carries NO purchase metadata and the purchase row has
    # NO snapshotted PI id yet, so both local joins miss. Resolution
    # must go through the PaymentIntent's metadata (Stripe API); the
    # full refund then makes the pending purchase terminal and the
    # later settlement grants NOTHING.
    _, user_id, _ = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    purchase = _pending_with_session(p164_env, user_id, rid)
    _stub_stripe_get_combined(monkeypatch)
    _PI_META["value"] = {"kind": "product", "purchase_id": str(purchase.id),
                         "user_id": str(user_id), "sku": "investigation_report",
                         "pricing_version": "1"}
    charge = {"id": "ch_early", "amount": 900, "amount_refunded": 900,
              "payment_intent": "pi_early", "metadata": {}}
    ev = {"id": "evt_refund_early", "type": "charge.refunded",
          "livemode": False, "data": {"object": charge}}
    r = _post_event(p164_env, ev)
    assert r.json()["status"] == "processed"
    from app import models
    with p164_env.sessions() as db:
        assert db.get(models.ProductPurchase, purchase.id).status == "refunded"
    r2 = _post_event(p164_env, _product_completed_event(
        "evt_complete_after_refund", purchase, pi="pi_early"))
    assert r2.json()["status"] == "duplicate"
    with p164_env.sessions() as db:
        assert db.query(models.Entitlement).count() == 0


def test_product_reversal_unresolved_is_retryable_not_ignored_p1a(p164_env, monkeypatch):
    # PI metadata ties the charge to the product family but the
    # purchase_id does not resolve locally yet: the event id must
    # NOT be consumed as 'ignored'. The handler rolls back (no
    # committed event row) and answers 500; once the purchase row
    # exists, redelivery of the SAME event processes the refund.
    _, user_id, _ = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    ghost_id = uuid.uuid4()
    _stub_stripe_get_combined(monkeypatch)
    _PI_META["value"] = {"kind": "product", "purchase_id": str(ghost_id),
                         "user_id": str(user_id), "sku": "investigation_report",
                         "pricing_version": "1"}
    charge = {"id": "ch_ghost", "amount": 900, "amount_refunded": 900,
              "payment_intent": "pi_ghost", "metadata": {}}
    ev = {"id": "evt_refund_ghost", "type": "charge.refunded",
          "livemode": False, "data": {"object": charge}}
    r = _post_event(p164_env, ev)
    assert r.status_code == 500
    from app import models
    with p164_env.sessions() as db:
        assert db.query(models.StripeWebhookEvent).filter_by(
            stripe_event_id="evt_refund_ghost").count() == 0
        p = models.ProductPurchase(
            id=ghost_id, user_id=user_id, sku="investigation_report",
            source_result_id=rid, stripe_session_id="cs_test_1",
            amount_cents=900, currency="usd", stripe_price_id=PRICE_ID,
            pricing_version=1, status="pending")
        db.add(p)
        db.commit()
    r2 = _post_event(p164_env, ev)
    assert r2.json()["status"] == "processed"
    with p164_env.sessions() as db:
        assert db.get(models.ProductPurchase, ghost_id).status == "refunded"
        assert db.query(models.Entitlement).count() == 0


def test_reversal_with_no_product_relation_still_ignored_p1a(p164_env, monkeypatch):
    # Boundary of P1-A: a charge whose PI metadata shows NO product
    # relation at all is genuinely unknown — ignored with 200, as
    # before (pack reversals keep their reconciliation-only path).
    _make_user(p164_env)
    _stub_stripe_get_combined(monkeypatch)
    _PI_META["value"] = {"kind": "pack", "pack_id": "starter"}
    charge = {"id": "ch_pack", "amount": 500, "amount_refunded": 500,
              "payment_intent": "pi_pack", "metadata": {}}
    ev = {"id": "evt_pack_refund", "type": "charge.refunded",
          "livemode": False, "data": {"object": charge}}
    r = _post_event(p164_env, ev)
    assert r.status_code == 200 and r.json()["status"] == "ignored"


def test_checkout_23_24h_window_reuses_when_session_open_p1b(p164_env, monkeypatch):
    # 23.5h-old pending row whose Stripe session is STILL OPEN (its
    # 24h lifetime runs from session creation, which postdated the
    # row): the row must be reused, never retired — paying that
    # session settles against this row and grants.
    _, user_id, csrf = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    pid = _seed_purchase(p164_env, user_id, rid, status="pending",
                         session_id="cs_old")
    _backdate_purchase(p164_env, pid, hours=23.5)
    _stub_session_get(monkeypatch, {"cs_old": "open"})
    _fake_stripe(monkeypatch, [])
    r = _checkout(p164_env, rid, csrf)
    assert r.status_code == 200, r.text[:300]
    assert r.json()["purchase_id"] == str(pid)
    from app import models
    with p164_env.sessions() as db:
        assert db.query(models.ProductPurchase).count() == 1
        assert db.get(models.ProductPurchase, pid).status == "pending"


def test_checkout_stale_pending_reuses_when_session_state_unconfirmed_p1b(p164_env, monkeypatch):
    # A Stripe retrieval FAILURE is not evidence of expiry: the
    # fail-safe is reuse, never retirement on a guess.
    import httpx
    _, user_id, csrf = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    pid = _seed_purchase(p164_env, user_id, rid, status="pending",
                         session_id="cs_old")
    _backdate_purchase(p164_env, pid, hours=26)

    def _boom(url, params=None, auth=None, headers=None, timeout=None):
        raise ConnectionError("stripe unreachable")
    monkeypatch.setattr(httpx, "get", _boom)
    _fake_stripe(monkeypatch, [])
    r = _checkout(p164_env, rid, csrf)
    assert r.status_code == 200, r.text[:300]
    assert r.json()["purchase_id"] == str(pid)
    from app import models
    with p164_env.sessions() as db:
        assert db.query(models.ProductPurchase).count() == 1


def test_checkout_stale_pending_retires_when_session_expired_p1b(p164_env, monkeypatch):
    # The preserved behaviour: a Stripe-CONFIRMED expired session
    # retires its row and a fresh purchase is created.
    _, user_id, csrf = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    pid = _seed_purchase(p164_env, user_id, rid, status="pending",
                         session_id="cs_old")
    _backdate_purchase(p164_env, pid, hours=26)
    _stub_session_get(monkeypatch, {"cs_old": "expired"})
    _fake_stripe(monkeypatch, [])
    r = _checkout(p164_env, rid, csrf)
    assert r.status_code == 200, r.text[:300]
    assert r.json()["purchase_id"] != str(pid)
    from app import models
    with p164_env.sessions() as db:
        assert db.query(models.ProductPurchase).count() == 2
        assert db.get(models.ProductPurchase, pid).status == "failed"


def test_expire_stale_product_purchase_requires_confirmed_expiry_p1b(p164_env, monkeypatch):
    from app import product_billing as pb
    from app import models
    _, user_id, _ = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    pid = _seed_purchase(p164_env, user_id, rid, status="pending",
                         session_id="cs_job")
    _backdate_purchase(p164_env, pid, hours=48)
    _stub_session_get(monkeypatch, {"cs_job": "open"})
    with p164_env.sessions() as db:
        assert pb.expire_stale_pending_product_purchases(db) == 0
        db.commit()
        assert db.get(models.ProductPurchase, pid).status == "pending"
    _stub_session_get(monkeypatch, {"cs_job": "expired"})
    with p164_env.sessions() as db:
        assert pb.expire_stale_pending_product_purchases(db) == 1
        db.commit()
        assert db.get(models.ProductPurchase, pid).status == "failed"


def test_admission_and_settlement_share_stable_lock_p1c(p164_env):
    # Construction evidence (sqlite): settlement and checkout
    # admission take the SAME stable per-(user, source, sku)
    # CapacityScope lock row, and the row is a lock only (used == 0,
    # no capacity consumed). The live serialisation is PostgreSQL —
    # see the pg-gated test below (CI evidence).
    from app import product_billing as pb
    from app import models
    _, user_id, _ = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    pid = _seed_purchase(p164_env, user_id, rid, status="pending",
                         session_id="cs_test_1")
    key = pb.admission_lock_key(user_id, rid, "investigation_report")
    with p164_env.sessions() as db:
        purchase = db.get(models.ProductPurchase, pid)
        out = pb.settle_product_purchase(
            db, purchase, stripe_event_id="evt_lock",
            stripe_session_id="cs_test_1",
            event_metadata={"kind": "product", "purchase_id": str(pid),
                            "user_id": str(user_id),
                            "sku": "investigation_report",
                            "pricing_version": "1"},
            amount_cents=900, currency="usd", payment_intent_id="pi_test_1",
            payment_status="paid", session_status="complete",
            mode="payment", session_price_id=PRICE_ID, livemode=False)
        assert out == "processed"
        db.commit()
        scope = db.query(models.CapacityScope).filter_by(scope_key=key).one()
        assert scope.used == 0
    rid2 = _source(p164_env, user_id)
    key2 = pb.admission_lock_key(user_id, rid2, "investigation_report")
    with p164_env.sessions() as db:
        _p, reused = pb.create_pending_product_purchase(
            db, user_id, "investigation_report", rid2)
        assert reused is False
        db.commit()
        scope2 = db.query(models.CapacityScope).filter_by(scope_key=key2).one()
        assert scope2.used == 0


def test_cleanup_preserves_source_with_pending_purchase_p1d(p164_env):
    # A pending product purchase protects its source's redemption
    # prerequisites exactly like an open-window entitlement: the
    # session can still settle and grant. Once the purchase is
    # terminal, cleanup proceeds normally.
    from app import credit_maintenance
    from app import models
    _, user_id, _ = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    pid = _seed_purchase(p164_env, user_id, rid, status="pending",
                         session_id="cs_pend")
    with p164_env.sessions() as db:
        src = db.get(models.Result, rid)
        manifest_before = src.storage_manifest
        src.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        db.commit()
    with p164_env.sessions() as db:
        credit_maintenance.cleanup_results(db)
    with p164_env.sessions() as db:
        src = db.get(models.Result, rid)
        assert src.deleted_at is None
        assert src.storage_manifest == manifest_before
        p = db.get(models.ProductPurchase, pid)
        p.status = "failed"
        db.commit()
    with p164_env.sessions() as db:
        credit_maintenance.cleanup_results(db)
    with p164_env.sessions() as db:
        src = db.get(models.Result, rid)
        assert src.deleted_at is not None
        assert src.storage_manifest == "{}"


def test_pending_insert_race_reuses_winner_p2a(p164_env, monkeypatch):
    # The winner of a pending-insert race is inserted (via the same
    # session, flushed) at the one moment the loser has already
    # SELECTed pending=None but not yet constructed its row — the
    # product_price_id call inside purchase construction. The loser's
    # flush then hits the partial unique index INSIDE its savepoint
    # and it must reuse the winner, not die with the outer
    # transaction aborted.
    from app import product_billing as pb
    from app import models, stripe_billing
    _, user_id, _ = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    orig_price = stripe_billing.product_price_id
    state = {"done": False, "winner_id": None}
    holder = {}
    def sneaky_price(sku):
        if not state["done"]:
            state["done"] = True
            db = holder["db"]
            w = models.ProductPurchase(
                user_id=user_id, sku="investigation_report",
                source_result_id=rid, amount_cents=900, currency="usd",
                stripe_price_id=PRICE_ID, pricing_version=1, status="pending")
            db.add(w)
            db.flush()
            state["winner_id"] = w.id
        return orig_price(sku)
    monkeypatch.setattr(stripe_billing, "product_price_id", sneaky_price)
    with p164_env.sessions() as db:
        holder["db"] = db
        purchase, reused = pb.create_pending_product_purchase(
            db, user_id, "investigation_report", rid)
        assert reused is True
        assert purchase.id == state["winner_id"]
        db.commit()
        assert db.query(models.ProductPurchase).filter_by(
            status="pending").count() == 1


def test_reconciliation_product_cross_midnight_settles_clean_both_days_p2b(p164_env):
    # Session CREATED day 1, purchase SETTLED (completed_at) day 2:
    # the session counts on day 2 (settlement day) on BOTH sides.
    # Day 1 must show neither an orphan session nor a mismatch;
    # day 2 pairs the prior-day session with the ledger gross.
    from app import payment_reconcile as PR
    from app import models
    _, user_id, _ = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    ent_id = _seed_entitlement(p164_env, user_id, rid)
    day1 = datetime(2026, 1, 1, tzinfo=timezone.utc).date()
    day2 = datetime(2026, 1, 2, tzinfo=timezone.utc).date()
    with p164_env.sessions() as db:
        ent = db.get(models.Entitlement, ent_id)
        pid = ent.product_purchase_id
        p = db.get(models.ProductPurchase, pid)
        p.stripe_session_id = "cs_xmid"
        p.completed_at = datetime(2026, 1, 2, 0, 30, tzinfo=timezone.utc)
        db.commit()
        session = {"id": "cs_xmid", "amount_total": 900,
                   "payment_intent": "pi_xmid",
                   "metadata": {"kind": "product", "purchase_id": str(pid),
                                "sku": "investigation_report"}}
        r1 = PR.compute_reconciliation(db, day1, [session], [])
        fam1 = r1["per_family"]["product"]
        assert fam1["stripe_gross_cents"] == 0
        assert fam1["ledger_gross_cents"] == 0
        assert not [d for d in r1["differences"] if d.get("family") == "product"]
        r2 = PR.compute_reconciliation(db, day2, [], [], prior_sessions=[session])
        fam2 = r2["per_family"]["product"]
        assert fam2["stripe_gross_cents"] == 900
        assert fam2["ledger_gross_cents"] == 900
        assert fam2["stripe_net_cents"] == fam2["ledger_net_cents"] == 900
        assert not [d for d in r2["differences"] if d.get("family") == "product"]


def test_reconciliation_partial_product_refund_nets_clean_p2c(p164_env):
    # The finding's example: a $3 partial refund on a $9 purchase.
    # The amount is persisted on the purchase, the entitlement stays
    # intact (F3), and reconciliation nets 600 == 600 with no
    # family_total_mismatch.
    from app import payment_reconcile as PR
    from app import models
    _, user_id, _ = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    purchase = _settled_purchase(p164_env, user_id, rid)
    _post_event(p164_env, _charge_event(
        "evt_partial_p2c", purchase, etype="charge.refunded",
        amount=900, refunded=300))
    with p164_env.sessions() as db:
        p = db.get(models.ProductPurchase, purchase.id)
        assert p.refunded_cents == 300
        assert p.status == "completed"
        assert db.query(models.Entitlement).one().status == "available"
        day = p.completed_at.date()
        session = {"id": p.stripe_session_id or "cs_test_1",
                   "amount_total": 900, "payment_intent": "pi_test_1",
                   "metadata": {"kind": "product", "purchase_id": str(p.id),
                                "sku": "investigation_report"}}
        charge = {"id": "ch_partial_p2c", "amount": 900,
                  "amount_refunded": 300, "payment_intent": "pi_test_1",
                  "metadata": {}, "disputed": False}
        result = PR.compute_reconciliation(db, day, [session], [charge])
    fam = result["per_family"]["product"]
    assert fam["stripe_refund_cents"] == 300
    assert fam["ledger_refund_cents"] == 300
    assert fam["stripe_net_cents"] == fam["ledger_net_cents"] == 600
    assert not any(d["kind"] == "family_total_mismatch"
                   for d in result["differences"])


def test_run_once_stale_credit_expiry_survives_recovery_p2d(p164_env, monkeypatch):
    # run_once order: expire_stale_pending_purchases flushes the
    # expiry, then recover_expired_redemptions unconditionally rolls
    # back after candidate selection. With per-job committed
    # boundaries the expiry PERSISTS in a fresh session.
    from app import credit_maintenance as cm
    from app import models
    _, user_id, _ = _make_user(p164_env)
    with p164_env.sessions() as db:
        p = models.CreditPurchase(
            user_id=user_id, pack_id="starter", credits=10,
            pricing_version=1, status="pending")
        db.add(p)
        db.commit()
        pid = p.id
        p.created_at = datetime.now(timezone.utc) - timedelta(hours=48)
        db.commit()
    monkeypatch.setattr("app.main.cleanup_pending_uploads", lambda: None)
    cm.run_once(reconcile=False)
    with p164_env.sessions() as db:
        assert db.get(models.CreditPurchase, pid).status == "failed"


def test_run_once_product_expire_and_lapse_survive_reconcile_p2d(p164_env, monkeypatch):
    # With reconcile=True, _reconcile_all_accounts' entry rollback
    # previously discarded the product expire + lapse jobs' flushed
    # work. Both must persist after a full run_once.
    from app import credit_maintenance as cm
    from app import models
    _, user_id, _ = _make_user(p164_env)
    rid = _source(p164_env, user_id)
    pid = _seed_purchase(p164_env, user_id, rid, status="pending",
                         session_id=None)
    _backdate_purchase(p164_env, pid, hours=48)
    ent_id = _seed_entitlement(
        p164_env, user_id, rid,
        deadline=datetime.now(timezone.utc) - timedelta(days=1))
    monkeypatch.setattr("app.main.cleanup_pending_uploads", lambda: None)
    cm.run_once(reconcile=True)
    with p164_env.sessions() as db:
        assert db.get(models.ProductPurchase, pid).status == "failed"
        assert db.get(models.Entitlement, ent_id).status == "refund_eligible"


# --- A1: PostgreSQL concurrency legs (CI only) ------------------------------
# Unique schema migrated to Alembic head per test (which also proves
# migration 0017 upgrades cleanly on PostgreSQL), NullPool factories so
# every thread uses its own connection, barrier-synchronized races.

pgmark = pytest.mark.skipif(
    not os.environ.get("TEST_POSTGRES_URL"),
    reason="TEST_POSTGRES_URL is required for PostgreSQL concurrency tests")


@pytest.fixture
def pg_factory():
    from pathlib import Path
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, text
    from sqlalchemy.pool import NullPool
    url = os.environ["TEST_POSTGRES_URL"]
    schema = "p164_test_" + uuid.uuid4().hex
    admin = create_engine(url, poolclass=NullPool)
    with admin.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_engine(
        url, connect_args={"options": f"-csearch_path={schema}"}, poolclass=NullPool)
    config = Config()
    config.set_main_option("script_location", str(Path(__file__).parents[1] / "alembic"))
    try:
        with engine.begin() as conn:
            config.attributes["connection"] = conn
            command.upgrade(config, "head")
        yield sessionmaker(bind=engine, autoflush=False), engine
    finally:
        engine.dispose()
        with admin.begin() as conn:
            conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


def _pg_seed(factory):
    from app import models as M
    now = datetime.now(timezone.utc)
    with factory() as db:
        user = M.User(email=f"pg_{uuid.uuid4().hex[:8]}@example.com", email_verified=True)
        db.add(user)
        db.flush()
        source = M.Result(
            user_id=user.id, type="analysis", free_request_id=f"pg-{uuid.uuid4().hex}",
            storage_manifest="{}", integrity_digest="x" * 64, byte_count=2,
            ready_at=now, expires_at=now + timedelta(days=7))
        db.add(source)
        db.flush()
        purchase = M.ProductPurchase(
            user_id=user.id, sku="investigation_report", source_result_id=source.id,
            amount_cents=900, currency="usd", stripe_price_id=PRICE_ID,
            pricing_version=1, status="completed", completed_at=now)
        db.add(purchase)
        db.flush()
        ent = M.Entitlement(
            user_id=user.id, product_purchase_id=purchase.id,
            sku="investigation_report", source_result_id=source.id,
            status="available", redemption_deadline=now + timedelta(days=37))
        db.add(ent)
        db.commit()
        return user.id, source.id, ent.id


@pgmark
def test_pg_same_entitlement_race_exactly_one_reserves(pg_factory):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from app import product_billing as pb
    from app import models as M
    from app.credits import AdmissionError
    factory, _engine = pg_factory
    _uid, _rid, ent_id = _pg_seed(factory)
    barrier = Barrier(2)

    def attempt(worker):
        with factory() as db:
            ent = db.get(M.Entitlement, ent_id)
            barrier.wait(timeout=10)
            try:
                red = pb.reserve_redemption(db, ent, request_hash="a" * 64, worker_id=worker)
                db.commit()
                return ("ok", str(red.id))
            except AdmissionError:
                db.rollback()
                return ("rejected", None)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, ["w1", "w2"]))
    assert sorted(r[0] for r in results) == ["ok", "rejected"]
    with factory() as db:
        live = db.query(M.EntitlementRedemption).filter(
            M.EntitlementRedemption.status == "reserved").count()
        assert live == 1


def _pg_seed_pending(factory):
    from app import models as M
    now = datetime.now(timezone.utc)
    with factory() as db:
        user = M.User(email=f"pg_{uuid.uuid4().hex[:8]}@example.com", email_verified=True)
        db.add(user)
        db.flush()
        source = M.Result(
            user_id=user.id, type="analysis", free_request_id=f"pg-{uuid.uuid4().hex}",
            storage_manifest="{}", integrity_digest="x" * 64, byte_count=2,
            ready_at=now, expires_at=now + timedelta(days=7))
        db.add(source)
        db.flush()
        purchase = M.ProductPurchase(
            user_id=user.id, sku="investigation_report", source_result_id=source.id,
            stripe_session_id="cs_pg_1", amount_cents=900, currency="usd",
            stripe_price_id=PRICE_ID, pricing_version=1, status="pending")
        db.add(purchase)
        db.commit()
        return user.id, source.id, purchase.id


@pgmark
def test_pg_admission_lock_blocks_settlement_until_release_p1c(pg_factory):
    # Deterministic P1-C evidence on PostgreSQL: while a checkout
    # admission transaction holds the stable per-(user, source, sku)
    # lock, a concurrent settlement of the same (user, source, sku)
    # CANNOT commit its grant in between the admission lookups; it
    # proceeds only after the admission transaction ends, and then
    # grants exactly one entitlement.
    import threading
    from app import product_billing as pb
    from app import models as M
    factory, _engine = pg_factory
    uid, rid, pid = _pg_seed_pending(factory)
    locked = threading.Event()
    release = threading.Event()
    settled = threading.Event()
    outcome = {}

    def hold_admission():
        with factory() as db:
            pb.lock_product_admission(db, uid, rid, "investigation_report")
            db.flush()
            locked.set()
            release.wait(timeout=20)
            db.commit()

    def settle():
        with factory() as db:
            purchase = db.get(M.ProductPurchase, pid)
            outcome["result"] = pb.settle_product_purchase(
                db, purchase, stripe_event_id="evt_pg_lock",
                stripe_session_id="cs_pg_1",
                event_metadata={"kind": "product", "purchase_id": str(pid),
                                "user_id": str(uid),
                                "sku": "investigation_report",
                                "pricing_version": "1"},
                amount_cents=900, currency="usd",
                payment_intent_id="pi_pg_1", payment_status="paid",
                session_status="complete", mode="payment",
                session_price_id=PRICE_ID, livemode=False)
            db.commit()
            settled.set()

    holder = threading.Thread(target=hold_admission)
    holder.start()
    assert locked.wait(timeout=15)
    worker = threading.Thread(target=settle)
    worker.start()
    # While the admission lock is held, settlement must not finish.
    assert not settled.wait(timeout=3)
    release.set()
    assert settled.wait(timeout=20)
    holder.join(timeout=20)
    worker.join(timeout=20)
    assert outcome["result"] == "processed"
    with factory() as db:
        assert db.query(M.Entitlement).count() == 1


@pgmark
def test_pg_revoke_during_generation_wins(pg_factory):
    from app import product_billing as pb
    from app import models as M
    from app.credits import AdmissionError
    factory, _engine = pg_factory
    _uid, _rid, ent_id = _pg_seed(factory)
    with factory() as db:
        ent = db.get(M.Entitlement, ent_id)
        red = pb.reserve_redemption(db, ent, request_hash="b" * 64, worker_id="w1")
        db.commit()
        red_id = red.id
    with factory() as db:
        assert pb.revoke_entitlement(db, db.get(M.Entitlement, ent_id)) is True
        db.commit()
    with factory() as db:
        with pytest.raises(AdmissionError):
            pb.complete_redemption(db, red_id, "w1", result_id=None)
        db.rollback()
        assert db.get(M.Entitlement, ent_id).status == "revoked"
