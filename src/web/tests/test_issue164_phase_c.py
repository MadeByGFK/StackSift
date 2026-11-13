"""Issue #164 Phase C: retire credit packs + credit UX — spec v1.1
(C1–C8 + C7.1 + founder CALL-1 hard-cap ruling, 2026-11-13).

Groups mirror the spec's Tests section:
 1 pack closure (410, zero Stripe, zero rows)   2 webhook legacy posture
 3 signup grant removed (C4)                    4 exports free + C2 matrix
 5 retention refusal / replay (C5)              6 display removal (C3)
 7 pricing page (dollar terms)                  8 data preservation
 9 reconciliation post-cutover alert (C6a)      10 hard cap (C1)
 11 C7.1 has_pdf_export_operation pins           12 runtime interaction

These tests FAIL on the base tree (packs live, signup grant 10,
export unlock charged, retention sold, badge/balance live) and PASS
on the built tree, except the premise-PRESERVED pins noted inline
(legacy settlement, C7.1 completed-op behaviour, identical-404).
"""
import copy
import hashlib
import hmac
import json
import re
import time
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

TEST_PASSWORD = "TestPass123!x"
WEBHOOK_SECRET = "whsec_test_164c"
PACK_PRICES = {"starter": "price_test_starter", "growth": "price_test_growth",
               "power": "price_test_power"}
PRICE_BY_SKU = {
    "compare": "price_test_compare",
    "batch": "price_test_batch",
    "large_file_analysis": "price_test_large_file",
    "investigation_report": "price_test_investigation",
}
LOG_A = b"2024-01-01 10:00:00 ERROR database connection failed\n" * 10


@pytest.fixture
def p164c_env(tmp_path, monkeypatch):
    from app import auth, email, main
    from app.db import Base, get_db
    import app.db as db_module
    from app.main import app
    engine = create_engine(
        f"sqlite:///{tmp_path / 'p164c.db'}",
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
    monkeypatch.setattr(main, "_PAID_PENDING_DIR", str(tmp_path / "pending"))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'p164c.db'}")
    for pack_id, price in PACK_PRICES.items():
        monkeypatch.setenv(f"STRIPE_PRICE_{pack_id.upper()}", price)
    monkeypatch.setenv("STRIPE_PRICE_COMPARE", PRICE_BY_SKU["compare"])
    monkeypatch.setenv("STRIPE_PRICE_BATCH", PRICE_BY_SKU["batch"])
    monkeypatch.setenv("STRIPE_PRICE_LARGE_FILE", PRICE_BY_SKU["large_file_analysis"])
    monkeypatch.setenv("STRIPE_PRICE_INVESTIGATION_REPORT",
                       PRICE_BY_SKU["investigation_report"])
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_164c_fixture")
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", WEBHOOK_SECRET)
    sent = []
    monkeypatch.setattr(email, "send_verification_email",
                        lambda a, t: sent.append(("verify", a, t)))
    monkeypatch.setattr(email, "send_password_reset_email",
                        lambda a, t: sent.append(("reset", a, t)))
    from app.service import analyze_upload as service_analyze
    from app.sample_data import SAMPLE_LOG
    sample_report = service_analyze("test.log", SAMPLE_LOG.encode())
    monkeypatch.setattr(main, "analyze_upload",
                        lambda *a, **k: copy.deepcopy(sample_report))
    try:
        with TestClient(app, base_url="https://testserver",
                        raise_server_exceptions=False,
                        client=("127.0.0.1", 50000)) as client:
            client.headers["X-CSRF-Token"] = \
                client.get("/auth/csrf").json()["csrf_token"]
            yield SimpleNamespace(client=client, sessions=sessions,
                                  sent=sent, engine=engine, app=app,
                                  monkeypatch=monkeypatch)
    finally:
        engine.dispose()


def _make_user(env, email=None):
    from app.models import User
    email = email or f"u{uuid.uuid4().hex[:8]}@example.com"
    c = env.client
    c.post("/auth/logout")
    c.headers["X-CSRF-Token"] = c.get("/auth/csrf").json()["csrf_token"]
    assert c.post("/auth/signup", data={"email": email,
                                        "password": TEST_PASSWORD}).status_code == 200
    token = next(t for kind, addr, t in env.sent
                 if kind == "verify" and addr == email)
    assert c.post("/auth/verify", data={"token": token}).status_code == 200
    c.headers["X-CSRF-Token"] = c.get("/auth/csrf").json()["csrf_token"]
    resp = c.post("/auth/login", data={"email": email, "password": TEST_PASSWORD})
    assert resp.status_code == 200, resp.text
    with env.sessions() as db:
        user_id = db.query(User).filter(User.email == email).one().id
    return email, user_id, resp.json()["csrf_token"]


def _grant(env, user_id, qty, key=None):
    from app import credits as C
    with env.sessions() as db:
        g = C.grant_credits(db, user_id, "purchase",
                            key or f"test-{uuid.uuid4().hex}", qty)
        db.commit()
        return g.id


def _balance(env, user_id):
    from app import models as M
    with env.sessions() as db:
        acct = db.query(M.CreditAccount).filter(
            M.CreditAccount.user_id == user_id).first()
        return acct.balance if acct else None


def _make_report(env, uid, *, expires_in_days=7, result_type="analysis",
                 payload=None):
    import json as _json
    from app import credits as C, models as M
    from app.sample_data import SAMPLE_LOG
    from app.service import analyze_upload
    if payload is None:
        payload = copy.deepcopy(analyze_upload("test.log", SAMPLE_LOG.encode()))
        payload["filename"] = "test.log"
        payload.pop("current_user", None)
        payload.pop("csrf_token", None)
    raw = _json.dumps(payload, default=str)
    now = C._utcnow()
    with env.sessions() as db:
        r = M.Result(
            user_id=uid, free_request_id=uuid.uuid4().hex, type=result_type,
            storage_manifest=raw, integrity_digest=C.hash_input(raw.encode()),
            byte_count=len(raw.encode()),
            ready_at=now, expires_at=now + timedelta(days=expires_in_days))
        db.add(r)
        db.commit()
        db.refresh(r)
        return r.id


def _fake_stripe(monkeypatch):
    import httpx
    captured = []
    state = {"n": 0}

    class Resp:
        def __init__(self, payload):
            self.status_code = 200
            self._payload = payload

        def json(self):
            return self._payload

    def _post(url, data=None, auth=None, headers=None, timeout=None):
        captured.append({"url": url, "data": data or {}})
        state["n"] += 1
        sid = f"cs_test_{state['n']}"
        return Resp({"url": f"https://checkout.stripe.com/pay/{sid}", "id": sid})

    monkeypatch.setattr(httpx, "post", _post)
    return captured


def _sign(payload: bytes, secret=WEBHOOK_SECRET, ts=None):
    ts = ts if ts is not None else int(time.time())
    sig = hmac.new(secret.encode(), f"{ts}.".encode() + payload,
                   hashlib.sha256).hexdigest()
    return f"t={ts},v1={sig}"


def _post_event(env, event_dict):
    raw = json.dumps(event_dict).encode()
    return env.client.post(
        "/credits/webhook", content=raw,
        headers={"stripe-signature": _sign(raw),
                 "content-type": "application/json"})


def _pack_event(event_id, session_id, purchase_id, user_id, *,
                pack_id="starter", amount=500, kind=None):
    meta = {"pack_id": pack_id, "purchase_id": str(purchase_id),
            "user_id": str(user_id), "pricing_version": "1"}
    if kind:
        meta["kind"] = kind
    return {"id": event_id, "type": "checkout.session.completed",
            "livemode": False,
            "data": {"object": {
                "id": session_id, "payment_status": "paid",
                "status": "complete", "mode": "payment",
                "amount_total": amount, "currency": "usd",
                "payment_intent": f"pi_{session_id}",
                "metadata": meta}}}


# --- Group 1: pack closure ---------------------------------------------------

def test_pack_checkout_410_zero_stripe_zero_rows(p164c_env):
    env = p164c_env
    _, uid, csrf = _make_user(env)
    captured = _fake_stripe(env.monkeypatch)
    from app import models as M
    for pack_id in ("starter", "growth", "power"):
        r = env.client.post("/credits/checkout",
                            data={"pack_id": pack_id, "csrf_token": csrf})
        assert r.status_code == 410, (pack_id, r.text[:200])
        assert "retired" in r.json()["error"]
    assert captured == []
    with env.sessions() as db:
        assert db.query(M.CreditPurchase).count() == 0


def test_pricing_page_has_no_pack_grid(p164c_env):
    env = p164c_env
    r = env.client.get("/credits")
    assert r.status_code == 200
    assert 'id="packs"' not in r.text
    assert 'name="pack_id"' not in r.text
    assert "/credits/checkout" not in r.text


# --- Group 2: webhook legacy posture (premise-PRESERVED settlement) ----------

def test_pack_webhook_redelivery_idempotent_no_second_grant(p164c_env):
    env = p164c_env
    _, uid, _csrf = _make_user(env)
    from app import credits as C, models as M
    with env.sessions() as db:
        purchase = C.create_pending_purchase(db, uid, "starter")
        db.commit()
        pid, sid = purchase.id, "cs_test_legacy_1"
        purchase.stripe_session_id = sid
        db.commit()
    ev = _pack_event("evt_legacy_1", sid, pid, uid)
    r = _post_event(env, ev)
    assert r.status_code == 200, r.text[:300]
    bal_after_first = _balance(env, uid)
    assert bal_after_first == 10  # starter = 10 credits, settled once
    # Redelivery with a NEW event id for the same completed purchase:
    # idempotent no-op, no second grant.
    ev2 = _pack_event("evt_legacy_2", sid, pid, uid)
    r = _post_event(env, ev2)
    assert r.status_code == 200, r.text[:300]
    assert _balance(env, uid) == bal_after_first
    with env.sessions() as db:
        grants = db.query(M.CreditGrant).filter(
            M.CreditGrant.user_id == uid, M.CreditGrant.source == "purchase").all()
        assert len(grants) == 1


def test_pack_webhook_kind_contradiction_fails_closed(p164c_env):
    env = p164c_env
    _, uid, _csrf = _make_user(env)
    from app import credits as C, models as M
    with env.sessions() as db:
        purchase = C.create_pending_purchase(db, uid, "starter")
        db.commit()
        pid = purchase.id
        purchase.stripe_session_id = "cs_test_contra"
        db.commit()
    # Pack purchase whose event claims kind=product: contradiction.
    ev = _pack_event("evt_contra_1", "cs_test_contra", pid, uid, kind="product")
    r = _post_event(env, ev)
    assert r.status_code in (400, 409, 422, 500) or _balance(env, uid) in (0, None)
    with env.sessions() as db:
        p = db.get(M.CreditPurchase, pid)
        assert p.status != "completed"


def test_unknown_pack_purchase_event_ignored(p164c_env):
    env = p164c_env
    _, uid, _csrf = _make_user(env)
    ev = _pack_event("evt_unknown_1", "cs_test_nope", uuid.uuid4(), uid)
    r = _post_event(env, ev)
    assert r.status_code == 200, r.text[:300]
    assert _balance(env, uid) in (0, None)


# --- Group 3: signup grant removed (C4) ---------------------------------------

def test_new_signup_creates_no_grant_account_or_ledger(p164c_env):
    env = p164c_env
    email, uid, _csrf = _make_user(env)
    from app import models as M
    with env.sessions() as db:
        assert db.query(M.CreditGrant).filter(
            M.CreditGrant.user_id == uid).count() == 0
        assert db.query(M.CreditAccount).filter(
            M.CreditAccount.user_id == uid).count() == 0
        assert db.query(M.CreditLedger).filter(
            M.CreditLedger.user_id == uid).count() == 0
        elig = db.query(M.SignupEligibility).filter(
            M.SignupEligibility.email_normalized == email).first()
        assert elig is None or not elig.grant_issued


def test_signup_reward_helper_disabled_no_error_no_writes(p164c_env):
    env = p164c_env
    _, uid, _csrf = _make_user(env)
    from app import credits as C, models as M
    with env.sessions() as db:
        assert C.grant_signup_reward(db, uid, "x@example.com") is None
        db.commit()
        assert db.query(M.CreditGrant).count() == 0
        assert db.query(M.SignupEligibility).count() == 0
    # grant_credits keeps its quantity > 0 invariant (C4)
    with env.sessions() as db:
        with pytest.raises(AssertionError):
            C.grant_credits(db, uid, "purchase", "k-zero", 0)


def test_signup_and_pricing_copy_no_free_credit_claim(p164c_env):
    env = p164c_env
    env.client.post("/auth/logout")
    r = env.client.get("/signup")
    assert "10 free credits" not in r.text
    r = env.client.get("/credits")
    assert "10 free credits" not in r.text
    assert "free credits" not in r.text.lower().replace(
        "no longer receive signup credits", "")


# --- Group 4: exports free + C2 matrix ----------------------------------------

def test_owner_pdf_export_free_no_balance_consult(p164c_env):
    env = p164c_env
    _, uid, csrf = _make_user(env)
    rid = _make_report(env, uid)  # zero-balance user (no grant anymore)
    r = env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert r.status_code == 200, r.text[:300]
    assert r.headers["content-type"].startswith("application/pdf")
    assert _balance(env, uid) in (0, None)


def test_owner_structured_export_free(p164c_env):
    env = p164c_env
    _, uid, csrf = _make_user(env)
    rid = _make_report(env, uid)
    for fmt in ("csv", "json"):
        r = env.client.post(f"/reports/{rid}/exports/{fmt}",
                            data={"csrf_token": csrf})
        assert r.status_code == 200, (fmt, r.text[:300])
    assert _balance(env, uid) in (0, None)


def test_comparison_structured_export_still_422(p164c_env):
    """C2: Phase C changes price only — comparison CSV/JSON stays
    unsupported (422), owner PDF is free."""
    env = p164c_env
    _, uid, csrf = _make_user(env)
    rid = _make_report(env, uid, result_type="comparison")
    r = env.client.post(f"/reports/{rid}/exports/csv",
                        data={"csrf_token": csrf})
    assert r.status_code == 422, r.text[:300]


def test_expired_report_exports_still_410(p164c_env):
    env = p164c_env
    _, uid, csrf = _make_user(env)
    rid = _make_report(env, uid, expires_in_days=-1)
    r = env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert r.status_code == 410
    r = env.client.post(f"/reports/{rid}/exports/json",
                        data={"csrf_token": csrf})
    assert r.status_code == 410


def test_export_creates_no_charge_operation(p164c_env):
    env = p164c_env
    _, uid, csrf = _make_user(env)
    rid = _make_report(env, uid)
    from app import models as M
    r = env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert r.status_code == 200
    with env.sessions() as db:
        ops = db.query(M.Operation).filter(M.Operation.user_id == uid).all()
        assert ops == []  # free generation creates no paid operation
        assert db.query(M.CreditLedger).filter(
            M.CreditLedger.user_id == uid).count() == 0


def test_share_link_pdf_and_json_free_on_link_authority(p164c_env):
    env = p164c_env
    _, uid, csrf = _make_user(env)
    rid = _make_report(env, uid)
    for fmt in ("pdf", "json"):
        r = env.client.post(
            f"/reports/{rid}/share",
            data={"csrf_token": csrf, "idempotency_key": f"share-{fmt}",
                  "share_format": fmt})
        assert r.status_code == 200, (fmt, r.text[:300])
        token = r.json()["share_url"].rsplit("/", 1)[1]
        anon = TestClient(env.app, base_url="https://testserver",
                          raise_server_exceptions=False)
        resp = anon.get(f"/s/{token}")
        assert resp.status_code == 200, (fmt, resp.text[:200])


def test_share_create_gated_format_no_402(p164c_env):
    """C8 premise-changed: locked-format share creation is gone."""
    env = p164c_env
    _, uid, csrf = _make_user(env)
    rid = _make_report(env, uid)
    r = env.client.post(
        f"/reports/{rid}/share",
        data={"csrf_token": csrf, "idempotency_key": "share-csv",
              "share_format": "csv"})
    assert r.status_code == 200, r.text[:300]
    assert "export_unlock_required" not in r.text


# --- Group 5: retention (C5) ---------------------------------------------------

def _seed_completed_extension(env, uid, rid, key="ret-key-1"):
    from app import credits as C, models as M
    from app import report_access as ra
    with env.sessions() as db:
        source = db.get(M.Result, rid)
        new_expiry = C._as_aware(source.expires_at) + timedelta(days=90)
        db.add(M.ReportAction(
            owner_user_id=uid, result_id=rid,
            action_kind="retention_extension", idempotency_key=key,
            request_hash=ra.action_request_hash(source, "retention_extension"),
            resulting_expiry=new_expiry, operation_id=None))
        source.expires_at = new_expiry
        db.commit()
        return new_expiry


def test_new_retention_extension_refused_410_no_mutation(p164c_env):
    env = p164c_env
    _, uid, csrf = _make_user(env)
    _grant(env, uid, 10)  # even a funded legacy balance cannot buy
    rid = _make_report(env, uid)
    from app import models as M
    with env.sessions() as db:
        before = db.get(M.Result, rid).expires_at
    r = env.client.post(f"/reports/{rid}/retention",
                        data={"csrf_token": csrf,
                              "idempotency_key": "new-ext-1"})
    assert r.status_code == 410, r.text[:300]
    assert "no longer sold" in r.json()["error"]
    with env.sessions() as db:
        assert db.get(M.Result, rid).expires_at == before
        assert db.query(M.ReportAction).filter(
            M.ReportAction.result_id == rid).count() == 0
    assert _balance(env, uid) == 10


def test_completed_extension_replay_post_cutover(p164c_env):
    """C5: a completed ReportAction retry returns its recorded
    response — never a second charge, never a 410."""
    env = p164c_env
    _, uid, csrf = _make_user(env)
    rid = _make_report(env, uid)
    new_expiry = _seed_completed_extension(env, uid, rid)
    r = env.client.post(f"/reports/{rid}/retention",
                        data={"csrf_token": csrf,
                              "idempotency_key": "ret-key-1"})
    assert r.status_code == 200, r.text[:300]
    body = r.json()
    assert body["replayed"] is True
    assert body["expires_at"].startswith(new_expiry.strftime("%Y-%m-%dT%H:%M"))


def test_extended_credit_era_report_exports_free_until_expiry(p164c_env):
    env = p164c_env
    _, uid, csrf = _make_user(env)
    rid = _make_report(env, uid)
    _seed_completed_extension(env, uid, rid)
    r = env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert r.status_code == 200


# --- Group 6: display removal (C3) ----------------------------------------------

def test_balance_endpoints_retired_410(p164c_env):
    env = p164c_env
    _make_user(env)
    for path in ("/auth/balance", "/credits/balance"):
        r = env.client.get(path)
        assert r.status_code == 410, (path, r.status_code)
        assert r.json().get("balance") is None  # no stale JSON served


def test_header_badge_and_quickbuy_removed_from_shared_script(p164c_env):
    env = p164c_env
    _make_user(env)
    r = env.client.get("/")
    assert "credit-badge" not in r.text
    assert "showCreditModal" not in r.text
    assert "/auth/balance" not in r.text
    assert "MODAL_PACKS" not in r.text


def test_settings_no_balance_no_buy_credits_plan_dollar(p164c_env):
    env = p164c_env
    _make_user(env)
    r = env.client.get("/settings")
    assert r.status_code == 200, r.text[:200]
    assert "Buy credits" not in r.text
    assert "credits available" not in r.text
    assert "Your current balance" not in r.text
    assert "Pay per report" in r.text
    assert "Purchase history" in r.text


def test_no_buy_credits_cta_on_402_pages(p164c_env):
    env = p164c_env
    _, uid, csrf = _make_user(env)
    r = env.client.get("/")
    assert "Buy credits" not in r.text


# --- Group 7: pricing page -------------------------------------------------------

def test_pricing_page_dollar_terms(p164c_env):
    env = p164c_env
    r = env.client.get("/credits")
    assert r.status_code == 200
    text = r.text
    for needle in ("$9", "$5", "Investigation Report", "Compare",
                   "Batch Analysis", "Large-File Analysis",
                   "Exports are free", "90 days",
                   "disputes@goodfolkdigital.com",
                   "Payment is captured at checkout"):
        assert needle in text, needle
    for banned in ("Simple credits", "Credit packs", "credits added to your balance",
                   "Credits never expire", "How many credits does",
                   "What are credits?", "2 credits per report",
                   "3 credits per run", "get 10 free credits"):
        assert banned not in text, banned
    assert 'id="offers"' in text and "offer-card" in text


def test_pricing_route_alias_preserved(p164c_env):
    env = p164c_env
    r = env.client.get("/pricing", follow_redirects=False)
    assert r.status_code == 301
    assert r.headers["location"].endswith("/credits")


def test_pricing_no_return_banner_from_query(p164c_env):
    """C6c: no settled/entitlement banner from a query string."""
    env = p164c_env
    _make_user(env)
    r = env.client.get("/credits?checkout=success")
    assert "credits are on their way" not in r.text
    assert "credits added to your balance" not in r.text
    assert "checkout-banner" not in r.text


# --- Group 8: data preservation ---------------------------------------------------

def test_credit_era_rows_byte_identical_after_flows(p164c_env):
    env = p164c_env
    _, uid, csrf = _make_user(env)
    from app import credits as C, models as M
    with env.sessions() as db:
        purchase = C.create_pending_purchase(db, uid, "growth")
        purchase.status = "completed"
        purchase.completed_at = C._utcnow()
        db.commit()
        pid = purchase.id
    _grant(env, uid, 25, key=f"purchase-grant-{pid}")
    rid = _make_report(env, uid)

    def snapshot():
        with env.sessions() as db:
            out = {}
            for model, name in ((M.CreditAccount, "acct"), (M.CreditGrant, "grant"),
                                (M.CreditLedger, "ledger"), (M.CreditPurchase, "purchase")):
                rows = db.query(model).all()
                out[name] = sorted(
                    repr({c.name: getattr(row, c.name)
                          for c in model.__table__.columns})
                    for row in rows)
            return out

    before = snapshot()
    env.client.get("/credits")
    env.client.post("/credits/checkout",
                    data={"pack_id": "starter", "csrf_token": csrf})
    env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    env.client.get("/settings")
    after = snapshot()
    assert before == after


# --- Group 9: reconciliation (C6a) --------------------------------------------------

def test_reconciliation_post_cutover_pack_completion_alerts(p164c_env, monkeypatch):
    from datetime import date
    env = p164c_env
    _, uid, _csrf = _make_user(env)
    from app import credits as C, models as M
    from app import payment_reconcile as pr
    day = date(2026, 11, 13)
    anchor = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)
    monkeypatch.setenv("PHASE_C_CUTOVER_AT", anchor.isoformat())
    with env.sessions() as db:
        purchase = C.create_pending_purchase(db, uid, "starter")
        purchase.status = "completed"
        purchase.completed_at = datetime(2026, 11, 13, 13, 0,
                                         tzinfo=timezone.utc)
        purchase.amount_cents = 500
        db.commit()
        result = pr.compute_reconciliation(db, day, [], [])
    kinds = [d["kind"] for d in result["differences"]]
    assert "post_cutover_pack_completion" in kinds


def test_reconciliation_product_only_day_no_pack_alert(p164c_env, monkeypatch):
    from datetime import date
    env = p164c_env
    _make_user(env)
    from app import payment_reconcile as pr
    monkeypatch.setenv("PHASE_C_CUTOVER_AT", "2026-11-13T12:00:00+00:00")
    with env.sessions() as db:
        result = pr.compute_reconciliation(db, date(2026, 11, 14), [], [])
    kinds = [d["kind"] for d in result["differences"]]
    assert "post_cutover_pack_completion" not in kinds


# --- Group 10: hard cap (C1 / CALL-1) ------------------------------------------------

def _run_free_analysis(env, n):
    r = env.client.post(
        "/analyze",
        files={"file": (f"f{n}.log", LOG_A + f" {n}\n".encode(), "text/plain")},
        data={"request_id": uuid.uuid4().hex})
    return r


def _seed_free_window(env, uid, ip="127.0.0.1", count=10):
    from app import credits as C, models as M
    now = C._utcnow()
    with env.sessions() as db:
        for i in range(count):
            db.add(M.FreeRequest(
                request_id=f"seed-{ip}-{i}-{uuid.uuid4().hex[:6]}",
                user_id=uid, anonymous_session_hash="seedhash",
                fingerprint=f"fp-{i}", status="completed",
                quota_bucket_trusted_ip=ip,
                quota_bucket_window_start=now,
                deadline=now + timedelta(minutes=5),
                created_at=now - timedelta(minutes=2)))
        db.commit()


def test_hard_cap_refusal_with_reset_no_consent_no_debit(p164c_env):
    env = p164c_env
    _, uid, csrf = _make_user(env)
    _grant(env, uid, 10)  # a funded balance buys nothing past the cap
    _seed_free_window(env, uid)
    r = _run_free_analysis(env, 11)
    assert r.status_code == 429, r.text[:300]
    assert "resets at" in r.text
    assert "not sold" in r.text
    from app import models as M
    with env.sessions() as db:
        assert db.query(M.Operation).filter(
            M.Operation.type == "additional_analysis").count() == 0
        assert db.query(M.Consent).filter(
            M.Consent.operation_type == "additional_analysis").count() == 0
    assert _balance(env, uid) == 10


def test_pre_cutover_additional_consent_refused_post_cutover(p164c_env):
    env = p164c_env
    _, uid, csrf = _make_user(env)
    _grant(env, uid, 10)
    from app import credits as C, models as M
    from app.analysis_admission import fingerprint
    from app import main
    content = LOG_A
    digest = fingerprint("f.log", content)
    with env.sessions() as db:
        consent = C.create_consent(db, uid, "additional_analysis", digest, 1)
        db.commit()
        cid = str(consent.id)
    main._store_paid_pending(cid, "f.log", content)
    r = env.client.post("/analyze/paid", data={
        "consent_id": cid, "file_hash": digest,
        "idempotency_key": uuid.uuid4().hex, "csrf_token": csrf})
    assert r.status_code == 429, r.text[:300]
    with env.sessions() as db:
        assert db.query(M.Operation).filter(
            M.Operation.type == "additional_analysis").count() == 0
    assert _balance(env, uid) == 10


def test_already_admitted_additional_op_settles_once_post_cutover(p164c_env):
    """C1: legacy settlement machinery untouched — an operation
    admitted pre-cutover completes exactly once on its old terms."""
    env = p164c_env
    _, uid, _csrf = _make_user(env)
    _grant(env, uid, 10)
    from app import credits as C, models as M
    from app.analysis_admission import fingerprint
    from app.sample_data import SAMPLE_LOG
    from app.service import analyze_upload
    digest = fingerprint("f.log", LOG_A)
    with env.sessions() as db:
        consent = C.create_consent(db, uid, "additional_analysis", digest, 1)
        db.commit()
        op = C.admit_paid_operation(
            db, uid, "additional_analysis", "adm-key-1", digest, 1,
            consent.id, "worker-1", input_manifest="127.0.0.1")
        db.commit()
        data = copy.deepcopy(analyze_upload("test.log", SAMPLE_LOG.encode()))
        result = C.store_result(db, uid, op.id, data)
        C.complete_operation(db, op.id, "worker-1", result.id)
        db.commit()
        assert db.get(M.Operation, op.id).status == "completed"
    assert _balance(env, uid) == 9  # exactly one 1-credit debit


def test_admit_at_cap_never_creates_paid_operation(p164c_env):
    env = p164c_env
    _, uid, _csrf = _make_user(env)
    _grant(env, uid, 10)
    from app import credits as C, models as M
    import app.analysis_admission as A
    ip = "203.0.113.9"
    now = C._utcnow()
    with env.sessions() as db:
        for i in range(10):
            db.add(M.FreeRequest(
                request_id=f"seed-{i}", user_id=uid,
                anonymous_session_hash="x", fingerprint=f"fp-{i}",
                quota_bucket_trusted_ip=ip, quota_bucket_window_start=now,
                deadline=now + timedelta(minutes=5),
                created_at=now - timedelta(minutes=2),
                status="completed"))
        db.commit()
        item, created = A.admit(db, uid, "anonhash", "new-key", "digest-x",
                                ip, "worker-9", consent_id=None)
        assert item is None and created is False
        db.rollback()
        assert db.query(M.Operation).filter(
            M.Operation.type == "additional_analysis").count() == 0


# --- Group 11: C7.1 has_pdf_export_operation pins --------------------------------------

def _seed_pdf_op(env, uid, rid, status, *, artifact_expired=False):
    from app import credits as C, models as M
    with env.sessions() as db:
        result_id = None
        if status == "completed":
            raw = json.dumps({"pdf_base64": "AAAA", "filename": "test.log"})
            now = C._utcnow()
            exp = now - timedelta(days=1) if artifact_expired else now + timedelta(days=7)
            pr = M.Result(
                user_id=uid, type="pdf", storage_manifest=raw,
                integrity_digest=C.hash_input(raw.encode()),
                byte_count=len(raw.encode()), ready_at=now, expires_at=exp)
            db.add(pr)
            db.commit()
            result_id = pr.id
        op = M.Operation(
            user_id=uid, type="pdf", idempotency_key=f"pdf-{rid}",
            request_hash="h", status=status, result_id=result_id,
            cost=2, worker_id="w",
            lease_expires_at=C._utcnow() + timedelta(minutes=5))
        db.add(op)
        db.commit()
        return op.id


def test_c71_failed_expired_ops_do_not_block_shared_generation(p164c_env):
    env = p164c_env
    _, uid, csrf = _make_user(env)
    rid = _make_report(env, uid)
    _seed_pdf_op(env, uid, rid, "failed")
    _seed_pdf_op(env, uid, rid, "expired")
    from app import models as M, report_access as ra
    with env.sessions() as db:
        source = db.get(M.Result, rid)
        assert ra.has_pdf_export_operation(db, source) is False
    # And the shared PDF actually generates on the fly (group 4 path).
    r = env.client.post(f"/reports/{rid}/share",
                        data={"csrf_token": csrf, "idempotency_key": "s-pdf",
                              "share_format": "pdf"})
    assert r.status_code == 200, r.text[:300]
    token = r.json()["share_url"].rsplit("/", 1)[1]
    anon = TestClient(env.app, base_url="https://testserver",
                      raise_server_exceptions=False)
    resp = anon.get(f"/s/{token}")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/pdf")


def test_c71_completed_op_expired_artifact_no_regeneration(p164c_env):
    env = p164c_env
    _, uid, csrf = _make_user(env)
    rid = _make_report(env, uid)
    _seed_pdf_op(env, uid, rid, "completed", artifact_expired=True)
    from app import models as M, report_access as ra
    with env.sessions() as db:
        source = db.get(M.Result, rid)
        assert ra.has_pdf_export_operation(db, source) is True
    # Owner path: controlled 410, no regeneration.
    r = env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert r.status_code == 410, r.text[:300]
    # Share path: identical indistinguishable 404.
    r = env.client.post(f"/reports/{rid}/share",
                        data={"csrf_token": csrf, "idempotency_key": "s-pdf2",
                              "share_format": "pdf"})
    assert r.status_code == 200, r.text[:300]
    token = r.json()["share_url"].rsplit("/", 1)[1]
    anon = TestClient(env.app, base_url="https://testserver",
                      raise_server_exceptions=False)
    assert anon.get(f"/s/{token}").status_code == 404


def test_c71_public_unknown_token_identical_404(p164c_env):
    env = p164c_env
    anon = TestClient(env.app, base_url="https://testserver",
                      raise_server_exceptions=False)
    assert anon.get("/s/" + "0" * 64).status_code == 404


# --- Group 12: runtime interaction (standing change 2) ----------------------------------

def test_runtime_no_balance_fetch_or_badge_on_main_surfaces(p164c_env):
    """DOM-source pin: no template that renders for a logged-in user
    fetches either retired balance API or injects a credit badge."""
    env = p164c_env
    _, uid, csrf = _make_user(env)
    rid = _make_report(env, uid)
    for path in ("/", "/reports", f"/reports/{rid}", "/settings", "/credits"):
        r = env.client.get(path)
        assert r.status_code in (200, 303), (path, r.status_code)
        assert "/auth/balance" not in r.text, path
        assert "/credits/balance" not in r.text, path
        assert "credit-badge" not in r.text, path


def test_runtime_settings_after_product_purchase_shows_entitlement_facts(p164c_env):
    env = p164c_env
    _, uid, csrf = _make_user(env)
    from app import models as M
    rid = _make_report(env, uid)
    with env.sessions() as db:
        db.add(M.ProductPurchase(
            user_id=uid, sku="investigation_report", source_result_id=rid,
            amount_cents=900, currency="usd", pricing_version=1,
            status="completed",
            completed_at=datetime.now(timezone.utc)))
        db.commit()
    r = env.client.get("/settings")
    assert "Investigation Report" in r.text
    assert "$9.00" in r.text
    assert "Your current balance" not in r.text


def test_runtime_consent_rerender_no_balance_line(p164c_env):
    """Failed-then-retried product consent renders carry no balance
    line and no credit branch on either render (no stale state)."""
    env = p164c_env
    _, uid, csrf = _make_user(env)
    for _ in range(2):
        r = env.client.post(
            "/compare",
            files={"file_a": ("a.log", LOG_A, "text/plain"),
                   "file_b": ("b.log", LOG_B_BYTES, "text/plain")})
        assert r.status_code == 402, r.text[:200]
        assert "Your balance" not in r.text
        assert "eligible credits" not in r.text
        assert "$5" in r.text


LOG_B_BYTES = (b"2024-01-01 10:00:00 ERROR database connection failed\n" * 5
               + b"2024-01-01 10:00:01 ERROR disk full\n" * 3)
