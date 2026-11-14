"""Issue #164 Phase B: digest-bound dollar SKUs (compare / batch /
large_file_analysis) — spec v1.4 (B-1..B-21).

Groups mirror the spec's Tests section (v1 groups 1-12 plus the
amendment groups):
 1 SKU catalog + fail-closed      2 digest binding (B-1a/B-1b)
 3 checkout at the quote step     4 redemption journeys
 5 F2 failure release             6 exports free (B-9)
 7 retention 90d + B-13 refusal   8 reconciliation per-SKU (B-14)
 9 no-credit invariant sweep     10 batch dollar specifics (B-19)
 11 oversize journey              12 cross-SKU isolation (B-6)
 13 consent billing mode (B-7)    14 cutover classes (B-12)
 15 deadline / lapse (B-11)       16 settlement compat + B-20/B-18
 Runtime-interaction tests (DOM-level) follow the groups.
 The PostgreSQL replay-vs-settlement race (B-21) skips without
 TEST_POSTGRES_URL and runs in CI's Postgres leg.

These tests FAIL on the base tree (no digest SKUs, no
/products/checkout, credit-only compare/batch/oversize) and PASS on
the built tree.
"""
import copy
import hashlib
import hmac
import json
import os
import re
import time
import uuid
from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

TEST_PASSWORD = "CorrectHorseBatteryStaple!1"
WEBHOOK_SECRET = "whsec_test_164b_fixture"
PRICE_BY_SKU = {
    "compare": "price_test_compare",
    "batch": "price_test_batch",
    "large_file_analysis": "price_test_large_file",
    "investigation_report": "price_test_investigation",
}

LOG_A = b"2024-01-01 10:00:00 ERROR database connection failed\n" * 10
LOG_B = (b"2024-01-01 10:00:00 ERROR database connection failed\n" * 5
         + b"2024-01-01 10:00:01 ERROR disk full\n" * 3)
SECRET_LOG = (b"2024-01-01 10:00:00 ERROR password=hunter2 failed\n" * 60000)


@pytest.fixture
def p164b_env(tmp_path, monkeypatch):
    from app import auth, email, main
    from app.db import Base, get_db
    import app.db as db_module
    from app.main import app
    engine = create_engine(
        f"sqlite:///{tmp_path / 'p164b.db'}",
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
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'p164b.db'}")
    monkeypatch.setenv("STRIPE_PRICE_COMPARE", PRICE_BY_SKU["compare"])
    monkeypatch.setenv("STRIPE_PRICE_BATCH", PRICE_BY_SKU["batch"])
    monkeypatch.setenv("STRIPE_PRICE_LARGE_FILE", PRICE_BY_SKU["large_file_analysis"])
    monkeypatch.setenv("STRIPE_PRICE_INVESTIGATION_REPORT",
                       PRICE_BY_SKU["investigation_report"])
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_164b_fixture")
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", WEBHOOK_SECRET)
    sent = []
    monkeypatch.setattr(email, "send_verification_email",
                        lambda a, t: sent.append(("verify", a, t)))
    monkeypatch.setattr(email, "send_password_reset_email",
                        lambda a, t: sent.append(("reset", a, t)))

    # Mocked execution boundaries (the house pattern: HTTP/ledger
    # tests never run the real worker).
    from app.service import analyze_upload as service_analyze

    def fake_compare(filename_a, content_a, filename_b, content_b):
        return (
            copy.deepcopy(service_analyze(
                filename_a, content_a, collect_comparison_evidence=True,
                use_alarm=False)),
            copy.deepcopy(service_analyze(
                filename_b, content_b, collect_comparison_evidence=True,
                use_alarm=False)))

    monkeypatch.setattr(main, "_execute_compare", fake_compare)

    def fake_batch(files):
        return [copy.deepcopy(service_analyze(fn, c, use_alarm=False))
                for _o, fn, c in files]

    monkeypatch.setattr(main, "_execute_batch", fake_batch)
    from app.sample_data import SAMPLE_LOG
    sample_report = service_analyze("test.log", SAMPLE_LOG.encode())
    monkeypatch.setattr(main, "_execute_oversize",
                        lambda *a, **k: copy.deepcopy(sample_report))
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
    token = env.sent[-1][2]
    assert c.post("/auth/verify", data={"token": token}).status_code == 200
    c.headers["X-CSRF-Token"] = c.get("/auth/csrf").json()["csrf_token"]
    resp = c.post("/auth/login", data={"email": email, "password": TEST_PASSWORD})
    assert resp.status_code == 200, resp.text
    with env.sessions() as db:
        user_id = db.query(User).filter(User.email == email).one().id
    return email, user_id, resp.json()["csrf_token"]


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
        captured.append({"url": url, "data": data or {}, "headers": headers})
        state["n"] += 1
        sid = f"cs_test_{state['n']}"
        return Resp({"url": f"https://checkout.stripe.com/pay/{sid}", "id": sid})

    monkeypatch.setattr(httpx, "post", _post)
    return captured


_LINE_PRICE = {"id": PRICE_BY_SKU["compare"]}


@pytest.fixture(autouse=True)
def _stub_line_items(monkeypatch):
    import httpx
    _LINE_PRICE["id"] = PRICE_BY_SKU["compare"]

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


def _completed_event(event_id, purchase, *, sku, digest, session_id,
                     amount=500, pi=None):
    meta = {"kind": "product", "purchase_id": str(purchase.id),
            "user_id": str(purchase.user_id), "sku": sku,
            "pricing_version": "1", "content_digest": digest}
    return {
        "id": event_id, "type": "checkout.session.completed",
        "livemode": False,
        "data": {"object": {
            "id": session_id, "payment_status": "paid",
            "status": "complete", "mode": "payment",
            "amount_total": amount, "currency": "usd",
            "payment_intent": pi or f"pi_{session_id}",
            "metadata": meta}}}


def _checkout(env, csrf, sku, digest):
    return env.client.post(
        "/products/checkout",
        data={"sku": sku, "content_digest": digest, "csrf_token": csrf})


def _buy_and_settle(env, csrf, sku, digest, *, event_id=None):
    """Full purchase: checkout route -> webhook settlement.
    Returns the Entitlement row id."""
    from app import models as M
    captured = _fake_stripe(env.monkeypatch)
    r = _checkout(env, csrf, sku, digest)
    assert r.status_code == 200, r.text[:300]
    purchase_id = r.json()["purchase_id"]
    with env.sessions() as db:
        purchase = db.get(M.ProductPurchase, uuid.UUID(purchase_id))
        session_id = purchase.stripe_session_id
        purchase_ref = SimpleNamespace(id=purchase.id, user_id=purchase.user_id)
    _LINE_PRICE["id"] = PRICE_BY_SKU[sku]
    ev = _completed_event(event_id or f"evt_{uuid.uuid4().hex[:8]}",
                          purchase_ref, sku=sku, digest=digest,
                          session_id=session_id)
    r = _post_event(env, ev)
    assert r.status_code == 200, r.text[:300]
    with env.sessions() as db:
        ent = db.query(M.Entitlement).filter(
            M.Entitlement.user_id == purchase_ref.user_id,
            M.Entitlement.sku == sku,
            M.Entitlement.content_digest == digest).one()
        return ent.id


def _balance(env, user_id):
    from app import models as M
    with env.sessions() as db:
        acct = db.query(M.CreditAccount).filter(
            M.CreditAccount.user_id == user_id).first()
        return acct.balance if acct else None


def _seed_grant(env, user_id, qty=10):
    """PREMISE CHANGED (#164 Phase C, Decision 3): the signup grant
    is removed, so a test that needs a funded legacy balance seeds
    the grant directly (the test_issue164_phase_c.py pattern)
    instead of relying on signup to create it."""
    from app import credits as C
    with env.sessions() as db:
        g = C.grant_credits(db, user_id, "purchase",
                            f"test-{uuid.uuid4().hex}", qty)
        db.commit()
        return g.id


def _consent_fields(page_text):
    def field(name):
        m = re.search(r'name="%s" value="([^"]+)"' % name, page_text)
        assert m, f"{name} not in page"
        return m.group(1)
    return field("consent_id"), field("file_hash")


def _post_compare(env, content_a=LOG_A, content_b=LOG_B,
                  name_a="a.log", name_b="b.log"):
    return env.client.post(
        "/compare",
        files={"file_a": (name_a, content_a, "text/plain"),
               "file_b": (name_b, content_b, "text/plain")})


def _confirm_compare(env, consent_id, file_hash, csrf):
    return env.client.post(
        "/compare/paid",
        data={"consent_id": consent_id, "file_hash": file_hash,
              "idempotency_key": consent_id, "csrf_token": csrf})


def _compare_digest(content_a=LOG_A, content_b=LOG_B,
                    name_a="a.log", name_b="b.log"):
    from app import main
    return main._compare_pair_hash(name_a, content_a, name_b, content_b)


# --- Group 1: SKU catalog + fail-closed ---------------------------------------

def test_sku_catalog_flat_five_dollars():
    from app import stripe_billing as sb
    for sku, env_name in (("compare", "STRIPE_PRICE_COMPARE"),
                          ("batch", "STRIPE_PRICE_BATCH"),
                          ("large_file_analysis", "STRIPE_PRICE_LARGE_FILE")):
        entry = sb.PRODUCT_SKUS[sku]
        assert entry["amount_cents"] == 500
        assert entry["currency"] == "usd"
        assert entry["price_env"] == env_name
        assert sku in sb.DIGEST_SKUS


def test_checkout_fail_closed_without_price_env(p164b_env, monkeypatch):
    env = p164b_env
    _, uid, csrf = _make_user(env)
    captured = _fake_stripe(monkeypatch)
    monkeypatch.delenv("STRIPE_PRICE_COMPARE", raising=False)
    r = _checkout(env, csrf, "compare", _compare_digest())
    assert r.status_code == 503, r.text[:300]
    assert captured == []  # zero Stripe calls
    from app import models as M
    with env.sessions() as db:
        assert db.query(M.ProductPurchase).count() == 0


def test_quote_fail_closed_without_price_env(p164b_env, monkeypatch):
    env = p164b_env
    _, uid, csrf = _make_user(env)
    captured = _fake_stripe(monkeypatch)
    monkeypatch.delenv("STRIPE_PRICE_COMPARE", raising=False)
    r = _post_compare(env)
    assert r.status_code == 503, r.text[:300]
    assert "Coming soon" in r.text
    assert captured == []
    from app import models as M
    with env.sessions() as db:
        assert db.query(M.Consent).filter(M.Consent.user_id == uid).count() == 0
        assert db.query(M.ProductPurchase).count() == 0


# --- Group 2: digest binding (B-1a / B-1b) -------------------------------------

def test_checkout_session_metadata_carries_digest(p164b_env):
    env = p164b_env
    _, uid, csrf = _make_user(env)
    captured = _fake_stripe(env.monkeypatch)
    digest = _compare_digest()
    r = _checkout(env, csrf, "compare", digest)
    assert r.status_code == 200, r.text[:300]
    data = captured[-1]["data"]
    assert data.get("metadata[content_digest]") == digest
    assert data.get("payment_intent_data[metadata][content_digest]") == digest
    assert data.get("metadata[sku]") == "compare"


def test_settlement_creates_digest_entitlement_with_30d_window(p164b_env):
    env = p164b_env
    _, uid, csrf = _make_user(env)
    digest = _compare_digest()
    ent_id = _buy_and_settle(env, csrf, "compare", digest)
    from app import credits as C, models as M
    with env.sessions() as db:
        ent = db.get(M.Entitlement, ent_id)
        purchase = db.get(M.ProductPurchase, ent.product_purchase_id)
        assert ent.source_result_id is None
        assert ent.content_digest == digest
        assert ent.status == "available"
        # B-11: exactly settlement + 30 days.
        assert C._as_aware(ent.redemption_deadline) == \
            C._as_aware(purchase.completed_at) + timedelta(days=30)


def test_settlement_digest_mismatch_rejected(p164b_env):
    env = p164b_env
    _, uid, csrf = _make_user(env)
    captured = _fake_stripe(env.monkeypatch)
    digest = _compare_digest()
    r = _checkout(env, csrf, "compare", digest)
    purchase_id = r.json()["purchase_id"]
    from app import models as M
    with env.sessions() as db:
        purchase = db.get(M.ProductPurchase, uuid.UUID(purchase_id))
        ref = SimpleNamespace(id=purchase.id, user_id=purchase.user_id)
        session_id = purchase.stripe_session_id
    _LINE_PRICE["id"] = PRICE_BY_SKU["compare"]
    ev = _completed_event("evt_digest_mismatch", ref, sku="compare",
                          digest="f" * 64, session_id=session_id)
    r = _post_event(env, ev)
    # Settlement validation failures follow the Phase A webhook
    # convention: HTTP 200 with {"status": "failed"}, no settlement.
    assert r.status_code == 200 and r.json() == {"status": "failed"}, r.text[:300]
    with env.sessions() as db:
        purchase = db.get(M.ProductPurchase, uuid.UUID(purchase_id))
        # The invalid settlement fails the purchase closed (Phase A
        # posture); no entitlement is created.
        assert purchase.status == "failed"
        assert db.query(M.Entitlement).count() == 0


def test_renamed_file_does_not_redeem(p164b_env):
    """B-1a: the digest binds (filename, redacted content); the same
    bytes under a new name are a different product input."""
    env = p164b_env
    _, uid, csrf = _make_user(env)
    _buy_and_settle(env, csrf, "compare", _compare_digest())
    r = _post_compare(env, name_a="renamed.log")
    assert r.status_code == 402, r.text[:300]
    assert "product-checkout-form" in r.text  # purchase path, not Run
    assert "already paid" not in r.text


def test_raw_secret_bytes_reupload_redeems(p164b_env):
    """B-1b: the digest is over REDACTED content, so re-uploading the
    raw-with-secrets bytes under the original name redeems."""
    env = p164b_env
    _, uid, csrf = _make_user(env)
    # Oversize journey is the natural home for a 60k-line secret log;
    # use compare with a small secret-bearing pair instead.
    secret_a = b"2024-01-01 10:00:00 ERROR api_key=abc123def456 failed\n" * 10
    secret_b = b"2024-01-01 10:00:00 ERROR disk full\n" * 5
    # The server fingerprints the REDACTED content (that is the
    # binding); a buyer-side digest is over the same redacted form.
    from app.redact import redact_secrets
    digest = _compare_digest(
        redact_secrets(secret_a.decode()).encode(),
        redact_secrets(secret_b.decode()).encode())
    assert redact_secrets(secret_a.decode()).encode() != secret_a
    _buy_and_settle(env, csrf, "compare", digest)
    r = _post_compare(env, secret_a, secret_b)
    assert r.status_code == 402, r.text[:300]
    assert "already paid" in r.text  # Run path offered
    consent_id, file_hash = _consent_fields(r.text)
    r = _confirm_compare(env, consent_id, file_hash, csrf)
    assert r.status_code == 200, r.text[:300]


# --- Groups 3+4: quote-step checkout + redemption journey ----------------------

def test_quote_step_shows_checkout_then_run_after_settlement(p164b_env):
    env = p164b_env
    _, uid, csrf = _make_user(env)
    r = _post_compare(env)
    assert r.status_code == 402, r.text[:300]
    assert "product-checkout-form" in r.text
    assert "Buy \u2014 $5" in r.text
    from app import stripe_billing as sb
    assert sb.PAY_NOW_PROMISE in r.text
    _buy_and_settle(env, csrf, "compare", _compare_digest())
    r = _post_compare(env)
    assert r.status_code == 402, r.text[:300]
    assert "already paid" in r.text  # F1 surface: Run, not Buy
    assert "product-checkout-form" not in r.text


def test_compare_redemption_end_to_end_no_credit_effects(p164b_env):
    env = p164b_env
    _, uid, csrf = _make_user(env)
    _seed_grant(env, uid, 10)  # Phase C: seeded directly, not signup
    assert _balance(env, uid) == 10
    from app import models as _M0
    with env.sessions() as db:
        ledger_before = db.query(_M0.CreditLedger).filter(
            _M0.CreditLedger.user_id == uid).count()
    ent_id = _buy_and_settle(env, csrf, "compare", _compare_digest())
    r = _post_compare(env)
    consent_id, file_hash = _consent_fields(r.text)
    r = _confirm_compare(env, consent_id, file_hash, csrf)
    assert r.status_code == 200, r.text[:300]
    from app import models as M
    with env.sessions() as db:
        op = db.query(M.Operation).filter(
            M.Operation.user_id == uid,
            M.Operation.type == "compare_logs").one()
        assert op.cost == 0 and op.status == "completed"
        assert op.entitlement_redemption_id is not None
        assert db.query(M.OperationAllocation).filter(
            M.OperationAllocation.operation_id == op.id).count() == 0
        assert db.query(M.CreditLedger).filter(
            M.CreditLedger.user_id == uid).count() == ledger_before
        assert db.get(M.Entitlement, ent_id).status == "redeemed"
        result = db.get(M.Result, op.result_id)
        assert result is not None and result.type == "comparison"
    assert _balance(env, uid) == 10  # untouched


def test_compare_confirm_without_entitlement_402(p164b_env):
    env = p164b_env
    _, uid, csrf = _make_user(env)
    r = _post_compare(env)
    assert r.status_code == 402
    from app import models as M
    with env.sessions() as db:
        consent = db.query(M.Consent).filter(M.Consent.user_id == uid).one()
        consent_id, file_hash = str(consent.id), consent.input_hash
    r = _confirm_compare(env, consent_id, file_hash, csrf)
    assert r.status_code == 402, r.text[:300]
    assert "Comparing two logs costs $5." in r.text
    with env.sessions() as db:
        assert db.query(M.Operation).count() == 0


def test_entitlement_redeems_exactly_once(p164b_env):
    env = p164b_env
    _, uid, csrf = _make_user(env)
    _buy_and_settle(env, csrf, "compare", _compare_digest())
    r = _post_compare(env)
    consent_id, file_hash = _consent_fields(r.text)
    assert _confirm_compare(env, consent_id, file_hash, csrf).status_code == 200
    r = _post_compare(env)
    assert "product-checkout-form" in r.text  # back to purchase path
    from app import models as M
    with env.sessions() as db:
        consent = db.query(M.Consent).filter(
            M.Consent.user_id == uid,
            M.Consent.consumed_by_operation_id.is_(None)).order_by(
            M.Consent.created_at.desc()).first()
        consent_id, file_hash = str(consent.id), consent.input_hash
    r = _confirm_compare(env, consent_id, file_hash, csrf)
    assert r.status_code == 402, r.text[:300]
    with env.sessions() as db:
        assert db.query(M.Operation).filter(
            M.Operation.user_id == uid).count() == 1


# --- Group 5: F2 failure release ------------------------------------------------

def test_compare_failure_releases_entitlement_for_retry(p164b_env, monkeypatch):
    env = p164b_env
    _, uid, csrf = _make_user(env)
    ent_id = _buy_and_settle(env, csrf, "compare", _compare_digest())
    from app import main

    def failing(a, b, c, d):
        return ({"error": "analysis_failed", "message": "x", "filename": "a.log"},
                {"error": "analysis_failed", "message": "x", "filename": "b.log"})

    monkeypatch.setattr(main, "_execute_compare", failing)
    r = _post_compare(env)
    consent_id, file_hash = _consent_fields(r.text)
    r = _confirm_compare(env, consent_id, file_hash, csrf)
    assert r.status_code == 400, r.text[:300]
    from app import models as M
    with env.sessions() as db:
        assert db.get(M.Entitlement, ent_id).status == "available"
        op = db.query(M.Operation).filter(M.Operation.user_id == uid).one()
        assert op.status == "failed"
    # Retry with a fresh consent succeeds on the SAME entitlement
    # (the purchase was not consumed by the failure).
    from app.service import analyze_upload as sa
    monkeypatch.setattr(main, "_execute_compare", lambda a, b, c, d: (
        copy.deepcopy(sa(a, b, collect_comparison_evidence=True, use_alarm=False)),
        copy.deepcopy(sa(c, d, collect_comparison_evidence=True, use_alarm=False))))
    r = _post_compare(env)
    consent_id, file_hash = _consent_fields(r.text)
    r = _confirm_compare(env, consent_id, file_hash, csrf)
    assert r.status_code == 200, r.text[:300]
    with env.sessions() as db:
        assert db.get(M.Entitlement, ent_id).status == "redeemed"


# --- Group 6: exports free (B-9) --------------------------------------------------

def test_compare_exports_pdf_free_no_csv_json(p164b_env):
    env = p164b_env
    _, uid, csrf = _make_user(env)
    _seed_grant(env, uid, 10)  # Phase C: seeded directly, not signup
    _buy_and_settle(env, csrf, "compare", _compare_digest())
    r = _post_compare(env)
    consent_id, file_hash = _consent_fields(r.text)
    r = _confirm_compare(env, consent_id, file_hash, csrf)
    assert r.status_code == 200, r.text[:300]
    # The report page renders the free-export label for product-paid
    # artifacts; CSV/JSON are not offered for comparison artifacts.
    assert "Export PDF (free)" in r.text
    assert "Export CSV" not in r.text and "Export JSON" not in r.text
    m = re.search(r'action="/reports/([0-9a-f-]{36})/pdf"', r.text)
    rid = m.group(1)
    pdf = env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
    assert _balance(env, uid) == 10


# --- Group 7: retention (Decision 7 + B-13) ---------------------------------------

def test_product_result_retention_90_days(p164b_env):
    env = p164b_env
    _, uid, csrf = _make_user(env)
    _buy_and_settle(env, csrf, "compare", _compare_digest())
    r = _post_compare(env)
    consent_id, file_hash = _consent_fields(r.text)
    assert _confirm_compare(env, consent_id, file_hash, csrf).status_code == 200
    from app import credits as C, models as M
    with env.sessions() as db:
        op = db.query(M.Operation).filter(M.Operation.user_id == uid).one()
        result = db.get(M.Result, op.result_id)
        delta = C._as_aware(result.expires_at) - C._as_aware(result.created_at)
        assert delta >= timedelta(days=89)


def test_extend_retention_refused_for_product_result(p164b_env):
    env = p164b_env
    _, uid, csrf = _make_user(env)
    _seed_grant(env, uid, 10)  # Phase C: seeded directly, not signup
    _buy_and_settle(env, csrf, "compare", _compare_digest())
    r = _post_compare(env)
    consent_id, file_hash = _consent_fields(r.text)
    assert _confirm_compare(env, consent_id, file_hash, csrf).status_code == 200
    from app import models as M
    with env.sessions() as db:
        op = db.query(M.Operation).filter(M.Operation.user_id == uid).one()
        rid = str(op.result_id)
    r = env.client.post(
        f"/reports/{rid}/retention",
        data={"idempotency_key": f"ext-{uuid.uuid4().hex}",
              "csrf_token": csrf})
    assert r.status_code == 409, r.text[:300]
    assert r.json() == {
        "error": "Paid reports include 90-day retention and can't be extended"}
    with env.sessions() as db:
        assert db.query(M.ReportAction).filter(
            M.ReportAction.result_id == uuid.UUID(rid)).count() == 0
    assert _balance(env, uid) == 10


# --- Group 13: consent billing mode (B-7) ------------------------------------------

def test_product_consent_row_shape(p164b_env):
    env = p164b_env
    _, uid, csrf = _make_user(env)
    r = _post_compare(env)
    assert r.status_code == 402
    from app import models as M
    with env.sessions() as db:
        consent = db.query(M.Consent).filter(M.Consent.user_id == uid).one()
        assert consent.sku == "compare"
        assert consent.max_cost == 0


def test_credit_consent_helper_shape_unchanged_no_http_mint(p164b_env):
    # PREMISE CHANGED (#164 Phase C, C1 / CALL-1 hard cap): the
    # credit consent helper's row shape is unchanged (legacy
    # settlement machinery is preserved), but the HTTP flow no
    # longer mints one — at the free-allowance cap, /analyze
    # refuses 429 with the reset time and no purchase route, and
    # creates NO additional_analysis consent.
    env = p164b_env
    _, uid, csrf = _make_user(env)
    from app import credits as C, models as M
    with env.sessions() as db:
        helper = C.create_consent(db, uid, "additional_analysis",
                                  "d" * 64, 1)
        db.commit()
        assert helper.sku is None
        assert helper.max_cost == 1
    with env.sessions() as db:
        for _ in range(10):
            db.add(M.FreeRequest(
                request_id=uuid.uuid4().hex, user_id=uid, fingerprint="old",
                status="failed", quota_bucket_trusted_ip="127.0.0.1",
                created_at=C._utcnow() - timedelta(minutes=2),
                deadline=C._utcnow()))
        db.commit()
    r = env.client.post(
        "/analyze",
        files={"file": ("t.log", b"2024-01-01 INFO hi\n", "text/plain")},
        data={"output": "html", "request_id": ""})
    assert r.status_code == 429, r.text[:300]
    assert "resets at" in r.text
    assert "not sold" in r.text
    assert "Your balance" not in r.text
    with env.sessions() as db:
        # Only the helper-created row exists; the HTTP attempt
        # minted nothing.
        assert db.query(M.Consent).filter(
            M.Consent.user_id == uid,
            M.Consent.operation_type == "additional_analysis").count() == 1
        assert db.query(M.Operation).filter(
            M.Operation.type == "additional_analysis").count() == 0


def test_validate_consent_billing_mode_mismatch():
    from app import credits as C
    from app.db import Base
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)
    from app.models import User
    with sessions() as db:
        u = User(id=uuid.uuid4(), email="mode@example.com", email_verified=True)
        db.add(u)
        db.commit()
        product = C.create_product_consent(db, u.id, "compare_logs", "d" * 64, "compare")
        credit = C.create_consent(db, u.id, "compare_logs", "e" * 64, 3)
        db.commit()
        # Product consent under credit expectations: refused.
        with pytest.raises(C.AdmissionError):
            C.validate_consent(db, product.id, u.id, "compare_logs", "d" * 64, 3)
        # Credit consent under dollar expectations: refused.
        with pytest.raises(C.AdmissionError):
            C.validate_consent(db, credit.id, u.id, "compare_logs", "e" * 64, 0,
                               sku="compare")
        # Each under its own mode: accepted.
        C.validate_consent(db, product.id, u.id, "compare_logs", "d" * 64, 0,
                           sku="compare")
        C.validate_consent(db, credit.id, u.id, "compare_logs", "e" * 64, 3)
    engine.dispose()


# --- Helpers for DB-level product admission --------------------------------------

def _seed_entitlement(env, user_id, sku, digest, *, status="available"):
    from app import credits as C, models as M
    with env.sessions() as db:
        purchase = M.ProductPurchase(
            user_id=user_id, sku=sku, content_digest=digest,
            status="completed", amount_cents=500, currency="usd",
            stripe_price_id=PRICE_BY_SKU[sku], pricing_version=1,
            completed_at=C._utcnow())
        db.add(purchase)
        db.flush()
        ent = M.Entitlement(
            user_id=user_id, sku=sku, product_purchase_id=purchase.id,
            content_digest=digest, status=status,
            redemption_deadline=C._utcnow() + timedelta(days=30))
        db.add(ent)
        db.commit()
        return purchase.id, ent.id


def _admit_product_op(env, user_id, *, sku="compare", op_type="compare_logs",
                      digest=None, worker="worker-1", extra_scopes=(),
                      seed=True):
    from app import credits as C, product_billing as pb
    digest = digest or ("a" * 64)
    if seed:
        _seed_entitlement(env, user_id, sku, digest)
    with env.sessions() as db:
        consent = C.create_product_consent(db, user_id, op_type, digest, sku)
        db.commit()
        consent_id = consent.id
    with env.sessions() as db:
        item = pb.admit_product_operation(
            db, user_id, op_type, sku, uuid.uuid4().hex, digest,
            consent_id, worker, input_manifest="127.0.0.1",
            extra_scopes=list(extra_scopes))
        db.commit()
        return item.id


# --- Group 12: cross-SKU isolation (B-6) -------------------------------------------

def test_cross_sku_entitlement_never_redeems(p164b_env):
    env = p164b_env
    _, uid, csrf = _make_user(env)
    # A large_file_analysis entitlement whose digest EQUALS the
    # compare pair digest must not redeem a compare run.
    _seed_entitlement(env, uid, "large_file_analysis", _compare_digest())
    r = _post_compare(env)
    assert "product-checkout-form" in r.text  # no Run path
    from app import models as M
    with env.sessions() as db:
        consent = db.query(M.Consent).filter(
            M.Consent.user_id == uid,
            M.Consent.operation_type == "compare_logs").one()
        consent_id, file_hash = str(consent.id), consent.input_hash
    r = _confirm_compare(env, consent_id, file_hash, csrf)
    assert r.status_code == 402, r.text[:300]
    with env.sessions() as db:
        assert db.query(M.Operation).count() == 0


# --- Group 10: batch dollar specifics (B-19 / B-15) ----------------------------------

def _post_batch(env, files):
    return env.client.post(
        "/batch",
        files=[("files", (name, content, "text/plain"))
               for name, content in files])


def _batch_files():
    return [("one.log", LOG_A), ("two.log", LOG_B), ("three.log", LOG_A)]


def _batch_digest(files):
    from app import main
    from app.redact import redact_secrets
    triples = [(i + 1, name,
                redact_secrets(content.decode("utf-8", "replace")).encode())
               for i, (name, content) in enumerate(files)]
    return main._batch_bundle_hash(triples)


def test_batch_redemption_no_claim_no_hit_dollar_snapshot(p164b_env):
    env = p164b_env
    _, uid, csrf = _make_user(env)
    _seed_grant(env, uid, 10)  # Phase C: seeded directly, not signup
    files = _batch_files()
    _seed_entitlement(env, uid, "batch", _batch_digest(files))
    r = _post_batch(env, files)
    assert r.status_code == 402, r.text[:300]
    consent_id, file_hash = _consent_fields(r.text)
    r = env.client.post(
        "/batch/paid",
        data={"consent_id": consent_id, "file_hash": file_hash,
              "idempotency_key": consent_id, "csrf_token": csrf})
    assert r.status_code == 200, r.text[:400]
    from app import models as M
    with env.sessions() as db:
        op = db.query(M.Operation).filter(
            M.Operation.user_id == uid, M.Operation.type == "batch").one()
        assert op.cost == 0 and op.free_allowance_claim is False
        assert db.query(M.RateLimitHit).count() == 0
        assert db.query(M.FreeRequest).count() == 0
        result = db.get(M.Result, op.result_id)
        manifest = json.loads(result.storage_manifest)
        assert manifest["pricing"] == {"sku": "batch", "amount_cents": 500}
    assert _balance(env, uid) == 10


def test_batch_burst_limit_from_operation_counts(p164b_env):
    """B-19: the paid-batch burst limit derives from durable
    Operation-row counts (batch_admission._count_batch_attempts),
    not from RateLimitHit rows — a dollar batch writes none."""
    env = p164b_env
    _, uid, csrf = _make_user(env)
    from app import credits as C, models as M, product_billing as pb
    for i in range(2):  # BURST_LIMIT batch attempts inside a minute
        op_id = _admit_product_op(
            env, uid, sku="batch", op_type="batch",
            digest=f"{i:064x}", extra_scopes=[("global:batch", 1)])
        with env.sessions() as db:
            C.release_operation(db, op_id, "worker-1", "analysis_failed")
            db.commit()
    with env.sessions() as db:
        assert db.query(M.RateLimitHit).count() == 0
        consent = C.create_product_consent(db, uid, "batch", "f" * 64, "batch")
        db.commit()
        consent_id = consent.id
    _seed_entitlement(env, uid, "batch", "f" * 64)
    with env.sessions() as db:
        with pytest.raises(C.AdmissionError, match="Too many requests"):
            pb.admit_product_operation(
                db, uid, "batch", "batch", uuid.uuid4().hex, "f" * 64,
                consent_id, "worker-9", input_manifest="127.0.0.1",
                extra_scopes=[("global:batch", 1)])
        db.rollback()
        assert db.query(M.RateLimitHit).count() == 0


# --- Group 11: oversize journey -------------------------------------------------------

def test_oversize_redemption_end_to_end(p164b_env):
    env = p164b_env
    _, uid, csrf = _make_user(env)
    _seed_grant(env, uid, 10)  # Phase C: seeded directly, not signup
    content = (b"2024-01-01 10:00:00 INFO heartbeat ok\n" * 50001)
    from app.analysis_admission import fingerprint
    digest = fingerprint("big.log", content)
    _buy_and_settle(env, csrf, "large_file_analysis", digest)
    r = env.client.post(
        "/analyze",
        files={"file": ("big.log", content, "text/plain")},
        data={"output": "html", "request_id": ""})
    assert r.status_code == 402, r.text[:300]
    assert "already paid" in r.text
    consent_id, file_hash = _consent_fields(r.text)
    r = env.client.post(
        "/analyze/paid",
        data={"consent_id": consent_id, "file_hash": file_hash,
              "idempotency_key": consent_id, "csrf_token": csrf})
    assert r.status_code == 200, r.text[:300]
    from app import models as M
    with env.sessions() as db:
        op = db.query(M.Operation).filter(
            M.Operation.user_id == uid,
            M.Operation.type == "oversize_analysis").one()
        assert op.cost == 0 and op.entitlement_redemption_id is not None
        result = db.get(M.Result, op.result_id)
        from app import credits as C
        delta = C._as_aware(result.expires_at) - C._as_aware(result.created_at)
        assert delta >= timedelta(days=89)
        rid = str(op.result_id)
    # Exports are free in every format the kind supports (B-9).
    r = env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert r.status_code == 200, r.text[:200]
    for suffix in ("csv", "json"):
        r = env.client.post(f"/reports/{rid}/exports/{suffix}",
                            data={"csrf_token": csrf})
        assert r.status_code == 200, (suffix, r.text[:200])
    assert _balance(env, uid) == 10


# --- Group 14: cutover classes (B-12) ---------------------------------------------------

def test_legacy_credit_consent_refused_compare(p164b_env):
    env = p164b_env
    _, uid, csrf = _make_user(env)
    _seed_grant(env, uid, 10)  # Phase C: seeded directly, not signup
    from app import credits as C, main, models as M
    digest = _compare_digest()
    with env.sessions() as db:
        consent = C.create_consent(db, uid, "compare_logs", digest, 3)
        db.commit()
        consent_id = consent.id
    main._store_compare_pending(str(consent_id), "a.log", LOG_A, "b.log", LOG_B)
    r = _confirm_compare(env, str(consent_id), digest, csrf)
    assert r.status_code == 409, r.text[:300]
    assert "previous credit pricing" in r.text
    with env.sessions() as db:
        assert db.query(M.Operation).count() == 0
    assert _balance(env, uid) == 10


def test_legacy_credit_consent_refused_oversize(p164b_env):
    env = p164b_env
    _, uid, csrf = _make_user(env)
    content = (b"2024-01-01 10:00:00 INFO heartbeat ok\n" * 50001)
    from app import credits as C, main, models as M
    from app.analysis_admission import fingerprint
    digest = fingerprint("big.log", content)
    with env.sessions() as db:
        consent = C.create_consent(db, uid, "oversize_analysis", digest, 3)
        db.commit()
        consent_id = consent.id
    main._store_paid_pending(str(consent_id), "big.log", content)
    r = env.client.post(
        "/analyze/paid",
        data={"consent_id": str(consent_id), "file_hash": digest,
              "idempotency_key": str(consent_id), "csrf_token": csrf})
    assert r.status_code == 409, r.text[:300]
    assert "previous credit pricing" in r.text
    with env.sessions() as db:
        assert db.query(M.Operation).count() == 0


def test_admitted_credit_operation_still_settles_on_credit_terms(p164b_env):
    """B-12 class 1: an operation admitted under credit terms
    settles on those terms (the credit engine is untouched).
    PREMISE CHANGED (#164 Phase C): the balance it settles against
    is seeded directly — the signup grant no longer funds it."""
    env = p164b_env
    _, uid, csrf = _make_user(env)
    _seed_grant(env, uid, 10)  # Phase C: seeded directly, not signup
    from app import credits as C, models as M
    from app.analysis_admission import fingerprint
    digest = fingerprint("big.log", b"x\n")
    with env.sessions() as db:
        consent = C.create_consent(db, uid, "oversize_analysis", digest, 3)
        db.commit()
        op = C.admit_paid_operation(
            db, uid, "oversize_analysis", uuid.uuid4().hex, digest, 3,
            consent.id, "w1", extra_scopes=[("global:oversize", 1)])
        db.commit()
        op_id, worker = op.id, op.worker_id
    with env.sessions() as db:
        result = C.store_result(db, uid, op_id, {"filename": "big.log",
                                                 "summary": {}}, severity="low")
        C.complete_operation(db, op_id, worker, result.id)
        db.commit()
    assert _balance(env, uid) == 7  # 10 - 3 credit settlement


# --- Group 15: deadline / lapse (B-11) ----------------------------------------------------

def test_redemption_after_window_410_and_refund_eligible(p164b_env):
    env = p164b_env
    _, uid, csrf = _make_user(env)
    ent_id = _buy_and_settle(env, csrf, "compare", _compare_digest())
    from app import credits as C, models as M
    with env.sessions() as db:
        ent = db.get(M.Entitlement, ent_id)
        ent.redemption_deadline = C._utcnow() - timedelta(seconds=1)
        db.commit()
    r = _post_compare(env)
    assert r.status_code == 402
    # The lapsed entitlement no longer renders the Run form; the
    # zero-cost consent still exists server-side and its confirm is
    # the 410 surface.
    with env.sessions() as db:
        consent = db.query(M.Consent).filter(
            M.Consent.user_id == uid,
            M.Consent.operation_type == "compare_logs").order_by(
            M.Consent.created_at.desc()).first()
        consent_id, file_hash = str(consent.id), consent.input_hash
    r = _confirm_compare(env, consent_id, file_hash, csrf)
    assert r.status_code == 410, r.text[:300]
    assert "refund" in r.text.lower()
    with env.sessions() as db:
        assert db.get(M.Entitlement, ent_id).status == "refund_eligible"
        purchase = db.query(M.ProductPurchase).filter(
            M.ProductPurchase.user_id == uid).one()
        assert purchase.status == "completed"  # money kept; refund is manual
        assert db.query(M.Operation).count() == 0


def test_webhook_redelivery_after_lapse_never_resurrects(p164b_env):
    env = p164b_env
    _, uid, csrf = _make_user(env)
    captured = _fake_stripe(env.monkeypatch)
    digest = _compare_digest()
    r = _checkout(env, csrf, "compare", digest)
    purchase_id = r.json()["purchase_id"]
    from app import credits as C, models as M
    with env.sessions() as db:
        purchase = db.get(M.ProductPurchase, uuid.UUID(purchase_id))
        ref = SimpleNamespace(id=purchase.id, user_id=purchase.user_id)
        session_id = purchase.stripe_session_id
    _LINE_PRICE["id"] = PRICE_BY_SKU["compare"]
    ev = _completed_event("evt_lapse_1", ref, sku="compare", digest=digest,
                          session_id=session_id)
    assert _post_event(env, ev).status_code == 200
    with env.sessions() as db:
        ent = db.query(M.Entitlement).filter(
            M.Entitlement.user_id == uid).one()
        ent.redemption_deadline = C._utcnow() - timedelta(seconds=1)
        ent.status = "refund_eligible"
        db.commit()
    # Redelivery of the same settlement event after lapse.
    r = _post_event(env, ev)
    assert r.status_code in (200, 409), r.text[:200]
    with env.sessions() as db:
        ent = db.query(M.Entitlement).filter(
            M.Entitlement.user_id == uid).one()
        assert ent.status == "refund_eligible"  # never resurrected


# --- Group 16: settlement compatibility + recovery ownership (B-17/B-18/B-20) --------------

def _expire_op(env, op_id):
    from app import credits as C, models as M
    with env.sessions() as db:
        op = db.get(M.Operation, op_id)
        op.lease_expires_at = C._utcnow() - timedelta(seconds=1)
        db.commit()


def _capacity_used(env, scope_key):
    from app import models as M
    with env.sessions() as db:
        row = db.query(M.CapacityScope).filter(
            M.CapacityScope.scope_key == scope_key).first()
        return row.used if row else 0


def test_product_recovery_releases_entitlement_when_stopped(p164b_env):
    env = p164b_env
    _, uid, csrf = _make_user(env)
    digest = "b" * 64
    _, ent_id = _seed_entitlement(env, uid, "compare", digest)
    op_id = _admit_product_op(env, uid, digest=digest, seed=False)
    _expire_op(env, op_id)
    from app import credits as C, models as M
    with env.sessions() as db:
        recovered = C.recover_expired_operations(
            db, executor_stopped=lambda oid, w, g: True)
        db.commit()
    assert recovered >= 1
    with env.sessions() as db:
        assert db.get(M.Operation, op_id).status == "expired"
        assert db.get(M.Entitlement, ent_id).status == "available"
        red = db.query(M.EntitlementRedemption).filter(
            M.EntitlementRedemption.entitlement_id == ent_id).one()
        assert red.status == "released"
    assert _capacity_used(env, "global:paid") == 0


def test_product_billing_recovery_excludes_operation_linked(p164b_env):
    """B-18: product_billing's own recovery must not touch an
    Operation-linked redemption — credits recovery owns it."""
    env = p164b_env
    _, uid, csrf = _make_user(env)
    digest = "c" * 64
    _, ent_id = _seed_entitlement(env, uid, "compare", digest)
    op_id = _admit_product_op(env, uid, digest=digest, seed=False)
    from app import models as M, product_billing as pb
    with env.sessions() as db:
        red = db.query(M.EntitlementRedemption).filter(
            M.EntitlementRedemption.entitlement_id == ent_id).one()
        from app import credits as C
        red.lease_expires_at = C._utcnow() - timedelta(seconds=1)
        db.commit()
    with env.sessions() as db:
        assert pb.recover_expired_redemptions(db) == 0
        db.rollback()
        red = db.query(M.EntitlementRedemption).filter(
            M.EntitlementRedemption.entitlement_id == ent_id).one()
        assert red.status == "reserved"
        assert pb.retry_stopped_redemption(
            db, red.id, executor_stopped=lambda oid, w, g: True) is False


def test_revoked_entitlement_no_evidence_keeps_capacity_held(p164b_env):
    """B-20: revocation alone is not executor evidence — the
    expired, revoked Operation stays reserved and keeps its
    capacity; a second pool admission is refused."""
    env = p164b_env
    _, uid, csrf = _make_user(env)
    digest = "d" * 64
    _, ent_id = _seed_entitlement(env, uid, "compare", digest)
    op_id = _admit_product_op(env, uid, digest=digest, seed=False)
    from app import credits as C, models as M
    with env.sessions() as db:
        ent = db.get(M.Entitlement, ent_id)
        ent.status = "revoked"
        db.commit()
    _expire_op(env, op_id)
    with env.sessions() as db:
        recovered = C.recover_expired_operations(db)  # no stop evidence
        db.commit()
        assert db.get(M.Operation, op_id).status == "reserved"
    assert recovered == 0
    assert _capacity_used(env, "global:paid") == 1  # still held


def test_revoked_entitlement_with_stop_evidence_terminalizes(p164b_env):
    env = p164b_env
    _, uid, csrf = _make_user(env)
    digest = "e" * 64
    _, ent_id = _seed_entitlement(env, uid, "compare", digest)
    op_id = _admit_product_op(env, uid, digest=digest, seed=False)
    from app import credits as C, models as M
    with env.sessions() as db:
        ent = db.get(M.Entitlement, ent_id)
        ent.status = "revoked"
        ent_version = ent.version
        db.commit()
    _expire_op(env, op_id)
    with env.sessions() as db:
        recovered = C.recover_expired_operations(
            db, executor_stopped=lambda oid, w, g: True)
        db.commit()
    assert recovered >= 1
    with env.sessions() as db:
        op = db.get(M.Operation, op_id)
        assert op.status == "failed" and op.failure_code == "entitlement_revoked"
        ent = db.get(M.Entitlement, ent_id)
        assert ent.status == "revoked" and ent.version == ent_version
        red = db.query(M.EntitlementRedemption).filter(
            M.EntitlementRedemption.entitlement_id == ent_id).one()
        assert red.status == "released"
        assert red.failure_code == "entitlement_revoked"
        assert db.query(M.Result).filter(
            M.Result.operation_id == op_id).count() == 0
    assert _capacity_used(env, "global:paid") == 0
    # Idempotent: a second recovery pass changes nothing.
    with env.sessions() as db:
        assert C.recover_expired_operations(
            db, executor_stopped=lambda oid, w, g: True) == 0


def test_revoked_entitlement_with_stored_result_suppresses_it(p164b_env):
    """B-20 evidence class (1): an authoritative stored Result
    terminalizes the revoked Operation, and the Result is
    suppressed — never published."""
    env = p164b_env
    _, uid, csrf = _make_user(env)
    digest = "f" * 64
    _, ent_id = _seed_entitlement(env, uid, "compare", digest)
    op_id = _admit_product_op(env, uid, digest=digest, seed=False)
    from app import credits as C, models as M
    with env.sessions() as db:
        op = db.get(M.Operation, op_id)
        result = C.store_result(db, uid, op_id,
                                {"filename": "a.log", "summary": {}},
                                result_type="comparison", severity=None)
        db.commit()
        result_id = result.id
    with env.sessions() as db:
        ent = db.get(M.Entitlement, ent_id)
        ent.status = "revoked"
        db.commit()
    _expire_op(env, op_id)
    with env.sessions() as db:
        recovered = C.recover_expired_operations(db)  # no stop evidence
        db.commit()
    assert recovered >= 1
    with env.sessions() as db:
        assert db.get(M.Operation, op_id).status == "failed"
        stored = db.get(M.Result, result_id)
        assert stored.deleted_at is not None  # suppressed, not published
    r = env.client.get(f"/reports/{result_id}")
    assert r.status_code in (303, 404)


# --- Group 8: reconciliation per-SKU (B-14) -------------------------------------------------

def _recon_product_day(env, *, stripe_amount=500, ledger_amount=500):
    from app import payment_reconcile as pr
    from app.models import ProductPurchase, User
    day = date(2026, 11, 10)
    with env.sessions() as db:
        u = User(id=uuid.uuid4(), email=f"r{uuid.uuid4().hex[:8]}@example.com",
                 email_verified=True)
        db.add(u)
        db.commit()
        p = ProductPurchase(
            id=uuid.uuid4(), user_id=u.id, sku="compare",
            content_digest="a" * 64, status="completed",
            stripe_session_id="cs_recon_b", stripe_payment_intent_id="pi_recon_b",
            amount_cents=ledger_amount, currency="usd",
            stripe_price_id=PRICE_BY_SKU["compare"], pricing_version=1,
            stripe_event_id="evt_recon_b",
            completed_at=datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc))
        db.add(p)
        db.commit()

    def fake_get(kind, day_):
        if kind == "sessions":
            return [{"id": "cs_recon_b", "amount_total": stripe_amount,
                     "currency": "usd", "payment_status": "paid",
                     "status": "complete", "payment_intent": "pi_recon_b",
                     "metadata": {"kind": "product", "sku": "compare",
                                  "purchase_id": "x"}}]
        if kind == "charges":
            return [{"id": "ch_recon_b", "amount": stripe_amount,
                     "amount_refunded": 0, "refunded": False,
                     "disputed": False, "payment_intent": "pi_recon_b",
                     "created": 0, "metadata": {}}]
        return []

    with env.sessions() as db:
        run = pr.reconcile_day(db, day, stripe_get=fake_get)
        return SimpleNamespace(
            per_family=copy.deepcopy(run.per_family),
            differences=copy.deepcopy(run.differences))


def test_reconciliation_per_sku_clean(p164b_env):
    run = _recon_product_day(p164b_env)
    product = run.per_family["product"]
    assert product["per_sku"]["compare"]["stripe_gross_cents"] == 500
    assert product["per_sku"]["compare"]["ledger_gross_cents"] == 500
    assert not [d for d in run.differences if d.get("sku") == "compare"]


def test_reconciliation_per_sku_mismatch_named(p164b_env):
    run = _recon_product_day(p164b_env, stripe_amount=400)
    kinds = [(d["kind"], d.get("sku")) for d in run.differences]
    assert ("sku_total_mismatch", "compare") in kinds


# --- Runtime interaction tests ---------------------------------------------------------------

def test_runtime_checkout_two_digests_no_stale_state(p164b_env):
    """DOM-level: checking out digest A then digest B must not leak
    A's digest or SKU into B's Stripe session."""
    env = p164b_env
    _, uid, csrf = _make_user(env)
    captured = _fake_stripe(env.monkeypatch)
    digest_a = _compare_digest()
    digest_b = _compare_digest(LOG_B, LOG_A, "a.log", "b.log")
    r1 = _checkout(env, csrf, "compare", digest_a)
    r2 = _checkout(env, csrf, "compare", digest_b)
    assert r1.status_code == 200 and r2.status_code == 200
    assert r1.json()["purchase_id"] != r2.json()["purchase_id"]
    meta = [c["data"] for c in captured]
    assert meta[0]["metadata[content_digest]"] == digest_a
    assert meta[1]["metadata[content_digest]"] == digest_b
    assert meta[1]["metadata[sku]"] == "compare"


def test_runtime_promise_and_price_stable_across_failed_retry(p164b_env, monkeypatch):
    """DOM-level: the pay-now promise and the $5 price read
    identically before and after a failed redemption attempt."""
    env = p164b_env
    _, uid, csrf = _make_user(env)
    _buy_and_settle(env, csrf, "compare", _compare_digest())
    from app import main, stripe_billing as sb

    def failing(a, b, c, d):
        return ({"error": "analysis_failed", "message": "x", "filename": "a.log"},
                {"error": "analysis_failed", "message": "x", "filename": "b.log"})

    monkeypatch.setattr(main, "_execute_compare", failing)
    r = _post_compare(env)
    assert sb.PAY_NOW_PROMISE not in r.text  # Run path: nothing to buy
    assert "$5" in r.text
    consent_id, file_hash = _consent_fields(r.text)
    assert _confirm_compare(env, consent_id, file_hash, csrf).status_code == 400
    # After the failure the entitlement is intact and the re-quote
    # still offers the Run path at the same terms.
    r = _post_compare(env)
    assert "already paid" in r.text and "$5" in r.text


def test_runtime_replay_after_redemption_returns_report_not_purchase(p164b_env):
    """DOM-level: re-confirming a completed redemption replays the
    report itself — the user is never asked to buy again."""
    env = p164b_env
    _, uid, csrf = _make_user(env)
    _buy_and_settle(env, csrf, "compare", _compare_digest())
    r = _post_compare(env)
    consent_id, file_hash = _consent_fields(r.text)
    first = _confirm_compare(env, consent_id, file_hash, csrf)
    assert first.status_code == 200
    rid = re.search(r'action="/reports/([0-9a-f-]{36})/pdf"', first.text).group(1)
    replay = _confirm_compare(env, consent_id, file_hash, csrf)
    assert replay.status_code == 200
    assert rid in replay.text
    assert "product-checkout-form" not in replay.text


# --- PR #182 remediation: Codex findings 1-3 ---------------------------------------------

def _capacity_snapshot(env, user_id):
    from app import models as M
    keys = ("global:batch", "global:oversize", "global:paid",
            f"user:{user_id}:paid")
    with env.sessions() as db:
        rows = {r.scope_key: r.used for r in db.query(M.CapacityScope).all()}
    return {k: rows.get(k, 0) for k in keys}


def _lapse_entitlement(env, ent_id):
    from app import credits as C, models as M
    with env.sessions() as db:
        ent = db.get(M.Entitlement, ent_id)
        ent.redemption_deadline = C._utcnow() - timedelta(seconds=1)
        db.commit()


def test_lapsed_batch_redemption_leaves_capacity_unchanged(p164b_env):
    """Finding 1 (P1): a lapsed Batch redemption must roll back the
    admission capacity it acquired (global:batch is single-slot, so a
    leak permanently exhausts it) while the entitlement still lands
    in refund_eligible and the endpoint answers 410 (B-11)."""
    env = p164b_env
    _, uid, csrf = _make_user(env)
    files = _batch_files()
    _, ent_id = _seed_entitlement(env, uid, "batch", _batch_digest(files))
    _lapse_entitlement(env, ent_id)
    r = _post_batch(env, files)
    assert r.status_code == 402, r.text[:300]
    from app import models as _M1
    with env.sessions() as db:
        consent = db.query(_M1.Consent).filter(
            _M1.Consent.user_id == uid,
            _M1.Consent.operation_type == "batch").one()
        consent_id, file_hash = str(consent.id), consent.input_hash
    before = _capacity_snapshot(env, uid)
    r = env.client.post(
        "/batch/paid",
        data={"consent_id": consent_id, "file_hash": file_hash,
              "idempotency_key": consent_id, "csrf_token": csrf})
    assert r.status_code == 410, r.text[:300]
    assert _capacity_snapshot(env, uid) == before
    from app import models as M
    with env.sessions() as db:
        assert db.get(M.Entitlement, ent_id).status == "refund_eligible"
        assert db.query(M.Operation).count() == 0


def test_lapsed_oversize_redemption_leaves_capacity_unchanged(p164b_env):
    """Finding 1 (P1), oversize twin: global:oversize is single-slot."""
    env = p164b_env
    _, uid, csrf = _make_user(env)
    content = (b"2024-01-01 10:00:00 INFO heartbeat ok\n" * 50001)
    from app.analysis_admission import fingerprint
    digest = fingerprint("big.log", content)
    _, ent_id = _seed_entitlement(env, uid, "large_file_analysis", digest)
    _lapse_entitlement(env, ent_id)
    r = env.client.post(
        "/analyze",
        files={"file": ("big.log", content, "text/plain")},
        data={"output": "html", "request_id": ""})
    assert r.status_code == 402, r.text[:300]
    from app import models as _M2
    with env.sessions() as db:
        consent = db.query(_M2.Consent).filter(
            _M2.Consent.user_id == uid,
            _M2.Consent.operation_type == "oversize_analysis").one()
        consent_id, file_hash = str(consent.id), consent.input_hash
    before = _capacity_snapshot(env, uid)
    r = env.client.post(
        "/analyze/paid",
        data={"consent_id": consent_id, "file_hash": file_hash,
              "idempotency_key": consent_id, "csrf_token": csrf})
    assert r.status_code == 410, r.text[:300]
    assert _capacity_snapshot(env, uid) == before
    from app import models as M
    with env.sessions() as db:
        assert db.get(M.Entitlement, ent_id).status == "refund_eligible"
        assert db.query(M.Operation).count() == 0


def test_runtime_product_checkout_return_settling_then_run(p164b_env):
    """Finding 2 (P1), DOM-level: the URL Stripe returns the buyer to
    (read from the actual session-creation payload) renders a
    settlement-aware surface — 'still settling' before the webhook,
    the Run form for the SAME pending consent after it — never the
    plain home page and never a second checkout prompt."""
    from urllib.parse import urlparse
    env = p164b_env
    _, uid, csrf = _make_user(env)
    r = _post_compare(env)
    assert r.status_code == 402, r.text[:300]
    from app import models as _M3
    with env.sessions() as db:
        consent = db.query(_M3.Consent).filter(
            _M3.Consent.user_id == uid,
            _M3.Consent.operation_type == "compare_logs").one()
        consent_id, file_hash = str(consent.id), consent.input_hash
    captured = _fake_stripe(env.monkeypatch)
    r = _checkout(env, csrf, "compare", _compare_digest())
    assert r.status_code == 200, r.text[:300]
    parsed = urlparse(captured[-1]["data"]["success_url"])
    landing = parsed.path + "?" + parsed.query
    r = env.client.get(landing)
    assert r.status_code == 200, r.text[:300]
    assert "still settling" in r.text
    assert "product-checkout-form" not in r.text
    # Settle the very purchase the checkout created (webhook-only).
    from app import models as M
    with env.sessions() as db:
        purchase = db.query(M.ProductPurchase).filter(
            M.ProductPurchase.user_id == uid).one()
        ref = SimpleNamespace(id=purchase.id, user_id=purchase.user_id)
        session_id = purchase.stripe_session_id
    _LINE_PRICE["id"] = PRICE_BY_SKU["compare"]
    ev = _completed_event("evt_return_1", ref, sku="compare",
                          digest=_compare_digest(), session_id=session_id)
    assert _post_event(env, ev).status_code == 200
    r = env.client.get(landing)
    assert r.status_code == 200, r.text[:300]
    assert "Payment received" in r.text
    assert "already paid" in r.text  # the Run path
    assert "product-checkout-form" not in r.text  # no duplicate checkout
    run_consent, run_hash = _consent_fields(r.text)
    assert (run_consent, run_hash) == (consent_id, file_hash)
    r = _confirm_compare(env, run_consent, run_hash, csrf)
    assert r.status_code == 200, r.text[:300]


def test_runtime_product_return_binds_to_purchase_not_latest_consent(p164b_env):
    """Finding 4 (P2), DOM-level: the return landing must bind to the
    checkout's purchase, not the buyer's LATEST consent. The buyer
    pays for digest A, then opens a quote for different files (digest
    B, a newer consent) in another tab; the return URL carrying A's
    purchase id must render A's Run form — never 'settling' and never
    B's consent."""
    env = p164b_env
    _, uid, csrf = _make_user(env)
    r = _post_compare(env)
    assert r.status_code == 402, r.text[:300]
    from app import models as M
    with env.sessions() as db:
        consent_a = db.query(M.Consent).filter(
            M.Consent.user_id == uid,
            M.Consent.operation_type == "compare_logs").one()
        consent_a_id, hash_a = str(consent_a.id), consent_a.input_hash
    captured = _fake_stripe(env.monkeypatch)
    r = _checkout(env, csrf, "compare", _compare_digest())
    assert r.status_code == 200, r.text[:300]
    purchase_a_id = r.json()["purchase_id"]
    # A newer consent B for different files, created AFTER checkout A.
    r = _post_compare(env, LOG_B, LOG_A)
    assert r.status_code == 402, r.text[:300]
    with env.sessions() as db:
        consents = db.query(M.Consent).filter(
            M.Consent.user_id == uid,
            M.Consent.operation_type == "compare_logs",
        ).order_by(M.Consent.created_at.asc()).all()
        assert len(consents) == 2
        consent_b = consents[-1]
        consent_b_id, hash_b = str(consent_b.id), consent_b.input_hash
        assert consent_b_id != consent_a_id and hash_b != hash_a
        # Make B strictly the latest consent, deterministically.
        consents[0].created_at = consents[0].created_at - timedelta(minutes=5)
        db.commit()
    # Settle ONLY purchase A (webhook-only settlement).
    with env.sessions() as db:
        purchase = db.get(M.ProductPurchase, uuid.UUID(purchase_a_id))
        ref = SimpleNamespace(id=purchase.id, user_id=purchase.user_id)
        session_id = purchase.stripe_session_id
    _LINE_PRICE["id"] = PRICE_BY_SKU["compare"]
    ev = _completed_event("evt_return_bind_a", ref, sku="compare",
                          digest=hash_a, session_id=session_id)
    assert _post_event(env, ev).status_code == 200
    # The return URL as minted after the fix carries the purchase id.
    landing = ("/products/return?product_checkout=success&sku=compare"
               f"&purchase={purchase_a_id}")
    r = env.client.get(landing)
    assert r.status_code == 200, r.text[:300]
    assert "still settling" not in r.text
    run_consent, run_hash = _consent_fields(r.text)
    assert (run_consent, run_hash) == (consent_a_id, hash_a)
    # Checkout wiring: the Stripe session URLs themselves carry the
    # purchase binding (success AND cancel).
    assert f"purchase={purchase_a_id}" in captured[-1]["data"]["success_url"]
    assert f"purchase={purchase_a_id}" in captured[-1]["data"]["cancel_url"]


def test_runtime_product_return_bound_settling_preserves_purchase(p164b_env):
    """Finding 4 (P2): before settlement, a purchase-bound return
    renders 'settling' and its Check-again link PRESERVES the
    purchase binding, so the recheck cannot drift to a newer
    consent either."""
    env = p164b_env
    _, uid, csrf = _make_user(env)
    r = _post_compare(env)
    assert r.status_code == 402, r.text[:300]
    captured = _fake_stripe(env.monkeypatch)
    r = _checkout(env, csrf, "compare", _compare_digest())
    assert r.status_code == 200, r.text[:300]
    purchase_id = r.json()["purchase_id"]
    assert f"purchase={purchase_id}" in captured[-1]["data"]["success_url"]
    landing = ("/products/return?product_checkout=success&sku=compare"
               f"&purchase={purchase_id}")
    r = env.client.get(landing)
    assert r.status_code == 200, r.text[:300]
    assert "still settling" in r.text
    assert f"purchase={purchase_id}" in r.text  # Check-again href


def test_runtime_product_return_unknown_purchase_binds_nothing(p164b_env):
    """Finding 4 (P2): a purchase parameter that does not resolve to
    THIS buyer's purchase for the SKU binds to nothing — even though
    the buyer holds a settled, ready-to-run consent A, the landing
    renders the honest 'missing' state instead of A's Run form."""
    env = p164b_env
    _, uid, csrf = _make_user(env)
    r = _post_compare(env)
    assert r.status_code == 402, r.text[:300]
    _buy_and_settle(env, csrf, "compare", _compare_digest())
    bogus = uuid.uuid4()
    r = env.client.get(
        "/products/return?product_checkout=success&sku=compare"
        f"&purchase={bogus}")
    assert r.status_code == 200, r.text[:300]
    assert "could not find a purchase" in r.text
    assert 'action="/compare/paid"' not in r.text


def test_runtime_product_return_missing_pending_renders_reupload_not_run(p164b_env):
    """Finding 5 (P2), DOM-level: entitlement + live consent exist
    but the pending payload is GONE (temp storage lost) — the landing
    must render the re-upload recovery state, NOT 'ready' with a Run
    form that would necessarily 410 at the paid handler. Checked on
    both the legacy (no purchase param) and purchase-bound URLs."""
    env = p164b_env
    _, uid, csrf = _make_user(env)
    r = _post_compare(env)
    assert r.status_code == 402, r.text[:300]
    from app import main, models as M
    with env.sessions() as db:
        consent = db.query(M.Consent).filter(
            M.Consent.user_id == uid,
            M.Consent.operation_type == "compare_logs").one()
        consent_id = str(consent.id)
    _buy_and_settle(env, csrf, "compare", _compare_digest())
    with env.sessions() as db:
        purchase_id = str(db.query(M.ProductPurchase).filter(
            M.ProductPurchase.user_id == uid).one().id)
    # The pending payload is lost after settlement.
    main._delete_paid_pending(consent_id)
    assert main._load_compare_pending(consent_id) is None
    for landing in (
            "/products/return?product_checkout=success&sku=compare",
            "/products/return?product_checkout=success&sku=compare"
            f"&purchase={purchase_id}"):
        r = env.client.get(landing)
        assert r.status_code == 200, r.text[:300]
        assert "Upload the same files" in r.text  # re-upload recovery
        assert 'action="/compare/paid"' not in r.text  # no Run form
        assert "Run comparison" not in r.text


def test_runtime_oversize_cancel_post_on_checkout_branch_releases_lockout(p164b_env):
    """Finding 3 (P2), DOM-level: on the dollar checkout branch the
    oversize consent page renders the CSRF cancel POST (not only a
    link home), exactly one Cancel control renders, and posting the
    cancel releases the one-live-consent lockout so a DIFFERENT
    oversize upload is accepted."""
    env = p164b_env
    _, uid, csrf = _make_user(env)
    content = (b"2024-01-01 10:00:00 INFO heartbeat ok\n" * 50001)
    r = env.client.post(
        "/analyze",
        files={"file": ("big.log", content, "text/plain")},
        data={"output": "html", "request_id": ""})
    assert r.status_code == 402, r.text[:300]
    assert "product-checkout-form" in r.text  # checkout branch
    assert 'action="/analyze/paid/cancel"' in r.text
    assert r.text.count('class="btn-cancel"') == 1  # one Cancel control
    cancel_form = r.text.split('action="/analyze/paid/cancel"', 1)[1]
    consent_id = re.search(r'name="consent_id" value="([^"]+)"',
                           cancel_form).group(1)
    cancel_csrf = re.search(r'name="csrf_token" value="([^"]+)"',
                            cancel_form).group(1)
    r = env.client.post(
        "/analyze/paid/cancel",
        data={"consent_id": consent_id, "csrf_token": cancel_csrf})
    assert r.status_code == 200, r.text[:200]
    # A different oversize upload now quotes instead of hitting the
    # one-live-consent lockout error.
    other = (b"2024-01-01 10:00:01 INFO a different heartbeat\n" * 50001)
    r = env.client.post(
        "/analyze",
        files={"file": ("other.log", other, "text/plain")},
        data={"output": "html", "request_id": ""})
    assert r.status_code == 402, r.text[:300]
    assert "already have an oversize upload" not in r.text
    assert "product-checkout-form" in r.text


# --- B-21: PostgreSQL replay-vs-settlement race ------------------------------------------------

@pytest.mark.skipif(not os.environ.get("TEST_POSTGRES_URL"),
                    reason="PostgreSQL leg runs in CI (TEST_POSTGRES_URL unset)")
def test_postgres_concurrent_admit_single_operation():
    """Two concurrent admissions with the same idempotency key on
    PostgreSQL produce exactly ONE Operation and ONE redemption —
    the replay branch under the B-21 lock order. Mirrors the
    test_batch_postgres_concurrency harness shape."""
    import threading
    from app import credits as C, models as M, product_billing as pb
    from app.db import Base
    engine = create_engine(os.environ["TEST_POSTGRES_URL"])
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)
    with sessions() as db:
        u = M.User(id=uuid.uuid4(),
                   email=f"pg{uuid.uuid4().hex[:8]}@example.com",
                   email_verified=True)
        db.add(u)
        db.commit()
        uid = u.id
        digest = "9" * 64
        purchase = M.ProductPurchase(
            user_id=uid, sku="compare", content_digest=digest,
            status="completed", amount_cents=500, currency="usd",
            stripe_price_id=PRICE_BY_SKU["compare"], pricing_version=1,
            completed_at=C._utcnow())
        db.add(purchase)
        db.flush()
        db.add(M.Entitlement(
            user_id=uid, sku="compare", product_purchase_id=purchase.id,
            content_digest=digest, status="available",
            redemption_deadline=C._utcnow() + timedelta(days=30)))
        consent = C.create_product_consent(db, uid, "compare_logs", digest,
                                           "compare")
        db.commit()
        consent_id = consent.id
    key = uuid.uuid4().hex
    results, errors = [], []

    def admit():
        try:
            with sessions() as db:
                item = pb.admit_product_operation(
                    db, uid, "compare_logs", "compare", key, digest,
                    consent_id, "worker-pg", input_manifest="127.0.0.1")
                db.commit()
                results.append(item.id)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=admit) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert errors == []
    assert len(set(results)) == 1
    with sessions() as db:
        assert db.query(M.Operation).filter(
            M.Operation.user_id == uid).count() == 1
        assert db.query(M.EntitlementRedemption).count() == 1
    engine.dispose()
