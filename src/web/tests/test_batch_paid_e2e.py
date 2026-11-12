"""Issue #103: batch analysis (paid) — HTTP + ledger coverage.

PREMISE CHANGED by issue #164 Phase B: batch is a flat $5
digest-bound product. The journey is now:

    signup -> verify (10-credit signup reward) -> login
      -> GET /batch form -> POST /batch (2-5 files, ALL validated first)
         -> 402 quote page: flat $5, zero-cost product consent
      -> (purchase settles out of band; tests seed the entitlement)
      -> POST /batch/paid -> ONE zero-cost product-backed Operation,
         NO free-allowance claim, NO credit movement -> sequential
         execution -> ONE combined Result (type "analysis",
         report_kind "batch", 90-day retention) -> history ->
         FREE PDF export for the whole combined report

Execution is mocked at the main._execute_batch boundary (the mocked-
execution pattern from #102/#104: HTTP/ledger tests never run the real
worker); the real supervised worker is covered in
test_batch_resources.py. Runs against SQLite and real PostgreSQL via
``migrated_engine``; the Postgres leg runs in CI (TEST_POSTGRES_URL)
and skips locally.
"""

import copy
import pathlib
import re
import uuid
from datetime import timedelta
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from test_account_migrations import migrated_engine  # noqa: F401  (fixture)
from app import auth, credits as C, db as DB, email, main, models as M
from app.service import analyze_upload as service_analyze


def _log(level, message, n):
    return (f"2024-01-01 10:00:00 {level} {message}\n".encode() * n)


LOG_1 = _log("ERROR", "database connection failed", 10) + _log("WARN", "cache miss", 5)
LOG_2 = _log("ERROR", "database connection failed", 5) + _log("ERROR", "disk full", 3)
LOG_3 = _log("INFO", "heartbeat ok", 4)
SMALL = _log("INFO", "heartbeat ok", 2)


@pytest.fixture
def batch_env(migrated_engine, monkeypatch, tmp_path):
    engine, _ = migrated_engine
    sessions = sessionmaker(bind=engine, autoflush=False)
    monkeypatch.setenv("DATABASE_URL", str(engine.url))
    monkeypatch.setattr(DB, "SessionLocal", sessions)
    monkeypatch.setattr(main, "_PAID_PENDING_DIR", str(tmp_path / "pending"))
    monkeypatch.setattr(auth, "auth_limiter", auth.AuthRateLimiter())
    monkeypatch.setattr(auth, "check_password_breached", lambda _: False)
    sent = []
    monkeypatch.setattr(
        email, "send_verification_email",
        lambda address, token: sent.append(("verify", address, token)))
    monkeypatch.setattr(
        email, "send_password_reset_email",
        lambda address, token: sent.append(("reset", address, token)))

    def fake_batch(files):
        return [copy.deepcopy(service_analyze(filename, content, use_alarm=False))
                for _ordinal, filename, content in files]

    monkeypatch.setenv("STRIPE_PRICE_BATCH", "price_test_batch")
    monkeypatch.setenv("STRIPE_PRICE_COMPARE", "price_test_compare")
    monkeypatch.setattr(main, "_execute_batch", fake_batch)

    def fake_compare(filename_a, content_a, filename_b, content_b):
        return (
            copy.deepcopy(service_analyze(filename_a, content_a,
                                           collect_comparison_evidence=True,
                                           use_alarm=False)),
            copy.deepcopy(service_analyze(filename_b, content_b,
                                           collect_comparison_evidence=True,
                                           use_alarm=False)),
        )

    monkeypatch.setattr(main, "_execute_compare", fake_compare)
    # Single-file path: precomputed sample report (SIGALRM pattern).
    from app.sample_data import SAMPLE_LOG
    sample_report = service_analyze("test.log", SAMPLE_LOG.encode())

    def fake_single(*args, **kwargs):
        return copy.deepcopy(sample_report)

    monkeypatch.setattr(main, "analyze_upload", fake_single)
    with TestClient(
        main.app,
        base_url="https://testserver",
        raise_server_exceptions=False,
        client=("127.0.0.1", 50000),
    ) as client:
        client.headers["X-CSRF-Token"] = client.get("/auth/csrf").json()["csrf_token"]
        yield SimpleNamespace(engine=engine, sessions=sessions, sent=sent,
                              client=client, tmp_path=tmp_path)


# --- helpers -----------------------------------------------------------------

def _signup_verify_login(env, email_addr=None):
    email_addr = email_addr or f"bat_{uuid.uuid4().hex[:8]}@example.com"
    password = "CorrectHorseBatteryStaple!1"
    r = env.client.post("/auth/signup", data={"email": email_addr, "password": password})
    assert r.status_code == 200, r.text[:300]
    token = env.sent[-1][2]
    r = env.client.post("/auth/verify", data={"token": token})
    assert r.status_code == 200, r.text[:300]
    env.client.headers["X-CSRF-Token"] = env.client.get("/auth/csrf").json()["csrf_token"]
    r = env.client.post("/auth/login", data={"email": email_addr, "password": password})
    assert r.status_code == 200, r.text[:300]
    csrf = r.json()["csrf_token"]
    env.client.headers["X-CSRF-Token"] = csrf
    with env.sessions() as db:
        uid = db.query(M.User).filter(M.User.email == email_addr).one().id
    return email_addr, uid, csrf


def _http_balance(env):
    r = env.client.get("/credits/balance")
    assert r.status_code == 200, r.text[:300]
    return r.json()["balance"]


def _post_batch(env, files):
    return env.client.post(
        "/batch",
        files=[("files", (name, content, "text/plain")) for name, content in files],
    )


def _three():
    return [("one.log", LOG_1), ("two.log", LOG_2), ("three.log", LOG_3)]


def _consent_fields(page_text):
    def field(name):
        m = re.search(r'name="%s" value="([^"]+)"' % name, page_text)
        assert m, f"{name} not in consent page"
        return m.group(1)
    return field("consent_id"), field("file_hash"), field("csrf_token")


def _confirm(env, consent_id, file_hash, csrf, idempotency_key=None):
    return env.client.post(
        "/batch/paid",
        data={"consent_id": consent_id, "file_hash": file_hash,
              "idempotency_key": idempotency_key or consent_id,
              "csrf_token": csrf})


def _report_id_from(html):
    m = re.search(r'action="/reports/([0-9a-f-]{36})/pdf"', html)
    assert m, "no PDF export form (hence no report id) in batch report"
    return m.group(1)


def _grant(env, uid, n, key):
    with env.sessions() as db:
        C.grant_credits(db, uid, "purchase", key, n)
        db.commit()


def _seed_batch_entitlement(env, uid, files):
    """Seed a settled $5 batch purchase + available entitlement bound
    to the ordered manifest digest of ``files`` [(name, content)]."""
    from app.redact import redact_secrets
    from app import models as _M
    triples = [(i + 1, name, redact_secrets(content.decode("utf-8", "replace")).encode())
               for i, (name, content) in enumerate(files)]
    digest = main._batch_bundle_hash(triples)
    with env.sessions() as db:
        purchase = _M.ProductPurchase(
            user_id=uid, sku="batch", content_digest=digest,
            status="completed", amount_cents=500, currency="usd",
            stripe_price_id="price_test_batch", pricing_version=1,
            completed_at=C._utcnow())
        db.add(purchase)
        db.flush()
        db.add(_M.Entitlement(
            user_id=uid, sku="batch", product_purchase_id=purchase.id,
            content_digest=digest, status="available",
            redemption_deadline=C._utcnow() + timedelta(days=30)))
        db.commit()
    return digest


def _seed_compare_entitlement(env, uid, content_a, content_b,
                              name_a="a.log", name_b="b.log"):
    from app import models as _M
    digest = main._compare_pair_hash(name_a, content_a, name_b, content_b)
    with env.sessions() as db:
        purchase = _M.ProductPurchase(
            user_id=uid, sku="compare", content_digest=digest,
            status="completed", amount_cents=500, currency="usd",
            stripe_price_id="price_test_compare", pricing_version=1,
            completed_at=C._utcnow())
        db.add(purchase)
        db.flush()
        db.add(_M.Entitlement(
            user_id=uid, sku="compare", product_purchase_id=purchase.id,
            content_digest=digest, status="available",
            redemption_deadline=C._utcnow() + timedelta(days=30)))
        db.commit()
    return digest


def _entitlement_status(env, uid, sku):
    with env.sessions() as db:
        row = db.query(M.Entitlement).filter(
            M.Entitlement.user_id == uid, M.Entitlement.sku == sku).first()
        return row.status if row else None


def _drain_signup(env, uid, qty):
    """Re-base the 10-credit signup grant (issue #151) to a lower balance:
    reduce the signup grant's remaining and the account balance together
    (mirroring how _grant helpers in test_compare_routes.py adjust both)."""
    with env.sessions() as db:
        grant = db.query(M.CreditGrant).filter(
            M.CreditGrant.user_id == uid,
            M.CreditGrant.source == "signup").one()
        assert grant.remaining >= qty
        grant.remaining -= qty
        account = db.query(M.CreditAccount).filter(
            M.CreditAccount.user_id == uid).one()
        account.balance -= qty
        db.commit()


def _ops(env, uid):
    with env.sessions() as db:
        return db.query(M.Operation).filter(
            M.Operation.user_id == uid, M.Operation.type == "batch").all()


def _hits(env):
    with env.sessions() as db:
        return db.query(M.RateLimitHit).filter(
            M.RateLimitHit.trusted_ip == "127.0.0.1").count()


def _seed_free(env, uid, n, *, minutes_ago=2):
    with env.sessions() as db:
        for _ in range(n):
            db.add(M.FreeRequest(
                request_id=uuid.uuid4().hex, user_id=uid, fingerprint="old",
                status="failed", quota_bucket_trusted_ip="127.0.0.1",
                created_at=C._utcnow() - timedelta(minutes=minutes_ago),
                deadline=C._utcnow()))
        db.commit()


def _seed_hits(env, n, *, minutes_ago=2):
    with env.sessions() as db:
        for _ in range(n):
            db.add(M.RateLimitHit(
                trusted_ip="127.0.0.1",
                hit_at=C._utcnow() - timedelta(minutes=minutes_ago)))
        db.commit()


def _pending_files(env):
    pending = pathlib.Path(main._PAID_PENDING_DIR)
    return list(pending.glob("pending-*.bin")) if pending.exists() else []


def _invariants_ok(env, uid):
    with env.sessions() as db:
        assert C.verify_account_invariants(db, uid) == []
        assert C.verify_capacity_invariants(db) == []


# --- auth ----------------------------------------------------------------------

def test_batch_get_requires_login_and_post_anonymous_401(batch_env):
    env = batch_env
    r = env.client.get("/batch", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    r = _post_batch(env, _three())
    assert r.status_code == 401, r.text[:300]
    with env.sessions() as db:
        assert db.query(M.Consent).count() == 0
        assert db.query(M.Operation).count() == 0
    assert _pending_files(env) == []


def test_batch_form_renders_for_user(batch_env):
    env = batch_env
    _signup_verify_login(env)
    r = env.client.get("/batch")
    assert r.status_code == 200, r.text[:300]
    assert 'name="files"' in r.text and "multiple" in r.text


# --- the full journey ------------------------------------------------------------

def test_full_batch_flow_dollar_paid(batch_env):
    env = batch_env
    _, uid, _ = _signup_verify_login(env)
    assert _http_balance(env) == 10
    _seed_batch_entitlement(env, uid, _three())
    r = _post_batch(env, _three())
    assert r.status_code == 402, r.text[:500]
    # Dollar quote copy (Phase B): flat $5, entitlement held -> Run path.
    assert "3 files. One flat price covers the whole batch." in r.text
    assert "One flat price covers the whole batch." in r.text
    assert "No charge if the batch fails" in r.text
    assert "Analyze 3 files \u2014 already paid" in r.text
    assert "free hourly allowance" not in r.text
    assert "1. one.log" in r.text and "2. two.log" in r.text and "3. three.log" in r.text
    consent_id, file_hash, csrf = _consent_fields(r.text)
    # Consent itself: zero-cost — no debit, no claim, no hit, no op.
    assert _http_balance(env) == 10
    assert _ops(env, uid) == [] and _hits(env) == 0
    confirmed = _confirm(env, consent_id, file_hash, csrf)
    assert confirmed.status_code == 200, confirmed.text[:500]
    assert "Batch \u2014 3 files" in confirmed.text
    assert "database connection failed" in confirmed.text
    assert "disk full" in confirmed.text
    assert _http_balance(env) == 10  # credits never move on the dollar path
    ops = _ops(env, uid)
    assert len(ops) == 1 and ops[0].cost == 0 and ops[0].status == "completed"
    assert ops[0].entitlement_redemption_id is not None
    assert ops[0].free_allowance_claim is False  # B-19: no claim
    assert _hits(env) == 0  # B-19: no RateLimitHit
    assert _entitlement_status(env, uid, "batch") == "redeemed"
    with env.sessions() as db:
        assert db.query(M.FreeRequest).count() == 0  # no second FreeRequest
        result = db.get(M.Result, ops[0].result_id)
        assert result is not None and result.type == "analysis"
        assert (C._as_aware(result.expires_at) - C._as_aware(result.created_at)
                ) >= timedelta(days=89)  # 90-day paid retention
        import json as _json
        manifest = _json.loads(result.storage_manifest)
        assert manifest["report_kind"] == "batch"
        assert [f["ordinal"] for f in manifest["files"]] == [1, 2, 3]
        combined = {e["template"]: e for e in manifest["combined_issues"]}
        db_template = next(t for t in combined if "database connection failed" in t)
        assert combined[db_template]["count"] == 15
        assert [f["count"] for f in combined[db_template]["files"]] == [10, 5]
    _invariants_ok(env, uid)
    # Retrievable through history, rendered with the batch template.
    rid = _report_id_from(confirmed.text)
    view = env.client.get(f"/reports/{rid}")
    assert view.status_code == 200, view.text[:300]
    assert "File 2: two.log" in view.text
    listing = env.client.get("/reports")
    assert "Batch \u2014 3 files" in listing.text
    assert _pending_files(env) == []  # pending bundle consumed/cleaned


def test_batch_dollar_ignores_free_allowance(batch_env):
    """B-19: an exhausted free allowance changes nothing on the
    dollar path — flat $5, no claim, no hit, balance untouched."""
    env = batch_env
    _, uid, _ = _signup_verify_login(env)
    _seed_free(env, uid, 10)
    _seed_batch_entitlement(env, uid, _three())
    r = _post_batch(env, _three())
    assert r.status_code == 402, r.text[:300]
    assert "One flat price covers the whole batch." in r.text
    consent_id, file_hash, csrf = _consent_fields(r.text)
    confirmed = _confirm(env, consent_id, file_hash, csrf)
    assert confirmed.status_code == 200, confirmed.text[:300]
    assert _http_balance(env) == 10
    ops = _ops(env, uid)
    assert len(ops) == 1 and ops[0].cost == 0
    assert ops[0].free_allowance_claim is False
    assert _hits(env) == 0
    _invariants_ok(env, uid)


# --- validation: ALL inputs before any run/reservation ---------------------------

@pytest.mark.parametrize("files,fragment", [
    ([("one.log", LOG_1), ("bad.csv", LOG_2), ("three.log", LOG_3)],
     "File 2 (bad.csv)"),
    ([("one.log", LOG_1), ("two.log", b""), ("three.log", LOG_3)],
     "File 2 (two.log)"),
    ([("one.log", LOG_1), ("two.log", b"\x89PNG\r\n\x1a\n" + b"\x00" * 32), ("three.log", LOG_3)],
     "File 2 (two.log)"),
    ([("one.log", LOG_1), ("two.log", LOG_2), ("three.log", b"x\n" * 50001)],
     "File 3 (three.log): exceeds the 50,000-line limit"),
    ([("one.log", b"y" * (10 * 1024 * 1024 + 1)), ("two.log", LOG_2)],
     "File 1 (one.log): exceeds the 10 MB free limit"),
])
def test_invalid_file_rejects_whole_batch(batch_env, monkeypatch, files, fragment):
    env = batch_env
    _, uid, _ = _signup_verify_login(env)
    calls = []
    monkeypatch.setattr(main, "_execute_batch", lambda f: calls.append(f) or [])
    r = _post_batch(env, files)
    assert r.status_code == 400, r.text[:400]
    assert fragment in r.text
    assert "No files were analyzed and nothing was charged." in r.text
    assert calls == []  # zero analyzer calls
    assert _http_balance(env) == 10
    assert _ops(env, uid) == []
    assert _hits(env) == 0
    assert _pending_files(env) == []
    with env.sessions() as db:
        assert db.query(M.Consent).filter(M.Consent.user_id == uid).count() == 0
        assert db.query(M.Result).count() == 0


def test_batch_count_limits(batch_env):
    env = batch_env
    _, uid, _ = _signup_verify_login(env)
    r = _post_batch(env, [("only.log", LOG_1)])
    assert r.status_code == 400, r.text[:300]
    assert "at least 2 files" in r.text
    r = _post_batch(env, [(f"f{i}.log", SMALL) for i in range(6)])
    assert r.status_code == 400, r.text[:300]
    assert "at most 5 files" in r.text
    # N=2 and N=5 pass validation at the same flat $5 (Decision 3).
    r = _post_batch(env, [("a.log", LOG_1), ("b.log", LOG_2)])
    assert r.status_code == 402 and "One flat price covers the whole batch." in r.text, r.text[:300]
    r = _post_batch(env, [(f"f{i}.log", SMALL) for i in range(5)])
    assert r.status_code == 402 and "One flat price covers the whole batch." in r.text, r.text[:300]


def test_batch_boundary_equality_50000_lines_passes(batch_env):
    env = batch_env
    _signup_verify_login(env)
    exact = b"2024-01-01 10:00:00 INFO heartbeat ok\n" * 50000
    r = _post_batch(env, [("big.log", exact), ("small.log", SMALL)])
    assert r.status_code == 402, r.text[:300]
    assert "One flat price covers the whole batch." in r.text


# --- failure release ---------------------------------------------------------------

def test_execution_failure_releases_entitlement_no_claim(batch_env, monkeypatch):
    env = batch_env
    _, uid, _ = _signup_verify_login(env)
    _seed_batch_entitlement(env, uid, _three())
    r = _post_batch(env, _three())
    consent_id, file_hash, csrf = _consent_fields(r.text)

    def failing(files):
        out = [copy.deepcopy(service_analyze(fn, c, use_alarm=False))
               for _o, fn, c in files]
        out[1] = {"error": "analysis_timeout", "message": "Analysis timed out.",
                  "filename": files[1][1]}
        return out

    monkeypatch.setattr(main, "_execute_batch", failing)
    failed = _confirm(env, consent_id, file_hash, csrf)
    assert failed.status_code == 400, failed.text[:400]
    assert "File 2 (two.log)" in failed.text
    assert _http_balance(env) == 10  # credits never moved
    ops = _ops(env, uid)
    assert len(ops) == 1 and ops[0].status == "failed" and ops[0].result_id is None
    # F2/B-19: no allowance claim, no hit; the entitlement is
    # released back to available for a retry.
    assert ops[0].free_allowance_claim is False
    assert _hits(env) == 0
    assert _entitlement_status(env, uid, "batch") == "available"
    with env.sessions() as db:
        assert db.query(M.Result).count() == 0
    assert _pending_files(env) == []
    _invariants_ok(env, uid)
    # A failed identity does not re-execute on replay.
    replay = _confirm(env, consent_id, file_hash, csrf)
    assert replay.status_code == 409, replay.text[:300]
    assert _http_balance(env) == 10


def test_execution_exception_releases_all(batch_env, monkeypatch):
    env = batch_env
    _, uid, _ = _signup_verify_login(env)
    _seed_batch_entitlement(env, uid, _three())
    r = _post_batch(env, _three())
    consent_id, file_hash, csrf = _consent_fields(r.text)

    def boom(files):
        raise RuntimeError("worker died")

    monkeypatch.setattr(main, "_execute_batch", boom)
    r = _confirm(env, consent_id, file_hash, csrf)
    assert r.status_code == 503, r.text[:300]
    assert _http_balance(env) == 10
    assert _ops(env, uid)[0].status == "failed"
    assert _entitlement_status(env, uid, "batch") == "available"  # F2
    _invariants_ok(env, uid)


# --- insufficient credits ------------------------------------------------------------

def test_batch_no_entitlement_quote_offers_checkout_and_confirm_402(batch_env):
    """Dollar analog of insufficient-at-quotation: without a settled
    entitlement the quote page offers Stripe checkout (never a
    credit purchase), and confirming anyway is a 402 naming the $5
    price — no operation, no claim."""
    env = batch_env
    _, uid, _ = _signup_verify_login(env)
    r = _post_batch(env, _three())
    assert r.status_code == 402, r.text[:400]
    assert "product-checkout-form" in r.text  # buy path, not credits
    assert "Buy \u2014 $5" in r.text
    assert "/credits" not in r.text
    # The checkout variant renders no consent form; the zero-cost
    # consent exists server-side — take its id/hash from the DB.
    with env.sessions() as db:
        consent = db.query(M.Consent).filter(
            M.Consent.user_id == uid).one()
        consent_id, file_hash = str(consent.id), consent.input_hash
    csrf = env.client.get("/auth/csrf").json()["csrf_token"]
    denied = _confirm(env, consent_id, file_hash, csrf)
    assert denied.status_code == 402, denied.text[:400]
    assert "Batch analysis costs $5." in denied.text
    assert _ops(env, uid) == []
    assert _http_balance(env) == 10


def test_batch_entitlement_consumed_before_confirmation_402(batch_env):
    """Dollar analog of insufficient-at-confirmation: the entitlement
    is redeemed by a first run between quote and confirm; the second
    confirm is a 402 with no partial state."""
    env = batch_env
    _, uid, _ = _signup_verify_login(env)
    _seed_batch_entitlement(env, uid, _three())
    r = _post_batch(env, _three())
    c1, h1, csrf = _consent_fields(r.text)
    r2 = _post_batch(env, _three())
    c2, h2, _ = _consent_fields(r2.text)
    assert _confirm(env, c2, h2, csrf).status_code == 200
    denied = _confirm(env, c1, h1, csrf)
    assert denied.status_code == 402, denied.text[:400]
    assert "Batch analysis costs $5." in denied.text
    assert len(_ops(env, uid)) == 1  # only the first run
    assert _http_balance(env) == 10


# --- price stability: no requote on the dollar path -----------------------------

def test_batch_quote_stable_across_allowance_change(batch_env):
    """Premise retired (B-12/B-15): a product consent never requotes.
    The free allowance being consumed between quote and confirm
    changes nothing — the run proceeds at the flat $5 with no claim."""
    env = batch_env
    _, uid, _ = _signup_verify_login(env)
    _seed_batch_entitlement(env, uid, _three())
    r = _post_batch(env, _three())
    assert "One flat price covers the whole batch." in r.text
    consent_id, file_hash, csrf = _consent_fields(r.text)
    _seed_free(env, uid, 10)  # allowance consumed elsewhere
    confirmed = _confirm(env, consent_id, file_hash, csrf)
    assert confirmed.status_code == 200, confirmed.text[:400]
    assert _http_balance(env) == 10
    ops = _ops(env, uid)
    assert len(ops) == 1 and ops[0].cost == 0
    assert ops[0].free_allowance_claim is False
    assert _hits(env) == 0


def test_second_batch_same_digest_cannot_double_redeem(batch_env):
    """One entitlement redeems exactly once: a second consent for the
    same digest confirms to a 402, never a second run."""
    env = batch_env
    _, uid, _ = _signup_verify_login(env)
    _seed_batch_entitlement(env, uid, _three())
    two = _three()
    r1 = _post_batch(env, two)
    c1, h1, csrf = _consent_fields(r1.text)
    r2 = _post_batch(env, two)
    c2, h2, _ = _consent_fields(r2.text)
    assert _confirm(env, c1, h1, csrf).status_code == 200
    second = _confirm(env, c2, h2, csrf)
    assert second.status_code == 402, second.text[:300]
    assert len(_ops(env, uid)) == 1
    assert _http_balance(env) == 10


# --- order / duplicates ------------------------------------------------------------------

def test_order_duplicates_and_identical_files(batch_env):
    env = batch_env
    _, uid, _ = _signup_verify_login(env)
    files = [("same.log", LOG_1), ("same.log", LOG_1), ("other.log", LOG_2)]
    _seed_batch_entitlement(env, uid, files)
    r = _post_batch(env, files)
    assert r.status_code == 402, r.text[:300]
    assert "One flat price covers the whole batch." in r.text  # flat price regardless of duplicates
    consent_id, file_hash, csrf = _consent_fields(r.text)
    confirmed = _confirm(env, consent_id, file_hash, csrf)
    assert confirmed.status_code == 200, confirmed.text[:400]
    i1 = confirmed.text.index("File 1: same.log")
    i2 = confirmed.text.index("File 2: same.log")
    i3 = confirmed.text.index("File 3: other.log")
    assert i1 < i2 < i3  # upload order preserved, duplicates distinct by ordinal
    assert _http_balance(env) == 10  # credits never move


# --- forgery / replay -----------------------------------------------------------------------

def test_batch_forgery_csrf_and_cross_user(batch_env):
    env = batch_env
    _, uid, csrf = _signup_verify_login(env)
    _seed_batch_entitlement(env, uid, _three())
    r = _post_batch(env, _three())
    consent_id, file_hash, _ = _consent_fields(r.text)
    bad_csrf = _confirm(env, consent_id, file_hash, "bogus")
    assert bad_csrf.status_code == 403, bad_csrf.text[:300]
    forged = _confirm(env, consent_id, "0" * 64, csrf)
    assert forged.status_code == 409, forged.text[:300]
    _, _, csrf2 = _signup_verify_login(env)
    cross = _confirm(env, consent_id, file_hash, csrf2)
    assert cross.status_code == 409, cross.text[:300]
    assert _ops(env, uid) == []
    assert _http_balance(env) == 10


def test_batch_content_substitution_409(batch_env):
    env = batch_env
    _, uid, csrf = _signup_verify_login(env)
    _seed_batch_entitlement(env, uid, _three())
    r = _post_batch(env, _three())
    consent_id, file_hash, _ = _consent_fields(r.text)
    pending = _pending_files(env)
    assert len(pending) == 1
    raw = bytearray(pending[0].read_bytes())
    nl = raw.index(b"\n")
    raw[nl + 1] = ord("9") if raw[nl + 1] != ord("9") else ord("8")
    pending[0].write_bytes(bytes(raw))
    r = _confirm(env, consent_id, file_hash, csrf)
    assert r.status_code == 409, r.text[:300]
    assert _ops(env, uid) == []


def test_batch_expired_consent_and_missing_pending(batch_env):
    env = batch_env
    _, uid, csrf = _signup_verify_login(env)
    _seed_batch_entitlement(env, uid, _three())
    r = _post_batch(env, _three())
    consent_id, file_hash, _ = _consent_fields(r.text)
    with env.sessions() as db:
        consent = db.get(M.Consent, uuid.UUID(consent_id))
        consent.expires_at = C._utcnow() - timedelta(seconds=1)
        db.commit()
    r = _confirm(env, consent_id, file_hash, csrf)
    assert r.status_code == 409, r.text[:300]
    r = _post_batch(env, _three())
    consent_id, file_hash, _ = _consent_fields(r.text)
    for p in _pending_files(env):
        p.unlink()
    r = _confirm(env, consent_id, file_hash, csrf)
    assert r.status_code == 410, r.text[:300]


def test_batch_completed_replay_no_recharge(batch_env):
    env = batch_env
    _, uid, _ = _signup_verify_login(env)
    _seed_batch_entitlement(env, uid, _three())
    r = _post_batch(env, _three())
    consent_id, file_hash, csrf = _consent_fields(r.text)
    first = _confirm(env, consent_id, file_hash, csrf)
    assert first.status_code == 200, first.text[:300]
    rid = _report_id_from(first.text)
    replay = _confirm(env, consent_id, file_hash, csrf)
    assert replay.status_code == 200, replay.text[:300]
    assert _report_id_from(replay.text) == rid
    assert _http_balance(env) == 10  # replay free, credits never moved
    assert len(_ops(env, uid)) == 1
    assert _hits(env) == 0  # no quota accounting on the dollar path


# --- PDF: free for dollar-paid batch artifacts (B-9) -----------------------------------

def test_batch_pdf_free_for_dollar_paid(batch_env):
    env = batch_env
    _, uid, csrf = _signup_verify_login(env)
    _seed_batch_entitlement(env, uid, _three())
    r = _post_batch(env, _three())
    consent_id, file_hash, _ = _consent_fields(r.text)
    confirmed = _confirm(env, consent_id, file_hash, csrf)
    rid = _report_id_from(confirmed.text)
    pdf = env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert pdf.status_code == 200, pdf.text[:300]
    assert pdf.content.startswith(b"%PDF")
    assert b"database connection failed" in pdf.content
    assert b"File 2: two.log" in pdf.content
    assert b"File 3: three.log" in pdf.content
    assert _http_balance(env) == 10  # no export charge at all
    again = env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert again.status_code == 200
    assert _http_balance(env) == 10
    _invariants_ok(env, uid)


def test_batch_pdf_failure_no_charge(batch_env, monkeypatch):
    env = batch_env
    _, uid, csrf = _signup_verify_login(env)
    _seed_batch_entitlement(env, uid, _three())
    r = _post_batch(env, _three())
    consent_id, file_hash, _ = _consent_fields(r.text)
    confirmed = _confirm(env, consent_id, file_hash, csrf)
    rid = _report_id_from(confirmed.text)
    balance_before = _http_balance(env)
    from app import pdf_export
    monkeypatch.setattr(pdf_export, "generate_batch_pdf",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("pdf boom")))
    pdf = env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert pdf.status_code == 500, pdf.text[:300]
    assert _http_balance(env) == balance_before
    _invariants_ok(env, uid)


# --- single-file / compare regressions -----------------------------------------------------------

def test_single_file_paths_unchanged(batch_env):
    env = batch_env
    _, uid, csrf = _signup_verify_login(env)
    # Free single analysis still free.
    r = env.client.post(
        "/analyze",
        files={"file": ("test.log", LOG_1, "text/plain")},
        data={"output": "html", "request_id": ""})
    assert r.status_code == 200, r.text[:300]
    assert _http_balance(env) == 10
    # Additional analysis still quotes exactly 1 credit.
    _seed_free(env, uid, 10)
    r = env.client.post(
        "/analyze",
        files={"file": ("test.log", LOG_1, "text/plain")},
        data={"output": "html", "request_id": ""})
    assert r.status_code == 402, r.text[:300]
    assert "Free analyses used up" in r.text and "Use 1 credit" in r.text


def test_compare_still_works(batch_env):
    env = batch_env
    _, uid, _ = _signup_verify_login(env)
    _seed_compare_entitlement(env, uid, LOG_1, LOG_2)
    r = env.client.post(
        "/compare",
        files={"file_a": ("a.log", LOG_1, "text/plain"),
               "file_b": ("b.log", LOG_2, "text/plain")})
    assert r.status_code == 402, r.text[:300]
    assert "$5" in r.text
    consent_id, file_hash, csrf = _consent_fields(r.text)
    confirmed = env.client.post(
        "/compare/paid",
        data={"consent_id": consent_id, "file_hash": file_hash,
              "idempotency_key": consent_id, "csrf_token": csrf})
    assert confirmed.status_code == 200, confirmed.text[:300]
    assert _http_balance(env) == 10  # dollar compare; credits untouched


def test_paid_batch_rate_limit_is_five_per_hour(batch_env):
    env = batch_env
    _, uid, _ = _signup_verify_login(env)
    with env.sessions() as db:
        for _ in range(5):
            C._consume_rate(db, "paid:batch", str(uid))
        db.commit()
        with pytest.raises(C.AdmissionError):
            C._consume_rate(db, "paid:batch", str(uid))
