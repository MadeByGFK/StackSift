"""Issue #164 S6/S7: Batch/Compare fidelity-first port — runtime tests.

Spec of record: s6-s7-port-spec-2026-11-12.md (v1) as amended by
s6-s7-port-spec-v1.1-amendments.md (A1-A8). This module covers the
server-harness half of RT-1..RT-14 (TestClient flows asserting
RENDERED control state on the ported templates, the Phase B pattern);
the executed-DOM half (staged lists, badge suppression in a real
browser, header toggle, native validation) lives in
test_issue164_s6s7_browser.py.

Teeth discipline: tests asserting the NEW presentation/copy fail on
the base tree 419462b6 and pass on the built tree (verified via the
build-s6s7-teeth clone; results in build-s6s7-report.md). Tests that
re-pin Phase B server semantics on the new markup are premise-
PRESERVED controls (A2/A7): they pass on both trees by design and are
labelled as such per test.
"""
import copy
import re
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

import test_issue164_phase_b as pb

LOG_A = pb.LOG_A
LOG_B = pb.LOG_B
PRICE_BY_SKU = pb.PRICE_BY_SKU

BATCH_FOOTNOTE = (
    "You have 30 days from the settled purchase to run this batch; "
    "re-uploading the same files, with the same filenames in the same "
    "upload order, redeems your purchase.")
COMPARE_FOOTNOTE = (
    "You have 30 days from the settled purchase to run this comparison; "
    "re-uploading the same two files, with the same filenames, redeems "
    "your purchase.")
BATCH_LEAD_IN = (
    "Batch analysis costs $5, paid by card at checkout. Exports are "
    "included, and the combined report is kept for 90 days.")
COMPARE_LEAD_IN = (
    "Comparison costs $5, paid by card at checkout. Exports are "
    "included, and the comparison is kept for 90 days.")


@pytest.fixture
def s6_env(tmp_path, monkeypatch):
    """The Phase B environment (same construction as p164b_env)."""
    from app import auth, email, main
    from app.db import Base, get_db
    import app.db as db_module
    from app.main import app
    engine = create_engine(
        f"sqlite:///{tmp_path / 's6.db'}",
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
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 's6.db'}")
    monkeypatch.setenv("STRIPE_PRICE_COMPARE", PRICE_BY_SKU["compare"])
    monkeypatch.setenv("STRIPE_PRICE_BATCH", PRICE_BY_SKU["batch"])
    monkeypatch.setenv("STRIPE_PRICE_LARGE_FILE",
                       PRICE_BY_SKU["large_file_analysis"])
    monkeypatch.setenv("STRIPE_PRICE_INVESTIGATION_REPORT",
                       PRICE_BY_SKU["investigation_report"])
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_s6_fixture")
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", pb.WEBHOOK_SECRET)
    sent = []
    monkeypatch.setattr(email, "send_verification_email",
                        lambda a, t: sent.append(("verify", a, t)))
    monkeypatch.setattr(email, "send_password_reset_email",
                        lambda a, t: sent.append(("reset", a, t)))

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
            yield pb.SimpleNamespace(
                client=client, sessions=sessions, sent=sent, engine=engine,
                app=app, monkeypatch=monkeypatch)
    finally:
        engine.dispose()


@pytest.fixture(autouse=True)
def _stub_line_items(monkeypatch):
    """Same Stripe line-items stub as the Phase B module."""
    import httpx
    pb._LINE_PRICE["id"] = PRICE_BY_SKU["compare"]

    class Resp:
        status_code = 200

        def json(self):
            if pb._LINE_PRICE["id"] is None:
                return {"data": []}
            return {"data": [{"price": {"id": pb._LINE_PRICE["id"]}}]}

    def _get(url, params=None, auth=None, headers=None, timeout=None):
        assert "/checkout/sessions/" in url and url.endswith("/line_items"), url
        return Resp()

    monkeypatch.setattr(httpx, "get", _get)


def _confirm_batch(env, consent_id, file_hash, csrf):
    return env.client.post(
        "/batch/paid",
        data={"consent_id": consent_id, "file_hash": file_hash,
              "idempotency_key": consent_id, "csrf_token": csrf})


def _settle(env, csrf, sku, digest):
    return pb._buy_and_settle(env, csrf, sku, digest)


# --- Entry surfaces: composition, titles, meta (A6), copy ---------------

def test_batch_entry_composition_and_copy(s6_env):
    env = s6_env
    pb._make_user(env)
    r = env.client.get("/batch")
    assert r.status_code == 200, r.text[:300]
    assert "<title>Batch analysis | stacksift.</title>" in r.text
    assert ('<meta name="description" content="Upload 2 to 5 log files '
            'and get one combined incident report, in upload order.">'
            in r.text)
    assert 'class="s6-eyebrow"' in r.text and ">Batch</p>" in r.text
    assert "Batch analysis costs $5 per batch" in r.text
    assert "quoted before you confirm" in r.text
    assert "1 credit for each additional file" not in r.text
    assert 'id="batch-dropzone"' in r.text
    assert "or browse your files — .log, .txt, .text" in r.text
    # CALL-2: the hint/accept list stays the live one — no .json.
    assert ".log, .txt, .json" not in r.text
    assert 'accept=".log,.txt,.text"' in r.text
    assert 'id="batch-staged"' in r.text
    assert "Get batch quote" in r.text
    # Standard live header (A5): toggle + signed-in set + logout form.
    assert 'class="nav-toggle"' in r.text
    assert '<nav class="nav-links" id="site-nav">' in r.text
    assert '<a href="/reports">My Reports</a>' in r.text
    assert '<a href="/settings">Settings</a>' in r.text
    assert 'action="/auth/logout"' in r.text
    # A1: the shared script is included in badge-suppressed mode — the
    # badge/quick-buy block is absent from the served page. Pin the
    # EXECUTABLE block, not the bare word: the retained script's own
    # comments (wireAuthForm header, PDF-modal handoff) legitimately
    # mention "credit-badge" on every page, suppressed or not. The
    # executed-DOM half (zero #credit-badge elements) is the browser
    # suite's test_a1_*.
    assert "auth/balance" not in r.text
    assert "badge.id = 'credit-badge'" not in r.text
    assert "MODAL_PACKS" not in r.text
    assert "function showCreditModal" not in r.text


def test_compare_entry_composition_and_copy(s6_env):
    env = s6_env
    pb._make_user(env)
    r = env.client.get("/compare")
    assert r.status_code == 200, r.text[:300]
    assert "<title>Compare two logs | stacksift.</title>" in r.text
    assert ('<meta name="description" content="Upload a before and '
            'after log and see what changed between them.">' in r.text)
    assert ">Compare</p>" in r.text
    # C-E3: inherited paragraph, price token only swapped.
    assert "Comparison costs $5, charged" in r.text
    assert "3 credits" not in r.text
    # The sub paragraph wraps across template lines; compare on
    # whitespace-normalized text (rendered HTML collapses it anyway).
    assert ("Existing reports cannot be compared retrospectively"
            in " ".join(r.text.split()))
    assert 'class="s6-compare-grid"' in r.text
    assert 'id="zone-a"' in r.text and 'id="zone-b"' in r.text
    assert "one .log, .txt, or .text file" in r.text
    assert "Compare ($5)" in r.text
    assert 'class="nav-toggle"' in r.text
    assert 'action="/auth/logout"' in r.text
    # A1 executable-block pins, as in the batch entry test above.
    assert "auth/balance" not in r.text
    assert "badge.id = 'credit-badge'" not in r.text
    assert "MODAL_PACKS" not in r.text
    assert "function showCreditModal" not in r.text


# --- RT-1 (corrected, A2): quote -> checkout -> return -> run ----------

def _rt1_flow(env, flow):
    from app import stripe_billing as sb
    _, uid, csrf = pb._make_user(env)
    if flow == "compare":
        r = pb._post_compare(env)
        digest = pb._compare_digest()
        sku = "compare"
        confirm = pb._confirm_compare
        lead_in, footnote = COMPARE_LEAD_IN, COMPARE_FOOTNOTE
        title = "Confirm comparison | stacksift."
    else:
        files = pb._batch_files()
        r = pb._post_batch(env, files)
        digest = pb._batch_digest(files)
        sku = "batch"
        confirm = _confirm_batch
        lead_in, footnote = BATCH_LEAD_IN, BATCH_FOOTNOTE
        title = "Confirm batch analysis | stacksift."
    assert r.status_code == 402, r.text[:300]
    # Checkout state on the ported composition.
    assert f"<title>{title}</title>" in r.text
    assert 'class="s6-consent-panel"' in r.text
    assert "Pay $5" in r.text
    assert "Buy — $5" not in r.text
    assert lead_in in r.text
    assert footnote in r.text
    assert sb.PAY_NOW_PROMISE in r.text
    # Promise sits ABOVE the actions (K7).
    assert r.text.index(sb.PAY_NOW_PROMISE) < r.text.index(
        'id="product-checkout-form"')
    # No balance line, no credit-era copy on the dollar consent.
    assert "Your balance" not in r.text
    assert "eligible credits" not in r.text
    assert "Use a Credit" not in r.text
    assert 'class="nav-toggle"' in r.text  # header on consent (H1)
    # Checkout -> settle -> return landing binds to THIS purchase.
    captured = pb._fake_stripe(env.monkeypatch)
    r = pb._checkout(env, csrf, sku, digest)
    assert r.status_code == 200, r.text[:300]
    purchase_id = r.json()["purchase_id"]
    _settle_rest = None
    # _buy_and_settle performs its own checkout; instead settle THIS
    # purchase directly via the webhook, like the Phase B return test.
    from app import models as M
    with env.sessions() as db:
        purchase = db.get(M.ProductPurchase, uuid.UUID(purchase_id))
        ref = pb.SimpleNamespace(id=purchase.id, user_id=purchase.user_id)
        session_id = purchase.stripe_session_id
    pb._LINE_PRICE["id"] = PRICE_BY_SKU[sku]
    ev = pb._completed_event(f"evt_rt1_{flow}", ref, sku=sku,
                             digest=digest, session_id=session_id)
    assert pb._post_event(env, ev).status_code == 200
    landing = (f"/products/return?product_checkout=success&sku={sku}"
               f"&purchase={purchase_id}")
    r = env.client.get(landing)
    assert r.status_code == 200, r.text[:300]
    assert "Payment received" in r.text
    assert 'class="s6-consent-panel"' in r.text  # ported return (A3)
    assert 'class="nav-toggle"' in r.text
    consent_id, file_hash = pb._consent_fields(r.text)
    r = confirm(env, consent_id, file_hash, csrf)
    assert r.status_code == 200, r.text[:400]
    # RT-1 corrected closing step: a FRESH re-upload of the same files
    # renders a NEW purchase quote (402 + checkout form) — Phase B's
    # intentional new-run contract, NOT replay.
    if flow == "compare":
        r = pb._post_compare(env)
    else:
        r = pb._post_batch(env, pb._batch_files())
    assert r.status_code == 402, r.text[:300]
    assert 'id="product-checkout-form"' in r.text
    assert "Pay $5" in r.text


def test_rt1_compare_quote_checkout_return_run(s6_env):
    _rt1_flow(s6_env, "compare")


def test_rt1_batch_quote_checkout_return_run(s6_env):
    _rt1_flow(s6_env, "batch")


# --- RT-2 (corrected, A2): consumed-key replay / Run re-quote / cross --

def test_rt2a_consumed_key_replay_compare(s6_env):
    env = s6_env
    _, uid, csrf = pb._make_user(env)
    _settle(env, csrf, "compare", pb._compare_digest())
    r = pb._post_compare(env)
    consent_id, file_hash = pb._consent_fields(r.text)
    first = pb._confirm_compare(env, consent_id, file_hash, csrf)
    assert first.status_code == 200
    replay = pb._confirm_compare(env, consent_id, file_hash, csrf)
    assert replay.status_code == 200  # replay returns the report
    rid = re.search(r'action="/reports/([0-9a-f-]{36})/pdf"',
                    first.text).group(1)
    assert rid in replay.text
    assert "product-checkout-form" not in replay.text
    from app import models as M
    with env.sessions() as db:
        assert db.query(M.Operation).filter(
            M.Operation.user_id == uid,
            M.Operation.type == "compare_logs").count() == 1
        ent = db.query(M.Entitlement).filter(
            M.Entitlement.user_id == uid).one()
        assert ent.status == "redeemed"


def test_rt2a_consumed_key_replay_batch(s6_env):
    env = s6_env
    _, uid, csrf = pb._make_user(env)
    files = pb._batch_files()
    _settle(env, csrf, "batch", pb._batch_digest(files))
    r = pb._post_batch(env, files)
    consent_id, file_hash = pb._consent_fields(r.text)
    first = _confirm_batch(env, consent_id, file_hash, csrf)
    assert first.status_code == 200, first.text[:300]
    replay = _confirm_batch(env, consent_id, file_hash, csrf)
    assert replay.status_code == 200
    from app import models as M
    with env.sessions() as db:
        assert db.query(M.Operation).filter(
            M.Operation.user_id == uid,
            M.Operation.type == "batch").count() == 1


def test_rt2b_failed_attempt_reupload_offers_run(s6_env, monkeypatch):
    """RT-2(b): an AVAILABLE (unredeemed) entitlement after a failed
    attempt re-quotes as the Run state — no checkout form, no promise."""
    from app import main, stripe_billing as sb
    env = s6_env
    _, uid, csrf = pb._make_user(env)
    _settle(env, csrf, "compare", pb._compare_digest())

    def failing(a, b, c, d):
        return ({"error": "analysis_failed", "message": "x", "filename": "a.log"},
                {"error": "analysis_failed", "message": "x", "filename": "b.log"})

    monkeypatch.setattr(main, "_execute_compare", failing)
    r = pb._post_compare(env)
    assert 'id="product-checkout-form"' not in r.text
    assert "already paid" in r.text
    assert sb.PAY_NOW_PROMISE not in r.text
    consent_id, file_hash = pb._consent_fields(r.text)
    assert pb._confirm_compare(env, consent_id, file_hash, csrf).status_code == 400
    r = pb._post_compare(env)
    assert "already paid" in r.text
    assert 'id="product-checkout-form"' not in r.text


def test_rt2_cross_flow_consent_refused(s6_env):
    """RT-2 cross-flow case: a Batch consent presented at the Compare
    paid endpoint (and vice versa) runs nothing and redeems nothing."""
    env = s6_env
    _, uid, csrf = pb._make_user(env)
    files = pb._batch_files()
    _settle(env, csrf, "batch", pb._batch_digest(files))
    r = pb._post_batch(env, files)
    batch_consent, batch_hash = pb._consent_fields(r.text)
    r = pb._confirm_compare(env, batch_consent, batch_hash, csrf)
    assert r.status_code in (400, 402, 404, 409, 410, 422), r.status_code
    from app import models as M
    with env.sessions() as db:
        assert db.query(M.Operation).count() == 0
        ent = db.query(M.Entitlement).filter(
            M.Entitlement.user_id == uid).one()
        assert ent.status == "available"


# --- RT-3: cross-SKU entitlement ----------------------------------------

def test_rt3_cross_sku_entitlement_never_renders_run(s6_env):
    env = s6_env
    _, uid, csrf = pb._make_user(env)
    pb._seed_grant(env, uid, 10)  # Phase C re-base: seeded directly, not signup
    pb._seed_entitlement(env, uid, "compare", pb._compare_digest())
    files = pb._batch_files()
    r = pb._post_batch(env, files)
    assert r.status_code == 402, r.text[:300]
    assert 'id="product-checkout-form"' in r.text  # checkout, not Run
    assert "already paid" not in r.text
    # And the Batch entitlement does not run at the Compare endpoint.
    pb._seed_entitlement(env, uid, "batch", pb._batch_digest(files))
    r = pb._post_compare(env, LOG_B, LOG_A)  # different digest pair
    assert 'id="product-checkout-form"' in r.text
    from app import models as M
    with env.sessions() as db:
        assert db.query(M.Operation).count() == 0
        assert pb._balance(env, uid) == 10  # no credit movement


# --- RT-4 (corrected, A2): promise absent on Run renders -----------------

def test_rt4_promise_absent_on_run_renders_both_flows(s6_env, monkeypatch):
    from app import main, stripe_billing as sb
    env = s6_env
    _, uid, csrf = pb._make_user(env)
    _settle(env, csrf, "compare", pb._compare_digest())
    files = pb._batch_files()
    # NOTE: a second _buy_and_settle for another SKU in one test hits
    # a Phase B harness limitation that fails identically on the base
    # tree (verified in the teeth clone); Phase B's own multi-SKU
    # tests seed the second entitlement directly, as here.
    pb._seed_entitlement(env, uid, "batch", pb._batch_digest(files))

    def failing_compare(a, b, c, d):
        return ({"error": "analysis_failed", "message": "x", "filename": "a.log"},
                {"error": "analysis_failed", "message": "x", "filename": "b.log"})

    monkeypatch.setattr(main, "_execute_compare", failing_compare)
    r = pb._post_compare(env)
    assert sb.PAY_NOW_PROMISE not in r.text  # inverted pin (A2)
    assert "$5" in r.text
    consent_id, file_hash = pb._consent_fields(r.text)
    assert pb._confirm_compare(env, consent_id, file_hash, csrf).status_code == 400
    r = pb._post_compare(env)
    assert sb.PAY_NOW_PROMISE not in r.text
    assert "already paid" in r.text and "$5" in r.text
    assert "still settling" not in r.text and "Payment received" not in r.text

    def failing_batch(fs):
        return [{"error": "analysis_failed", "message": "x", "filename": fn}
                for _o, fn, _c in fs]

    monkeypatch.setattr(main, "_execute_batch", failing_batch)
    r = pb._post_batch(env, files)
    assert sb.PAY_NOW_PROMISE not in r.text
    assert "$5" in r.text
    consent_id, file_hash = pb._consent_fields(r.text)
    assert _confirm_batch(env, consent_id, file_hash, csrf).status_code == 400
    r = pb._post_batch(env, files)
    assert sb.PAY_NOW_PROMISE not in r.text
    assert "already paid" in r.text


# --- RT-5: cancel / return paths -----------------------------------------

def test_rt5a_consent_cancel_leaves_no_phantom_run(s6_env):
    env = s6_env
    pb._make_user(env)
    r = pb._post_compare(env)
    assert r.status_code == 402
    assert '<a href="/" class="s6-btn-cancel">Cancel</a>' in r.text
    # Consent unconsumed: re-upload renders a fresh CHECKOUT state.
    r = pb._post_compare(env)
    assert 'id="product-checkout-form"' in r.text
    assert "already paid" not in r.text


def test_rt5b_cancelled_return_state(s6_env):
    env = s6_env
    pb._make_user(env)
    for sku, start in (("compare", "/compare"), ("batch", "/batch")):
        r = env.client.get(
            f"/products/return?product_checkout=cancelled&sku={sku}")
        assert r.status_code == 200, r.text[:300]
        assert "Nothing was charged" in r.text
        assert f'href="{start}"' in r.text
        assert 'class="s6-consent-panel"' in r.text
    from app import models as M
    with env.sessions() as db:
        assert db.query(M.Entitlement).count() == 0


def test_rt5cd_return_binding_controls_on_ported_template(s6_env):
    """Premise-PRESERVED controls (A4/A7): unknown purchase binds
    nothing; legacy no-param URL keeps the latest-consent fallback;
    settling renders before the webhook and ready after."""
    env = s6_env
    _, uid, csrf = pb._make_user(env)
    r = pb._post_compare(env)
    assert r.status_code == 402
    _settle(env, csrf, "compare", pb._compare_digest())
    bogus = uuid.uuid4()
    r = env.client.get(
        "/products/return?product_checkout=success&sku=compare"
        f"&purchase={bogus}")
    assert "could not find a purchase" in r.text
    assert 'action="/compare/paid"' not in r.text
    # Legacy URL (no purchase param) still binds the live consent.
    r = env.client.get("/products/return?product_checkout=success&sku=compare")
    assert 'action="/compare/paid"' in r.text


# --- RT-6: success-only Compare, both directions --------------------------

def test_rt6_identical_pair_succeeds_and_charges(s6_env):
    env = s6_env
    _, uid, csrf = pb._make_user(env)
    digest = pb._compare_digest(LOG_A, LOG_A)
    _settle(env, csrf, "compare", digest)
    r = pb._post_compare(env, LOG_A, LOG_A)
    consent_id, file_hash = pb._consent_fields(r.text)
    r = pb._confirm_compare(env, consent_id, file_hash, csrf)
    assert r.status_code == 200, r.text[:300]
    from app import models as M
    with env.sessions() as db:
        ent = db.query(M.Entitlement).filter(
            M.Entitlement.user_id == uid).one()
        assert ent.status == "redeemed"


def test_rt6_worker_failure_releases_entitlement(s6_env, monkeypatch):
    from app import main
    env = s6_env
    _, uid, csrf = pb._make_user(env)
    _settle(env, csrf, "compare", pb._compare_digest())

    def failing(a, b, c, d):
        return ({"error": "analysis_failed", "message": "x", "filename": "a.log"},
                {"error": "analysis_failed", "message": "x", "filename": "b.log"})

    monkeypatch.setattr(main, "_execute_compare", failing)
    r = pb._post_compare(env)
    consent_id, file_hash = pb._consent_fields(r.text)
    assert pb._confirm_compare(env, consent_id, file_hash, csrf).status_code == 400
    from app import models as M
    with env.sessions() as db:
        # F2 (Phase B pin): the failed attempt records a FAILED
        # operation and NO result; the entitlement is released.
        op = db.query(M.Operation).filter(
            M.Operation.user_id == uid).one()
        assert op.status == "failed"
        assert db.query(M.Result).filter(
            M.Result.type == "comparison").count() == 0
        ent = db.query(M.Entitlement).filter(
            M.Entitlement.user_id == uid).one()
        assert ent.status == "available"
    r = pb._post_compare(env)
    assert "already paid" in r.text  # Run offered, no second purchase


# --- RT-8 (server half): order / duplicates / swap ------------------------

def test_rt8_batch_order_changes_digest_and_duplicates_render(s6_env):
    env = s6_env
    _, uid, csrf = pb._make_user(env)
    files = pb._batch_files()
    _settle(env, csrf, "batch", pb._batch_digest(files))
    reordered = [files[1], files[0], files[2]]
    r = pb._post_batch(env, reordered)
    assert r.status_code == 402
    assert 'id="product-checkout-form"' in r.text  # different digest
    assert "already paid" not in r.text
    # Duplicate filenames render as distinct ordinal chips.
    dup = [("same.log", LOG_A), ("same.log", LOG_B)]
    r = pb._post_batch(env, dup)
    assert r.status_code == 402
    assert "1. same.log" in r.text and "2. same.log" in r.text
    assert "bytes across 2 files, in upload order" in r.text


def test_rt8_compare_swap_refused_at_paid_endpoint(s6_env):
    env = s6_env
    _, uid, csrf = pb._make_user(env)
    _settle(env, csrf, "compare", pb._compare_digest())
    r = pb._post_compare(env, LOG_B, LOG_A)  # swapped pair = new digest
    assert 'id="product-checkout-form"' in r.text
    # The checkout render carries no consent_id field; take the
    # swapped pair's consent from the DB (the batch e2e pattern).
    from app import models as M
    with env.sessions() as db:
        consent = db.query(M.Consent).filter(
            M.Consent.user_id == uid,
            M.Consent.operation_type == "compare_logs",
            M.Consent.input_hash == pb._compare_digest(LOG_B, LOG_A),
        ).one()
        consent_id, file_hash = str(consent.id), consent.input_hash
    r = pb._confirm_compare(env, consent_id, file_hash, csrf)
    assert r.status_code == 402  # no entitlement for the swapped digest
    with env.sessions() as db:
        assert db.query(M.Operation).count() == 0


# --- RT-10: fail-closed (premise-preserved control, A7) -------------------

@pytest.mark.parametrize("flow", ["compare", "batch"])
def test_rt10_fail_closed_on_ported_surfaces(s6_env, monkeypatch, flow):
    env = s6_env
    _, uid, csrf = pb._make_user(env)
    captured = pb._fake_stripe(monkeypatch)
    if flow == "compare":
        monkeypatch.delenv("STRIPE_PRICE_COMPARE", raising=False)
        r = pb._post_compare(env)
        entry = env.client.get("/compare")
    else:
        monkeypatch.delenv("STRIPE_PRICE_BATCH", raising=False)
        r = pb._post_batch(env, pb._batch_files())
        entry = env.client.get("/batch")
    assert r.status_code == 503, r.text[:300]
    assert "Coming soon" in r.text
    assert captured == []
    assert entry.status_code == 200  # entry GET renders unchanged
    from app import models as M
    with env.sessions() as db:
        assert db.query(M.ProductPurchase).count() == 0


# --- RT-11: return after pending-payload deletion, per flow ---------------

@pytest.mark.parametrize("flow", ["compare", "batch"])
def test_rt11_return_after_pending_deletion_renders_reupload(s6_env, flow):
    from app import main
    env = s6_env
    _, uid, csrf = pb._make_user(env)
    if flow == "compare":
        r = pb._post_compare(env)
        digest = pb._compare_digest()
        sku = "compare"
        paid_action = "/compare/paid"
    else:
        files = pb._batch_files()
        r = pb._post_batch(env, files)
        digest = pb._batch_digest(files)
        sku = "batch"
        paid_action = "/batch/paid"
    assert r.status_code == 402, r.text[:300]
    from app import models as M
    with env.sessions() as db:
        consent = db.query(M.Consent).filter(
            M.Consent.user_id == uid).order_by(
            M.Consent.created_at.desc()).first()
        consent_id = str(consent.id)
    _settle(env, csrf, sku, digest)
    with env.sessions() as db:
        purchase_id = str(db.query(M.ProductPurchase).filter(
            M.ProductPurchase.user_id == uid,
            M.ProductPurchase.sku == sku).first().id)
    main._delete_paid_pending(consent_id)
    if flow == "batch":
        assert main._load_batch_pending(consent_id) is None
    else:
        assert main._load_compare_pending(consent_id) is None
    for landing in (
            f"/products/return?product_checkout=success&sku={sku}",
            f"/products/return?product_checkout=success&sku={sku}"
            f"&purchase={purchase_id}"):
        r = env.client.get(landing)
        assert r.status_code == 200, r.text[:300]
        assert "Upload the same files" in r.text  # no_consent state
        assert f'action="{paid_action}"' not in r.text  # NO Run form
        assert 'class="s6-consent-panel"' in r.text


# --- RT-12: credit-branch isolation render ---------------------------------

def test_rt12_credit_branch_isolation_render(s6_env):
    """After exercising the new product layout, an Additional Analysis
    request past the free quota renders WITHOUT any of the new product
    composition. Phase C re-base: the CREDIT consent render this test
    originally pinned is retired (C1 hard cap) — the render is now the
    429 refusal (reset time, "Additional analyses are not sold"), with
    no consent and no operation created."""
    env = s6_env
    _, uid, csrf = pb._make_user(env)
    # Exercise the product layout end to end first.
    _settle(env, csrf, "compare", pb._compare_digest())
    r = pb._post_compare(env)
    assert 'class="s6-consent-panel"' in r.text
    consent_id, file_hash = pb._consent_fields(r.text)
    assert pb._confirm_compare(env, consent_id, file_hash, csrf).status_code == 200
    # Exhaust the free quota, then quote a single file -> credit
    # consent. Quota exhaustion is seeded directly (the oversize
    # suite's _exhaust_quota pattern): ten FreeRequest rows in the
    # current hour. Driving ten real analyses instead would trip the
    # shared in-memory IP limiter (429) before the credit path.
    from app import credits as C, models as M2
    from datetime import timedelta as _td
    with env.sessions() as db:
        for _ in range(10):
            db.add(M2.FreeRequest(
                request_id=uuid.uuid4().hex, user_id=uid,
                fingerprint="old", status="failed",
                quota_bucket_trusted_ip="127.0.0.1",
                created_at=C._utcnow() - _td(minutes=2),
                deadline=C._utcnow()))
        db.commit()
    r = env.client.post(
        "/analyze",
        files={"file": ("extra.log", LOG_A, "text/plain")},
        data={"output": "html", "request_id": ""})
    assert r.status_code == 429, r.text[:300]
    assert "resets at" in r.text
    assert "not sold" in r.text
    with env.sessions() as db:
        assert db.query(M2.Operation).filter(
            M2.Operation.type == "additional_analysis").count() == 0
        assert db.query(M2.Consent).filter(
            M2.Consent.operation_type == "additional_analysis").count() == 0
    # None of the new product composition leaks into the refusal render.
    assert "s6-consent-panel" not in r.text
    assert "s6-chip" not in r.text
    assert "s6-lead" not in r.text
    assert "s6-foot" not in r.text


# --- A3: Oversize isolation -------------------------------------------------

def test_a3_oversize_render_isolated_except_pay_label(s6_env):
    env = s6_env
    _, uid, csrf = pb._make_user(env)
    content = (b"2024-01-01 10:00:00 INFO heartbeat ok\n" * 50001)
    r = env.client.post(
        "/analyze",
        files={"file": ("big.log", content, "text/plain")},
        data={"output": "html", "request_id": ""})
    assert r.status_code == 402, r.text[:300]
    assert 'id="product-checkout-form"' in r.text  # checkout branch
    # Legacy composition preserved; ONLY the label changed (CALL-3).
    assert 'class="consent-box"' in r.text
    assert "s6-consent-panel" not in r.text
    assert 'class="nav-toggle"' not in r.text
    assert "<title>StackSift — Confirm</title>" in r.text  # Phase C title
    assert "Pay $5" in r.text
    assert "Buy — $5" not in r.text
    assert "Results are available for 90 days." in r.text
    # Exactly ONE Cancel control: the CSRF POST form, not nested in the
    # checkout form, and no cancel link.
    assert r.text.count('action="/analyze/paid/cancel"') == 1
    assert r.text.count('class="btn-cancel"') == 1
    checkout_form = r.text.split('id="product-checkout-form"', 1)[1]
    checkout_form = checkout_form.split("</form>", 1)[0]
    assert "btn-cancel" not in checkout_form
    assert 'name="csrf_token"' in r.text.split(
        'action="/analyze/paid/cancel"', 1)[1].split("</form>", 1)[0]
    # Run render: seed the entitlement and re-quote.
    from app.analysis_admission import fingerprint
    digest = fingerprint("big.log", content)
    pb._seed_entitlement(env, uid, "large_file_analysis", digest)
    r = env.client.post(
        "/analyze",
        files={"file": ("big.log", content, "text/plain")},
        data={"output": "html", "request_id": ""})
    assert r.status_code == 402, r.text[:300]
    assert 'id="product-checkout-form"' not in r.text  # Run branch
    assert "already paid" in r.text
    assert r.text.count('action="/analyze/paid/cancel"') == 1
    assert r.text.count('class="btn-cancel"') == 1
    assert "s6-consent-panel" not in r.text


def test_a3_oversize_return_keeps_legacy_presentation(s6_env):
    env = s6_env
    pb._make_user(env)
    r = env.client.get(
        "/products/return?product_checkout=cancelled"
        "&sku=large_file_analysis")
    assert r.status_code == 200, r.text[:300]
    assert "Nothing was charged" in r.text
    assert 'class="consent-box"' in r.text
    assert "s6-consent-panel" not in r.text
    assert 'class="nav-toggle"' not in r.text


# --- A6: meta descriptions are exactly the four adopted strings -------------

def test_a6_meta_descriptions_exact_and_scoped(s6_env):
    env = s6_env
    pb._make_user(env)
    r = pb._post_compare(env)
    assert ('<meta name="description" content="Review both logs and '
            'the total before confirming a comparison.">' in r.text)
    r = pb._post_batch(env, pb._batch_files())
    assert ('<meta name="description" content="Review the files and '
            'total before confirming a combined batch analysis.">'
            in r.text)
    # No other screen in the flows gains one.
    r = env.client.get(
        "/products/return?product_checkout=cancelled&sku=compare")
    assert '<meta name="description"' not in r.text


# --- Cross-feature sweep: retention / exports / TTL --------------------------

def test_sweep_retention_terms_on_ported_screens(s6_env):
    """Retention display: dollar-paid Batch artifacts carry 90-day
    terms on the ported screens; nothing states 7 days for them.
    (Free exports for dollar-paid artifacts are pinned by the Phase B
    group-6 tests, premise-preserved.)"""
    env = s6_env
    _, uid, csrf = pb._make_user(env)
    # Checkout render (no entitlement yet): the lead-in states the
    # 90-day term; nothing states 7 days.
    r = pb._post_batch(env, pb._batch_files())
    assert r.status_code == 402
    assert "kept for 90 days" in r.text
    assert "7 days" not in r.text
    _settle(env, csrf, "batch", pb._batch_digest(pb._batch_files()))
    r = pb._post_batch(env, pb._batch_files())
    assert r.status_code == 402
    assert "7 days" not in r.text
    consent_id, file_hash = pb._consent_fields(r.text)
    r = _confirm_batch(env, consent_id, file_hash, csrf)
    assert r.status_code == 200, r.text[:300]


def test_sweep_pending_ttl_expiry_then_reupload_redeems(s6_env):
    """Entitlement x pending-TTL: settle, let the pending payload be
    swept, re-upload identical bytes -> Run state redeems and runs."""
    from app import main
    env = s6_env
    _, uid, csrf = pb._make_user(env)
    _settle(env, csrf, "compare", pb._compare_digest())
    r = pb._post_compare(env)
    consent_id, file_hash = pb._consent_fields(r.text)
    main._delete_paid_pending(consent_id)  # the sweep's end state
    r = pb._post_compare(env)  # identical bytes re-uploaded
    assert "already paid" in r.text
    consent_id, file_hash = pb._consent_fields(r.text)
    r = pb._confirm_compare(env, consent_id, file_hash, csrf)
    assert r.status_code == 200, r.text[:300]
    # One byte altered -> different digest -> checkout state.
    altered = LOG_B[:-2] + b"X\n"
    r = pb._post_compare(env, LOG_A, altered)
    assert 'id="product-checkout-form"' in r.text


def test_sweep_f1_second_checkout_blocked_same_digest(s6_env):
    """F1 block: a second checkout for the same digest while an
    entitlement is live is refused (409); while the first purchase is
    merely pending it reuses that purchase (no duplicate row); a
    different digest is always allowed."""
    env = s6_env
    _, uid, csrf = pb._make_user(env)
    pb._fake_stripe(env.monkeypatch)
    digest = pb._compare_digest()
    r = pb._checkout(env, csrf, "compare", digest)
    assert r.status_code == 200
    r2 = pb._checkout(env, csrf, "compare", digest)
    assert r2.status_code == 200
    assert r2.json()["purchase_id"] == r.json()["purchase_id"]  # reused
    from app import models as M
    with env.sessions() as db:
        assert db.query(M.ProductPurchase).filter(
            M.ProductPurchase.user_id == uid).count() == 1
    _settle(env, csrf, "compare", digest)
    r3 = pb._checkout(env, csrf, "compare", digest)
    assert r3.status_code == 409, r3.text[:200]  # entitlement live: blocked
    other = pb._compare_digest(LOG_B, LOG_A)
    r4 = pb._checkout(env, csrf, "compare", other)
    assert r4.status_code == 200  # different digest is allowed


# --- RT-14 (server half): crafted POST with B missing ------------------------

def test_rt14_crafted_post_missing_b_renders_server_error(s6_env):
    env = s6_env
    pb._make_user(env)
    r = env.client.post(
        "/compare",
        files={"file_a": ("a.log", LOG_A, "text/plain")})
    assert r.status_code == 400, r.text[:300]
    assert "Please choose two files" in r.text
    # The error renders on the PORTED entry template.
    assert 'class="s6-compare-grid"' in r.text
    assert 'role="alert"' in r.text
