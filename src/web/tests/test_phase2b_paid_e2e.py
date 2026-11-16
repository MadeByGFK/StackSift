"""Issue #48: full paid-workflow HTTP integration coverage.

Drives the complete paid journey over HTTP for a real signed-up user:

    signup -> verify (10-credit signup reward) -> login
      -> consent page (POST /analyze with the free quota exhausted)
      -> paid analysis (POST /analyze/paid) -> reserve + settle
      -> retrieve (GET /reports/{id})
      -> PDF export (POST /reports/{id}/pdf)
      -> idempotent re-export and paid replay (no double charge)
      -> insufficient-credits 402 (no charge, no operation)
      -> analysis failure releases the reservation (no charge)

Credit balances are asserted over HTTP (GET /credits/balance) at every
step. This closes the accepted limitation from PR #36: credit settlement
and result retrieval were covered at the unit level only.

Runs against SQLite and real PostgreSQL via ``migrated_engine``. The
Postgres leg runs in CI (TEST_POSTGRES_URL) and skips locally.

PREMISE CHANGED (#164 Phase C): the signup grant is removed and
``GET /credits/balance`` is retired (410), and an unconsumed
additional-analysis consent can no longer admit or debit (hard cap —
429). The subjects below are the PRESERVED legacy behaviours:
settlement and replay of operations admitted BEFORE cutover, and
failure release. Fixtures therefore seed the legacy balance and the
admitted operation directly (grant_credits / create_consent /
admit_paid_operation / store_result / complete_operation, mirroring
test_issue164_phase_c.py) and the HTTP calls exercise the replay
fence; balances are read from the ledger in the DB (the retired HTTP
endpoint's exact value), and PDF exports are now FREE.
"""

import copy
import re
import uuid
from datetime import timedelta
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from test_account_migrations import migrated_engine  # noqa: F401  (fixture)
from app import auth, credits as C, db as DB, email, main, models as M
from app.analysis_admission import fingerprint
from app.sample_data import SAMPLE_LOG


@pytest.fixture
def paid_env(migrated_engine, monkeypatch, tmp_path):
    """HTTP client bound to a migrated (alembic) database, no pre-made user.

    Mirrors test_phase2a_regressions.env, but leaves user creation to the
    real signup -> verify -> login flow and mocks the mailer (conftest
    pattern) so the 10-credit signup reward is granted exactly as in
    production.
    """
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
        lambda address, token: sent.append(("verify", address, token)),
    )
    monkeypatch.setattr(
        email, "send_password_reset_email",
        lambda address, token: sent.append(("reset", address, token)),
    )
    # The diagnostic service uses SIGALRM (main thread only). Precompute one
    # real report, then serve deep copies over the HTTP execution boundary.
    report = main.analyze_upload("test.log", SAMPLE_LOG.encode())

    def fake_analyze(*args):
        return copy.deepcopy(report)

    monkeypatch.setattr(main, "analyze_upload", fake_analyze)
    with TestClient(
        main.app,
        base_url="https://testserver",
        raise_server_exceptions=False,
        client=("127.0.0.1", 50000),
    ) as client:
        client.headers["X-CSRF-Token"] = client.get("/auth/csrf").json()["csrf_token"]
        yield SimpleNamespace(engine=engine, sessions=sessions, sent=sent, client=client)


# --- helpers ---------------------------------------------------------------

LOG_CONTENT = (
    b"2024-01-01 10:00:00 INFO app starting\n"
    b"2024-01-01 10:00:01 WARN deprecated config key used\n"
    b"2024-01-01 10:00:02 ERROR failed to connect to db: timeout\n"
    b"2024-01-01 10:00:03 ERROR failed to connect to db: timeout\n"
    b"2024-01-01 10:00:04 INFO retrying connection\n"
)


def _signup_verify_login(env, email_addr=None):
    """Full account flow over HTTP. Returns (email, user_id, session csrf)."""
    email_addr = email_addr or f"e2e_{uuid.uuid4().hex[:8]}@example.com"
    password = "TestPass123!x"
    r = env.client.post("/auth/signup", data={"email": email_addr, "password": password})
    assert r.status_code == 200, r.text[:300]
    token = next(t for kind, addr, t in env.sent if kind == "verify" and addr == email_addr)
    r = env.client.post("/auth/verify", data={"token": token})
    assert r.status_code == 200, r.text[:300]
    env.client.headers["X-CSRF-Token"] = env.client.get("/auth/csrf").json()["csrf_token"]
    r = env.client.post("/auth/login", data={"email": email_addr, "password": password})
    assert r.status_code == 200, r.text[:300]
    csrf = r.json()["csrf_token"]
    env.client.headers["X-CSRF-Token"] = csrf
    with env.sessions() as db:
        uid = db.query(M.User).filter(M.User.email == email_addr).one().id
    env.current_uid = uid
    return email_addr, uid, csrf


def _http_balance(env):
    """Phase C re-base: ``GET /credits/balance`` is retired (410) and
    the signup grant is removed, so the ledger balance is read
    directly from the DB for the currently signed-in user
    (``env.current_uid``, set by _signup_verify_login); a user with
    no credit account has balance 0."""
    uid = getattr(env, "current_uid", None)
    assert uid is not None, "_http_balance before signup/login"
    with env.sessions() as db:
        account = db.query(M.CreditAccount).filter(
            M.CreditAccount.user_id == uid).first()
        return account.balance if account is not None else 0


def _drain_signup(env, uid, qty):
    """Reduce the user's credit balance by ``qty``.

    Phase C re-base: no signup grant exists to drain (issue #151's
    premise is retired), so this drains the user's grants FIFO —
    each grant's remaining and the account balance together
    (mirroring the _grant helpers in test_compare_routes.py) — which
    keeps the premise "the balance is genuinely lowered by qty" for
    balances seeded directly in fixtures."""
    with env.sessions() as db:
        grants = db.query(M.CreditGrant).filter(
            M.CreditGrant.user_id == uid,
            M.CreditGrant.remaining > 0).order_by(
                M.CreditGrant.created_at).all()
        assert sum(g.remaining for g in grants) >= qty
        left = qty
        for grant in grants:
            take = min(grant.remaining, left)
            grant.remaining -= take
            left -= take
            if not left:
                break
        account = db.query(M.CreditAccount).filter(
            M.CreditAccount.user_id == uid).one()
        account.balance -= qty
        db.commit()


def _seed_balance(env, uid, qty):
    """Seed a legacy credit balance directly (Phase C: never via the
    retired signup grant)."""
    with env.sessions() as db:
        C.grant_credits(db, uid, "purchase",
                        f"seed-{uuid.uuid4().hex}", qty)
        db.commit()


def _paid_form(env, uid, csrf, filename="test.log", content=LOG_CONTENT):
    """Build a /analyze/paid form around a consent created directly
    in the fixture (Phase C: POST /analyze at the cap renders the
    429 hard-cap refusal, not a consent page)."""
    digest = fingerprint(filename, content)
    with env.sessions() as db:
        consent = C.create_consent(db, uid, "additional_analysis", digest, 1)
        db.commit()
        cid = str(consent.id)
    main._store_paid_pending(cid, filename, content)
    return {
        "consent_id": cid,
        "file_hash": digest,
        "idempotency_key": cid,
        "csrf_token": csrf,
    }


def _seed_completed_paid_analysis(env, uid, form):
    """Admit + settle a paid analysis on pre-cutover credit terms,
    directly in the fixture: consent -> admit (reserve 1 credit) ->
    store_result -> complete_operation. Returns the report id.
    The HTTP layer is then exercised through the replay fence."""
    with env.sessions() as db:
        op = C.admit_paid_operation(
            db, uid, "additional_analysis", form["idempotency_key"],
            form["file_hash"], 1, uuid.UUID(form["consent_id"]),
            "seed-worker")
        data = main.analyze_upload("test.log", LOG_CONTENT)
        result = C.store_result(db, uid, op.id, data)
        C.complete_operation(db, op.id, "seed-worker", result.id)
        db.commit()
        return result.id


def _exhaust_quota(env, uid):
    """Simulate an exhausted free hourly quota (10 requests in the last hour)."""
    with env.sessions() as db:
        for _ in range(10):
            db.add(M.FreeRequest(
                request_id=uuid.uuid4().hex, user_id=uid, fingerprint="old",
                status="failed", quota_bucket_trusted_ip="127.0.0.1",
                created_at=C._utcnow() - timedelta(minutes=2), deadline=C._utcnow(),
            ))
        db.commit()


def _consent_page(env, filename="test.log", content=LOG_CONTENT):
    """POST /analyze with quota exhausted -> 402 consent page over HTTP."""
    r = env.client.post(
        "/analyze",
        files={"file": (filename, content, "text/plain")},
        data={"output": "html", "request_id": ""},
    )
    assert r.status_code == 402, f"consent page: {r.status_code} {r.text[:300]}"

    def field(name):
        m = re.search(r'name="%s" value="([^"]+)"' % name, r.text)
        assert m, f"{name} not in consent page"
        return m.group(1)

    return {
        "consent_id": field("consent_id"),
        "file_hash": field("file_hash"),
        "idempotency_key": field("idempotency_key"),
        "csrf_token": field("csrf_token"),
    }


def _report_id_from(html):
    m = re.search(r"/reports/([0-9a-f-]{36})/pdf", html)
    assert m, "report PDF link not found in analysis response"
    return m.group(1)


def _csrf_from(html):
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert m, "csrf_token not found in page"
    return m.group(1)


# --- the full flow ----------------------------------------------------------

def test_full_paid_flow_signup_to_pdf(paid_env):
    """admit -> analyze -> settle -> retrieve -> PDF, one HTTP journey.

    PREMISE CHANGED (#164 Phase C): signup grants nothing and no new
    additional-analysis admission is sold, so the admit -> settle
    leg is seeded as a pre-cutover admitted operation (see
    _seed_completed_paid_analysis) and the HTTP journey exercises
    its replay; PDF exports are FREE (no 2-credit unlock charge).
    Balance journey: 10 seeded -> 9 after the seeded settlement ->
    9 through replay and both exports."""
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    assert _http_balance(env) == 0  # Phase C: no signup grant
    _seed_balance(env, uid, 10)
    assert _http_balance(env) == 10  # seeded legacy balance

    _exhaust_quota(env, uid)
    form = _paid_form(env, uid, csrf)
    assert _http_balance(env) == 10  # creating the consent charges nothing

    rid = _seed_completed_paid_analysis(env, uid, form)
    assert _http_balance(env) == 9  # 1 credit reserved then settled

    # Replay the settled paid analysis over HTTP: recorded outcome,
    # no second charge, and it names the same report.
    paid = env.client.post("/analyze/paid", data=form)
    assert paid.status_code == 200, paid.text[:500]
    assert _http_balance(env) == 9
    assert _report_id_from(paid.text) == str(rid)

    # Retrieve the paid result over HTTP.
    view = env.client.get(f"/reports/{rid}")
    assert view.status_code == 200
    assert "test.log" in view.text

    # Export PDF in the same flow: FREE for all reports (Phase C).
    csrf = _csrf_from(view.text)
    pdf = env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert pdf.status_code == 200
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.content[:4] == b"%PDF"
    assert _http_balance(env) == 9  # no export charge at all

    # Re-downloading the same export is not a new charge (idempotent).
    pdf2 = env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert pdf2.status_code == 200
    assert _http_balance(env) == 9

    # Replaying the paid analysis with the same idempotency key is free.
    replay = env.client.post("/analyze/paid", data=form)
    assert replay.status_code == 200
    assert _http_balance(env) == 9


def test_paid_insufficient_credits_402_without_charge(paid_env):
    """A fresh admission the balance cannot cover is refused with no
    charge and no operation.

    PREMISE CHANGED (#164 Phase C): there is no new credit admission
    at ANY balance — an unconsumed additional-analysis consent
    presented after cutover is refused 429 (hard cap) after the
    already-admitted replay lookup, with no validate/debit. The
    settled leg and the report journey are seeded pre-cutover
    admissions (balance 3 -> 2), and the PDF export is FREE, so the
    balance is still 2 (not 0) when the fresh consent is refused."""
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    # Seed the legacy balance directly (Phase C: no signup grant).
    _seed_balance(env, uid, 3)
    assert _http_balance(env) == 3
    _exhaust_quota(env, uid)

    form = _paid_form(env, uid, csrf)
    rid = _seed_completed_paid_analysis(env, uid, form)
    paid = env.client.post("/analyze/paid", data=form)
    assert paid.status_code == 200, paid.text[:500]
    assert _http_balance(env) == 2
    assert _report_id_from(paid.text) == str(rid)

    # The PDF export no longer spends the remaining credits: FREE.
    view = env.client.get(f"/reports/{rid}")
    assert view.status_code == 200
    pdf = env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": _csrf_from(view.text)})
    assert pdf.status_code == 200
    assert _http_balance(env) == 2

    # A fresh consent now fails at admission: 429, nothing reserved,
    # nothing charged, no operation created for it.
    content = b"2024-01-01 11:00:00 INFO other\n"
    digest = fingerprint("other.log", content)
    with env.sessions() as db:
        consent = C.create_consent(db, uid, "additional_analysis", digest, 1)
        db.commit()
        cid = str(consent.id)
    main._store_paid_pending(cid, "other.log", content)
    denied = env.client.post("/analyze/paid", data={
        "consent_id": cid,
        "file_hash": digest,
        "idempotency_key": cid,
        "csrf_token": csrf,
    })
    assert denied.status_code == 429, denied.text[:300]
    assert _http_balance(env) == 2
    with env.sessions() as db:
        assert C.find_operation(db, uid, "additional_analysis", cid, digest) is None


def test_paid_analysis_failure_releases_credits(paid_env, monkeypatch):
    """A failed paid analysis releases the reservation: balance unchanged.

    PREMISE CHANGED (#164 Phase C): a NEW admission can no longer
    reach execution (unconsumed consents refuse 429), so the failure
    leg is a pre-cutover admitted operation whose execution failed:
    admit (reserve 1) -> release_operation on failure restores the
    full balance, and the HTTP replay of that failed identity is a
    409 that re-executes nothing and charges nothing."""
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    _seed_balance(env, uid, 10)
    assert _http_balance(env) == 10
    _exhaust_quota(env, uid)
    form = _paid_form(env, uid, csrf)
    with env.sessions() as db:
        op = C.admit_paid_operation(
            db, uid, "additional_analysis", form["idempotency_key"],
            form["file_hash"], 1, uuid.UUID(form["consent_id"]),
            "seed-worker")
        db.commit()
        op_id = op.id
    assert _http_balance(env) == 9  # 1 credit reserved by the admission
    with env.sessions() as db:
        C.release_operation(db, op_id, "seed-worker", "analysis_failed")
        db.commit()
    assert _http_balance(env) == 10  # reservation released, nothing settled
    calls = []
    monkeypatch.setattr(main, "analyze_upload",
                        lambda *a: calls.append(a) or {"error": True, "message": "bad log"})
    failed = env.client.post("/analyze/paid", data=form)
    assert failed.status_code == 409, failed.text[:300]
    assert calls == []  # the failed identity never re-executes
    assert _http_balance(env) == 10
    with env.sessions() as db:
        assert db.get(M.Operation, op_id).status == "failed"
