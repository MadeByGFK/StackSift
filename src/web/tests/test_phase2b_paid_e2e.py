"""Issue #48: full paid-workflow HTTP integration coverage.

Drives the complete paid journey over HTTP for a real signed-up user:

    signup -> verify (3-credit signup reward) -> login
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
    pattern) so the 3-credit signup reward is granted exactly as in
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
    return email_addr, uid, csrf


def _http_balance(env):
    r = env.client.get("/credits/balance")
    assert r.status_code == 200, r.text[:300]
    return r.json()["balance"]


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
    """admit -> analyze -> settle -> retrieve -> PDF, one HTTP journey."""
    env = paid_env
    _, uid, _ = _signup_verify_login(env)
    assert _http_balance(env) == 3  # signup reward, asserted over HTTP

    _exhaust_quota(env, uid)
    form = _consent_page(env)
    assert _http_balance(env) == 3  # the consent page itself charges nothing

    paid = env.client.post("/analyze/paid", data=form)
    assert paid.status_code == 200, paid.text[:500]
    assert _http_balance(env) == 2  # 1 credit reserved then settled
    rid = _report_id_from(paid.text)

    # Retrieve the paid result over HTTP.
    view = env.client.get(f"/reports/{rid}")
    assert view.status_code == 200
    assert "test.log" in view.text

    # Export PDF in the same flow: costs 2 credits.
    csrf = _csrf_from(view.text)
    pdf = env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert pdf.status_code == 200
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.content[:4] == b"%PDF"
    assert _http_balance(env) == 0

    # Re-downloading the same export is not a new charge (idempotent).
    pdf2 = env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert pdf2.status_code == 200
    assert _http_balance(env) == 0

    # Replaying the paid analysis with the same idempotency key is free.
    replay = env.client.post("/analyze/paid", data=form)
    assert replay.status_code == 200
    assert _http_balance(env) == 0


def test_paid_insufficient_credits_402_without_charge(paid_env):
    """402 when the balance cannot cover admission: no charge, no operation."""
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    _exhaust_quota(env, uid)

    form = _consent_page(env)
    paid = env.client.post("/analyze/paid", data=form)
    assert paid.status_code == 200, paid.text[:500]
    assert _http_balance(env) == 2
    rid = _report_id_from(paid.text)

    # Spend the last 2 credits on a PDF export.
    view = env.client.get(f"/reports/{rid}")
    assert view.status_code == 200
    pdf = env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": _csrf_from(view.text)})
    assert pdf.status_code == 200
    assert _http_balance(env) == 0

    # A fresh consent now fails at admission: 402, nothing reserved.
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
    assert denied.status_code == 402, denied.text[:300]
    assert _http_balance(env) == 0
    with env.sessions() as db:
        assert C.find_operation(db, uid, "additional_analysis", cid, digest) is None


def test_paid_analysis_failure_releases_credits(paid_env, monkeypatch):
    """A failed paid analysis releases the reservation: balance unchanged."""
    env = paid_env
    _, uid, _ = _signup_verify_login(env)
    _exhaust_quota(env, uid)
    form = _consent_page(env)
    monkeypatch.setattr(main, "analyze_upload", lambda *a: {"error": True, "message": "bad log"})
    failed = env.client.post("/analyze/paid", data=form)
    assert failed.status_code == 400, failed.text[:300]
    assert _http_balance(env) == 3  # reservation released, nothing settled
