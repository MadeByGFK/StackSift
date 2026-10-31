"""Issue #104: oversize analysis (paid, 3 credits) — HTTP + ledger coverage.

Drives the oversize journey over HTTP for a real signed-up user:

    signup -> verify (3-credit signup reward) -> login
      -> oversize upload -> 402 consent page quoting 3 credits
      -> POST /analyze/paid -> reserve (-3) + settle (-3 net on success,
         full reversal on failure) -> retrieve (GET /reports)
      -> separate 2-credit PDF export -> replay (no recharge)

Execution is mocked at the main._execute_oversize boundary (the T5
mocked-execution pattern: HTTP/ledger tests never run the real worker);
real subprocess behavior is covered directly in test_oversize_resources.py
and in the service-level worker tests below.

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

OVERSIZE_402 = (
    "Oversize analysis costs 3 credits. "
    "You do not have enough eligible Power-Up credits."
)


@pytest.fixture
def oversize_env(migrated_engine, monkeypatch, tmp_path):
    """HTTP client bound to a migrated database, no pre-made user.

    Mirrors test_phase2b_paid_e2e.paid_env, plus a mocked oversize
    execution boundary (main._execute_oversize) so HTTP tests stay fast
    and deterministic; the real worker is tested separately.
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
    report = main.analyze_upload("test.log", SAMPLE_LOG.encode())

    def fake_analyze(*args, **kwargs):
        return copy.deepcopy(report)

    monkeypatch.setattr(main, "analyze_upload", fake_analyze)
    monkeypatch.setattr(main, "_execute_oversize", fake_analyze)
    with TestClient(
        main.app,
        base_url="https://testserver",
        raise_server_exceptions=False,
        client=("127.0.0.1", 50000),
    ) as client:
        client.headers["X-CSRF-Token"] = client.get("/auth/csrf").json()["csrf_token"]
        yield SimpleNamespace(engine=engine, sessions=sessions, sent=sent, client=client)


# --- helpers ---------------------------------------------------------------

def _signup_verify_login(env, email_addr=None):
    email_addr = email_addr or f"ov_{uuid.uuid4().hex[:8]}@example.com"
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


def _line_content(nlines, prefix=b"2024-01-01 10:00:00 INFO heartbeat ok"):
    return (prefix + b"\n") * nlines


def _byte_content():
    """12.5 MB, exactly 50,000 lines: byte-only oversize (lines at the
    free ceiling, bytes over it)."""
    line = b"2024-01-01 10:00:00 INFO " + b"x" * 222 + b"\n"
    return line * 50000


def _post_oversize(env, content, filename="big.log"):
    return env.client.post(
        "/analyze",
        files={"file": (filename, content, "text/plain")},
        data={"output": "html", "request_id": ""},
    )


def _consent_fields(page_text):
    def field(name):
        m = re.search(r'name="%s" value="([^"]+)"' % name, page_text)
        assert m, f"{name} not in consent page"
        return m.group(1)
    return field("consent_id"), field("file_hash")


def _confirm(env, consent_id, file_hash, csrf, idempotency_key=None):
    return env.client.post(
        "/analyze/paid",
        data={
            "consent_id": consent_id,
            "file_hash": file_hash,
            "idempotency_key": idempotency_key or consent_id,
            "csrf_token": csrf,
        },
    )


def _exhaust_quota(env, uid):
    with env.sessions() as db:
        for _ in range(10):
            db.add(M.FreeRequest(
                request_id=uuid.uuid4().hex, user_id=uid, fingerprint="old",
                status="failed", quota_bucket_trusted_ip="127.0.0.1",
                created_at=C._utcnow() - timedelta(minutes=2), deadline=C._utcnow(),
            ))
        db.commit()


def _ops(env, uid):
    with env.sessions() as db:
        return db.query(M.Operation).filter(
            M.Operation.user_id == uid,
            M.Operation.type == "oversize_analysis").all()


# --- free path untouched ---------------------------------------------------

def test_free_size_stays_free(oversize_env):
    env = oversize_env
    _, uid, _ = _signup_verify_login(env)
    r = env.client.post(
        "/analyze",
        files={"file": ("test.log", b"2024-01-01 10:00:00 INFO hi\n", "text/plain")},
        data={"output": "html", "request_id": ""},
    )
    assert r.status_code == 200, r.text[:300]
    assert _http_balance(env) == 3
    assert _ops(env, uid) == []


# --- quotation ---------------------------------------------------------------

def test_byte_only_oversize_quotes_3(oversize_env):
    env = oversize_env
    _, uid, _ = _signup_verify_login(env)
    content = _byte_content()
    assert len(content) > 10 * 1024 * 1024 and content.count(b"\n") == 50000
    r = _post_oversize(env, content)
    assert r.status_code == 402, r.text[:300]
    assert "Oversize analysis" in r.text
    assert "Use 3 credits" in r.text
    assert "Analyze up to 100 MB / 500,000 lines." in r.text
    assert "No charge if the analysis fails. Results are available for 7 days." in r.text
    # Consent itself changes neither balance nor allocations, and creates
    # no operation.
    assert _http_balance(env) == 3
    assert _ops(env, uid) == []


def test_line_only_oversize_quotes_3_with_quota_remaining(oversize_env):
    env = oversize_env
    _signup_verify_login(env)
    # Free hourly quota is untouched here, yet oversize still quotes 3:
    # oversize never converts into a free run.
    r = _post_oversize(env, _line_content(50001))
    assert r.status_code == 402, r.text[:300]
    assert "Use 3 credits" in r.text


def test_additional_analysis_wording_unchanged(oversize_env):
    env = oversize_env
    _, uid, _ = _signup_verify_login(env)
    _exhaust_quota(env, uid)
    r = env.client.post(
        "/analyze",
        files={"file": ("test.log", b"2024-01-01 10:00:00 INFO hi\n", "text/plain")},
        data={"output": "html", "request_id": ""},
    )
    assert r.status_code == 402, r.text[:300]
    assert "Free analyses used up" in r.text
    assert "Use 1 credit" in r.text
    assert "Use 3 credits" not in r.text


# --- success / settlement ----------------------------------------------------

def test_confirm_success_net_minus_3_and_retrievable(oversize_env):
    env = oversize_env
    _, uid, csrf = _signup_verify_login(env)
    r = _post_oversize(env, _line_content(50001))
    assert r.status_code == 402, r.text[:300]
    consent_id, file_hash = _consent_fields(r.text)
    r = _confirm(env, consent_id, file_hash, csrf)
    assert r.status_code == 200, r.text[:300]
    assert _http_balance(env) == 0
    ops = _ops(env, uid)
    assert len(ops) == 1
    assert ops[0].cost == 3 and ops[0].status == "completed"
    assert ops[0].result_id is not None
    with env.sessions() as db:
        result = db.get(M.Result, ops[0].result_id)
        assert result is not None and result.type == "analysis"
        assert C._as_aware(result.expires_at) > C._utcnow()
        assert (C._as_aware(result.expires_at) - C._as_aware(result.created_at)
                ) <= timedelta(days=7, minutes=1)
        allocs = db.query(M.OperationAllocation).filter(
            M.OperationAllocation.operation_id == ops[0].id).all()
        assert all(a.state == "consumed" for a in allocs)
        assert sum(a.quantity for a in allocs) == 3
        scope = db.query(M.CapacityScope).filter(
            M.CapacityScope.scope_key == "global:oversize").one()
        assert scope.used == 0  # permits released on completion
    # The report is retrievable through /reports. (The mocked execution
    # report carries the fixture filename "test.log", not the upload name.)
    r = env.client.get("/reports")
    assert r.status_code == 200, r.text[:300]
    assert "test.log" in r.text
    r = env.client.get(f"/reports/{ops[0].result_id}")
    assert r.status_code == 200, r.text[:300]


def test_confirm_failure_restores_full_reservation(oversize_env, monkeypatch):
    env = oversize_env
    _, uid, csrf = _signup_verify_login(env)
    r = _post_oversize(env, _line_content(50001))
    consent_id, file_hash = _consent_fields(r.text)

    def failing(*args, **kwargs):
        return {"error": "analysis_failed",
                "message": "Analysis failed.", "filename": "big.log"}

    monkeypatch.setattr(main, "_execute_oversize", failing)
    r = _confirm(env, consent_id, file_hash, csrf)
    assert r.status_code == 400, r.text[:300]
    assert _http_balance(env) == 3  # full reversal, no partial debit
    ops = _ops(env, uid)
    assert len(ops) == 1 and ops[0].status == "failed"
    assert ops[0].result_id is None
    with env.sessions() as db:
        scope = db.query(M.CapacityScope).filter(
            M.CapacityScope.scope_key == "global:oversize").one()
        assert scope.used == 0


def test_oversize_report_retention_7d_and_separate_pdf(oversize_env):
    env = oversize_env
    _, uid, csrf = _signup_verify_login(env)
    r = _post_oversize(env, _line_content(50001))
    consent_id, file_hash = _consent_fields(r.text)
    r = _confirm(env, consent_id, file_hash, csrf)
    assert r.status_code == 200, r.text[:300]
    assert _http_balance(env) == 0
    with env.sessions() as db:
        C.grant_credits(db, uid, "purchase", "test-pack", 5)
        db.commit()
        result_id = _ops(env, uid)[0].result_id
    assert _http_balance(env) == 5
    # PDF export remains a separate 2-credit operation.
    r = env.client.post(f"/reports/{result_id}/pdf", data={"csrf_token": csrf})
    assert r.status_code == 200, r.text[:300]
    assert r.headers["content-type"] == "application/pdf"
    assert _http_balance(env) == 3


# --- insufficient credits ------------------------------------------------------

def test_insufficient_at_quotation_exact_message_and_cta(oversize_env):
    env = oversize_env
    _, uid, csrf = _signup_verify_login(env)
    r = _post_oversize(env, _line_content(50001))
    consent_id, file_hash = _consent_fields(r.text)
    assert _confirm(env, consent_id, file_hash, csrf).status_code == 200
    assert _http_balance(env) == 0
    # A second oversize upload now quotes the exact 402 message with the
    # /credits CTA, and creates no operation or partial reservation.
    r = _post_oversize(env, _line_content(50002))
    assert r.status_code == 402, r.text[:300]
    assert OVERSIZE_402 in r.text
    assert "/credits" in r.text
    assert len(_ops(env, uid)) == 1  # only the first, completed operation


def test_insufficient_at_confirmation_after_balance_change(oversize_env):
    # True after-quotation drain: quote at 3, spend 1 via additional
    # analysis, then confirm the oversize consent -> 402, no reservation.
    env = oversize_env
    _, uid, csrf = _signup_verify_login(env)
    r = _post_oversize(env, _line_content(50001))
    assert r.status_code == 402, r.text[:300]
    consent_id, file_hash = _consent_fields(r.text)
    _exhaust_quota(env, uid)
    r = env.client.post(
        "/analyze",
        files={"file": ("test.log", b"2024-01-01 10:00:00 INFO hi\n", "text/plain")},
        data={"output": "html", "request_id": ""},
    )
    assert r.status_code == 402, r.text[:300]
    cid, fhash = _consent_fields(r.text)
    assert _confirm(env, cid, fhash, csrf).status_code == 200
    assert _http_balance(env) == 2
    r = _confirm(env, consent_id, file_hash, csrf)
    assert r.status_code == 402, r.text[:300]
    assert OVERSIZE_402 in r.text
    assert _http_balance(env) == 2
    assert _ops(env, uid) == []  # no partial reservation


# --- anonymous / unsupported ---------------------------------------------------

def test_anonymous_oversize_gets_no_consent_or_artifact(oversize_env, tmp_path):
    env = oversize_env
    r = _post_oversize(env, _line_content(50001))
    assert r.status_code == 400, r.text[:300]
    assert "50,000 lines" in r.text
    assert "Use 3 credits" not in r.text
    with env.sessions() as db:
        assert db.query(M.Consent).count() == 0
        assert db.query(M.Operation).count() == 0
    import pathlib
    pending = pathlib.Path(str(tmp_path / "pending"))
    assert not list(pending.glob("pending-*.bin")) if pending.exists() else True


def test_unsupported_line_ceiling_rejected_before_consent(oversize_env):
    env = oversize_env
    _signup_verify_login(env)
    r = _post_oversize(env, _line_content(500001))
    assert r.status_code == 400, r.text[:300]
    assert "500,000 lines" in r.text
    assert "Use 3 credits" not in r.text
    with env.sessions() as db:
        assert db.query(M.Consent).count() == 0


# --- forgery / cross-user / replay ----------------------------------------------

def test_forgery_cases(oversize_env):
    env = oversize_env
    _, uid, csrf = _signup_verify_login(env)
    r = _post_oversize(env, _line_content(50001))
    consent_id, file_hash = _consent_fields(r.text)
    # Wrong fingerprint -> 409.
    r = _confirm(env, consent_id, "0" * 64, csrf)
    assert r.status_code == 409, r.text[:300]
    # Invalid CSRF -> 403.
    r = _confirm(env, consent_id, file_hash, "bogus-csrf")
    assert r.status_code == 403, r.text[:300]


def test_cross_user_consent_409_with_valid_csrf(oversize_env):
    env = oversize_env
    _, uid_a, csrf_a = _signup_verify_login(env)
    r = _post_oversize(env, _line_content(50001))
    consent_id, file_hash = _consent_fields(r.text)
    _, _, csrf_b = _signup_verify_login(env)
    r = _confirm(env, consent_id, file_hash, csrf_b)
    assert r.status_code == 409, r.text[:300]
    assert _ops(env, uid_a) == []


def test_expired_consent_409_and_missing_pending_410(oversize_env):
    env = oversize_env
    _, uid, csrf = _signup_verify_login(env)
    r = _post_oversize(env, _line_content(50001))
    consent_id, file_hash = _consent_fields(r.text)
    with env.sessions() as db:
        consent = db.get(M.Consent, uuid.UUID(consent_id))
        consent.expires_at = C._utcnow() - timedelta(seconds=1)
        db.commit()
    r = _confirm(env, consent_id, file_hash, csrf)
    assert r.status_code == 409, r.text[:300]
    # Fresh consent, pending file deleted -> 410.
    r = _post_oversize(env, _line_content(50001))
    # One-live rule: the expired consent above no longer blocks a new one.
    assert r.status_code == 402, r.text[:300]
    consent_id2, file_hash2 = _consent_fields(r.text)
    import pathlib
    for p in pathlib.Path(main._PAID_PENDING_DIR).glob("pending-*.bin"):
        p.unlink()
    r = _confirm(env, consent_id2, file_hash2, csrf)
    assert r.status_code == 410, r.text[:300]


def test_input_substitution_409(oversize_env):
    env = oversize_env
    _, uid, csrf = _signup_verify_login(env)
    r = _post_oversize(env, _line_content(50001))
    consent_id, file_hash = _consent_fields(r.text)
    import pathlib
    for p in pathlib.Path(main._PAID_PENDING_DIR).glob("pending-*.bin"):
        raw = p.read_bytes()
        nl = raw.index(b"\n")
        p.write_bytes(raw[:nl + 1] + b"2024-01-01 10:00:00 INFO tampered\n")
    r = _confirm(env, consent_id, file_hash, csrf)
    assert r.status_code == 409, r.text[:300]
    assert _ops(env, uid) == []


def test_same_consent_different_key_409(oversize_env):
    env = oversize_env
    _, uid, csrf = _signup_verify_login(env)
    r = _post_oversize(env, _line_content(50001))
    consent_id, file_hash = _consent_fields(r.text)
    assert _confirm(env, consent_id, file_hash, csrf).status_code == 200
    # Same consent, different idempotency key: the consent is already
    # consumed -> 409, and no second operation is created.
    r = _confirm(env, consent_id, file_hash, csrf,
                 idempotency_key="different-key-" + uuid.uuid4().hex)
    assert r.status_code == 409, r.text[:300]
    assert len(_ops(env, uid)) == 1


def test_completed_replay_does_not_recharge(oversize_env):
    env = oversize_env
    _, uid, csrf = _signup_verify_login(env)
    r = _post_oversize(env, _line_content(50001))
    consent_id, file_hash = _consent_fields(r.text)
    assert _confirm(env, consent_id, file_hash, csrf).status_code == 200
    assert _http_balance(env) == 0
    r = _confirm(env, consent_id, file_hash, csrf)
    assert r.status_code == 200, r.text[:300]
    assert _http_balance(env) == 0
    assert len(_ops(env, uid)) == 1


def test_failed_replay_does_not_restart(oversize_env, monkeypatch):
    env = oversize_env
    _, uid, csrf = _signup_verify_login(env)
    r = _post_oversize(env, _line_content(50001))
    consent_id, file_hash = _consent_fields(r.text)
    monkeypatch.setattr(
        main, "_execute_oversize",
        lambda *a, **k: {"error": "analysis_failed",
                         "message": "Analysis failed.", "filename": "big.log"})
    assert _confirm(env, consent_id, file_hash, csrf).status_code == 400
    assert _http_balance(env) == 3
    r = _confirm(env, consent_id, file_hash, csrf)
    assert r.status_code == 409, r.text[:300]
    assert _http_balance(env) == 3
    assert len(_ops(env, uid)) == 1


# --- pending budget / cleanup ---------------------------------------------------

def test_one_live_oversize_pending_409(oversize_env):
    env = oversize_env
    _signup_verify_login(env)
    r = _post_oversize(env, _line_content(50001))
    assert r.status_code == 402, r.text[:300]
    r = _post_oversize(env, _line_content(50002))
    assert r.status_code == 409, r.text[:300]
    assert "already have an oversize upload" in r.text


def test_pending_budget_exhaustion_503_no_consent(oversize_env, monkeypatch):
    env = oversize_env
    _, uid, _ = _signup_verify_login(env)
    monkeypatch.setattr(main, "_PAID_PENDING_BUDGET", 1024)
    r = _post_oversize(env, _line_content(50001))
    assert r.status_code == 503, r.text[:300]
    # Storage failure rolls the consent back: no dangling consent row.
    with env.sessions() as db:
        assert db.query(M.Consent).filter(M.Consent.user_id == uid).count() == 0


def test_pending_cleanup_on_success_and_failure(oversize_env, monkeypatch):
    import pathlib
    env = oversize_env
    _, uid, csrf = _signup_verify_login(env)
    r = _post_oversize(env, _line_content(50001))
    consent_id, file_hash = _consent_fields(r.text)
    assert _confirm(env, consent_id, file_hash, csrf).status_code == 200
    pending_dir = pathlib.Path(main._PAID_PENDING_DIR)
    assert list(pending_dir.glob("pending-*.bin")) == []
    assert list(pending_dir.glob("pending-*.meta.json")) == []
    # Failure path cleans up too (fresh consent: the first is consumed).
    with env.sessions() as db:
        C.grant_credits(db, uid, "purchase", "test-pack-2", 5)
        db.commit()
    r = _post_oversize(env, _line_content(50001))
    assert r.status_code == 402, r.text[:300]
    consent_id, file_hash = _consent_fields(r.text)
    monkeypatch.setattr(
        main, "_execute_oversize",
        lambda *a, **k: {"error": "analysis_failed",
                         "message": "Analysis failed.", "filename": "big.log"})
    assert _confirm(env, consent_id, file_hash, csrf).status_code == 400
    assert list(pending_dir.glob("pending-*.bin")) == []
    assert list(pending_dir.glob("pending-*.meta.json")) == []


def test_chunk_boundary_route_counts_lines_correctly(oversize_env):
    # A multi-byte character straddling the 1 MiB chunk boundary must not
    # corrupt the line count: 50,001 lines total, first line 1 MiB long
    # with 'é' split across the boundary.
    env = oversize_env
    _signup_verify_login(env)
    first = b"A" * (1024 * 1024 - 1) + "é".encode() + b"\n"
    rest = _line_content(50000)
    content = first + rest
    assert content.count(b"\n") == 50001
    r = _post_oversize(env, content)
    assert r.status_code == 402, r.text[:300]
    assert "50,001 lines" in r.text


# --- service-level boundaries (no HTTP) -----------------------------------------

def test_classify_boundaries():
    from app.service import classify_upload_size as cls
    assert cls(10 * 1024 * 1024, 50000) == "standard"
    assert cls(10 * 1024 * 1024 + 1, 1) == "oversize"      # byte-only
    assert cls(1, 50001) == "oversize"                      # line-only
    assert cls(100 * 1024 * 1024, 500000) == "oversize"     # ceilings inclusive
    assert cls(100 * 1024 * 1024 + 1, 1) == "unsupported"
    assert cls(1, 500001) == "unsupported"


def test_count_original_lines_pre_redaction_t6():
    # A PEM block collapses 4 lines to 1 after redaction; classification
    # and the oversize ceiling must still see the ORIGINAL line count.
    from app.service import count_original_lines, analyze_upload
    block = (b"-----BEGIN PRIVATE KEY-----\nMIIabc\nMIIdef\n"
             b"-----END PRIVATE KEY-----\n")
    nblocks = 125001  # 500,004 original lines, ~125k redacted lines
    content = block * nblocks
    assert count_original_lines(content) == 500004
    out = analyze_upload("k.log", content, allow_oversize=True, use_alarm=False)
    assert out.get("error") == "too_many_lines"
    assert "500,000" in out["message"]


def test_service_oversize_boundaries():
    from app.service import analyze_upload
    # Standard path rejects 50,001 lines; oversize path accepts 60,000.
    content60k = _line_content(60000)
    out = analyze_upload("s.log", content60k)
    assert out.get("error") == "too_many_lines"
    out = analyze_upload("s.log", content60k, allow_oversize=True, use_alarm=False)
    assert "error" not in out
    # Standard path rejects >10 MiB; oversize path rejects >100 MiB with
    # the 100 MB message (rejection happens before any analysis runs).
    big = b"x" * (100 * 1024 * 1024 + 1)
    out = analyze_upload("b.log", big, allow_oversize=True, use_alarm=False)
    assert out.get("error") == "file_too_large"
    assert "100MB" in out["message"]


def test_chunk_boundary_line_counting_unit():
    from app.service import count_original_lines
    # CRLF pair straddling the 2 MiB chunk boundary: still exactly 2 lines.
    content = b"x" * (2 * 1024 * 1024 - 1) + b"\r\n" + b"y"
    assert count_original_lines(content) == 2
    # Multi-byte char straddling the 1 MiB boundary: still 2 lines.
    content = b"A" * (1024 * 1024 - 1) + "é".encode() + b"\n" + b"z\n"
    assert count_original_lines(content) == 2


# --- worker: real subprocess -----------------------------------------------------

def test_worker_real_subprocess_oversize():
    from app.analysis_worker import run_supervised
    data = run_supervised("w.log", _line_content(60000))
    assert "error" not in data, data
    assert data["results"]["level_counts"]["INFO"] == 60000


def test_worker_timeout_returns_error_dict():
    from app.analysis_worker import run_supervised
    data = run_supervised("w.log", _line_content(60000), timeout=0.001)
    assert data.get("error") == "analysis_timeout"


def test_worker_memory_failure_returns_error_dict():
    from app.analysis_worker import run_supervised
    data = run_supervised("w.log", _line_content(100),
                          memory_limit=1024 * 1024)
    assert data.get("error") == "worker_failed"


def test_worker_result_filename_is_original_not_input_log():
    # Follow-up fix P2: the child only ever sees "input.log", so the
    # parent must overwrite (not setdefault) the result filename.
    from app.analysis_worker import run_supervised
    data = run_supervised("my-real-name.log", _line_content(100))
    assert "error" not in data, data
    assert data["filename"] == "my-real-name.log"


def test_worker_parent_dir_cleaned_including_child_orphan(monkeypatch):
    # Follow-up fix P2: a timeout-killed child leaves its service temp
    # file behind; it must live in the parent-owned per-run directory
    # (TMPDIR) and be removed wholesale with that directory.
    import json
    import os
    import subprocess
    from types import SimpleNamespace
    from app import analysis_worker

    seen_dirs = []

    def fake_run(argv, timeout=None, capture_output=None, env=None):
        in_path, out_path = argv[3], argv[4]
        run_dir = os.path.dirname(in_path)
        seen_dirs.append(run_dir)
        # The child must have been pointed at the per-run dir.
        assert env is not None and env.get("TMPDIR") == run_dir
        # Mimic the killed child's orphaned service temp file.
        with open(os.path.join(run_dir, "tmp-orphan.log"), "w") as f:
            f.write("redacted content\n")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump({"filename": "input.log"}, f)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    data = analysis_worker.run_supervised("real.log", b"2024-01-01 INFO x\n")
    assert data["filename"] == "real.log"
    assert seen_dirs and not os.path.exists(seen_dirs[0])


# --- ledger-level: rate, pool, recovery, T10 ---------------------------------------

def test_oversize_rate_policy_explicit_30_per_hour(oversize_env):
    env = oversize_env
    _, uid, _ = _signup_verify_login(env)
    with env.sessions() as db:
        for _ in range(30):
            C._consume_rate(db, "paid:oversize_analysis", str(uid))
        db.commit()
        with pytest.raises(C.AdmissionError):
            C._consume_rate(db, "paid:oversize_analysis", str(uid))


def _direct_oversize_op(env, uid, key_suffix):
    """Admit one oversize operation directly (DB level, no HTTP)."""
    from app.analysis_admission import fingerprint as fp
    with env.sessions() as db:
        content = b"2024-01-01 10:00:00 INFO x\n"
        digest = fp("w.log", content)
        consent = C.create_consent(db, uid, "oversize_analysis", digest, 3)
        db.commit()
        op = C.admit_paid_operation(
            db, uid, "oversize_analysis", f"key-{key_suffix}", digest, 3,
            consent.id, "worker-1", extra_scopes=[("global:oversize", 1)])
        db.commit()
        return op.id


def test_oversize_worker_pool_size_1(oversize_env):
    env = oversize_env
    _, uid_a, _ = _signup_verify_login(env)
    _, uid_b, _ = _signup_verify_login(env)
    _direct_oversize_op(env, uid_a, "a")
    # Second concurrent oversize admission (another user) is refused by
    # the pool scope while the first holds it.
    with pytest.raises(C.AdmissionError, match="global:oversize"):
        _direct_oversize_op(env, uid_b, "b")
    with env.sessions() as db:
        op_id = db.query(M.Operation).filter(
            M.Operation.user_id == uid_a,
            M.Operation.type == "oversize_analysis").one().id
        C.release_operation(db, op_id, "worker-1", "test_release")
        db.commit()
    # After release the pool is free again.
    _direct_oversize_op(env, uid_b, "b2")


def test_executor_stop_evidence_for_oversize_recovery(oversize_env):
    env = oversize_env
    _, uid, _ = _signup_verify_login(env)
    op_id = _direct_oversize_op(env, uid, "rec")
    with env.sessions() as db:
        op = db.get(M.Operation, op_id)
        op.lease_expires_at = C._utcnow() - timedelta(seconds=1)
        db.commit()
    # Without executor-termination evidence, the expired operation stays
    # reserved (lease expiry alone is insufficient).
    with env.sessions() as db:
        assert C.recover_expired_operations(db) == 0
        assert db.get(M.Operation, op_id).status == "reserved"
    # With generation-specific stop evidence, it releases and the full
    # reservation returns to the balance.
    with env.sessions() as db:
        recovered = C.recover_expired_operations(
            db, executor_stopped=lambda oid, w, g: True)
        assert recovered == 1
        assert db.get(M.Operation, op_id).status == "expired"
    assert _http_balance(env) == 3


def test_no_enumeration_constraint_on_operation_type_t10():
    # T10: Operation.type / Consent.operation_type are plain String(30)
    # columns with no enumeration constraint — verified here against the
    # model metadata (the migrated_engine legs above prove the same rows
    # persist on SQLite and, in CI, on PostgreSQL).
    from sqlalchemy import String
    assert isinstance(M.Operation.__table__.c.type.type, String)
    assert isinstance(M.Consent.__table__.c.operation_type.type, String)
    for table in (M.Operation.__table__, M.Consent.__table__):
        for constraint in table.constraints:
            sql = str(constraint.sqltext) if hasattr(constraint, "sqltext") else ""
            assert "oversize" not in sql.lower()
            assert not (("type" in sql.lower()) and ("IN" in sql.upper()))
