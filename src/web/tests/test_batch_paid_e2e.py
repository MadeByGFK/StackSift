"""Issue #103: batch analysis (paid) — HTTP + ledger coverage.

Drives the batch journey over HTTP for a real signed-up user:

    signup -> verify (3-credit signup reward) -> login
      -> GET /batch form -> POST /batch (2-5 files, ALL validated first)
         -> 402 consent page quoting (free-first ? 0 : 1) + (N-1) credits
      -> POST /batch/paid -> ONE reservation + free-allowance claim in
         the same transaction -> sequential execution -> ONE combined
         Result (type "analysis", report_kind "batch") -> history ->
         ONE 2-credit PDF export for the whole combined report

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

def test_full_batch_flow_free_first_quote_2_net_minus_2(batch_env):
    env = batch_env
    _, uid, _ = _signup_verify_login(env)
    assert _http_balance(env) == 3
    r = _post_batch(env, _three())
    assert r.status_code == 402, r.text[:500]
    # Quote copy: both halves of the failure semantics (trim B8).
    assert "3 files. First file: free hourly allowance." in r.text
    assert "2 additional files \u00d7 1 credit. Total: 2 credits." in r.text
    assert "Analyze 3 files \u2014 use 2 credits" in r.text
    assert "All credits are released if the batch fails" in r.text
    assert "is counted even if the batch fails and is not restored" in r.text
    assert "1. one.log" in r.text and "2. two.log" in r.text and "3. three.log" in r.text
    consent_id, file_hash, csrf = _consent_fields(r.text)
    # Consent itself: no debit, no claim, no hit, no operation.
    assert _http_balance(env) == 3
    assert _ops(env, uid) == [] and _hits(env) == 0
    confirmed = _confirm(env, consent_id, file_hash, csrf)
    assert confirmed.status_code == 200, confirmed.text[:500]
    assert "Batch \u2014 3 files" in confirmed.text
    assert "database connection failed" in confirmed.text
    assert "disk full" in confirmed.text
    assert _http_balance(env) == 1  # 3 - 2 exactly
    ops = _ops(env, uid)
    assert len(ops) == 1 and ops[0].cost == 2 and ops[0].status == "completed"
    assert ops[0].free_allowance_claim is True
    assert _hits(env) == 1  # one shared-system claim for the first file only
    with env.sessions() as db:
        assert db.query(M.FreeRequest).count() == 0  # no second FreeRequest
        result = db.get(M.Result, ops[0].result_id)
        assert result is not None and result.type == "analysis"
        assert (C._as_aware(result.expires_at) - C._as_aware(result.created_at)
                ) <= timedelta(days=7, minutes=1)
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


def test_batch_allowance_exhausted_quote_3_no_claim(batch_env):
    env = batch_env
    _, uid, _ = _signup_verify_login(env)
    _seed_free(env, uid, 10)
    r = _post_batch(env, _three())
    assert r.status_code == 402, r.text[:300]
    assert "First file: 1 credit (free allowance used)" in r.text
    assert "Total: 3 credits" in r.text
    assert "5 credits" not in r.text  # never the obsolete COST_BATCH
    consent_id, file_hash, csrf = _consent_fields(r.text)
    confirmed = _confirm(env, consent_id, file_hash, csrf)
    assert confirmed.status_code == 200, confirmed.text[:300]
    assert _http_balance(env) == 0
    ops = _ops(env, uid)
    assert len(ops) == 1 and ops[0].cost == 3
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
    assert "No files were analyzed and no credits were reserved." in r.text
    assert calls == []  # zero analyzer calls
    assert _http_balance(env) == 3
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
    # N=2 and N=5 pass validation (fund the 5-file quote first).
    _grant(env, uid, 5, "count-topup")
    r = _post_batch(env, [("a.log", LOG_1), ("b.log", LOG_2)])
    assert r.status_code == 402 and "Total: 1 credits" in r.text, r.text[:300]
    r = _post_batch(env, [(f"f{i}.log", SMALL) for i in range(5)])
    assert r.status_code == 402 and "Total: 4 credits" in r.text, r.text[:300]


def test_batch_boundary_equality_50000_lines_passes(batch_env):
    env = batch_env
    _signup_verify_login(env)
    exact = b"2024-01-01 10:00:00 INFO heartbeat ok\n" * 50000
    r = _post_batch(env, [("big.log", exact), ("small.log", SMALL)])
    assert r.status_code == 402, r.text[:300]
    assert "Total: 1 credits" in r.text


# --- failure release ---------------------------------------------------------------

def test_execution_failure_releases_all_credits_but_not_free_attempt(batch_env, monkeypatch):
    env = batch_env
    _, uid, _ = _signup_verify_login(env)
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
    assert _http_balance(env) == 3  # FULL reservation released
    ops = _ops(env, uid)
    assert len(ops) == 1 and ops[0].status == "failed" and ops[0].result_id is None
    # B8: the admitted free attempt is NOT restored.
    assert ops[0].free_allowance_claim is True
    assert _hits(env) == 1
    with env.sessions() as db:
        assert db.query(M.Result).count() == 0
    assert _pending_files(env) == []
    _invariants_ok(env, uid)
    # A failed identity does not re-execute on replay.
    replay = _confirm(env, consent_id, file_hash, csrf)
    assert replay.status_code == 409, replay.text[:300]
    assert _http_balance(env) == 3


def test_execution_exception_releases_all(batch_env, monkeypatch):
    env = batch_env
    _, uid, _ = _signup_verify_login(env)
    r = _post_batch(env, _three())
    consent_id, file_hash, csrf = _consent_fields(r.text)

    def boom(files):
        raise RuntimeError("worker died")

    monkeypatch.setattr(main, "_execute_batch", boom)
    r = _confirm(env, consent_id, file_hash, csrf)
    assert r.status_code == 503, r.text[:300]
    assert _http_balance(env) == 3
    assert _ops(env, uid)[0].status == "failed"
    _invariants_ok(env, uid)


# --- insufficient credits ------------------------------------------------------------

def test_insufficient_at_quotation_402_exact_total_and_cta(batch_env):
    env = batch_env
    _, uid, _ = _signup_verify_login(env)
    # Spend the signup reward on a first batch (free-first N=3 -> 2).
    r = _post_batch(env, _three())
    consent_id, file_hash, csrf = _consent_fields(r.text)
    assert _confirm(env, consent_id, file_hash, csrf).status_code == 200
    assert _http_balance(env) == 1
    # Second batch: total 2 (allowance still available) > eligible 1.
    r = _post_batch(env, _three())
    assert r.status_code == 402, r.text[:400]
    assert "This 3-file batch costs 2 credits. Insufficient eligible Power-Up credits." in r.text
    assert "/credits" in r.text
    assert len(_ops(env, uid)) == 1  # no new reservation


def test_insufficient_at_confirmation_402_no_claim(batch_env):
    env = batch_env
    _, uid, csrf = _signup_verify_login(env)
    r = _post_batch(env, _three())
    assert r.status_code == 402, r.text[:300]
    consent_id, file_hash, _ = _consent_fields(r.text)
    # Drain 2 credits via a PDF export of a free single-file report.
    single = env.client.post(
        "/analyze",
        files={"file": ("test.log", LOG_1, "text/plain")},
        data={"output": "html", "request_id": ""})
    assert single.status_code == 200, single.text[:300]
    rid = _report_id_from(single.text)
    pdf = env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert pdf.status_code == 200, pdf.text[:300]
    assert _http_balance(env) == 1
    hits_before = _hits(env)
    denied = _confirm(env, consent_id, file_hash, csrf)
    assert denied.status_code == 402, denied.text[:400]
    assert "This 3-file batch costs 2 credits." in denied.text
    assert "/credits" in denied.text
    assert _http_balance(env) == 1
    assert _ops(env, uid) == []  # no partial reservation
    assert _hits(env) == hits_before  # claim rolled back with the denial


# --- quote changes between quote and confirm -------------------------------------------

def test_quote_change_up_requotes_never_silent_reprice(batch_env):
    env = batch_env
    _, uid, _ = _signup_verify_login(env)
    r = _post_batch(env, _three())
    assert "Total: 2 credits" in r.text
    consent_id, file_hash, csrf = _consent_fields(r.text)
    _seed_free(env, uid, 10)  # allowance consumed elsewhere
    requote = _confirm(env, consent_id, file_hash, csrf)
    assert requote.status_code == 402, requote.text[:400]
    assert "Total: 3 credits" in requote.text
    assert _http_balance(env) == 3  # nothing charged by the re-quote
    assert _ops(env, uid) == []
    consent2, hash2, csrf2 = _consent_fields(requote.text)
    assert consent2 != consent_id
    confirmed = _confirm(env, consent2, hash2, csrf2)
    assert confirmed.status_code == 200, confirmed.text[:300]
    assert _http_balance(env) == 0
    assert _ops(env, uid)[0].free_allowance_claim is False


def test_quote_change_down_requotes(batch_env):
    env = batch_env
    _, uid, _ = _signup_verify_login(env)
    _seed_free(env, uid, 10)
    r = _post_batch(env, _three())
    assert "Total: 3 credits" in r.text
    consent_id, file_hash, csrf = _consent_fields(r.text)
    # The old free requests age out of the rolling hour.
    with env.sessions() as db:
        for fr in db.query(M.FreeRequest).all():
            fr.created_at = C._utcnow() - timedelta(hours=3)
        db.commit()
    requote = _confirm(env, consent_id, file_hash, csrf)
    assert requote.status_code == 402, requote.text[:400]
    assert "Total: 2 credits" in requote.text
    assert _http_balance(env) == 3
    assert _ops(env, uid) == []
    consent2, hash2, csrf2 = _consent_fields(requote.text)
    confirmed = _confirm(env, consent2, hash2, csrf2)
    assert confirmed.status_code == 200, confirmed.text[:300]
    assert _http_balance(env) == 1
    assert _ops(env, uid)[0].free_allowance_claim is True


def test_second_batch_cannot_claim_tenth_allowance_again(batch_env):
    """Sequential form of the B2 race: 9 free used, two batch quotes at
    total 1; the first confirm claims the tenth, the second re-quotes."""
    env = batch_env
    _, uid, _ = _signup_verify_login(env)
    _grant(env, uid, 5, "tenth-topup")
    _seed_free(env, uid, 9)
    _seed_hits(env, 9)
    two = [("a.log", LOG_1), ("b.log", LOG_2)]
    r1 = _post_batch(env, two)
    assert "Total: 1 credits" in r1.text, r1.text[:300]
    c1, h1, csrf = _consent_fields(r1.text)
    r2 = _post_batch(env, two)
    assert "Total: 1 credits" in r2.text, r2.text[:300]
    c2, h2, _ = _consent_fields(r2.text)
    assert _confirm(env, c1, h1, csrf).status_code == 200
    requote = _confirm(env, c2, h2, csrf)
    assert requote.status_code == 402, requote.text[:300]
    assert "Total: 2 credits" in requote.text
    claims = [op for op in _ops(env, uid) if op.free_allowance_claim]
    assert len(claims) == 1


# --- order / duplicates ------------------------------------------------------------------

def test_order_duplicates_and_identical_files(batch_env):
    env = batch_env
    _, uid, _ = _signup_verify_login(env)
    _grant(env, uid, 3, "dup-topup")
    files = [("same.log", LOG_1), ("same.log", LOG_1), ("other.log", LOG_2)]
    r = _post_batch(env, files)
    assert r.status_code == 402, r.text[:300]
    assert "Total: 2 credits" in r.text  # identical files separately billable
    consent_id, file_hash, csrf = _consent_fields(r.text)
    confirmed = _confirm(env, consent_id, file_hash, csrf)
    assert confirmed.status_code == 200, confirmed.text[:400]
    i1 = confirmed.text.index("File 1: same.log")
    i2 = confirmed.text.index("File 2: same.log")
    i3 = confirmed.text.index("File 3: other.log")
    assert i1 < i2 < i3  # upload order preserved, duplicates distinct by ordinal
    assert _http_balance(env) == 4  # 3 + 3 granted - 2


# --- forgery / replay -----------------------------------------------------------------------

def test_batch_forgery_csrf_and_cross_user(batch_env):
    env = batch_env
    _, uid, csrf = _signup_verify_login(env)
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
    assert _http_balance(env) == 3


def test_batch_content_substitution_409(batch_env):
    env = batch_env
    _, uid, csrf = _signup_verify_login(env)
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
    r = _post_batch(env, _three())
    consent_id, file_hash, csrf = _consent_fields(r.text)
    first = _confirm(env, consent_id, file_hash, csrf)
    assert first.status_code == 200, first.text[:300]
    rid = _report_id_from(first.text)
    replay = _confirm(env, consent_id, file_hash, csrf)
    assert replay.status_code == 200, replay.text[:300]
    assert _report_id_from(replay.text) == rid
    assert _http_balance(env) == 1
    assert len(_ops(env, uid)) == 1
    assert _hits(env) == 1  # replay does not recount quota


# --- PDF: one 2-credit charge for the whole artifact -------------------------------------------

def test_batch_pdf_one_charge_and_free_redownload(batch_env):
    env = batch_env
    _, uid, csrf = _signup_verify_login(env)
    r = _post_batch(env, _three())
    consent_id, file_hash, _ = _consent_fields(r.text)
    confirmed = _confirm(env, consent_id, file_hash, csrf)
    rid = _report_id_from(confirmed.text)
    _grant(env, uid, 5, "pdf-topup")
    assert _http_balance(env) == 6
    pdf = env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert pdf.status_code == 200, pdf.text[:300]
    assert pdf.content.startswith(b"%PDF")
    assert b"database connection failed" in pdf.content
    assert b"File 2: two.log" in pdf.content
    assert b"File 3: three.log" in pdf.content
    assert _http_balance(env) == 4  # exactly -2 ONCE, not per file
    again = env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert again.status_code == 200
    assert _http_balance(env) == 4  # re-download free
    _invariants_ok(env, uid)


def test_batch_pdf_failure_releases_charge(batch_env, monkeypatch):
    env = batch_env
    _, uid, csrf = _signup_verify_login(env)
    _grant(env, uid, 5, "pdf-fail-topup")
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
    assert _http_balance(env) == 3
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
    r = env.client.post(
        "/compare",
        files={"file_a": ("a.log", LOG_1, "text/plain"),
               "file_b": ("b.log", LOG_2, "text/plain")})
    assert r.status_code == 402, r.text[:300]
    assert "3 credits" in r.text
    consent_id, file_hash, csrf = _consent_fields(r.text)
    confirmed = env.client.post(
        "/compare/paid",
        data={"consent_id": consent_id, "file_hash": file_hash,
              "idempotency_key": consent_id, "csrf_token": csrf})
    assert confirmed.status_code == 200, confirmed.text[:300]
    assert _http_balance(env) == 0


def test_paid_batch_rate_limit_is_five_per_hour(batch_env):
    env = batch_env
    _, uid, _ = _signup_verify_login(env)
    with env.sessions() as db:
        for _ in range(5):
            C._consume_rate(db, "paid:batch", str(uid))
        db.commit()
        with pytest.raises(C.AdmissionError):
            C._consume_rate(db, "paid:batch", str(uid))
