"""Issue #102: compare two logs (paid, 3 credits) — HTTP + ledger coverage.

Drives the comparison journey over HTTP for a real signed-up user:

    signup -> verify (3-credit signup reward) -> login
      -> POST /compare (two files) -> 402 consent page quoting 3 credits
         with the identical/no-material-difference disclosure
      -> POST /compare/paid -> reserve (-3) + settle (-3 net on success,
         full reversal on failure) -> retrieve (GET /reports/{id})
      -> separate 2-credit PDF export -> replay (no recharge)

Execution is mocked at the main._execute_compare boundary (the mocked-
execution pattern: HTTP/ledger tests never run the real worker); the
real supervised worker with the evidence flag is covered directly below,
and analyze_upload's evidence flag is covered at service level.

Runs against SQLite and real PostgreSQL via ``migrated_engine``. The
Postgres leg runs in CI (TEST_POSTGRES_URL) and skips locally.
"""

import copy
import re
import uuid
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from test_account_migrations import migrated_engine  # noqa: F401  (fixture)
from app import auth, credits as C, db as DB, email, main, models as M
from app.compare_service import compare_results
from app.pdf_export import generate_comparison_pdf
from app.service import analyze_upload


def _log(level, message, n):
    return (f"2024-01-01 10:00:00 {level} {message}\n".encode() * n)


LOG_A = (
    _log("ERROR", "database connection failed", 10)
    + _log("WARN", "cache miss", 10)
    + _log("ERROR", "disk full", 5)
    + _log("WARN", "slow query detected", 6)
)
LOG_B = (
    _log("ERROR", "database connection failed", 20)
    + _log("WARN", "cache miss", 10)
    + _log("ERROR", "slow query detected", 6)
    + _log("ERROR", "auth token expired", 7)
)
# Hand-checked expectation for LOG_A -> LOG_B: 1 new (auth), 1 resolved
# (disk), 1 material volume change (database 10 -> 20), 1 severity shift
# (slow query WARN -> ERROR at equal counts).


@pytest.fixture
def compare_env(migrated_engine, monkeypatch, tmp_path):
    """HTTP client bound to a migrated database, no pre-made user."""
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

    def fake_compare(filename_a, content_a, filename_b, content_b):
        # Real service analysis (in-process), not the supervised worker:
        # the worker path is covered by test_worker_compare_evidence.
        # use_alarm=False: the route runs this in a worker thread, where
        # SIGALRM cannot be armed (production uses the subprocess worker,
        # which has the same no-alarm property).
        return (
            copy.deepcopy(analyze_upload(filename_a, content_a,
                                         collect_comparison_evidence=True,
                                         use_alarm=False)),
            copy.deepcopy(analyze_upload(filename_b, content_b,
                                         collect_comparison_evidence=True,
                                         use_alarm=False)),
        )

    monkeypatch.setattr(main, "_execute_compare", fake_compare)
    with TestClient(
        main.app,
        base_url="https://testserver",
        raise_server_exceptions=False,
        client=("127.0.0.1", 50000),
    ) as client:
        client.headers["X-CSRF-Token"] = client.get("/auth/csrf").json()["csrf_token"]
        yield SimpleNamespace(engine=engine, sessions=sessions, sent=sent, client=client)


def _signup_verify_login(env, email_addr=None):
    email_addr = email_addr or f"cmp_{uuid.uuid4().hex[:8]}@example.com"
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


def _post_compare(env, content_a=LOG_A, content_b=LOG_B):
    return env.client.post(
        "/compare",
        files={
            "file_a": ("a.log", content_a, "text/plain"),
            "file_b": ("b.log", content_b, "text/plain"),
        },
    )


def _consent_fields(page_text):
    def field(name):
        m = re.search(r'name="%s" value="([^"]+)"' % name, page_text)
        assert m, f"{name} not in consent page"
        return m.group(1)
    return field("consent_id"), field("file_hash"), field("csrf_token")


def _confirm(env, consent_id, file_hash, csrf, idempotency_key=None):
    return env.client.post(
        "/compare/paid",
        data={
            "consent_id": consent_id,
            "file_hash": file_hash,
            "idempotency_key": idempotency_key or consent_id,
            "csrf_token": csrf,
        },
    )


def _report_id_from(html):
    m = re.search(r'action="/reports/([0-9a-f-]{36})/pdf"', html)
    assert m, "no PDF export form (hence no report id) in comparison report"
    return m.group(1)


def _grant(env, uid, n):
    # A grant alone is not spendable: settlement also checks the account
    # balance, so top up both (mirrors what a purchase would record).
    with env.sessions() as db:
        db.add(M.CreditGrant(user_id=uid, source="admin", source_key="test-topup",
                             issued=n, remaining=n, reserved=0))
        account = db.query(M.CreditAccount).filter(
            M.CreditAccount.user_id == uid).one()
        account.balance += n
        db.commit()


# --- journey ---------------------------------------------------------------

def test_compare_requires_login(compare_env):
    env = compare_env
    r = env.client.get("/compare", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login"


def test_full_compare_flow_net_minus_3_and_retrievable(compare_env):
    env = compare_env
    _, uid, _ = _signup_verify_login(env)
    assert _http_balance(env) == 3
    r = _post_compare(env)
    assert r.status_code == 402, r.text[:300]
    assert "3 credits" in r.text
    assert "even if the logs are identical or show no material differences" in r.text
    consent_id, file_hash, csrf = _consent_fields(r.text)
    assert _http_balance(env) == 3  # consent charges nothing
    confirmed = _confirm(env, consent_id, file_hash, csrf)
    assert confirmed.status_code == 200, confirmed.text[:500]
    assert "auth token expired" in confirmed.text  # new
    assert "disk full" in confirmed.text  # resolved
    assert "database connection failed" in confirmed.text  # volume change
    assert "Resolved means the pattern was not observed in B" in confirmed.text
    assert _http_balance(env) == 0
    rid = _report_id_from(confirmed.text)
    view = env.client.get(f"/reports/{rid}")
    assert view.status_code == 200, view.text[:300]
    assert "auth token expired" in view.text
    # Separate 2-credit PDF export (funded by a top-up grant).
    _grant(env, uid, 5)
    pdf = env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert pdf.status_code == 200, pdf.text[:300]
    assert pdf.content.startswith(b"%PDF")
    assert b"auth token expired" in pdf.content
    assert b"database connection failed" in pdf.content
    assert _http_balance(env) == 3  # 5 granted - 2 PDF
    # Replay the same confirmation: no recharge, same report.
    replay = _confirm(env, consent_id, file_hash, csrf)
    assert replay.status_code == 200, replay.text[:300]
    assert _report_id_from(replay.text) == rid
    assert _http_balance(env) == 3


def test_identical_pair_still_costs_3_and_reports_no_material(compare_env):
    env = compare_env
    _, _, _ = _signup_verify_login(env)
    r = _post_compare(env, content_a=LOG_A, content_b=LOG_A)
    assert r.status_code == 402, r.text[:300]
    consent_id, file_hash, csrf = _consent_fields(r.text)
    confirmed = _confirm(env, consent_id, file_hash, csrf)
    assert confirmed.status_code == 200, confirmed.text[:500]
    assert "No material differences" in confirmed.text
    assert _http_balance(env) == 0


def test_invalid_b_rejected_before_analysis_or_charge(compare_env, monkeypatch):
    env = compare_env
    _, uid, _ = _signup_verify_login(env)
    calls = []
    orig = main._execute_compare
    monkeypatch.setattr(main, "_execute_compare",
                        lambda *a: calls.append(a) or orig(*a))
    oversize_b = b"x" * (11 * 1024 * 1024)
    r = _post_compare(env, content_b=oversize_b)
    assert r.status_code == 413, r.text[:300]
    assert calls == []
    assert _http_balance(env) == 3
    with env.sessions() as db:
        assert db.query(M.Operation).filter(
            M.Operation.user_id == uid,
            M.Operation.type == "compare_logs").count() == 0


def test_compare_failure_releases_full_reservation(compare_env, monkeypatch):
    env = compare_env
    _, _, _ = _signup_verify_login(env)
    r = _post_compare(env)
    consent_id, file_hash, csrf = _consent_fields(r.text)
    monkeypatch.setattr(main, "_execute_compare",
                        lambda *a: ({"filename": "a.log"},
                                    {"error": "analysis_timeout",
                                     "message": "Comparison failed."}))
    failed = _confirm(env, consent_id, file_hash, csrf)
    assert failed.status_code == 400, failed.text[:300]
    assert _http_balance(env) == 3  # full reversal, no report stored
    with env.sessions() as db:
        assert db.query(M.Result).filter(
            M.Result.type == "comparison").count() == 0


def test_compare_forgery_and_cross_user(compare_env):
    env = compare_env
    _, uid, _ = _signup_verify_login(env)
    r = _post_compare(env)
    consent_id, file_hash, csrf = _consent_fields(r.text)
    # Input substitution: a different pair hash does not match the consent.
    bad = _confirm(env, consent_id, "0" * 64, csrf)
    assert bad.status_code == 409, bad.text[:300]
    assert _http_balance(env) == 3
    # Cross-user consent: a second user cannot confirm the first's consent.
    _, _, csrf2 = _signup_verify_login(env, email_addr=f"cmp2_{uuid.uuid4().hex[:8]}@example.com")
    cross = _confirm(env, consent_id, file_hash, csrf2)
    assert cross.status_code == 409, cross.text[:300]


def test_compare_rate_policy_explicit_30_per_hour(compare_env):
    env = compare_env
    _, uid, _ = _signup_verify_login(env)
    _grant(env, uid, 200)
    for _ in range(30):
        r = _post_compare(env)
        assert r.status_code == 402, r.text[:300]
        consent_id, file_hash, csrf = _consent_fields(r.text)
        confirmed = _confirm(env, consent_id, file_hash, csrf)
        assert confirmed.status_code == 200, confirmed.text[:300]
    r = _post_compare(env)
    assert r.status_code == 402, r.text[:300]
    consent_id, file_hash, csrf = _consent_fields(r.text)
    denied = _confirm(env, consent_id, file_hash, csrf)
    assert denied.status_code == 429, denied.text[:300]


# --- service / worker level -------------------------------------------------

def test_analyze_upload_evidence_flag_additive():
    plain = analyze_upload("a.log", LOG_A)
    assert "comparison_evidence" not in plain["results"]
    flagged = analyze_upload("a.log", LOG_A, collect_comparison_evidence=True)
    evidence = flagged["results"]["comparison_evidence"]
    assert set(evidence) == set(plain["results"]["issues"])
    for template, entry in evidence.items():
        assert sum(entry["level_counts"].values()) == plain["results"]["issues"][template]["count"]
    # Issues themselves are unchanged by the flag.
    assert flagged["results"]["issues"] == plain["results"]["issues"]


def test_worker_compare_evidence(monkeypatch, tmp_path):
    from app.analysis_worker import run_supervised
    out = run_supervised("a.log", LOG_A, collect_comparison_evidence=True)
    assert "error" not in out, out
    assert out["filename"] == "a.log"
    assert set(out["results"]["comparison_evidence"]) == set(out["results"]["issues"])
    payload = compare_results(out["results"], out["results"])
    assert payload["no_material_differences"] is True


def test_comparison_pdf_contains_all_change_entries():
    a = analyze_upload("a.log", LOG_A, collect_comparison_evidence=True)["results"]
    b = analyze_upload("b.log", LOG_B, collect_comparison_evidence=True)["results"]
    a["file"], b["file"] = "a.log", "b.log"
    payload = compare_results(a, b)
    pdf = generate_comparison_pdf(__import__("json").dumps(payload), "a.log -> b.log")
    assert pdf.startswith(b"%PDF")
    for template in ("auth token expired", "disk full",
                     "database connection failed", "slow query detected"):
        assert template.encode() in pdf
