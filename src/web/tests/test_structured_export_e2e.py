"""Issue #105 e2e tests: structured export (CSV/JSON) routes + settlement.

Mirrors test_phase2b_reports_pdf.py patterns (auth_env, _get_csrf_from_page,
real balance deltas). Price is the founder-ruled uniform export price:
COST_STRUCTURED_EXPORT == 2 (2026-11-01 batched ruling, same as PDF).
"""

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from test_account_migrations import migrated_engine  # noqa: F401
from test_phase2a_regressions import env  # noqa: F401
from test_phase2b_paid_e2e import paid_env  # noqa: F401  (fixture, same import pattern)
from test_phase2b_reports_pdf import (
    _create_result,
    _get_csrf_from_page,
    _login,
    _signup_and_verify,
)
from app import credits as C


def _balance(auth_env, user_id):
    db = auth_env.sessions()
    try:
        return C.get_balance_summary(db, user_id)["balance"]
    finally:
        db.close()


def _grant(auth_env, user_id, qty, key=None):
    db = auth_env.sessions()
    try:
        C.grant_credits(db, user_id, "purchase", key or f"test-{uuid.uuid4().hex}", qty)
        db.commit()
    finally:
        db.close()


def _ops(auth_env, user_id, op_type="structured_export"):
    from app import models
    db = auth_env.sessions()
    try:
        return db.query(models.Operation).filter(
            models.Operation.user_id == user_id,
            models.Operation.type == op_type,
        ).all()
    finally:
        db.close()


def _artifacts(auth_env, user_id):
    from app import models
    db = auth_env.sessions()
    try:
        return db.query(models.Result).filter(
            models.Result.user_id == user_id,
            models.Result.type == "structured_export",
        ).all()
    finally:
        db.close()


def _session_csrf(auth_env):
    """CSRF from the auth endpoint (custom payloads may not render the
    full report template, so don't scrape the report page for these)."""
    token = auth_env.client.get("/auth/csrf").json()["csrf_token"]
    auth_env.client.headers["X-CSRF-Token"] = token
    return token


def _setup(auth_env, filename="test.log", extra_credits=10):
    email, user_id = _signup_and_verify(auth_env)
    rid = _create_result(auth_env, user_id, filename)
    if extra_credits:
        _grant(auth_env, user_id, extra_credits)
    _login(auth_env, email)
    csrf = _get_csrf_from_page(auth_env, f"/reports/{rid}")
    return email, user_id, rid, csrf


def _custom_result(auth_env, user_id, payload, *, expired=False, report_type="analysis"):
    from app import models
    manifest = json.dumps(payload, default=str)
    now = datetime.now(timezone.utc)
    db = auth_env.sessions()
    try:
        result = models.Result(
            user_id=user_id, type=report_type,
            free_request_id=f"test-{uuid.uuid4().hex}",
            storage_manifest=manifest,
            integrity_digest=hashlib.sha256(manifest.encode()).hexdigest(),
            byte_count=len(manifest.encode()),
            ready_at=now - timedelta(days=8) if expired else now,
            expires_at=now - timedelta(days=1) if expired else now + timedelta(days=7),
        )
        db.add(result)
        db.commit()
        return result.id
    finally:
        db.close()


def _sample_payload(**overrides):
    payload = {
        "filename": "custom.log",
        "results": {
            "total_lines": 3, "parsed_lines": 3, "malformed_lines": 0,
            "level_counts": {"ERROR": 2, "WARN": 1},
            "issues": {
                "boom, \"quoted\"\nline": {
                    "level": "ERROR", "count": 2, "services": ["api", "db"],
                    "first_seen": "2026-01-01T00:00:00Z",
                    "last_seen": "2026-01-01T00:05:00Z",
                    "correlation": {"nested": [1, 2]},
                },
                "warn thing": {
                    "level": "WARN", "count": 1, "services": [],
                    "first_seen": None, "last_seen": None,
                },
            },
            "events": [{"ts": "2026-01-01", "msg": "x"}],
        },
        "sorted_issues": [
            ["boom, \"quoted\"\nline", {"level": "ERROR", "count": 2}],
            ["warn thing", {"level": "WARN", "count": 1}],
        ],
        "legacy_field": {"keep": "me ✓"},
    }
    payload.update(overrides)
    return payload


# --- happy path / charging -------------------------------------------------

def test_csv_export_success_and_exact_charge(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    before = _balance(auth_env, user_id)
    resp = auth_env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    assert resp.status_code == 200, resp.text[:300]
    assert resp.headers["content-type"].startswith("text/csv")
    assert "attachment" in resp.headers["content-disposition"]
    assert ".csv" in resp.headers["content-disposition"]
    assert resp.headers.get("x-export-download-url", "").startswith("/exports/")
    lines = resp.content.decode("utf-8").split("\r\n")
    assert lines[0] == "template,level,count,services,first_seen,last_seen"
    assert _balance(auth_env, user_id) == before - C.COST_STRUCTURED_EXPORT == before - 2
    arts = _artifacts(auth_env, user_id)
    assert len(arts) == 1
    manifest = json.loads(arts[0].storage_manifest)
    assert manifest["artifact_kind"] == "structured_export"
    assert manifest["format"] == "csv"
    assert manifest["source_result_id"] == str(rid)
    with auth_env.sessions() as db:
        assert C.verify_account_invariants(db, user_id) == []
        assert C.verify_capacity_invariants(db) == []


def test_json_export_equals_full_stored_payload(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    resp = auth_env.client.post(f"/reports/{rid}/exports/json", data={"csrf_token": csrf})
    assert resp.status_code == 200, resp.text[:300]
    db = auth_env.sessions()
    try:
        from app import models
        source = db.get(models.Result, rid)
        expected = C.result_payload(source, user_id=user_id,
                                     operation_id=source.operation_id,
                                     free_request_id=source.free_request_id)
    finally:
        db.close()
    exported = json.loads(resp.content)
    assert exported == expected
    assert "current_user" not in exported and "csrf_token" not in exported


def test_csv_and_json_are_separate_purchases(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    before = _balance(auth_env, user_id)
    r1 = auth_env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    r2 = auth_env.client.post(f"/reports/{rid}/exports/json", data={"csrf_token": csrf})
    assert r1.status_code == r2.status_code == 200
    assert _balance(auth_env, user_id) == before - 4
    assert len(_artifacts(auth_env, user_id)) == 2
    # Another report is a separate purchase.
    rid2 = _create_result(auth_env, user_id, "second.log")
    r3 = auth_env.client.post(f"/reports/{rid2}/exports/csv", data={"csrf_token": csrf})
    assert r3.status_code == 200
    assert _balance(auth_env, user_id) == before - 6


def test_repeated_post_and_get_download_free_identical(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    r1 = auth_env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    assert r1.status_code == 200
    url = r1.headers["x-export-download-url"]
    mid = _balance(auth_env, user_id)
    r2 = auth_env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    assert r2.status_code == 200 and r2.content == r1.content
    dl = auth_env.client.get(url)
    assert dl.status_code == 200 and dl.content == r1.content
    assert _balance(auth_env, user_id) == mid
    assert len(_ops(auth_env, user_id)) == 1


def test_report_page_shows_priced_forms_and_download_link(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    page = auth_env.client.get(f"/reports/{rid}")
    assert page.status_code == 200
    assert f"/reports/{rid}/exports/csv" in page.text
    assert f"/reports/{rid}/exports/json" in page.text
    assert f"Export CSV ({C.COST_STRUCTURED_EXPORT} credits)" in page.text
    assert f"Export JSON ({C.COST_STRUCTURED_EXPORT} credits)" in page.text
    assert "First generation is charged; re-download is free while retained." in page.text
    r1 = auth_env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    assert r1.status_code == 200
    page2 = auth_env.client.get(f"/reports/{rid}")
    assert r1.headers["x-export-download-url"] in page2.text


# --- validation before reservation ------------------------------------------

def test_unsupported_format_rejected_before_charge(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    before = _balance(auth_env, user_id)
    resp = auth_env.client.post(f"/reports/{rid}/exports/xml", data={"csrf_token": csrf})
    assert resp.status_code == 400
    assert _balance(auth_env, user_id) == before
    assert _ops(auth_env, user_id) == [] and _artifacts(auth_env, user_id) == []


def test_auth_csrf_bad_uuid_foreign_missing(auth_env):
    email, user_id, rid, csrf = _setup(auth_env)
    before = _balance(auth_env, user_id)
    # bad UUID -> 400
    r = auth_env.client.post("/reports/not-a-uuid/exports/csv", data={"csrf_token": csrf})
    assert r.status_code == 400
    # missing -> 404
    r = auth_env.client.post(f"/reports/{uuid.uuid4()}/exports/csv", data={"csrf_token": csrf})
    assert r.status_code == 404
    # invalid CSRF -> 403
    r = auth_env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": "bogus"})
    assert r.status_code == 403
    # foreign -> 404
    email2, uid2 = _signup_and_verify(auth_env)
    rid2 = _create_result(auth_env, uid2, "other.log")
    r = auth_env.client.post(f"/reports/{rid2}/exports/csv", data={"csrf_token": csrf})
    assert r.status_code == 404
    assert _balance(auth_env, user_id) == before
    assert _ops(auth_env, user_id) == []
    # no session -> 401 (fresh client)
    from fastapi.testclient import TestClient
    with TestClient(auth_env.app, base_url="https://testserver") as anon:
        r = anon.post(f"/reports/{rid}/exports/csv", data={"csrf_token": "x"})
        assert r.status_code == 401


def test_expired_and_tampered_source_no_charge(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    before = _balance(auth_env, user_id)
    expired_id = _custom_result(auth_env, user_id, _sample_payload(), expired=True)
    r = auth_env.client.post(f"/reports/{expired_id}/exports/csv", data={"csrf_token": csrf})
    assert r.status_code == 410
    # tampered manifest (digest mismatch)
    from app import models
    db = auth_env.sessions()
    try:
        src = db.get(models.Result, rid)
        src.storage_manifest = src.storage_manifest + " "
        db.commit()
    finally:
        db.close()
    r = auth_env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    assert r.status_code == 500
    assert _balance(auth_env, user_id) == before
    assert _ops(auth_env, user_id) == [] and _artifacts(auth_env, user_id) == []


def test_csv_contradiction_422_before_reservation(auth_env):
    email, user_id = _signup_and_verify(auth_env)
    _grant(auth_env, user_id, 10)
    payload = _sample_payload()
    payload["sorted_issues"][0][1]["count"] = 999  # contradicts issues map
    rid = _custom_result(auth_env, user_id, payload)
    _login(auth_env, email)
    csrf = _session_csrf(auth_env)
    before = _balance(auth_env, user_id)
    r = auth_env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    assert r.status_code == 422
    assert _balance(auth_env, user_id) == before
    assert _ops(auth_env, user_id) == [] and _artifacts(auth_env, user_id) == []


def test_custom_payload_csv_roundtrip_and_json_identity(auth_env):
    email, user_id = _signup_and_verify(auth_env)
    _grant(auth_env, user_id, 10)
    payload = _sample_payload()
    rid = _custom_result(auth_env, user_id, payload)
    _login(auth_env, email)
    csrf = _session_csrf(auth_env)
    import csv as csvmod, io
    r = auth_env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    assert r.status_code == 200, r.text[:300]
    rows = list(csvmod.DictReader(io.StringIO(r.content.decode("utf-8"))))
    assert [row["template"] for row in rows] == [k for k, _ in payload["sorted_issues"]]
    assert rows[0]["services"] == '["api","db"]'
    assert rows[0]["count"] == "2"
    assert rows[1]["first_seen"] == ""
    rj = auth_env.client.post(f"/reports/{rid}/exports/json", data={"csrf_token": csrf})
    assert rj.status_code == 200
    assert json.loads(rj.content) == payload


@pytest.mark.parametrize("kind", ["comparison", "batch", "something-else"])
def test_report_kind_discriminators_422_before_charge(auth_env, kind):
    email, user_id = _signup_and_verify(auth_env)
    _grant(auth_env, user_id, 10)
    rid = _custom_result(auth_env, user_id, _sample_payload(report_kind=kind))
    _login(auth_env, email)
    csrf = _session_csrf(auth_env)
    before = _balance(auth_env, user_id)
    for fmt in ("csv", "json"):
        r = auth_env.client.post(f"/reports/{rid}/exports/{fmt}", data={"csrf_token": csrf})
        assert r.status_code == 422, (kind, fmt, r.text[:200])
        assert "not yet supported" in r.json()["error"]
    assert _balance(auth_env, user_id) == before
    assert _ops(auth_env, user_id) == [] and _artifacts(auth_env, user_id) == []


# --- money paths ---------------------------------------------------------------

def test_insufficient_eligible_402_dynamic_price(auth_env):
    email, user_id = _signup_and_verify(auth_env)  # 3 signup credits, no grant
    rid = _create_result(auth_env, user_id)
    _login(auth_env, email)
    csrf = _get_csrf_from_page(auth_env, f"/reports/{rid}")
    # Spend 2 on PDF -> 1 left (eligible), total also 1.
    pdf = auth_env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert pdf.status_code == 200
    rid2 = _create_result(auth_env, user_id, "second.log")
    r = auth_env.client.post(f"/reports/{rid2}/exports/csv", data={"csrf_token": csrf})
    assert r.status_code == 402
    assert r.json()["purchase_url"] == "/credits"
    assert f"costs {C.COST_STRUCTURED_EXPORT} credits" in r.json()["error"]
    assert _ops(auth_env, user_id) == [] and _artifacts(auth_env, user_id) == []
    # Eligible vs total: spend-restricted user with a balance still gets 402.
    from app import models
    _grant(auth_env, user_id, 10)
    db = auth_env.sessions()
    try:
        db.add(models.Restriction(user_id=user_id, action="spend",
                                  cause_type="test", cause_id="t", reason="test"))
        db.commit()
    finally:
        db.close()
    assert _balance(auth_env, user_id) > 2
    r = auth_env.client.post(f"/reports/{rid2}/exports/json", data={"csrf_token": csrf})
    assert r.status_code == 402
    assert _ops(auth_env, user_id) == []


def test_generation_failure_releases_then_retry_succeeds_once(auth_env, monkeypatch):
    _, user_id, rid, csrf = _setup(auth_env)
    before = _balance(auth_env, user_id)
    from app import structured_export as se
    real = se.payload_to_csv
    calls = {"n": 0}

    def flaky(payload):
        calls["n"] += 1
        # Call 1 is the route's pre-reservation validation; fail only the
        # post-reservation generation (call 2), once.
        if calls["n"] == 2:
            raise RuntimeError("boom")
        return real(payload)

    monkeypatch.setattr(se, "payload_to_csv", flaky)
    r = auth_env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    assert r.status_code == 500, r.text[:300]
    assert _balance(auth_env, user_id) == before  # full release
    assert _artifacts(auth_env, user_id) == []
    ops = _ops(auth_env, user_id)
    assert len(ops) == 1 and ops[0].status == "failed"
    with auth_env.sessions() as db:
        assert C.verify_account_invariants(db, user_id) == []
        assert C.verify_capacity_invariants(db) == []
    # Retry succeeds once with a fresh (retry-suffixed) identity...
    monkeypatch.setattr(se, "payload_to_csv", real)
    r2 = auth_env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    assert r2.status_code == 200, r2.text[:300]
    assert _balance(auth_env, user_id) == before - 2
    ops = _ops(auth_env, user_id)
    assert len(ops) == 2
    completed = [o for o in ops if o.status == "completed"]
    assert len(completed) == 1 and "-retry-" in completed[0].idempotency_key
    # ...and later retries FIND that completed retry and stay free (this is
    # the PDF retry-discovery gap, designed out).
    r3 = auth_env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    assert r3.status_code == 200 and r3.content == r2.content
    assert _balance(auth_env, user_id) == before - 2
    assert len(_ops(auth_env, user_id)) == 2


def test_storage_failure_releases(auth_env, monkeypatch):
    _, user_id, rid, csrf = _setup(auth_env)
    before = _balance(auth_env, user_id)
    monkeypatch.setattr(C, "store_structured_export_result",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("store boom")))
    r = auth_env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    assert r.status_code == 500
    assert _balance(auth_env, user_id) == before
    assert _artifacts(auth_env, user_id) == []
    with auth_env.sessions() as db:
        assert C.verify_account_invariants(db, user_id) == []


def test_reserved_operation_returns_409(auth_env):
    from app import models
    _, user_id, rid, csrf = _setup(auth_env)
    db = auth_env.sessions()
    try:
        db.add(models.Operation(
            user_id=user_id, type="structured_export", status="reserved",
            idempotency_key=f"structured-{rid}-csv-v1", request_hash="x",
            cost=2, worker_id="other-worker",
            lease_expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        ))
        db.commit()
    finally:
        db.close()
    r = auth_env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    assert r.status_code == 409
    assert "already in progress" in r.json()["error"].lower()


def test_rate_limit_mapping_is_pdf_like():
    assert C.RATE_LIMIT_STRUCTURED_EXPORT == 10
    assert C.COST_STRUCTURED_EXPORT == 2


# --- download route -------------------------------------------------------------

def test_download_after_source_expiry_but_post_still_410(auth_env):
    from app import models
    _, user_id, rid, csrf = _setup(auth_env)
    r1 = auth_env.client.post(f"/reports/{rid}/exports/json", data={"csrf_token": csrf})
    assert r1.status_code == 200
    url = r1.headers["x-export-download-url"]
    # Expire the SOURCE only; the artifact keeps its own 7 days.
    db = auth_env.sessions()
    try:
        src = db.get(models.Result, rid)
        src.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        db.commit()
    finally:
        db.close()
    dl = auth_env.client.get(url)
    assert dl.status_code == 200 and dl.content == r1.content
    r2 = auth_env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    assert r2.status_code == 410


def test_download_foreign_expired_and_tampered(auth_env):
    from app import models
    _, user_id, rid, csrf = _setup(auth_env)
    r1 = auth_env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    url = r1.headers["x-export-download-url"]
    export_id = url.rsplit("/", 1)[-1]
    # Foreign user -> 404
    email2, uid2 = _signup_and_verify(auth_env)
    _login(auth_env, email2)
    assert auth_env.client.get(url).status_code == 404
    _login(auth_env, _signup_email(auth_env, user_id))
    # Tampered content (digest mismatch, envelope re-sealed) -> 410
    db = auth_env.sessions()
    try:
        art = db.get(models.Result, uuid.UUID(export_id))
        manifest = json.loads(art.storage_manifest)
        manifest["content_base64"] = "AAAA"
        raw = json.dumps(manifest)
        art.storage_manifest = raw
        art.integrity_digest = hashlib.sha256(raw.encode()).hexdigest()
        art.byte_count = len(raw.encode())
        db.commit()
    finally:
        db.close()
    assert auth_env.client.get(url).status_code == 410
    # Expired artifact -> 410
    db = auth_env.sessions()
    try:
        art = db.get(models.Result, uuid.UUID(export_id))
        manifest = json.loads(art.storage_manifest)
        import base64
        manifest["content_base64"] = base64.b64encode(b"template,level\r\n").decode()
        manifest["content_byte_count"] = len(b"template,level\r\n")
        manifest["content_digest"] = hashlib.sha256(b"template,level\r\n").hexdigest()
        raw = json.dumps(manifest)
        art.storage_manifest = raw
        art.integrity_digest = hashlib.sha256(raw.encode()).hexdigest()
        art.byte_count = len(raw.encode())
        art.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        db.commit()
    finally:
        db.close()
    assert auth_env.client.get(url).status_code == 410
    # Bad UUID -> 400; missing -> 404
    assert auth_env.client.get("/exports/nope").status_code == 400
    assert auth_env.client.get(f"/exports/{uuid.uuid4()}").status_code == 404


def _signup_email(auth_env, user_id):
    from app import models
    db = auth_env.sessions()
    try:
        return db.get(models.User, user_id).email
    finally:
        db.close()


def test_paid_origin_source_also_exports(paid_env):
    """Spec §9.7: a paid-origin owned analysis is a valid export source."""
    from test_phase2b_paid_e2e import (
        _consent_page, _csrf_from, _exhaust_quota, _http_balance,
        _report_id_from, _signup_verify_login,
    )
    env = paid_env
    _, uid, _ = _signup_verify_login(env)
    _grant_paid(env, uid, 10)
    _exhaust_quota(env, uid)
    form = _consent_page(env)
    paid = env.client.post("/analyze/paid", data=form)
    assert paid.status_code == 200, paid.text[:300]
    rid = _report_id_from(paid.text)
    view = env.client.get(f"/reports/{rid}")
    csrf = _csrf_from(view.text)
    before = _http_balance(env)
    r = env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    assert r.status_code == 200, r.text[:300]
    assert _http_balance(env) == before - 2


def _grant_paid(env, user_id, qty):
    with env.sessions() as db:
        C.grant_credits(db, user_id, "purchase", f"test-{uuid.uuid4().hex}", qty)
        db.commit()
