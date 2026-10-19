"""Phase 2B tests: report history + PDF export."""

import json
import uuid
from datetime import datetime, timedelta, timezone


def _signup_and_verify(auth_env, email=None):
    """Create a verified user. Returns (email, user_id)."""
    from app.models import User
    email = email or f"test_{uuid.uuid4().hex[:8]}@example.com"
    auth_env.client.post("/auth/signup", data={
        "email": email, "password": "TestPass123!x",
    })
    db = auth_env.sessions()
    try:
        user = db.query(User).filter(User.email == email).one()
        user.email_verified = True
        db.commit()
        return email, user.id
    finally:
        db.close()


def _login(auth_env, email, password="TestPass123!x"):
    """Log in via JSON API. Returns response."""
    # Refresh CSRF header (fixture sets it, but login rotates it)
    auth_env.client.headers["X-CSRF-Token"] = auth_env.client.get("/auth/csrf").json()["csrf_token"]
    resp = auth_env.client.post("/auth/login", data={"email": email, "password": password})
    if resp.status_code == 200:
        auth_env.client.headers["X-CSRF-Token"] = resp.json()["csrf_token"]
    return resp


def _create_result(auth_env, user_id, filename="test.log"):
    """Create a Result row using the test DB session."""
    from app import models
    import hashlib
    manifest = json.dumps({
        "filename": filename,
        "results": {"total_lines": 100, "parsed_lines": 95, "error_count": 5},
        "health": {"label": "Needs attention", "color": "yellow"},
        "findings": [{"message": "Test finding 1"}, {"message": "Test finding 2"}],
    })
    now = datetime.now(timezone.utc)
    db = auth_env.sessions()
    try:
        result = models.Result(
            user_id=user_id,
            type="analysis",
            storage_manifest=manifest,
            integrity_digest=hashlib.sha256(manifest.encode()).hexdigest(),
            byte_count=len(manifest.encode()),
            ready_at=now,
            expires_at=now + timedelta(days=7),
        )
        db.add(result)
        db.commit()
        return result.id
    finally:
        db.close()


def _get_csrf_from_page(auth_env, url):
    """Extract CSRF token from an HTML page."""
    import re
    resp = auth_env.client.get(url)
    m = re.search(r'name="csrf_token" value="([^"]+)"', resp.text)
    return m.group(1) if m else ""


def test_reports_list_requires_login(auth_env):
    """Unauthenticated /reports redirects to login."""
    resp = auth_env.client.get("/reports", follow_redirects=False)
    assert resp.status_code in (303, 307)
    assert "/login" in resp.headers["location"]


def test_reports_list_empty(auth_env):
    """Logged-in user with no reports sees empty state."""
    email, user_id = _signup_and_verify(auth_env)
    resp = _login(auth_env, email)
    assert resp.status_code == 200
    resp = auth_env.client.get("/reports")
    assert resp.status_code == 200
    assert "No reports yet" in resp.text


def test_reports_list_shows_reports(auth_env):
    """Logged-in user sees their past reports."""
    email, user_id = _signup_and_verify(auth_env)
    rid = _create_result(auth_env, user_id, "app.log")
    _login(auth_env, email)
    resp = auth_env.client.get("/reports")
    assert resp.status_code == 200
    assert "app.log" in resp.text
    assert str(rid) in resp.text


def test_reports_list_only_own_reports(auth_env):
    """Users cannot see other users' reports."""
    email1, uid1 = _signup_and_verify(auth_env, "user1@example.com")
    email2, uid2 = _signup_and_verify(auth_env, "user2@example.com")
    _create_result(auth_env, uid1, "user1.log")
    _create_result(auth_env, uid2, "user2.log")
    _login(auth_env, email1)
    resp = auth_env.client.get("/reports")
    assert resp.status_code == 200
    assert "user1.log" in resp.text
    assert "user2.log" not in resp.text


def test_report_view_ownership(auth_env):
    """Cannot view another user's report."""
    email1, uid1 = _signup_and_verify(auth_env, "user1@example.com")
    email2, uid2 = _signup_and_verify(auth_env, "user2@example.com")
    rid = _create_result(auth_env, uid2, "secret.log")
    _login(auth_env, email1)
    resp = auth_env.client.get(f"/reports/{rid}")
    assert resp.status_code == 404


def test_report_view_own(auth_env):
    """Can view own report."""
    email, user_id = _signup_and_verify(auth_env)
    rid = _create_result(auth_env, user_id, "myapp.log")
    _login(auth_env, email)
    resp = auth_env.client.get(f"/reports/{rid}")
    assert resp.status_code == 200
    assert "myapp.log" in resp.text


def test_report_view_expired(auth_env):
    """Expired report returns 410."""
    from app import models
    import hashlib
    email, user_id = _signup_and_verify(auth_env)
    manifest = json.dumps({"filename": "old.log"})
    now = datetime.now(timezone.utc)
    db = auth_env.sessions()
    try:
        result = models.Result(
            user_id=user_id, type="analysis", storage_manifest=manifest,
            integrity_digest=hashlib.sha256(manifest.encode()).hexdigest(),
            byte_count=len(manifest.encode()),
            ready_at=now - timedelta(days=8),
            expires_at=now - timedelta(days=1),
        )
        db.add(result)
        db.commit()
        rid = result.id
    finally:
        db.close()
    _login(auth_env, email)
    resp = auth_env.client.get(f"/reports/{rid}")
    assert resp.status_code == 410


def test_report_view_excludes_pdf_results(auth_env):
    """Cannot view a PDF result via the report endpoint."""
    from app import models
    import hashlib
    email, user_id = _signup_and_verify(auth_env)
    manifest = json.dumps({"filename": "doc.pdf", "pdf_base64": "abc"})
    now = datetime.now(timezone.utc)
    db = auth_env.sessions()
    try:
        result = models.Result(
            user_id=user_id, type="pdf",
            storage_manifest=manifest,
            integrity_digest=hashlib.sha256(manifest.encode()).hexdigest(),
            byte_count=len(manifest.encode()),
            ready_at=now, expires_at=now + timedelta(days=7),
        )
        db.add(result)
        db.commit()
        rid = result.id
    finally:
        db.close()
    _login(auth_env, email)
    resp = auth_env.client.get(f"/reports/{rid}")
    assert resp.status_code == 404


def test_pdf_export_success(auth_env):
    """PDF export with credits returns PDF bytes."""
    email, user_id = _signup_and_verify(auth_env)
    rid = _create_result(auth_env, user_id)
    _login(auth_env, email)
    csrf = _get_csrf_from_page(auth_env, f"/reports/{rid}")
    resp = auth_env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content[:4] == b"%PDF"


def test_pdf_export_deducts_credits(auth_env):
    """PDF export deducts exactly 2 credits."""
    from app import credits as credits_helpers
    email, user_id = _signup_and_verify(auth_env)
    rid = _create_result(auth_env, user_id)
    _login(auth_env, email)

    db = auth_env.sessions()
    try:
        before = credits_helpers.get_balance_summary(db, user_id)["balance"]
    finally:
        db.close()

    csrf = _get_csrf_from_page(auth_env, f"/reports/{rid}")
    resp = auth_env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert resp.status_code == 200

    db = auth_env.sessions()
    try:
        after = credits_helpers.get_balance_summary(db, user_id)["balance"]
        assert after == before - 2
    finally:
        db.close()


def test_pdf_export_idempotent(auth_env):
    """Re-exporting same report doesn't double-charge."""
    from app import credits as credits_helpers
    email, user_id = _signup_and_verify(auth_env)
    rid = _create_result(auth_env, user_id)
    _login(auth_env, email)
    csrf = _get_csrf_from_page(auth_env, f"/reports/{rid}")

    r1 = auth_env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert r1.status_code == 200

    db = auth_env.sessions()
    try:
        mid = credits_helpers.get_balance_summary(db, user_id)["balance"]
    finally:
        db.close()

    r2 = auth_env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert r2.status_code == 200

    db = auth_env.sessions()
    try:
        after = credits_helpers.get_balance_summary(db, user_id)["balance"]
        assert after == mid
    finally:
        db.close()


def test_pdf_export_insufficient_credits(auth_env):
    """PDF export with <2 credits returns 402."""
    email, user_id = _signup_and_verify(auth_env)
    rid = _create_result(auth_env, user_id)
    _login(auth_env, email)
    csrf = _get_csrf_from_page(auth_env, f"/reports/{rid}")
    # First export: 3 -> 1 credit
    r1 = auth_env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert r1.status_code == 200
    # Second report needs 2, only have 1
    rid2 = _create_result(auth_env, user_id, "second.log")
    r2 = auth_env.client.post(f"/reports/{rid2}/pdf", data={"csrf_token": csrf})
    assert r2.status_code == 402
    assert "Insufficient credits" in r2.json()["error"]


def test_pdf_export_requires_csrf(auth_env):
    """PDF export without CSRF returns 403."""
    email, user_id = _signup_and_verify(auth_env)
    rid = _create_result(auth_env, user_id)
    _login(auth_env, email)
    # Clear CSRF header and don't send token in form
    old = auth_env.client.headers.pop("X-CSRF-Token", None)
    try:
        resp = auth_env.client.post(f"/reports/{rid}/pdf", data={})
        assert resp.status_code == 403
    finally:
        if old:
            auth_env.client.headers["X-CSRF-Token"] = old


def test_reports_pagination(auth_env):
    """Reports list paginates at 20 per page."""
    email, user_id = _signup_and_verify(auth_env)
    for i in range(25):
        _create_result(auth_env, user_id, f"log{i}.log")
    _login(auth_env, email)
    r1 = auth_env.client.get("/reports?page=1")
    assert r1.status_code == 200
    assert "Page 1 of 2" in r1.text
    r2 = auth_env.client.get("/reports?page=2")
    assert r2.status_code == 200
    assert "Page 2 of 2" in r2.text


def test_pdf_generation_unit():
    """PDF generator produces valid PDF bytes."""
    from app.pdf_export import generate_report_pdf
    manifest = json.dumps({
        "filename": "test.log",
        "results": {"total_lines": 50},
        "health": {"label": "Healthy"},
        "findings": [{"message": "All good"}],
    })
    pdf_bytes = generate_report_pdf(manifest, "test.log")
    assert pdf_bytes[:4] == b"%PDF"
    assert len(pdf_bytes) > 1000
