"""Phase 2B tests: report history + PDF export."""

import json
import uuid
from datetime import datetime, timedelta, timezone


def _signup_and_verify(auth_env, email=None):
    """Create a verified user via the real email-verification flow.

    Redeems the actual verification token (captured by the fixture's
    mocked mailer) so the 3-credit signup reward is granted exactly as
    in production. Returns (email, user_id).
    """
    from app.models import User
    email = email or f"test_{uuid.uuid4().hex[:8]}@example.com"
    auth_env.client.post("/auth/signup", data={
        "email": email, "password": "TestPass123!x",
    })
    token = next(t for kind, addr, t in auth_env.sent if kind == "verify" and addr == email)
    resp = auth_env.client.post("/auth/verify", data={"token": token})
    assert resp.status_code == 200, f"verify failed: {resp.status_code} {resp.text[:200]}"
    db = auth_env.sessions()
    try:
        user = db.query(User).filter(User.email == email).one()
        assert user.email_verified
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
    """Create a Result row using the test DB session.

    Builds the manifest with the real analysis service so the stored
    schema matches production exactly (the report template requires the
    full schema: level_counts, sorted_issues, timeline, ...).
    """
    from app import models
    from app.service import analyze_upload
    import hashlib
    log_content = (
        b"2024-01-01 10:00:00 INFO app starting\n"
        b"2024-01-01 10:00:01 WARN deprecated config key used\n"
        b"2024-01-01 10:00:02 ERROR failed to connect to db: timeout\n"
        b"2024-01-01 10:00:03 ERROR failed to connect to db: timeout\n"
        b"2024-01-01 10:00:04 INFO retrying connection\n"
    )
    data = analyze_upload(filename, log_content)
    assert "error" not in data, f"fixture analysis failed: {data}"
    # Same serialization as credits.store_result (default=str for datetimes).
    manifest = json.dumps(data, default=str)
    now = datetime.now(timezone.utc)
    db = auth_env.sessions()
    try:
        result = models.Result(
            user_id=user_id,
            type="analysis",
            free_request_id=f"test-{uuid.uuid4().hex}",  # Satisfies ck_result_exactly_one_origin
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
            free_request_id=f"test-exp-{uuid.uuid4().hex}",
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
            free_request_id=f"test-pdf-{uuid.uuid4().hex}",
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


def test_pdf_export_concurrent_returns_409(auth_env):
    """Second export while first is in-progress returns 409, not a hijacked operation."""
    from app import models
    from datetime import datetime, timezone
    email, user_id = _signup_and_verify(auth_env)
    rid = _create_result(auth_env, user_id, "concurrent.log")
    _login(auth_env, email)
    # Manually create a reserved (in-progress) operation for the same export
    db = auth_env.sessions()
    try:
        op = models.Operation(
            user_id=user_id,
            type="pdf",
            status="reserved",
            idempotency_key=f"pdf-{rid}",
            request_hash="dummy",
            cost=2,
            worker_id="other-worker-123",
            lease_expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        )
        db.add(op)
        db.commit()
    finally:
        db.close()
    # Attempting the export should return 409, not proceed with our worker ID
    csrf = auth_env.client.get("/auth/csrf").json()["csrf_token"]
    auth_env.client.headers["X-CSRF-Token"] = csrf
    resp = auth_env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert resp.status_code == 409
    assert "already in progress" in resp.json()["error"].lower()


def test_pdf_replay_validates_integrity(auth_env):
    """Replaying a completed export validates the stored PDF result."""
    from app import models, credits as credits_helpers
    from datetime import datetime, timezone
    import base64 as b64
    email, user_id = _signup_and_verify(auth_env)
    rid = _create_result(auth_env, user_id, "replay.log")
    _login(auth_env, email)
    # Create a completed operation with a corrupted PDF result (bad digest)
    db = auth_env.sessions()
    try:
        # Create a PDF result with mismatched digest
        manifest = json.dumps({"pdf_base64": b64.b64encode(b"fake-pdf").decode(), "filename": "replay.log"})
        pdf_result = models.Result(
            user_id=user_id,
            type="pdf",
            free_request_id=f"test-pdf-corrupt-{uuid.uuid4().hex}",
            storage_manifest=manifest,
            integrity_digest="0" * 64,  # Wrong digest
            byte_count=len(manifest.encode()),
            ready_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        )
        db.add(pdf_result)
        db.flush()
        op = models.Operation(
            user_id=user_id,
            type="pdf",
            status="completed",
            idempotency_key=f"pdf-{rid}",
            request_hash="dummy",
            cost=2,
            worker_id="worker-123",
            lease_expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            result_id=pdf_result.id,
        )
        db.add(op)
        db.commit()
    finally:
        db.close()
    # The replay should fail validation and return 410 (not return corrupt data,
    # not attempt to reuse the completed operation's idempotency key)
    csrf = auth_env.client.get("/auth/csrf").json()["csrf_token"]
    auth_env.client.headers["X-CSRF-Token"] = csrf
    resp = auth_env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert resp.status_code == 410
    assert "no longer available" in resp.json()["error"].lower()


def test_pdf_export_retry_after_failure(auth_env):
    """Failed PDF export can be retried with a new operation identity."""
    from app import models
    from datetime import datetime, timezone
    email, user_id = _signup_and_verify(auth_env)
    rid = _create_result(auth_env, user_id, "retry.log")
    _login(auth_env, email)
    # Create a failed operation for the same export (simulating a prior failure)
    db = auth_env.sessions()
    try:
        failed_op = models.Operation(
            user_id=user_id,
            type="pdf",
            status="failed",
            idempotency_key=f"pdf-{rid}",
            request_hash="dummy-hash",
            cost=2,
            worker_id="failed-worker-123",
            lease_expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            failure_code="generation_failed",
        )
        db.add(failed_op)
        db.commit()
        failed_op_id = failed_op.id
    finally:
        db.close()
    # Retry should succeed with a NEW operation (not reuse the failed one)
    # User has 3 credits from signup, export costs 2
    csrf = auth_env.client.get("/auth/csrf").json()["csrf_token"]
    auth_env.client.headers["X-CSRF-Token"] = csrf
    resp = auth_env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    # Verify a new operation was created (not the failed one)
    db = auth_env.sessions()
    try:
        ops = db.query(models.Operation).filter(
            models.Operation.user_id == user_id,
            models.Operation.type == "pdf",
        ).all()
        # Should have 2 operations: the failed one and the new successful one
        assert len(ops) == 2
        new_ops = [op for op in ops if op.id != failed_op_id]
        assert len(new_ops) == 1
        assert new_ops[0].status == "completed"
        assert new_ops[0].idempotency_key != f"pdf-{rid}"  # New key for retry
        assert new_ops[0].idempotency_key.startswith(f"pdf-{rid}-retry-")
    finally:
        db.close()
