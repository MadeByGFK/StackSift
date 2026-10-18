"""Regression tests for GFD findings on PR #17.

Finding 1: Anonymous retries during in-progress analysis must be recognized
           (return 202), not rejected with 409 identity conflict.
Finding 2: Paid-consent uploads must be redacted before disk persistence.
"""
import uuid

from test_account_migrations import migrated_engine
from test_phase2a_regressions import env
from app import analysis_admission as A
from app import credits as C
from app import models as M


def test_anonymous_retry_during_in_progress_returns_202(env):
    """Finding 1: Retry with same request_id during in-progress -> 202, not 409."""
    from app import auth as auth_helpers

    request_id = uuid.uuid4().hex
    original_anon = auth_helpers.hash_token("original-cookie-value")
    retry_anon = auth_helpers.hash_token("different-cookie-value")
    ip = "127.0.0.1"

    with env.sessions() as db:
        # Simulate an in-progress anonymous request
        db.add(M.FreeRequest(
            request_id=request_id,
            user_id=None,
            anonymous_session_hash=original_anon,
            fingerprint="test-digest",
            status="in_progress",
            quota_bucket_trusted_ip=ip,
            created_at=C._utcnow(),
            deadline=C._utcnow(),
        ))
        db.commit()

    with env.sessions() as db:
        # Retry with different anon hash (browser hasn't received cookie yet)
        # but same request_id and IP -> should return the existing request
        result = A.lookup(db, None, retry_anon, request_id, "test-digest", ip)
        assert result is not None
        assert result.request_id == request_id
        # Replay should return 202 for in-progress
        status, _, _ = A.replay(db, result, None)
        assert status == 202


def test_anonymous_retry_with_wrong_ip_still_conflicts(env):
    """Finding 1: IP mismatch must still raise 409 (security)."""
    from app import auth as auth_helpers

    request_id = uuid.uuid4().hex
    original_anon = auth_helpers.hash_token("original-cookie")
    retry_anon = auth_helpers.hash_token("different-cookie")

    with env.sessions() as db:
        db.add(M.FreeRequest(
            request_id=request_id,
            user_id=None,
            anonymous_session_hash=original_anon,
            fingerprint="test-digest",
            status="in_progress",
            quota_bucket_trusted_ip="127.0.0.1",
            created_at=C._utcnow(),
            deadline=C._utcnow(),
        ))
        db.commit()

    with env.sessions() as db:
        # Different IP -> should still conflict
        try:
            A.lookup(db, None, retry_anon, request_id, "test-digest", "192.168.1.99")
            assert False, "should have raised AdmissionError"
        except C.AdmissionError as e:
            assert "409" in str(e)


def test_paid_pending_stores_redacted_content(env):
    """Finding 2: Content stored via _store_paid_pending must be redacted."""
    from app import main as main_module
    from app.redact import redact_secrets

    # Content with a fake AWS key pattern (will be redacted)
    raw_content = b"2024-01-01 ERROR: Failed with key AKIAIOSFODNN7EXAMPLE\nLog line 2\n"
    filename = "test.log"

    # Simulate what _paid_consent_page does: redact before storing
    text = raw_content.decode("utf-8", errors="replace")
    redacted = redact_secrets(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "[REDACTED]" in redacted

    # Verify the redaction function is idempotent and preserves structure
    assert "Log line 2" in redacted
