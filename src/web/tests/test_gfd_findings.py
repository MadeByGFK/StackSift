"""Regression tests for GFD findings on PR #17.

Finding 1: Anonymous retries during in-progress analysis must be recognized
           (return 202), not rejected with 409. Requires matching fingerprint + IP.
Finding 2: Paid-consent uploads must be redacted before disk persistence.
           Fail closed on redaction error.
"""
import uuid

from test_account_migrations import migrated_engine
from test_phase2a_regressions import env
from app import analysis_admission as A
from app import credits as C
from app import models as M


def test_anonymous_retry_during_in_progress_returns_202(env):
    """Finding 1: Same request_id + IP + fingerprint during in-progress -> 202."""
    from app import auth as auth_helpers

    request_id = uuid.uuid4().hex
    original_anon = auth_helpers.hash_token("original-cookie-value")
    retry_anon = auth_helpers.hash_token("different-cookie-value")
    ip = "127.0.0.1"
    digest = "test-digest-123"

    with env.sessions() as db:
        db.add(M.FreeRequest(
            request_id=request_id,
            user_id=None,
            anonymous_session_hash=original_anon,
            fingerprint=digest,
            status="in_progress",
            quota_bucket_trusted_ip=ip,
            created_at=C._utcnow(),
            deadline=C._utcnow(),
        ))
        db.commit()

    with env.sessions() as db:
        result = A.lookup(db, None, retry_anon, request_id, digest, ip)
        assert result is not None
        assert result.request_id == request_id
        status, _, _ = A.replay(db, result, None)
        assert status == 202


def test_anonymous_retry_fingerprint_mismatch_conflicts(env):
    """Finding 1: Same ID + IP but DIFFERENT content -> 409."""
    from app import auth as auth_helpers

    request_id = uuid.uuid4().hex
    original_anon = auth_helpers.hash_token("original-cookie")
    retry_anon = auth_helpers.hash_token("different-cookie")
    ip = "127.0.0.1"

    with env.sessions() as db:
        db.add(M.FreeRequest(
            request_id=request_id,
            user_id=None,
            anonymous_session_hash=original_anon,
            fingerprint="original-digest",
            status="in_progress",
            quota_bucket_trusted_ip=ip,
            created_at=C._utcnow(),
            deadline=C._utcnow(),
        ))
        db.commit()

    with env.sessions() as db:
        try:
            A.lookup(db, None, retry_anon, request_id, "different-digest", ip)
            assert False, "should have raised AdmissionError"
        except C.AdmissionError as e:
            assert "409" in str(e)


def test_anonymous_retry_wrong_ip_conflicts(env):
    """Finding 1: IP mismatch must still raise 409."""
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
        try:
            A.lookup(db, None, retry_anon, request_id, "test-digest", "192.168.1.99")
            assert False, "should have raised AdmissionError"
        except C.AdmissionError as e:
            assert "409" in str(e)


def test_redact_secrets_removes_aws_keys():
    """Finding 2: redact_secrets must remove sensitive patterns."""
    from app.redact import redact_secrets

    raw = "2024-01-01 ERROR: key=AKIAIOSFODNN7EXAMPLE failed\nOK line\n"
    redacted = redact_secrets(raw)
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "[REDACTED]" in redacted
    assert "OK line" in redacted
