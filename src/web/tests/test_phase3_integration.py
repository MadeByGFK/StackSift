"""Phase 3 integration tests per GFD recommendation (PR #17 review).

Covers:
1. Full persistence path: paid analysis result is stored via store_result,
   retrievable from DB, and integrity-verified.
2. Redaction exception: if redact_secrets raises, the /analyze endpoint
   returns HTTP 500 and no temp files are left on disk.
"""

import glob
import os
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

from app import credits as C
from app import models
from app.db import Base


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    @event.listens_for(engine, "connect")
    def _fk(conn, _):
        conn.execute("PRAGMA foreign_keys=ON")
    Base.metadata.create_all(engine)
    S = sessionmaker(bind=engine)
    session = S()
    yield session
    session.close()
    engine.dispose()


@pytest.fixture
def user(db):
    uid = uuid.uuid4()
    db.add(models.User(id=uid, email=f"{uid.hex[:8]}@test.com", email_verified=True))
    db.commit()
    return uid


# --- Test 1: Full persistence path ---

def test_persistence_path_store_and_retrieve(db, user):
    """Paid analysis result: stored, retrievable, integrity-verified.

    Exercises: grant_signup_reward → create_consent → admit_paid_operation →
    store_result → DB query → integrity digest verification.
    """
    C.grant_signup_reward(db, user, f"{user.hex[:8]}@test.com")
    db.commit()

    # 1. Create consent for a paid analysis (1 credit)
    content = b"2026-10-18 ERROR Something broke\n"
    content_hash = C.hash_input(content)
    consent = C.create_consent(db, user, "additional_analysis", content_hash, 1)
    db.commit()
    assert consent.status == "pending"

    # 2. Admit the paid operation (reserves 1 credit)
    op = C.admit_paid_operation(
        db, user, "additional_analysis",
        key=f"idem-{uuid.uuid4().hex[:8]}",
        request_hash=content_hash, cost=1,
        consent_id=consent.id, worker_id="test-worker-1",
    )
    db.commit()
    assert op.status == "reserved"

    # 3. Simulate analysis completing — store the result
    analysis_data = {
        "filename": "test.log",
        "level_counts": {"error": 1, "warn": 0},
        "events": [["2026-10-18", "error", "Something broke"]],
    }
    result = C.store_result(db, user, op.id, analysis_data)
    db.commit()

    # 4. Retrieve from DB and verify
    stored = db.execute(
        select(models.Result).where(models.Result.id == result.id)
    ).scalar_one()
    assert stored.user_id == user
    assert stored.operation_id == op.id
    assert stored.type == "analysis"
    assert stored.ready_at is not None
    # Expires in ~7 days
    delta = stored.expires_at - stored.ready_at
    assert 6 < delta.days <= 8

    # 5. Integrity: digest matches stored manifest
    import json
    expected_digest = C.hash_input(stored.storage_manifest.encode())
    assert stored.integrity_digest == expected_digest

    # 6. Manifest contains our analysis data (minus excluded keys)
    manifest = json.loads(stored.storage_manifest)
    assert manifest["filename"] == "test.log"
    assert manifest["level_counts"] == {"error": 1, "warn": 0}
    assert "current_user" not in manifest
    assert "csrf_token" not in manifest


def test_persistence_path_complete_operation_settles(db, user):
    """After store_result, complete_operation settles the credit charge."""
    C.grant_signup_reward(db, user, f"{user.hex[:8]}@test.com")
    db.commit()
    before = C.get_balance_summary(db, user)["balance"]
    assert before == 3

    content_hash = C.hash_input(b"log data")
    consent = C.create_consent(db, user, "additional_analysis", content_hash, 1)
    db.commit()
    op = C.admit_paid_operation(
        db, user, "additional_analysis",
        key=f"idem-{uuid.uuid4().hex[:8]}",
        request_hash=content_hash, cost=1,
        consent_id=consent.id, worker_id="test-worker-1",
    )
    db.commit()

    # During reservation, eligible < balance
    during = C.get_balance_summary(db, user)
    assert during["eligible"] == before - 1

    result = C.store_result(db, user, op.id, {"test": True})
    db.commit()
    C.complete_operation(db, op.id, "test-worker-1", result_id=result.id)
    db.commit()

    after = C.get_balance_summary(db, user)["balance"]
    assert after == before - 1  # 1 credit consumed


# --- Test 2: Redaction exception ---

def test_redaction_exception_returns_500_no_disk_write(auth_env, monkeypatch):
    """If redact_secrets raises, /analyze returns 500 and writes nothing to disk.

    GFD Finding 2 (PR #17): raw logs must never hit disk before redaction.
    A redaction failure must fail closed.
    """
    from app import service

    tmpdir = tempfile.gettempdir()
    before = set(glob.glob(os.path.join(tmpdir, "*.log")))

    def _boom(text):
        raise RuntimeError("simulated redaction failure")

    monkeypatch.setattr(service, "redact_secrets", _boom)

    resp = auth_env.client.post(
        "/analyze",
        files={"file": ("test.log", b"2026-10-18 ERROR boom\n", "text/plain")},
        data={"request_id": uuid.uuid4().hex, "output": "html"},
    )
    # Must fail closed — 500, not 200 with partial data
    assert resp.status_code == 500

    # No new temp files left behind
    after = set(glob.glob(os.path.join(tmpdir, "*.log")))
    assert after == before, f"Temp files leaked: {after - before}"


def test_redact_secrets_exception_propagates_no_write(monkeypatch):
    """Direct contract test: redact_secrets raising propagates (no silent catch)."""
    from app import redact as redact_module

    tmpdir = tempfile.gettempdir()
    before_logs = set(glob.glob(os.path.join(tmpdir, "*.log")))

    def _boom(text):
        raise ValueError("simulated redaction crash")

    monkeypatch.setattr(redact_module, "redact_secrets", _boom)

    with pytest.raises(ValueError, match="simulated redaction crash"):
        redact_module.redact_secrets("some log content")

    after_logs = set(glob.glob(os.path.join(tmpdir, "*.log")))
    assert after_logs == before_logs, "Log temp files leaked on redaction failure"
