"""Issue #107: migration for ReportSharing + ReportAction (draft §8).

Upgrade creates both tables with their unique identities; downgrade to
the previous head (0012_batch_free_claim) removes exactly them; the
existing test_account_migrations upgrade test separately asserts
compare_metadata == [] at head, which pins model/migration parity.
"""

import uuid
from datetime import timedelta

import pytest
from alembic import command
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from test_account_migrations import migrated_engine  # noqa: F401  (fixture)
from app import credits as C, models as M


def _user_and_result(db):
    user = M.User(email=f"mig_{uuid.uuid4().hex[:8]}@example.com", email_verified=True)
    db.add(user)
    db.flush()
    now = C._utcnow()
    result = M.Result(
        user_id=user.id, free_request_id=uuid.uuid4().hex, type="analysis",
        storage_manifest="{}", integrity_digest="0" * 64, byte_count=2,
        ready_at=now, expires_at=now + timedelta(days=7))
    db.add(result)
    db.flush()
    return user, result


def test_report_access_tables_and_uniqueness(migrated_engine):
    engine, _ = migrated_engine
    names = set(inspect(engine).get_table_names())
    assert "report_sharing" in names and "report_actions" in names
    factory = sessionmaker(bind=engine)
    with factory() as db:
        user, result = _user_and_result(db)
        db.add(M.ReportSharing(result_id=result.id, owner_user_id=user.id,
                               token_hash="a" * 64, generation=1))
        db.commit()
        # One sharing row per report.
        db.add(M.ReportSharing(result_id=result.id, owner_user_id=user.id,
                               token_hash="b" * 64, generation=1))
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()
        # One active token hash globally.
        user2, result2 = _user_and_result(db)
        db.add(M.ReportSharing(result_id=result2.id, owner_user_id=user2.id,
                               token_hash="a" * 64, generation=1))
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()
        # Action identity is unique per (owner, result, kind, key).
        db.add(M.ReportAction(owner_user_id=user.id, result_id=result.id,
                              action_kind="share_rotate", idempotency_key="k1",
                              request_hash="c" * 64, generation=2))
        db.commit()
        db.add(M.ReportAction(owner_user_id=user.id, result_id=result.id,
                              action_kind="share_rotate", idempotency_key="k1",
                              request_hash="c" * 64, generation=3))
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()


def test_report_access_downgrade_and_reupgrade(migrated_engine):
    engine, config = migrated_engine
    with engine.begin() as conn:
        config.attributes["connection"] = conn
        command.downgrade(config, "0012_batch_free_claim")
        names = set(inspect(conn).get_table_names())
        assert "report_sharing" not in names and "report_actions" not in names
        assert "results" in names  # earlier tables untouched
        command.upgrade(config, "head")
        names = set(inspect(conn).get_table_names())
        assert "report_sharing" in names and "report_actions" in names
