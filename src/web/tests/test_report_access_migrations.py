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
                               token_hash="a" * 64, generation=1,
                               share_format="txt"))
        db.commit()
        # PREMISE CHANGED (issue #135): sharing is one row per
        # (report, format), not one per report — a second row for a
        # DIFFERENT format is legal...
        db.add(M.ReportSharing(result_id=result.id, owner_user_id=user.id,
                               token_hash="b" * 64, generation=1,
                               share_format="pdf"))
        db.commit()
        # ...but a second row for the SAME (report, format) is not.
        db.add(M.ReportSharing(result_id=result.id, owner_user_id=user.id,
                               token_hash="d" * 64, generation=1,
                               share_format="txt"))
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


def test_sharing_rework_downgrade_with_multi_format_rows(migrated_engine):
    """PR #138 remediation (finding 5): downgrading 0014 while
    per-format rows exist must consolidate to one row per report
    BEFORE the unique index on result_id is restored — the old
    downgrade failed outright on SQLite and PostgreSQL.

    Policy (documented in the migration): keep the earliest-created
    ACTIVE row per report (non-revoked, with a token), tie-break by
    created_at then id; delete the rest."""
    from datetime import datetime, timezone
    from sqlalchemy import text as _text

    engine, config = migrated_engine
    factory = sessionmaker(bind=engine)
    base = datetime(2026, 11, 1, tzinfo=timezone.utc)
    with factory() as db:
        user, result = _user_and_result(db)
        other_user, other_result = _user_and_result(db)
        # Earliest row overall is REVOKED (no token) — not kept.
        db.add(M.ReportSharing(
            result_id=result.id, owner_user_id=user.id,
            token_hash=None, generation=2, share_format="txt",
            revoked_at=base, created_at=base))
        # Earliest ACTIVE row — this one must survive.
        kept = M.ReportSharing(
            result_id=result.id, owner_user_id=user.id,
            token_hash="b" * 64, generation=1, share_format="pdf",
            raw_token="b" * 64, created_at=base + timedelta(hours=1))
        db.add(kept)
        # Later active row for another format — deleted by downgrade.
        db.add(M.ReportSharing(
            result_id=result.id, owner_user_id=user.id,
            token_hash="c" * 64, generation=1, share_format="csv",
            raw_token="c" * 64, created_at=base + timedelta(hours=2)))
        # A different report's single row is untouched.
        solo = M.ReportSharing(
            result_id=other_result.id, owner_user_id=other_user.id,
            token_hash="d" * 64, generation=1, share_format="txt",
            raw_token="d" * 64, created_at=base)
        db.add(solo)
        db.commit()
        kept_id, solo_id = str(kept.id), str(solo.id)

    with engine.begin() as conn:
        config.attributes["connection"] = conn
        command.downgrade(config, "0013_report_access")
        rows = conn.execute(_text(
            "SELECT id FROM report_sharing ORDER BY created_at")).fetchall()
        ids = {str(r[0]) for r in rows}
        assert ids == {kept_id, solo_id}, (
            f"downgrade kept {ids}, expected earliest-active {kept_id} "
            f"plus the other report's {solo_id}")
        # The restored index on result_id is unique again.
        indexes = inspect(conn).get_indexes("report_sharing")
        result_idx = [i for i in indexes
                      if i["column_names"] == ["result_id"]]
        assert result_idx and result_idx[0]["unique"]
        # Re-upgrade restores the per-format schema cleanly.
        command.upgrade(config, "head")
        cols = {c["name"] for c in inspect(conn).get_columns("report_sharing")}
        assert "share_format" in cols and "raw_token" in cols
