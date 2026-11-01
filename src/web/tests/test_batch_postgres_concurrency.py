"""Issue #103 (trim B2): PostgreSQL concurrency proof for the batch
free-allowance claim.

SQLite legs cannot prove this: the claim's safety comes from row locks
(global capacity scope first, then the per-IP RateLimitBucket and
FreeBucket rows) inside the same transaction as the credit
reservation. These tests follow the test_shared_rate_limit.py pattern:
a unique schema migrated to Alembic head per test, NullPool factories
so every thread uses its own connection, and barrier-synchronized
threads racing for the tenth free allowance.

Requires TEST_POSTGRES_URL (provided by CI); skips locally without it.
"""

import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from threading import Barrier

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from app import analysis_admission as A, batch_admission as BA, credits as C, models as M

pytestmark = pytest.mark.skipif(
    not os.environ.get("TEST_POSTGRES_URL"),
    reason="TEST_POSTGRES_URL is required for batch PG concurrency tests",
)

IP = "203.0.113.99"


@pytest.fixture
def pg_factory():
    url = os.environ["TEST_POSTGRES_URL"]
    schema = "batch_test_" + uuid.uuid4().hex
    admin = create_engine(url, poolclass=NullPool)
    with admin.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_engine(
        url, connect_args={"options": f"-csearch_path={schema}"}, poolclass=NullPool)
    config = Config()
    config.set_main_option("script_location", str(Path(__file__).parents[1] / "alembic"))
    try:
        with engine.begin() as conn:
            config.attributes["connection"] = conn
            command.upgrade(config, "head")
        yield sessionmaker(bind=engine, autoflush=False), engine
    finally:
        engine.dispose()
        with admin.begin() as conn:
            conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


def _make_user(factory, *, credits=5):
    with factory() as db:
        user = M.User(email=f"pg_{uuid.uuid4().hex[:8]}@example.com",
                      email_verified=True)
        db.add(user)
        db.flush()
        uid = user.id
        C.grant_credits(db, uid, "purchase", f"pg-pack-{uuid.uuid4().hex}", credits)
        db.commit()
        return uid


def _make_consent(factory, uid, total):
    with factory() as db:
        consent = C.create_consent(db, uid, "batch", "h" * 64, total)
        db.commit()
        return consent.id


def _seed_free(factory, n, *, minutes_ago=2):
    with factory() as db:
        for _ in range(n):
            db.add(M.FreeRequest(
                request_id=uuid.uuid4().hex, fingerprint="old", status="failed",
                anonymous_session_hash="a" * 64,
                quota_bucket_trusted_ip=IP,
                created_at=C._utcnow() - timedelta(minutes=minutes_ago),
                deadline=C._utcnow()))
        db.commit()


def _seed_hits(factory, n, *, minutes_ago=2):
    with factory() as db:
        for _ in range(n):
            db.add(M.RateLimitHit(
                trusted_ip=IP, hit_at=C._utcnow() - timedelta(minutes=minutes_ago)))
        db.commit()


def test_two_batches_race_for_tenth_allowance_exactly_one_claims(pg_factory):
    factory, _engine = pg_factory
    _seed_free(factory, 9)
    _seed_hits(factory, 9)
    uid_a, uid_b = _make_user(factory), _make_user(factory)
    consent_a = _make_consent(factory, uid_a, 1)
    consent_b = _make_consent(factory, uid_b, 1)
    barrier = Barrier(2)

    def attempt(uid, consent_id, key):
        with factory() as db:
            barrier.wait(timeout=30)
            try:
                op = BA.admit_batch_operation(
                    db, uid, key, "h" * 64, consent_id, f"w-{key}", IP, 2)
                db.commit()
                return ("admitted", op.free_allowance_claim, op.cost)
            except BA.RequoteRequired as rq:
                db.rollback()
                return ("requote", rq.new_total, None)

    with ThreadPoolExecutor(2) as executor:
        results = list(executor.map(
            lambda args: attempt(*args),
            [(uid_a, consent_a, "race-a"), (uid_b, consent_b, "race-b")]))
    admitted = [r for r in results if r[0] == "admitted"]
    requoted = [r for r in results if r[0] == "requote"]
    assert len(admitted) == 1 and admitted[0][1] is True and admitted[0][2] == 1
    assert len(requoted) == 1 and requoted[0][1] == 2
    with factory() as db:
        # Exactly one claim and one shared-system hit were added: the
        # allowance total is exactly 10 in BOTH systems, never 11.
        assert BA.durable_hourly_used(db, IP) == 10
        assert BA.shared_hourly_used(db, IP) == 10
        assert db.query(M.Operation).filter(
            M.Operation.type == "batch",
            M.Operation.free_allowance_claim.is_(True)).count() == 1


def test_batch_and_single_race_for_tenth_allowance(pg_factory):
    factory, _engine = pg_factory
    _seed_free(factory, 9)
    _seed_hits(factory, 9)
    uid_batch = _make_user(factory)
    uid_single = _make_user(factory)
    consent_id = _make_consent(factory, uid_batch, 1)
    barrier = Barrier(2)

    def batch_attempt():
        with factory() as db:
            barrier.wait(timeout=30)
            try:
                op = BA.admit_batch_operation(
                    db, uid_batch, "race-batch", "h" * 64, consent_id,
                    "w-batch", IP, 2)
                db.commit()
                return ("batch", op.free_allowance_claim)
            except BA.RequoteRequired:
                db.rollback()
                return ("batch", False)

    def single_attempt():
        with factory() as db:
            barrier.wait(timeout=30)
            item, created = A.admit(db, uid_single, None, "race-single",
                                    "d" * 64, IP, "w-single")
            if item is None:
                db.rollback()
                return ("single", False)  # paid offer: no free claim
            db.commit()
            return ("single", created)

    with ThreadPoolExecutor(2) as executor:
        futures = [executor.submit(batch_attempt), executor.submit(single_attempt)]
        results = dict(f.result() for f in futures)
    # Exactly one side claimed the tenth allowance.
    assert results["batch"] != results["single"]
    with factory() as db:
        assert BA.durable_hourly_used(db, IP) == 10
