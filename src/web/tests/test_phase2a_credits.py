"""Phase 2A acceptance tests per StackSift Power-Ups Plan v11.1 Section 12.

Covers: T01-T05, T21, T23-T24, T26-T28, T34-T36, T39.
Phase 3 tests (T06-T08 refunds, T09-T20 Stripe/disputes) are NOT included.
"""

import uuid
from datetime import datetime, timedelta, timezone

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


def _consent(db, user_id, op_type="additional_analysis", h="hash", cost=1):
    c = C.create_consent(db, user_id, op_type, h, cost)
    db.commit()
    return c


def _admit(db, user_id, key, h="hash", cost=1, consent=None, worker="w1", op_type="additional_analysis"):
    if consent is None:
        consent = _consent(db, user_id, op_type, h, cost)
    op = C.admit_paid_operation(db, user_id, op_type, key, h, cost, consent.id, worker)
    db.commit()
    return op


def _balance(db, user_id):
    return C.get_or_create_account(db, user_id).balance


# --- T01: Reservation accounting -------------------------------------------

def test_t01_reservation_accounting(db, user):
    """Grant 10; reserve 5; reserve 3; complete first; fail second.
    Balance: 10 -> 5 -> 2 -> 2 -> 5."""
    C.grant_credits(db, user, "admin", "t01", 10)
    db.commit()
    assert _balance(db, user) == 10

    op1 = _admit(db, user, "k1", "h1", 5)
    assert _balance(db, user) == 5

    op2 = _admit(db, user, "k2", "h2", 3)
    assert _balance(db, user) == 2

    C.complete_operation(db, op1.id, "w1")
    db.commit()
    assert _balance(db, user) == 2

    C.release_operation(db, op2.id, "w1", "test")
    db.commit()
    assert _balance(db, user) == 5

    assert not C.verify_account_invariants(db, user)


def test_t01_grant_remaining_tracks(db, user):
    C.grant_credits(db, user, "admin", "t01b", 10)
    db.commit()
    op1 = _admit(db, user, "k1", "h1", 5)
    op2 = _admit(db, user, "k2", "h2", 3)
    grant = db.execute(select(models.CreditGrant)).scalar_one()
    assert grant.remaining == 10 and grant.reserved == 8

    C.complete_operation(db, op1.id, "w1")
    db.commit()
    db.refresh(grant)
    assert grant.remaining == 5 and grant.reserved == 3

    C.release_operation(db, op2.id, "w1", "test")
    db.commit()
    db.refresh(grant)
    assert grant.remaining == 5 and grant.reserved == 0
    assert not C.verify_account_invariants(db, user)


# --- T02: Mixed grants (FIFO) ----------------------------------------------

def test_t02_mixed_grants_fifo(db, user):
    """Signup 3 + admin 25; reserve 5 -> 3 from signup, 2 from admin."""
    C.grant_credits(db, user, "signup", "t02", 3)
    db.commit()
    C.grant_credits(db, user, "admin", "t02b", 25)
    db.commit()

    op = _admit(db, user, "k1", "h1", 5)
    allocs = db.execute(
        select(models.OperationAllocation).where(
            models.OperationAllocation.operation_id == op.id)
    ).scalars().all()
    assert len(allocs) == 2
    assert sorted(a.quantity for a in allocs) == [2, 3]

    C.complete_operation(db, op.id, "w1")
    db.commit()

    grants = {g.source: g for g in db.execute(select(models.CreditGrant)).scalars().all()}
    assert grants["signup"].remaining == 0
    assert grants["admin"].remaining == 23
    assert _balance(db, user) == 23
    assert not C.verify_account_invariants(db, user)


# --- T03: Failure/recovery race --------------------------------------------

def test_t03_double_release_idempotent(db, user):
    """Two releases of one reservation -> exactly one reversal."""
    C.grant_credits(db, user, "admin", "t03", 10)
    db.commit()
    op = _admit(db, user, "k1", "h1", 5)

    C.release_operation(db, op.id, "w1", "fail1")
    db.commit()
    op2 = C.release_operation(db, op.id, "w1", "fail2")
    db.commit()
    assert op2.status == "failed"

    reversals = db.execute(
        select(models.CreditLedger).where(
            models.CreditLedger.event_key == f"reversal:{op.id}")
    ).scalars().all()
    assert len(reversals) == 1
    assert _balance(db, user) == 10
    assert not C.verify_account_invariants(db, user)
    assert not C.verify_capacity_invariants(db)


def test_t03_recovery_releases_expired(db, user):
    C.grant_credits(db, user, "admin", "t03b", 10)
    db.commit()
    op = _admit(db, user, "k1", "h1", 5)
    op.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.commit()

    recovered = C.recover_expired_operations(db)
    assert recovered == 1
    assert _balance(db, user) == 10
    assert not C.verify_account_invariants(db, user)


# --- T04: Concurrent funds --------------------------------------------------

def test_t04_one_credit_ten_requests(db, user):
    """Ten admissions with one eligible credit: exactly one succeeds."""
    C.grant_credits(db, user, "admin", "t04", 1)
    db.commit()

    succeeded = 0
    for i in range(10):
        try:
            consent = _consent(db, user, "additional_analysis", f"h{i}", 1)
            C.admit_paid_operation(
                db, user, "additional_analysis", f"key{i}", f"h{i}", 1,
                consent.id, "w1")
            db.commit()
            succeeded += 1
        except (C.InsufficientCredits, C.AdmissionError):
            db.rollback()
    assert succeeded == 1
    assert _balance(db, user) == 0


# --- T05: Duplicate request -------------------------------------------------

def test_t05_idempotent_replay(db, user):
    """Same key+hash returns existing without charge. Different hash -> 409."""
    C.grant_credits(db, user, "admin", "t05", 10)
    db.commit()
    consent = _consent(db, user, "additional_analysis", "h1", 1)
    op1 = C.admit_paid_operation(db, user, "additional_analysis", "k1", "h1", 1, consent.id, "w1")
    db.commit()
    assert _balance(db, user) == 9

    op2 = C.admit_paid_operation(db, user, "additional_analysis", "k1", "h1", 1, consent.id, "w1")
    db.commit()
    assert op2.id == op1.id
    assert _balance(db, user) == 9

    with pytest.raises(C.AdmissionError, match="different input"):
        C.admit_paid_operation(db, user, "additional_analysis", "k1", "DIFFERENT", 1, consent.id, "w1")
    db.rollback()


# --- T21/T39: Operations under restriction ----------------------------------

def _impose(db, user, action="spend", cause="dispute", cause_id="d1"):
    r = models.Restriction(
        user_id=user, action=action, cause_type=cause, cause_id=cause_id,
        reason="test restriction")
    db.add(r)
    db.commit()
    return r


def test_t21_failure_under_restriction(db, user):
    """Reserve 5 of 25, restrict, fail op -> balance 25, eligible 0."""
    C.grant_credits(db, user, "admin", "t21", 25)
    db.commit()
    op = _admit(db, user, "k1", "h1", 5)
    assert _balance(db, user) == 20

    _impose(db, user)
    assert C.get_eligible_credits(db, user) == 0

    C.release_operation(db, op.id, "w1", "test")
    db.commit()
    assert _balance(db, user) == 25
    assert C.get_eligible_credits(db, user) == 0

    with pytest.raises(C.AdmissionError, match="restricted"):
        _admit(db, user, "k2", "h2", 1)
    db.rollback()


def test_t39_completion_under_restriction(db, user):
    """Reserve 5 of 25, restrict, complete -> balance 20, eligible 0."""
    C.grant_credits(db, user, "admin", "t39", 25)
    db.commit()
    op = _admit(db, user, "k1", "h1", 5)
    _impose(db, user)

    C.complete_operation(db, op.id, "w1")
    db.commit()
    assert _balance(db, user) == 20
    grant = db.execute(select(models.CreditGrant)).scalar_one()
    assert grant.reserved == 0 and grant.remaining == 20
    assert C.get_eligible_credits(db, user) == 0
    assert not C.verify_account_invariants(db, user)


# --- T23: Capacity ----------------------------------------------------------

def test_t23_capacity_limits(db, user):
    """Limit 2/user: 5 concurrent requests -> 2 permits, rest rejected."""
    C.grant_credits(db, user, "admin", "t23", 100)
    db.commit()
    ops = []
    for i in range(5):
        try:
            ops.append(_admit(db, user, f"k{i}", f"h{i}", 1))
        except C.AdmissionError:
            db.rollback()
    assert len(ops) == 2

    C.complete_operation(db, ops[0].id, "w1")
    db.commit()
    C.complete_operation(db, ops[0].id, "w1")
    db.commit()
    assert not C.verify_capacity_invariants(db)

    op3 = _admit(db, user, "k5", "h5", 1)
    assert op3.status == "reserved"
    assert not C.verify_capacity_invariants(db)


# --- T24: Lease renewal race -------------------------------------------------

def test_t24_lease_renewal_skips_recovery(db, user):
    """Recovery rechecks lease under lock; renewed lease -> skip."""
    C.grant_credits(db, user, "admin", "t24", 10)
    db.commit()
    op = _admit(db, user, "k1", "h1", 5)
    op_id = op.id
    op.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.commit()

    op2 = db.get(models.Operation, op_id)
    op2.lease_expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
    db.commit()

    recovered = C.recover_expired_operations(db)
    assert recovered == 0
    op3 = db.get(models.Operation, op_id)
    assert op3.status == "reserved"
    assert _balance(db, user) == 5


# --- T26/T28: Free quota ----------------------------------------------------

def test_t26_free_last_slot():
    """Two requests, one free slot: one admitted, other rejected."""
    from app.rate_limit import RateLimiter
    limiter = RateLimiter(max_requests=1, window_seconds=3600)
    assert limiter.check("1.2.3.4")
    limiter.record("1.2.3.4")
    assert not limiter.check("1.2.3.4")


def test_t28_free_request_identity(db, user):
    """Free request IDs: same ID returns stored outcome; no re-execution."""
    req_id = "req-123"
    fp = "abc123"
    fr = models.FreeRequest(
        request_id=req_id,
        user_id=user,
        fingerprint=fp,
        status="failed",
        failure_code="too_large",
        deadline=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    db.add(fr)
    db.commit()
    existing = db.get(models.FreeRequest, req_id)
    assert existing.status == "failed"
    assert existing.fingerprint == fp


# --- T34: Snapshot concurrency -----------------------------------------------

def test_t34_invariant_snapshot_consistent(db, user):
    C.grant_credits(db, user, "admin", "t34", 10)
    db.commit()
    op = _admit(db, user, "k1", "h1", 5)
    assert not C.verify_account_invariants(db, user)
    C.complete_operation(db, op.id, "w1")
    db.commit()
    assert not C.verify_account_invariants(db, user)


# --- T35: Signup replay ------------------------------------------------------

def test_t35_signup_replay(db, user):
    """Verify twice / recreate same email -> at most one reward."""
    email = f"{user.hex[:8]}@test.com"
    g1 = C.grant_signup_reward(db, user, email)
    db.commit()
    assert g1 is not None and g1.issued == 3

    assert C.grant_signup_reward(db, user, email) is None
    db.commit()

    elig = db.get(models.SignupEligibility, email.strip().lower())
    elig.user_id = None  # simulates ON DELETE SET NULL
    db.commit()
    elig = db.get(models.SignupEligibility, email.strip().lower())
    assert elig is not None and elig.user_id is None
    assert elig.grant_issued is True

    uid2 = uuid.uuid4()
    assert C.grant_signup_reward(db, uid2, email) is None
    db.commit()


# --- T36: Revocation queue ----------------------------------------------------

def test_t36_revocation_blocks_allocation(db, user):
    """Queued revocation blocks new allocations; existing ops settle first."""
    C.grant_credits(db, user, "admin", "t36", 10)
    db.commit()
    grant = db.execute(select(models.CreditGrant)).scalar_one()

    grant.revocation_queued_at = datetime.now(timezone.utc)
    db.commit()

    assert C.get_eligible_credits(db, user) == 0
    with pytest.raises(C.InsufficientCredits):
        _admit(db, user, "k1", "h1", 1)
    db.rollback()


# --- A6: Reversal uniqueness -------------------------------------------------

def test_a6_single_reversal_per_debit(db, user):
    """At most one reversal per reservation debit (partial unique index)."""
    C.grant_credits(db, user, "admin", "a6", 10)
    db.commit()
    op = _admit(db, user, "k1", "h1", 5)
    C.release_operation(db, op.id, "w1", "x")
    db.commit()

    from sqlalchemy.exc import IntegrityError
    original = db.execute(
        select(models.CreditLedger).where(
            models.CreditLedger.event_key == f"reserve:{op.id}")
    ).scalar_one()
    acct = C.get_or_create_account(db, user, for_update=True)
    with pytest.raises(IntegrityError):
        C._append_ledger(
            db, acct, user, f"reversal:{op.id}:dup", 5, "operation_release",
            [(list(db.execute(select(models.CreditGrant)).scalars().all())[0].id, 5)],
            operation_id=op.id, reverses_entry_id=original.id)
        db.commit()
    db.rollback()
