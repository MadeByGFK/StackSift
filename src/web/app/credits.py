"""Phase 2A: Power-Up credit accounting and admission.

Implements the v11.1 transition contracts:
  GRANT / RESERVE / COMPLETE / RELEASE / ADMIN_REVOKE

Invariants enforced (v11.1 Section 2.1):
  A1: SUM(ledger.delta) == balance == SUM(grant.remaining - grant.reserved)
  A2: 0 <= reserved <= remaining <= issued per grant
  A3: SUM(active allocations) per grant == grant.reserved
  A4: Reserved operation allocations total exactly its cost
  A5: Settle once (complete) or release once (failure)
  A6: Unique event keys; at most one reversal per debit; ledger append-only

Global lock order (v11.1 Section 4.1):
  capacity_scopes -> credit_accounts -> credit_grants ->
  operations -> operation_allocations -> permits/permit_scopes ->
  consents -> restrictions -> signup_eligibility

Phase 3 (Stripe/purchases/refunds) is NOT implemented here.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import models


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_aware(dt: datetime | None) -> datetime | None:
    """Ensure timezone-aware datetime (SQLite returns naive)."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


# ---------------------------------------------------------------------------
# Configuration (v11.1 Section 6: unvalidated proposals, config not hardcoded)
# ---------------------------------------------------------------------------

# Pricing version 1 (approved 2026-10-15)
PRICING_VERSION = 1
COST_ADDITIONAL_ANALYSIS = 1  # CONFIRMED
COST_PDF = 2  # Proposed (Phase 2B)
COST_BATCH = 5  # Proposed (gated)

# Signup reward (approved 2026-10-15)
SIGNUP_REWARD_CREDITS = 3

# Capacity limits (v11.1 Section 6: UNVALIDATED PROPOSALS - benchmarks required)
DEFAULT_USER_CONCURRENT_LIMIT = 2
DEFAULT_GLOBAL_CONCURRENT_LIMIT = 20

# Paid rate limits per hour (proposed)
RATE_LIMIT_PAID_ANALYSIS = 30
RATE_LIMIT_PDF = 10
RATE_LIMIT_BATCH = 5

# Consent validity
CONSENT_TTL = timedelta(minutes=15)

# Operation lease
LEASE_TTL = timedelta(minutes=5)


# ---------------------------------------------------------------------------
# Account helpers
# ---------------------------------------------------------------------------

def get_or_create_account(db: Session, user_id: uuid.UUID, for_update: bool = False) -> models.CreditAccount:
    """Get or create the credit account row. Optionally lock it."""
    q = select(models.CreditAccount).where(models.CreditAccount.user_id == user_id)
    if for_update:
        q = q.with_for_update()
    account = db.execute(q).scalar_one_or_none()
    if account is None:
        account = models.CreditAccount(user_id=user_id, balance=0, ledger_sequence=0)
        db.add(account)
        db.flush()
    return account


def _next_sequence(db: Session, account: models.CreditAccount) -> int:
    """Increment and return the next ledger sequence. Caller must hold account lock."""
    account.ledger_sequence += 1
    db.flush()
    return account.ledger_sequence


def _append_ledger(
    db: Session,
    account: models.CreditAccount,
    user_id: uuid.UUID,
    event_key: str,
    delta: int,
    reason: str,
    grant_splits: list[tuple[uuid.UUID, int]],
    operation_id: uuid.UUID | None = None,
    adjustment_id: uuid.UUID | None = None,
    reverses_entry_id: uuid.UUID | None = None,
) -> models.CreditLedger:
    """Append a ledger entry with grant attribution. Updates account balance.

    Caller must hold the account row lock. This is the ONLY function that
    writes to credit_ledger (append-only enforcement point).
    """
    assert delta != 0, "zero-delta ledger entries prohibited"
    assert sum(s for _, s in grant_splits) == delta, "grant splits must sum to delta"

    seq = _next_sequence(db, account)
    new_balance = account.balance + delta
    assert new_balance >= 0, "balance would go negative"

    entry = models.CreditLedger(
        user_id=user_id,
        account_sequence=seq,
        event_key=event_key,
        delta=delta,
        balance_after=new_balance,
        reason=reason,
        operation_id=operation_id,
        adjustment_id=adjustment_id,
        reverses_entry_id=reverses_entry_id,
    )
    db.add(entry)
    db.flush()

    for grant_id, signed_delta in grant_splits:
        assert signed_delta != 0
        db.add(models.LedgerGrant(
            ledger_entry_id=entry.id,
            grant_id=grant_id,
            signed_delta=signed_delta,
        ))

    account.balance = new_balance
    db.flush()
    return entry


# ---------------------------------------------------------------------------
# GRANT transition
# ---------------------------------------------------------------------------

def grant_credits(
    db: Session,
    user_id: uuid.UUID,
    source: str,
    source_key: str,
    quantity: int,
) -> models.CreditGrant:
    """GRANT N: create a new grant and credit the account."""
    assert quantity > 0
    account = get_or_create_account(db, user_id, for_update=True)

    grant = models.CreditGrant(
        user_id=user_id,
        source=source,
        source_key=source_key,
        issued=quantity,
        remaining=quantity,
        reserved=0,
    )
    db.add(grant)
    db.flush()

    _append_ledger(
        db, account, user_id,
        event_key=f"grant:{grant.id}",
        delta=quantity,
        reason="grant",
        grant_splits=[(grant.id, quantity)],
    )
    return grant


def grant_signup_reward(db: Session, user_id: uuid.UUID, email: str) -> models.CreditGrant | None:
    """Grant the approved 3-credit signup reward. Idempotent per email."""
    normalized = email.strip().lower()
    elig = db.get(models.SignupEligibility, normalized)
    if elig is None:
        elig = models.SignupEligibility(
            email_normalized=normalized,
            user_id=user_id,
            grant_issued=False,
        )
        db.add(elig)
        db.flush()
    db.refresh(elig, with_for_update=True)
    if elig.grant_issued:
        return None

    grant = grant_credits(db, user_id, "signup", normalized, SIGNUP_REWARD_CREDITS)
    elig.grant_issued = True
    elig.granted_at = _utcnow()
    elig.issued_grant_id = grant.id
    elig.user_id = user_id
    db.flush()
    return grant


# ---------------------------------------------------------------------------
# Restriction checks
# ---------------------------------------------------------------------------

def has_active_restriction(db: Session, user_id: uuid.UUID, action: str) -> bool:
    """Check for any active (non-lifted) restriction on the given action."""
    q = select(func.count()).select_from(models.Restriction).where(
        models.Restriction.user_id == user_id,
        models.Restriction.action == action,
        models.Restriction.lifted_at.is_(None),
    )
    return db.execute(q).scalar() > 0


def get_eligible_credits(db: Session, user_id: uuid.UUID) -> int:
    """Eligible credits for new operations.

    Sums available from grants not revoked/queued, zero if spend-restricted.
    available = remaining - reserved - held (held=0 in Phase 2A, no refunds).
    """
    if has_active_restriction(db, user_id, "spend"):
        return 0
    q = select(
        func.coalesce(func.sum(models.CreditGrant.remaining - models.CreditGrant.reserved), 0)
    ).where(
        models.CreditGrant.user_id == user_id,
        models.CreditGrant.revoked_at.is_(None),
        models.CreditGrant.revocation_queued_at.is_(None),
    )
    return db.execute(q).scalar() or 0


# ---------------------------------------------------------------------------
# RESERVE (part of atomic admission)
# ---------------------------------------------------------------------------

def _allocate_fifo(
    db: Session,
    user_id: uuid.UUID,
    cost: int,
) -> list[tuple[models.CreditGrant, int]]:
    """Allocate `cost` credits from eligible grants, oldest first."""
    grants = db.execute(
        select(models.CreditGrant)
        .where(
            models.CreditGrant.user_id == user_id,
            models.CreditGrant.revoked_at.is_(None),
            models.CreditGrant.revocation_queued_at.is_(None),
        )
        .order_by(models.CreditGrant.created_at, models.CreditGrant.id)
        .with_for_update()
    ).scalars().all()

    allocations: list[tuple[models.CreditGrant, int]] = []
    remaining_cost = cost
    for grant in grants:
        if remaining_cost <= 0:
            break
        available = grant.remaining - grant.reserved
        if available <= 0:
            continue
        take = min(available, remaining_cost)
        allocations.append((grant, take))
        remaining_cost -= take

    if remaining_cost > 0:
        raise InsufficientCredits(f"need {cost}, short {remaining_cost}")
    return allocations


class InsufficientCredits(Exception):
    pass


class AdmissionError(Exception):
    pass


# ---------------------------------------------------------------------------
# Consent
# ---------------------------------------------------------------------------

def create_consent(
    db: Session,
    user_id: uuid.UUID,
    operation_type: str,
    input_hash: str,
    max_cost: int,
) -> models.Consent:
    """Create a server-bound consent for a paid operation."""
    consent = models.Consent(
        user_id=user_id,
        operation_type=operation_type,
        input_hash=input_hash,
        max_cost=max_cost,
        pricing_version=PRICING_VERSION,
        expires_at=_utcnow() + CONSENT_TTL,
    )
    db.add(consent)
    db.flush()
    return consent


def validate_consent(
    db: Session,
    consent_id: uuid.UUID,
    user_id: uuid.UUID,
    operation_type: str,
    input_hash: str,
    cost: int,
) -> models.Consent:
    """Validate a consent is usable for this operation. Raises AdmissionError."""
    consent = db.get(models.Consent, consent_id)
    if consent is None:
        raise AdmissionError("consent not found")
    if consent.user_id != user_id:
        raise AdmissionError("consent owner mismatch")
    if consent.operation_type != operation_type:
        raise AdmissionError("consent type mismatch")
    if consent.input_hash != input_hash:
        raise AdmissionError("consent input mismatch")
    if consent.max_cost < cost:
        raise AdmissionError("consent max cost exceeded")
    if consent.pricing_version != PRICING_VERSION:
        raise AdmissionError("consent pricing version stale")
    if _as_aware(consent.expires_at) < _utcnow():
        raise AdmissionError("consent expired")
    if consent.consumed_by_operation_id is not None:
        raise AdmissionError("consent already consumed")
    return consent


# ---------------------------------------------------------------------------
# Capacity (permits)
# ---------------------------------------------------------------------------

def _ensure_capacity_scope(db: Session, scope_key: str, limit: int) -> models.CapacityScope:
    """Get or create a capacity scope row, locked FOR UPDATE.

    Uses upsert-then-lock: INSERT ... ON CONFLICT DO NOTHING, then
    SELECT FOR UPDATE on the stable row (v11.1 Section 3.4).
    """
    from sqlalchemy.dialects.sqlite import insert as sqlite_insert
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    if db.bind.dialect.name == "postgresql":
        stmt = pg_insert(models.CapacityScope).values(
            scope_key=scope_key, used=0, max_limit=limit,
        ).on_conflict_do_nothing(index_elements=["scope_key"])
    else:
        stmt = sqlite_insert(models.CapacityScope).values(
            scope_key=scope_key, used=0, max_limit=limit,
        ).on_conflict_do_nothing(index_elements=["scope_key"])
    db.execute(stmt)
    db.flush()
    scope = db.execute(
        select(models.CapacityScope).where(models.CapacityScope.scope_key == scope_key)
        .with_for_update()
    ).scalar_one()
    return scope


def _acquire_capacity(db: Session, user_id: uuid.UUID) -> list[str]:
    """Acquire one unit of user + global paid-operation capacity.

    Returns the scope keys acquired. Raises AdmissionError if at limit.
    Lock order: lexicographic scope-key order (v11.1 Section 4.1).
    """
    user_scope = f"user:{user_id}:paid"
    global_scope = "global:paid"
    scopes = sorted([global_scope, user_scope])

    acquired = []
    for scope_key in scopes:
        limit = DEFAULT_GLOBAL_CONCURRENT_LIMIT if scope_key == global_scope else DEFAULT_USER_CONCURRENT_LIMIT
        scope = _ensure_capacity_scope(db, scope_key, limit)
        if scope.used >= scope.max_limit:
            raise AdmissionError(f"capacity exhausted: {scope_key}")
        scope.used += 1
        acquired.append(scope_key)
    db.flush()
    return acquired


def _release_capacity(db: Session, permit: models.Permit, user_id: uuid.UUID) -> None:
    """Release a permit's capacity. Only decrements if actually transitioned (A10)."""
    result = db.execute(
        select(models.Permit).where(
            models.Permit.id == permit.id,
            models.Permit.released_at.is_(None),
        ).with_for_update()
    ).scalar_one_or_none()
    if result is None:
        return

    result.released_at = _utcnow()
    memberships = db.execute(
        select(models.PermitScope).where(models.PermitScope.permit_id == permit.id)
    ).scalars().all()
    for ms in sorted(memberships, key=lambda m: m.scope_key):
        scope = db.execute(
            select(models.CapacityScope).where(models.CapacityScope.scope_key == ms.scope_key)
            .with_for_update()
        ).scalar_one()
        scope.used = max(0, scope.used - ms.quantity)
    db.flush()


# ---------------------------------------------------------------------------
# Atomic paid admission (v11.1 Section 4.2)
# ---------------------------------------------------------------------------

def admit_paid_operation(
    db: Session,
    user_id: uuid.UUID,
    operation_type: str,
    idempotency_key: str,
    request_hash: str,
    cost: int,
    consent_id: uuid.UUID,
    worker_id: str,
    input_manifest: str | None = None,
) -> models.Operation:
    """Atomically admit a paid operation.

    In one transaction (global lock order):
      1. Capacity acquisition (permits)
      2. Restriction check
      3. Consent validation
      4. Eligible grant allocation (FIFO)
      5. Operation + permit creation
      6. Ledger debit (-cost)
      7. Rate consumption

    Idempotent: matching key+hash returns existing operation without new charge.
    """
    existing = db.execute(
        select(models.Operation).where(
            models.Operation.user_id == user_id,
            models.Operation.type == operation_type,
            models.Operation.idempotency_key == idempotency_key,
        )
    ).scalar_one_or_none()
    if existing is not None:
        if existing.request_hash != request_hash:
            raise AdmissionError("idempotency key reused with different input (409)")
        return existing

    acquired_scopes = _acquire_capacity(db, user_id)

    try:
        if has_active_restriction(db, user_id, "spend"):
            raise AdmissionError("account spending restricted")

        consent = validate_consent(db, consent_id, user_id, operation_type, request_hash, cost)

        account = get_or_create_account(db, user_id, for_update=True)
        allocations = _allocate_fifo(db, user_id, cost)
        assert sum(q for _, q in allocations) == cost, "incomplete allocation"

        now = _utcnow()
        operation = models.Operation(
            user_id=user_id,
            type=operation_type,
            idempotency_key=idempotency_key,
            request_hash=request_hash,
            input_manifest=input_manifest,
            cost=cost,
            pricing_version=PRICING_VERSION,
            consent_id=consent.id,
            status="reserved",
            worker_id=worker_id,
            lease_generation=1,
            lease_expires_at=now + LEASE_TTL,
        )
        db.add(operation)
        db.flush()

        consent.consumed_by_operation_id = operation.id

        for grant, qty in allocations:
            grant.reserved += qty
            db.add(models.OperationAllocation(
                operation_id=operation.id,
                grant_id=grant.id,
                quantity=qty,
                state="reserved",
            ))
        db.flush()

        permit = models.Permit(
            operation_id=operation.id,
            worker_id=worker_id,
            lease_generation=1,
            heartbeat_at=now,
            expires_at=now + LEASE_TTL,
        )
        db.add(permit)
        db.flush()
        for scope_key in acquired_scopes:
            db.add(models.PermitScope(permit_id=permit.id, scope_key=scope_key, quantity=1))
        db.flush()

        grant_splits = [(grant.id, -qty) for grant, qty in allocations]
        _append_ledger(
            db, account, user_id,
            event_key=f"reserve:{operation.id}",
            delta=-cost,
            reason="reserve",
            grant_splits=grant_splits,
            operation_id=operation.id,
        )

        _consume_rate(db, f"paid:{operation_type}", str(user_id))

        db.flush()
        return operation

    except Exception:
        raise


def _consume_rate(db: Session, policy: str, owner: str) -> None:
    """Atomically consume one unit from a rate bucket. Raises AdmissionError if over limit."""
    limit = {
        "paid:additional_analysis": RATE_LIMIT_PAID_ANALYSIS,
        "paid:pdf": RATE_LIMIT_PDF,
        "paid:batch": RATE_LIMIT_BATCH,
    }.get(policy, 30)
    window_start = _utcnow().replace(minute=0, second=0, microsecond=0)

    bucket = db.execute(
        select(models.RateBucket).where(
            models.RateBucket.policy == policy,
            models.RateBucket.owner == owner,
            models.RateBucket.window_start == window_start,
        ).with_for_update()
    ).scalar_one_or_none()
    if bucket is None:
        bucket = models.RateBucket(
            policy=policy, owner=owner, window_start=window_start,
            attempts=0, max_limit=limit,
        )
        db.add(bucket)
        db.flush()
        bucket = db.execute(
            select(models.RateBucket).where(
                models.RateBucket.policy == policy,
                models.RateBucket.owner == owner,
                models.RateBucket.window_start == window_start,
            ).with_for_update()
        ).scalar_one()

    if bucket.attempts >= bucket.max_limit:
        raise AdmissionError(f"rate limit exceeded: {policy}")
    bucket.attempts += 1
    db.flush()


# ---------------------------------------------------------------------------
# COMPLETE transition
# ---------------------------------------------------------------------------

def complete_operation(
    db: Session,
    operation_id: uuid.UUID,
    worker_id: str,
    result_id: uuid.UUID | None = None,
) -> models.Operation:
    """COMPLETE: settle allocations, no ledger change (already debited at RESERVE).

    Follows global lock order (v11.1 Section 4.1):
      capacity_scopes -> credit_accounts -> credit_grants -> operations
    Discovery reads precede the transaction; re-validate under locks.
    """
    # Phase 1: Discovery (no locks) - find which rows we'll need
    disc_op = db.get(models.Operation, operation_id)
    if disc_op is None:
        raise AdmissionError("operation not found")
    if disc_op.status != "reserved":
        if disc_op.status == "completed":
            return disc_op
        raise AdmissionError(f"operation already {disc_op.status}")

    disc_permit = db.execute(
        select(models.Permit).where(models.Permit.operation_id == operation_id)
    ).scalar_one_or_none()
    scope_keys: list[str] = []
    if disc_permit:
        scope_keys = sorted([
            ps.scope_key for ps in db.execute(
                select(models.PermitScope).where(models.PermitScope.permit_id == disc_permit.id)
            ).scalars().all()
        ])

    disc_allocs = db.execute(
        select(models.OperationAllocation).where(
            models.OperationAllocation.operation_id == operation_id,
            models.OperationAllocation.state == "reserved",
        )
    ).scalars().all()
    grant_ids = sorted(set(a.grant_id for a in disc_allocs))
    user_id = disc_op.user_id

    # Phase 2: Acquire locks in global order
    # 1. capacity_scopes (lexicographic)
    for sk in scope_keys:
        db.execute(
            select(models.CapacityScope).where(models.CapacityScope.scope_key == sk)
            .with_for_update()
        ).scalar_one()
    # 2. credit_accounts
    account = db.execute(
        select(models.CreditAccount).where(models.CreditAccount.user_id == user_id)
        .with_for_update()
    ).scalar_one_or_none()
    # 3. credit_grants (ID order)
    grants: dict[uuid.UUID, models.CreditGrant] = {}
    for gid in grant_ids:
        grants[gid] = db.execute(
            select(models.CreditGrant).where(models.CreditGrant.id == gid)
            .with_for_update()
        ).scalar_one()
    # 4. operations (re-validate under lock)
    op = db.execute(
        select(models.Operation).where(models.Operation.id == operation_id)
        .with_for_update()
    ).scalar_one()
    if op.status != "reserved":
        if op.status == "completed":
            return op
        raise AdmissionError(f"operation already {op.status}")
    if op.worker_id != worker_id:
        raise AdmissionError("worker ownership mismatch")
    if _as_aware(op.lease_expires_at) < _utcnow():
        raise AdmissionError("lease expired")

    # Phase 3: Work (all locks held)
    # Require a stored result (v11.1: every charged operation needs durable result)
    if result_id is None and op.result_id is None:
        raise AdmissionError("completion requires a stored result")

    allocations = db.execute(
        select(models.OperationAllocation).where(
            models.OperationAllocation.operation_id == operation_id,
            models.OperationAllocation.state == "reserved",
        ).with_for_update()
    ).scalars().all()

    for alloc in allocations:
        grant = grants[alloc.grant_id]
        grant.reserved -= alloc.quantity
        grant.remaining -= alloc.quantity
        assert grant.reserved >= 0 and grant.remaining >= 0
        alloc.state = "consumed"
    db.flush()

    op.status = "completed"
    op.completed_at = _utcnow()
    if result_id:
        op.result_id = result_id
    db.flush()

    # Release capacity (permit already discovered; re-fetch under lock)
    permit = db.execute(
        select(models.Permit).where(models.Permit.operation_id == operation_id)
        .with_for_update()
    ).scalar_one_or_none()
    if permit and permit.released_at is None:
        permit.released_at = _utcnow()
        for sk in scope_keys:
            scope = db.execute(
                select(models.CapacityScope).where(models.CapacityScope.scope_key == sk)
                .with_for_update()
            ).scalar_one()
            # Find quantity from permit_scopes
            ps = db.execute(
                select(models.PermitScope).where(
                    models.PermitScope.permit_id == permit.id,
                    models.PermitScope.scope_key == sk,
                )
            ).scalar_one()
            scope.used = max(0, scope.used - ps.quantity)
    db.flush()
    return op


# ---------------------------------------------------------------------------
# RELEASE transition
# ---------------------------------------------------------------------------

def release_operation(
    db: Session,
    operation_id: uuid.UUID,
    worker_id: str,
    failure_code: str,
    _is_recovery: bool = False,
) -> models.Operation:
    """RELEASE: return reserved credits via compensating ledger entry.

    Follows global lock order (v11.1 Section 4.1):
      capacity_scopes -> credit_accounts -> credit_grants -> operations
    """
    # Phase 1: Discovery (no locks)
    disc_op = db.get(models.Operation, operation_id)
    if disc_op is None:
        raise AdmissionError("operation not found")
    if disc_op.status != "reserved":
        if disc_op.status in ("failed", "expired"):
            return disc_op
        raise AdmissionError(f"operation already {disc_op.status}")

    disc_permit = db.execute(
        select(models.Permit).where(models.Permit.operation_id == operation_id)
    ).scalar_one_or_none()
    scope_keys: list[str] = []
    if disc_permit:
        scope_keys = sorted([
            ps.scope_key for ps in db.execute(
                select(models.PermitScope).where(models.PermitScope.permit_id == disc_permit.id)
            ).scalars().all()
        ])

    disc_allocs = db.execute(
        select(models.OperationAllocation).where(
            models.OperationAllocation.operation_id == operation_id,
            models.OperationAllocation.state == "reserved",
        )
    ).scalars().all()
    grant_ids = sorted(set(a.grant_id for a in disc_allocs))
    user_id = disc_op.user_id

    # Phase 2: Acquire locks in global order
    for sk in scope_keys:
        db.execute(
            select(models.CapacityScope).where(models.CapacityScope.scope_key == sk)
            .with_for_update()
        ).scalar_one()
    account = db.execute(
        select(models.CreditAccount).where(models.CreditAccount.user_id == user_id)
        .with_for_update()
    ).scalar_one_or_none()
    if account is None:
        account = models.CreditAccount(user_id=user_id, balance=0, ledger_sequence=0)
        db.add(account)
        db.flush()
    grants: dict[uuid.UUID, models.CreditGrant] = {}
    for gid in grant_ids:
        grants[gid] = db.execute(
            select(models.CreditGrant).where(models.CreditGrant.id == gid)
            .with_for_update()
        ).scalar_one()
    op = db.execute(
        select(models.Operation).where(models.Operation.id == operation_id)
        .with_for_update()
    ).scalar_one()
    if op.status != "reserved":
        if op.status in ("failed", "expired"):
            return op
        raise AdmissionError(f"operation already {op.status}")
    if not _is_recovery and op.worker_id != worker_id:
        raise AdmissionError("worker ownership mismatch")

    # Phase 3: Work (all locks held)
    allocations = db.execute(
        select(models.OperationAllocation).where(
            models.OperationAllocation.operation_id == operation_id,
            models.OperationAllocation.state == "reserved",
        ).with_for_update()
    ).scalars().all()

    grant_splits = []
    for alloc in allocations:
        grant = grants[alloc.grant_id]
        grant.reserved -= alloc.quantity
        assert grant.reserved >= 0
        alloc.state = "released"
        grant_splits.append((grant.id, alloc.quantity))
    db.flush()

    original = db.execute(
        select(models.CreditLedger).where(
            models.CreditLedger.user_id == op.user_id,
            models.CreditLedger.event_key == f"reserve:{operation_id}",
        )
    ).scalar_one_or_none()

    total = sum(q for _, q in grant_splits)
    if total > 0:
        _append_ledger(
            db, account, op.user_id,
            event_key=f"reversal:{operation_id}",
            delta=total,
            reason="operation_release",
            grant_splits=grant_splits,
            operation_id=operation_id,
            reverses_entry_id=original.id if original else None,
        )

    op.status = "failed" if failure_code != "expired" else "expired"
    op.failure_code = failure_code
    op.completed_at = _utcnow()
    db.flush()

    permit = db.execute(
        select(models.Permit).where(models.Permit.operation_id == operation_id)
        .with_for_update()
    ).scalar_one_or_none()
    if permit and permit.released_at is None:
        permit.released_at = _utcnow()
        for sk in scope_keys:
            scope = db.execute(
                select(models.CapacityScope).where(models.CapacityScope.scope_key == sk)
                .with_for_update()
            ).scalar_one()
            ps = db.execute(
                select(models.PermitScope).where(
                    models.PermitScope.permit_id == permit.id,
                    models.PermitScope.scope_key == sk,
                )
            ).scalar_one()
            scope.used = max(0, scope.used - ps.quantity)
    db.flush()
    return op


# ---------------------------------------------------------------------------
# Recovery
# ---------------------------------------------------------------------------

def recover_expired_operations(db: Session, batch_size: int = 100) -> int:
    """Find reserved operations with expired leases and release them.
    
    If a ready Result exists (linked or unlinked), complete instead of release.
    This handles crashes between Result creation and operation.result_id update.
    """
    now = _utcnow()
    candidates = db.execute(
        select(models.Operation.id).where(
            models.Operation.status == "reserved",
            models.Operation.lease_expires_at < now,
        ).limit(batch_size)
    ).scalars().all()

    recovered = 0
    for op_id in candidates:
        try:
            op = db.execute(
                select(models.Operation).where(models.Operation.id == op_id)
                .with_for_update()
            ).scalar_one_or_none()
            if op is None or op.status != "reserved":
                continue
            if _as_aware(op.lease_expires_at) >= _utcnow():
                continue
            # Check for ready result: first via op.result_id, then via
            # Result.operation_id (handles crash between Result creation
            # and operation.result_id update)
            result_id = op.result_id
            if result_id is None:
                orphan = db.execute(
                    select(models.Result).where(
                        models.Result.operation_id == op_id,
                        models.Result.ready_at.isnot(None),
                        models.Result.deleted_at.is_(None),
                    )
                ).scalar_one_or_none()
                if orphan:
                    result_id = orphan.id
            if result_id:
                result = db.get(models.Result, result_id)
                if result and result.ready_at and not result.deleted_at:
                    complete_operation(db, op_id, op.worker_id, result_id=result_id)
                    db.commit()
                    recovered += 1
                    continue
            release_operation(db, op_id, op.worker_id, "expired", _is_recovery=True)
            db.commit()
            recovered += 1
        except Exception:
            db.rollback()
    return recovered


# ---------------------------------------------------------------------------
# Invariant verification (v11.1 Section 11.2)
# ---------------------------------------------------------------------------

def verify_account_invariants(db: Session, user_id: uuid.UUID) -> list[str]:
    """Verify A1-A10 for an account. Returns list of violations (empty = pass)."""
    violations = []

    account = db.execute(
        select(models.CreditAccount).where(models.CreditAccount.user_id == user_id)
    ).scalar_one_or_none()
    if account is None:
        return []

    ledger_sum = db.execute(
        select(func.coalesce(func.sum(models.CreditLedger.delta), 0)).where(
            models.CreditLedger.user_id == user_id)
    ).scalar() or 0
    if ledger_sum != account.balance:
        violations.append(f"A1: ledger sum {ledger_sum} != balance {account.balance}")

    grant_net = db.execute(
        select(func.coalesce(
            func.sum(models.CreditGrant.remaining - models.CreditGrant.reserved), 0
        )).where(models.CreditGrant.user_id == user_id)
    ).scalar() or 0
    if grant_net != account.balance:
        violations.append(f"A1: grant net {grant_net} != balance {account.balance}")

    bad_grants = db.execute(
        select(func.count()).select_from(models.CreditGrant).where(
            models.CreditGrant.user_id == user_id,
            ~((models.CreditGrant.reserved >= 0)
              & (models.CreditGrant.reserved <= models.CreditGrant.remaining)
              & (models.CreditGrant.remaining <= models.CreditGrant.issued)),
        )
    ).scalar()
    if bad_grants:
        violations.append(f"A2: {bad_grants} grants violate bounds")

    grant_rows = db.execute(
        select(models.CreditGrant).where(models.CreditGrant.user_id == user_id)
    ).scalars().all()
    for g in grant_rows:
        alloc_sum = db.execute(
            select(func.coalesce(func.sum(models.OperationAllocation.quantity), 0)).where(
                models.OperationAllocation.grant_id == g.id,
                models.OperationAllocation.state == "reserved",
            )
        ).scalar() or 0
        if alloc_sum != g.reserved:
            violations.append(
                f"A3: grant {g.id} reserved={g.reserved} != allocation sum {alloc_sum}")

    return violations


def verify_capacity_invariants(db: Session) -> list[str]:
    """Verify A10: capacity counters equal active permit memberships."""
    violations = []
    scopes = db.execute(select(models.CapacityScope)).scalars().all()
    for scope in scopes:
        membership_sum = db.execute(
            select(func.coalesce(func.sum(models.PermitScope.quantity), 0))
            .select_from(models.PermitScope)
            .join(models.Permit, models.Permit.id == models.PermitScope.permit_id)
            .where(
                models.PermitScope.scope_key == scope.scope_key,
                models.Permit.released_at.is_(None),
            )
        ).scalar() or 0
        if membership_sum != scope.used:
            violations.append(
                f"A10: scope {scope.scope_key} used={scope.used} != memberships {membership_sum}")
    return violations


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def hash_input(data: bytes) -> str:
    """SHA-256 hex digest for request fingerprints."""
    return hashlib.sha256(data).hexdigest()


def get_balance_summary(db: Session, user_id: uuid.UUID) -> dict:
    """Return balance, eligible, reserved, and restriction status for UI."""
    account = db.execute(
        select(models.CreditAccount).where(models.CreditAccount.user_id == user_id)
    ).scalar_one_or_none()
    balance = account.balance if account else 0
    eligible = get_eligible_credits(db, user_id)
    reserved = db.execute(
        select(func.coalesce(func.sum(models.CreditGrant.reserved), 0)).where(
            models.CreditGrant.user_id == user_id)
    ).scalar() or 0
    restricted = has_active_restriction(db, user_id, "spend")
    return {
        "balance": balance,
        "eligible": eligible,
        "reserved": reserved,
        "restricted": restricted,
    }
