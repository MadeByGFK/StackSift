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
import json
import logging
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
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    from sqlalchemy.dialects.sqlite import insert as sqlite_insert
    insert = pg_insert if db.bind.dialect.name == "postgresql" else sqlite_insert
    db.execute(insert(models.CreditAccount).values(
        user_id=user_id, balance=0, ledger_sequence=0,
    ).on_conflict_do_nothing(index_elements=["user_id"]))
    q = select(models.CreditAccount).where(models.CreditAccount.user_id == user_id)
    if for_update:
        q = q.with_for_update().execution_options(populate_existing=True)
    return db.execute(q).scalar_one()


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
        .order_by(models.CreditGrant.id)
        .with_for_update().execution_options(populate_existing=True)
    ).scalars().all()

    allocations: list[tuple[models.CreditGrant, int]] = []
    remaining_cost = cost
    for grant in sorted(grants, key=lambda g: (g.created_at, g.id)):
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
    consent = db.get(models.Consent, consent_id, populate_existing=True)
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
    if consent.consumed_by_operation_id is not None or consent.consumed_by_free_request_id is not None:
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
        .with_for_update().execution_options(populate_existing=True)
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
        free_active = db.scalar(select(func.count()).select_from(models.FreeRequest).where(
            models.FreeRequest.status == "in_progress")) if scope_key == global_scope else 0
        if scope.used + free_active >= scope.max_limit:
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
        ).with_for_update().execution_options(populate_existing=True)
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
            .with_for_update().execution_options(populate_existing=True)
        ).scalar_one()
        scope.used -= ms.quantity
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

    _ensure_capacity_scope(db, "global:paid", DEFAULT_GLOBAL_CONCURRENT_LIMIT)
    existing = find_operation(db, user_id, operation_type, idempotency_key, request_hash)
    if existing is not None:
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
        ).with_for_update().execution_options(populate_existing=True)
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
            ).with_for_update().execution_options(populate_existing=True)
        ).scalar_one()

    if bucket.attempts >= bucket.max_limit:
        raise AdmissionError(f"rate limit exceeded: {policy}")
    bucket.attempts += 1
    db.flush()


# ---------------------------------------------------------------------------
# COMPLETE transition
# ---------------------------------------------------------------------------

def find_operation(db, user_id, operation_type, key, request_hash):
    op = db.execute(select(models.Operation).where(
        models.Operation.user_id == user_id, models.Operation.type == operation_type,
        models.Operation.idempotency_key == key,
    ).execution_options(populate_existing=True)).scalar_one_or_none()
    if op is not None and op.request_hash != request_hash:
        raise AdmissionError("idempotency key reused with different input (409)")
    return op


def _lock_operation(db, operation_id):
    """Discovery is non-authoritative; all settlement paths use this lock order."""
    with db.no_autoflush:
        owner = db.execute(select(models.Operation.user_id).where(
            models.Operation.id == operation_id)).scalar_one_or_none()
        if owner is None:
            raise AdmissionError("operation not found")
        scope_keys = db.execute(select(models.PermitScope.scope_key)
            .join(models.Permit, models.Permit.id == models.PermitScope.permit_id)
            .where(models.Permit.operation_id == operation_id)
            .order_by(models.PermitScope.scope_key)).scalars().all()
        for key in scope_keys:
            db.execute(select(models.CapacityScope).where(models.CapacityScope.scope_key == key)
                .with_for_update().execution_options(populate_existing=True)).scalar_one()
        account = db.execute(select(models.CreditAccount).where(models.CreditAccount.user_id == owner)
            .with_for_update().execution_options(populate_existing=True)).scalar_one()
        grant_ids = select(models.OperationAllocation.grant_id).where(
            models.OperationAllocation.operation_id == operation_id)
        grants = db.execute(select(models.CreditGrant).where(models.CreditGrant.id.in_(grant_ids))
            .order_by(models.CreditGrant.id).with_for_update()
            .execution_options(populate_existing=True)).scalars().all()
        op = db.execute(select(models.Operation).where(models.Operation.id == operation_id)
            .with_for_update().execution_options(populate_existing=True)).scalar_one()
    return op, account, {g.id: g for g in grants}


def result_payload(result, *, user_id, operation_id=None, free_request_id=None, allow_expired=False):
    """Validate identity and integrity before publication or replay."""
    if (result is None or result.user_id != user_id or result.operation_id != operation_id
            or result.free_request_id != free_request_id or not result.ready_at or result.deleted_at):
        raise AdmissionError("result unavailable")
    if not allow_expired and _as_aware(result.expires_at) <= _utcnow():
        raise AdmissionError("result expired")
    raw = result.storage_manifest.encode("utf-8")
    if len(raw) != result.byte_count or hash_input(raw) != result.integrity_digest:
        raise AdmissionError("result integrity mismatch")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise AdmissionError("invalid result")
    return data


def store_result(db, user_id, operation_id, data):
    # Obtain domain locks BEFORE inserting the result's operation FK.
    op, _, _ = _lock_operation(db, operation_id)
    if op.status != "reserved":
        raise AdmissionError("operation is no longer reserved")
    raw = json.dumps({k: v for k, v in data.items() if k not in ("current_user", "csrf_token")}, default=str)
    now = _utcnow()
    result = models.Result(user_id=user_id, operation_id=operation_id, type="analysis",
        storage_manifest=raw, integrity_digest=hash_input(raw.encode()), byte_count=len(raw.encode()),
        ready_at=now, expires_at=now + timedelta(days=7))
    db.add(result)
    db.flush()
    return result



def store_pdf_result(db, user_id, operation_id, pdf_bytes: bytes, filename: str):
    """Store a generated PDF as a Result of type 'pdf'.

    The PDF bytes are stored in the storage_manifest as base64.
    Follows the same pattern as store_result.
    """
    import base64 as _b64
    op, _, _ = _lock_operation(db, operation_id)
    if op.status != "reserved":
        raise AdmissionError("operation is no longer reserved")
    if op.type != "pdf":
        raise AdmissionError("operation is not a PDF export")
    manifest = json.dumps({
        "filename": filename,
        "pdf_base64": _b64.b64encode(pdf_bytes).decode("ascii"),
        "source": "pdf_export",
    })
    now = _utcnow()
    result = models.Result(
        user_id=user_id,
        operation_id=operation_id,
        type="pdf",
        storage_manifest=manifest,
        integrity_digest=hash_input(pdf_bytes),
        byte_count=len(pdf_bytes),
        ready_at=now,
        expires_at=now + timedelta(days=7),
    )
    db.add(result)
    db.flush()
    return result

def _settle_complete(db, op, grants, result):
    result_payload(result, user_id=op.user_id, operation_id=op.id)
    allocations = db.execute(select(models.OperationAllocation).where(
        models.OperationAllocation.operation_id == op.id, models.OperationAllocation.state == "reserved")
        .with_for_update().execution_options(populate_existing=True)).scalars().all()
    if sum(a.quantity for a in allocations) != op.cost:
        raise AdmissionError("allocation total does not match cost")
    for a in allocations:
        grants[a.grant_id].reserved -= a.quantity
        grants[a.grant_id].remaining -= a.quantity
        a.state = "consumed"
    op.status, op.completed_at, op.result_id = "completed", _utcnow(), result.id
    permit = db.execute(select(models.Permit).where(models.Permit.operation_id == op.id)).scalar_one()
    _release_capacity(db, permit, op.user_id)
    db.flush()
    return op


def complete_operation(db, operation_id, worker_id, result_id=None, *, lease_generation=1):
    op, _, grants = _lock_operation(db, operation_id)
    if op.status == "completed":
        return op
    if op.status != "reserved":
        raise AdmissionError(f"operation already {op.status}")
    if op.worker_id != worker_id or op.lease_generation != lease_generation:
        raise AdmissionError("worker ownership mismatch")
    if _as_aware(op.lease_expires_at) < _utcnow():
        raise AdmissionError("lease expired")
    return _settle_complete(db, op, grants, db.get(models.Result, result_id or op.result_id)
        if (result_id or op.result_id) else None)


def _settle_release(db, op, account, grants, failure_code):
    allocations = db.execute(select(models.OperationAllocation).where(
        models.OperationAllocation.operation_id == op.id, models.OperationAllocation.state == "reserved")
        .with_for_update().execution_options(populate_existing=True)).scalars().all()
    if sum(a.quantity for a in allocations) != op.cost:
        raise AdmissionError("allocation total does not match cost")
    for a in allocations:
        grants[a.grant_id].reserved -= a.quantity
        a.state = "released"
    original = db.execute(select(models.CreditLedger).where(
        models.CreditLedger.user_id == op.user_id,
        models.CreditLedger.event_key == f"reserve:{op.id}")).scalar_one()
    _append_ledger(db, account, op.user_id, f"reversal:{op.id}", op.cost, "operation_release",
        [(a.grant_id, a.quantity) for a in allocations], operation_id=op.id, reverses_entry_id=original.id)
    op.status = "expired" if failure_code == "expired" else "failed"
    op.failure_code, op.completed_at = failure_code, _utcnow()
    op.lease_generation += 1  # late publication from this executor is rejected
    permit = db.execute(select(models.Permit).where(models.Permit.operation_id == op.id)).scalar_one()
    _release_capacity(db, permit, op.user_id)
    db.flush()
    return op


def release_operation(db, operation_id, worker_id, failure_code, *, lease_generation=1):
    op, account, grants = _lock_operation(db, operation_id)
    if op.status in ("failed", "expired"):
        return op
    if op.status != "reserved":
        raise AdmissionError(f"operation already {op.status}")
    if op.worker_id != worker_id or op.lease_generation != lease_generation:
        raise AdmissionError("worker ownership mismatch")
    return _settle_release(db, op, account, grants, failure_code)


def recover_expired_operations(db, batch_size=100, *, executor_stopped=None):
    """Recover results; release only with supervisor evidence for this generation.

    executor_stopped(id, worker_id, generation) must confirm termination, not just
    expiry or a missing heartbeat. Without that integration, unknown work stays
    reserved for operator investigation. A ready result is registered only after
    computation ends, so it can be settled without restarting any executor.
    """
    candidates = db.execute(select(models.Operation.id, models.Operation.worker_id,
        models.Operation.lease_generation).where(models.Operation.status == "reserved",
        models.Operation.lease_expires_at < _utcnow()).order_by(models.Operation.lease_expires_at)
        .limit(batch_size)).all()
    db.rollback()  # discovery has no authority and holds no domain locks
    recovered = 0
    for op_id, worker_id, generation in candidates:
        stopped = executor_stopped is not None and executor_stopped(op_id, worker_id, generation)
        try:
            op, account, grants = _lock_operation(db, op_id)
            if (op.status != "reserved" or _as_aware(op.lease_expires_at) >= _utcnow()
                    or op.worker_id != worker_id or op.lease_generation != generation):
                db.rollback()
                continue
            result = db.execute(select(models.Result).where(models.Result.operation_id == op_id,
                models.Result.deleted_at.is_(None))).scalar_one_or_none()
            if result is not None:
                _settle_complete(db, op, grants, result)
            elif stopped:
                _settle_release(db, op, account, grants, "expired")
            else:
                logging.getLogger(__name__).warning("Expired operation %s awaits executor termination evidence", op_id)
                db.rollback()
                continue
            db.commit()
            recovered += 1
        except Exception:
            db.rollback()
            logging.getLogger(__name__).exception("Recovery failed for operation %s", op_id)
    return recovered


# ---------------------------------------------------------------------------
# Invariant verification (v11.1 Section 11.2)
# ---------------------------------------------------------------------------

def _verify_account_invariants(db: Session, user_id: uuid.UUID) -> list[str]:
    """Check applicable Phase 2A invariants; refunds/holds remain Phase 3."""
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

    entries = db.execute(select(models.CreditLedger).where(models.CreditLedger.user_id == user_id)
        .order_by(models.CreditLedger.account_sequence)).scalars().all()
    running = 0
    for sequence, entry in enumerate(entries, 1):
        running += entry.delta
        splits = db.execute(select(models.LedgerGrant).where(models.LedgerGrant.ledger_entry_id == entry.id)).scalars().all()
        if sum(split.signed_delta for split in splits) != entry.delta:
            violations.append(f"A6: entry {entry.id} attribution total mismatch")
        if entry.account_sequence != sequence or entry.balance_after != running:
            violations.append(f"A6: entry {entry.id} sequence/balance mismatch")
        for split in splits:
            grant = db.get(models.CreditGrant, split.grant_id)
            if grant is None or grant.user_id != user_id:
                violations.append(f"A9: entry {entry.id} grant owner mismatch")
    if account.ledger_sequence != len(entries):
        violations.append("A6: account sequence mismatch")
    for grant in grant_rows:
        net = db.scalar(select(func.coalesce(func.sum(models.LedgerGrant.signed_delta), 0))
            .where(models.LedgerGrant.grant_id == grant.id))
        if net != grant.remaining - grant.reserved:
            violations.append(f"A1: grant {grant.id} ledger attribution mismatch")
    for op in db.execute(select(models.Operation).where(models.Operation.user_id == user_id)).scalars():
        allocations = db.execute(select(models.OperationAllocation).where(models.OperationAllocation.operation_id == op.id)).scalars().all()
        if sum(a.quantity for a in allocations) != op.cost:
            violations.append(f"A4: operation {op.id} allocation total mismatch")
        expected = {'reserved': 'reserved', 'completed': 'consumed', 'failed': 'released', 'expired': 'released'}.get(op.status)
        if expected is None or any(a.state != expected for a in allocations):
            violations.append(f"A5: operation {op.id} settlement mismatch")
        for allocation in allocations:
            if db.get(models.CreditGrant, allocation.grant_id).user_id != user_id:
                violations.append(f"A9: operation {op.id} grant owner mismatch")
        debit = next((e for e in entries if e.event_key == f'reserve:{op.id}'), None)
        if debit is None or debit.delta != -op.cost:
            violations.append(f"A6: operation {op.id} reservation debit mismatch")
        if op.status in ('failed', 'expired') and (debit is None or not any(
                e.reverses_entry_id == debit.id and e.delta == op.cost for e in entries)):
            violations.append(f"A6: operation {op.id} reversal mismatch")

    return violations


def _verify_capacity_invariants(db: Session) -> list[str]:
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


def _snapshot_check(db, check, *args):
    # A fresh Session avoids both READ COMMITTED statement snapshots and stale
    # ORM objects inherited from a caller's earlier reads.
    if db.bind.dialect.name != "postgresql":
        db.expire_all()
        return check(db, *args)
    with db.get_bind().connect().execution_options(isolation_level="REPEATABLE READ") as conn:
        with Session(bind=conn) as snapshot:
            return check(snapshot, *args)


def verify_account_invariants(db, user_id):
    return _snapshot_check(db, _verify_account_invariants, user_id)


def verify_capacity_invariants(db):
    return _snapshot_check(db, _verify_capacity_invariants)


def reconcile_account(db, user_id):
    violations = verify_account_invariants(db, user_id)
    if not violations:
        return []
    db.rollback()
    # Reconfirm with the serialization locks before imposing any restriction.
    _ensure_capacity_scope(db, "global:paid", DEFAULT_GLOBAL_CONCURRENT_LIMIT)
    get_or_create_account(db, user_id, for_update=True)
    db.expire_all()
    violations = _verify_account_invariants(db, user_id)
    if violations and not db.scalar(select(models.Restriction.id).where(
            models.Restriction.user_id == user_id, models.Restriction.cause_type == 'invariant',
            models.Restriction.cause_id == 'account', models.Restriction.lifted_at.is_(None))):
        db.add(models.Restriction(user_id=user_id, action='spend', cause_type='invariant',
            cause_id='account', reason='; '.join(violations)))
        logging.getLogger(__name__).critical("Credit invariants failed for account %s: %s", user_id, violations)
    db.commit()
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
