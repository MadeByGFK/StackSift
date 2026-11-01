"""Batch free-first quota accounting (issue #103, trim B2).

The batch first file follows the normal free rules, but the free hourly
allowance (10/hour per trusted IP) is tracked by TWO systems:

- durable admission: ``FreeRequest`` rows (app.analysis_admission), and
- the shared limiter: ``RateLimitHit`` rows under a per-IP
  ``RateLimitBucket`` lock row (app.rate_limit.PostgresRateLimiter).

A batch must claim the allowance in BOTH systems, atomically with its
single credit reservation, or alternating single/batch routes could
claim the tenth allowance twice. This module provides that claim:

- ``free_first_available()`` is a READ-ONLY quote check (no hits, no
  claims, no reservation). Database errors propagate; callers fail
  closed with 503 and never assume a free allowance.
- ``admit_batch_operation()`` runs inside the caller's transaction:
    1. global capacity serialization FIRST (the lexicographically
       first batch capacity scope, ``global:batch``, matching the
       lock-first contract in credits.admit_paid_operation, AND the
       ``global:paid`` scope that analysis_admission.admit() — the
       single-file route — serializes on: holding it from counting
       through commit is what makes the batch claim and a concurrent
       single-file admission mutually exclusive, since the single
       route's durable claim is its FreeRequest created under that
       same lock);
    2. quota/admission locks next (RateLimitBucket row for the IP,
       then the FreeBucket row) — never an inverse nested order;
    3. counters recomputed under those locks; a changed price raises
       RequoteRequired (never a silent reprice);
    4. a free-first claim writes exactly one RateLimitHit and bumps
       the FreeBucket counter in THIS transaction, and the Operation
       row created by credits.admit_paid_operation carries
       ``free_allowance_claim=True`` (counted by analysis_admission
       alongside FreeRequest rows).
  Any failure rolls the whole transaction back, so no hit, claim, or
  reservation survives a denied admission. A later execution failure
  releases the credits in full but does NOT restore the admitted free
  attempt (trim B8) — the hit/claim rows are admission history, exactly
  like a failed FreeRequest.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from app import credits as C, models as M

FREE_HOURLY_LIMIT = 10
BURST_LIMIT = 2

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class RequoteRequired(Exception):
    """The free-first position changed between quote and confirm.

    Carries the recomputed total; the caller must issue a replacement
    consent at the new total and run nothing.
    """

    def __init__(self, new_total: int, new_first_cost: int):
        super().__init__(f"batch price changed; new total is {new_total} credits")
        self.new_total = new_total
        self.new_first_cost = new_first_cost


# -- counting helpers (transaction-neutral: no commit/rollback) ------------

def _count_free_requests(db, ip: str, since) -> int:
    return db.scalar(select(func.count()).select_from(M.FreeRequest).where(
        M.FreeRequest.quota_bucket_trusted_ip == ip,
        M.FreeRequest.created_at > since)) or 0


def _count_batch_claims(db, ip: str, since) -> int:
    return db.scalar(select(func.count()).select_from(M.Operation).where(
        M.Operation.type == "batch",
        M.Operation.input_manifest == ip,
        M.Operation.free_allowance_claim.is_(True),
        M.Operation.created_at > since)) or 0


def _count_batch_attempts(db, ip: str, since) -> int:
    return db.scalar(select(func.count()).select_from(M.Operation).where(
        M.Operation.type == "batch",
        M.Operation.input_manifest == ip,
        M.Operation.created_at > since)) or 0


def _count_additional_attempts(db, ip: str, since) -> int:
    return db.scalar(select(func.count()).select_from(M.Operation).where(
        M.Operation.type == "additional_analysis",
        M.Operation.input_manifest == ip,
        M.Operation.created_at > since)) or 0


def _count_rate_hits(db, ip: str, since) -> int:
    return db.scalar(select(func.count()).select_from(M.RateLimitHit).where(
        M.RateLimitHit.trusted_ip == ip,
        M.RateLimitHit.hit_at > since)) or 0


def durable_hourly_used(db, ip: str, now=None) -> int:
    now = now or C._utcnow()
    since = now - timedelta(hours=1)
    return _count_free_requests(db, ip, since) + _count_batch_claims(db, ip, since)


def shared_hourly_used(db, ip: str, now=None) -> int:
    now = now or C._utcnow()
    return _count_rate_hits(db, ip, now - timedelta(hours=1))


def free_first_available(db, ip: str) -> bool:
    """Read-only: True when the shared 10/hour allowance has room in
    BOTH accounting systems. Records nothing."""
    now = C._utcnow()
    return (durable_hourly_used(db, ip, now) < FREE_HOURLY_LIMIT
            and shared_hourly_used(db, ip, now) < FREE_HOURLY_LIMIT)


def batch_price(db, ip: str, file_count: int) -> tuple[int, int, bool]:
    """Read-only quote: (total, first_file_cost, free_first_available)."""
    free = free_first_available(db, ip)
    total = C.batch_total_cost(file_count, free)
    return total, (0 if free else C.COST_ADDITIONAL_ANALYSIS), free


# -- quota locks -------------------------------------------------------------

def _lock_rate_bucket(db, ip: str) -> None:
    """Upsert + FOR UPDATE the per-IP shared-limiter bucket row.

    Same pattern as PostgresRateLimiter._lock_bucket, but transaction-
    neutral: this module never calls the limiter's admit(), because
    that commits/rolls back internally and would break the atomic
    reservation transaction.
    """
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    from sqlalchemy.dialects.sqlite import insert as sqlite_insert
    insert = pg_insert if db.bind.dialect.name == "postgresql" else sqlite_insert
    db.execute(insert(M.RateLimitBucket).values(trusted_ip=ip)
               .on_conflict_do_nothing(index_elements=["trusted_ip"]))
    db.flush()
    db.execute(select(M.RateLimitBucket).where(M.RateLimitBucket.trusted_ip == ip)
               .with_for_update().execution_options(populate_existing=True)).scalar_one()


def _lock_free_bucket(db, ip: str):
    """Upsert + FOR UPDATE the durable FreeBucket row (analysis_admission
    uses the same epoch-window row)."""
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    from sqlalchemy.dialects.sqlite import insert as sqlite_insert
    insert = pg_insert if db.bind.dialect.name == "postgresql" else sqlite_insert
    db.execute(insert(M.FreeBucket).values(
        trusted_ip=ip, window_start=_EPOCH, policy_version=1, attempts=0)
        .on_conflict_do_nothing())
    db.flush()
    return db.execute(select(M.FreeBucket).where(
        M.FreeBucket.trusted_ip == ip,
        M.FreeBucket.window_start == _EPOCH,
        M.FreeBucket.policy_version == 1)
        .with_for_update().execution_options(populate_existing=True)).scalar_one()


# -- atomic admission ---------------------------------------------------------

def admit_batch_operation(db, user_id, idempotency_key: str, request_hash: str,
                          consent_id, worker_id: str, ip: str, file_count: int):
    """Admit one batch operation with its free-first claim, atomically.

    Returns the Operation (an existing one on an idempotent replay, in
    which case no new claim/hit is recorded). Raises RequoteRequired
    when the price moved since the quote, InsufficientCredits /
    AdmissionError from the ledger path otherwise. The caller owns
    commit/rollback.
    """
    # 1. Global capacity serialization first (lexicographically first
    # batch scope), before the authoritative identity lookup — the
    # contract credits.admit_paid_operation documents for oversize.
    # global:paid is locked in the same step: it is the serialization
    # row for single-file durable admission, so the counts below and
    # the claim they produce cannot interleave with a concurrent
    # single-file FreeRequest creation.
    C._ensure_capacity_scope(db, "global:batch", 1)
    C._ensure_capacity_scope(db, "global:paid", C.DEFAULT_GLOBAL_CONCURRENT_LIMIT)
    existing = C.find_operation(db, user_id, "batch", idempotency_key, request_hash)
    if existing is not None:
        return existing

    # 2. Quota/admission locks (never inverse to the capacity order).
    _lock_rate_bucket(db, ip)
    free_bucket = _lock_free_bucket(db, ip)

    now = C._utcnow()
    # 3. Recompute under lock: burst (2/minute across BOTH routes) and
    # the hourly free-first position in both accounting systems.
    minute = now - timedelta(minutes=1)
    burst = (_count_free_requests(db, ip, minute)
             + _count_additional_attempts(db, ip, minute)
             + _count_batch_attempts(db, ip, minute)
             + 0)  # shared-limiter burst is enforced by its own hits below
    shared_burst = _count_rate_hits(db, ip, minute)
    if burst >= BURST_LIMIT or shared_burst >= BURST_LIMIT:
        raise C.AdmissionError("Too many requests. Please wait a minute and try again.")
    free_available = (durable_hourly_used(db, ip, now) < FREE_HOURLY_LIMIT
                      and shared_hourly_used(db, ip, now) < FREE_HOURLY_LIMIT)
    first_cost = 0 if free_available else C.COST_ADDITIONAL_ANALYSIS
    total = C.batch_total_cost(file_count, free_available)

    consent = db.get(M.Consent, consent_id, populate_existing=True)
    if consent is not None and consent.max_cost != total:
        raise RequoteRequired(total, first_cost)

    # 4. Record the claim in the shared system in THIS transaction; the
    # durable system reads it back from the Operation row created below.
    claiming = free_available
    if claiming:
        db.add(M.RateLimitHit(trusted_ip=ip, hit_at=now))
        free_bucket.attempts += 1
        db.flush()

    return C.admit_paid_operation(
        db, user_id, "batch", idempotency_key, request_hash, total,
        consent_id, worker_id, input_manifest=ip,
        extra_scopes=[("global:batch", 1)],
        free_allowance_claim=claiming,
    )
