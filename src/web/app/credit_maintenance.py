"""Idempotent maintenance; executor expiry never proves termination.

Run with `python -m app.credit_maintenance` from a configured environment.
The web lifespan also schedules these jobs. Unknown executors remain held and
logged until an operator/supervisor supplies generation-specific evidence to
recover_expired_operations / recover_free_requests.
"""
import logging
from sqlalchemy import select
from app import credits as C, models as M


def recover_free_requests(db, *, executor_stopped=None):
    candidates = db.execute(select(M.FreeRequest.request_id, M.FreeRequest.execution_generation).where(
        M.FreeRequest.status == 'in_progress', M.FreeRequest.deadline < C._utcnow()).limit(100)).all()
    db.rollback()
    for key, generation in candidates:
        if executor_stopped is None or not executor_stopped(key, generation):
            logging.getLogger(__name__).warning('Free request %s awaits executor termination evidence', key)
            continue
        C._ensure_capacity_scope(db, 'global:paid', C.DEFAULT_GLOBAL_CONCURRENT_LIMIT)
        fr = db.get(M.FreeRequest, key, populate_existing=True, with_for_update=True)
        if fr.status == 'in_progress' and fr.execution_generation == generation and C._as_aware(fr.deadline) < C._utcnow():
            fr.status, fr.failure_code = 'failed', 'expired'
            fr.execution_generation += 1
        db.commit()


def cleanup_results(db):
    # Same capacity-first order as settlement; retain identities, remove payloads.
    C._ensure_capacity_scope(db, 'global:paid', C.DEFAULT_GLOBAL_CONCURRENT_LIMIT)
    rows = db.scalars(select(M.Result).where(M.Result.expires_at <= C._utcnow(), M.Result.deleted_at.is_(None)))
    for result in rows:
        result.storage_manifest = '{}'
        result.deleted_at = C._utcnow()
    db.commit()


def run_once(*, reconcile=False):
    from app.db import SessionLocal
    from app.main import cleanup_pending_uploads
    cleanup_pending_uploads()
    with SessionLocal() as db:
        C.recover_expired_operations(db)
        recover_free_requests(db)
        cleanup_results(db)
        # Issue #70: abandoned checkouts must not sit pending forever.
        C.expire_stale_pending_purchases(db)
        if reconcile:
            accounts = db.scalars(select(M.CreditAccount.user_id)).all()
            db.rollback()
            for user_id in accounts:
                C.reconcile_account(db, user_id)
        # Issue #72: daily Stripe-to-ledger reconciliation. Guarded so a
        # job failure never breaks the maintenance loop.
        try:
            from app import payment_reconcile as PR
            PR.run_payment_reconciliation_if_due(db)
        except Exception:
            logging.getLogger(__name__).exception("Payment reconciliation failed")


if __name__ == '__main__':
    run_once(reconcile=True)
