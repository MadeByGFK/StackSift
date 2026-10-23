"""Idempotent maintenance; executor expiry never proves termination.

Run with `python -m app.credit_maintenance` from a configured environment.
The web lifespan also schedules these jobs. Unknown executors remain held and
logged until an operator/supervisor supplies generation-specific evidence to
recover_expired_operations / recover_free_requests.

Issue #58: jobs that fail repeatedly, stuck credit reservations, and sustained
analysis failures alert the founder via app.ops_alerts (OPS_ALERT_EMAIL).
"""
import logging
from datetime import timedelta

from sqlalchemy import func, select

from app import credits as C, models as M
from app import ops_alerts

# Consecutive job failures before the founder is alerted. One failure is
# noise (transient DB/network); three in a row is a broken job.
JOB_FAILURE_ALERT_THRESHOLD = 3
# Failed analyses in the trailing window that count as "sustained".
SUSTAINED_FAILURE_THRESHOLD = 5
SUSTAINED_FAILURE_WINDOW_MINUTES = 60

_job_failures: dict[str, int] = {}


def reset_job_state() -> None:
    """Clear in-process job-failure counts. Tests only."""
    _job_failures.clear()


def _run_job(db, name, fn):
    """Run one maintenance job; alert on sustained (consecutive) failure.

    A job exception is contained: the session is rolled back and the loop
    continues with the next job. The failure count resets on the first
    success, so only an actually-broken job pages the founder — a single
    transient failure is just a log line.
    """
    log = logging.getLogger(__name__)
    try:
        result = fn(db)
    except Exception:
        if db is not None:
            try:
                db.rollback()
            except Exception:
                pass
        count = _job_failures.get(name, 0) + 1
        _job_failures[name] = count
        log.exception("Maintenance job %s failed (%d consecutive)", name, count)
        if count == JOB_FAILURE_ALERT_THRESHOLD:
            ops_alerts.send_ops_alert(
                f"Maintenance job failing: {name}",
                f"<p>Maintenance job <b>{name}</b> failed "
                f"{JOB_FAILURE_ALERT_THRESHOLD} times in a row. "
                "Check service logs for the tracebacks; the loop kept "
                "running its other jobs.</p>",
                dedupe_key=f"maintenance-job-{name}",
            )
        return None
    _job_failures[name] = 0
    return result


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


def count_stuck_reservations(db) -> dict:
    """Reservations held by work that is not progressing (issue #58).

    Paid operations stay 'reserved' past their lease, and free requests stay
    in_progress past their deadline, only when no executor-termination
    evidence arrived — recovery needs a human. Count them so the alert can
    name the scale of the pile-up.
    """
    now = C._utcnow()
    stuck_ops = db.scalar(
        select(func.count())
        .select_from(M.Operation)
        .where(M.Operation.status == "reserved", M.Operation.lease_expires_at < now)
    ) or 0
    stuck_free = db.scalar(
        select(func.count())
        .select_from(M.FreeRequest)
        .where(M.FreeRequest.status == "in_progress", M.FreeRequest.deadline < now)
    ) or 0
    return {"operations": stuck_ops, "free_requests": stuck_free}


def count_recent_failures(db, *, window_minutes=SUSTAINED_FAILURE_WINDOW_MINUTES) -> dict:
    """Analyses that failed inside the trailing window (issue #58)."""
    cutoff = C._utcnow() - timedelta(minutes=window_minutes)
    failed_ops = db.scalar(
        select(func.count())
        .select_from(M.Operation)
        .where(M.Operation.status == "failed", M.Operation.updated_at >= cutoff)
    ) or 0
    failed_free = db.scalar(
        select(func.count())
        .select_from(M.FreeRequest)
        .where(M.FreeRequest.status == "failed", M.FreeRequest.updated_at >= cutoff)
    ) or 0
    return {"operations": failed_ops, "free_requests": failed_free}


def check_ops_signals(db) -> dict:
    """Alert-worthy ops conditions; runs inside the maintenance loop.

    Returns the observed counts so tests and logs can assert on them.
    Alerts are throttled per condition (see app.ops_alerts).
    """
    signals: dict = {}
    stuck = count_stuck_reservations(db)
    signals["stuck_reservations"] = stuck
    if stuck["operations"] or stuck["free_requests"]:
        ops_alerts.send_ops_alert(
            "Stuck credit reservations need review",
            "<p>Credit reservations are held by work that is not progressing: "
            f"{stuck['operations']} paid operation(s) past their lease and "
            f"{stuck['free_requests']} free request(s) past their deadline. "
            "Recovery needs executor-termination evidence a human must "
            "supply — see service logs for the affected IDs.</p>",
            dedupe_key="stuck-reservations",
        )
    recent = count_recent_failures(db)
    signals["recent_failures"] = recent
    if recent["operations"] + recent["free_requests"] >= SUSTAINED_FAILURE_THRESHOLD:
        ops_alerts.send_ops_alert(
            "Sustained analysis failures",
            f"<p>{recent['operations'] + recent['free_requests']} analyses failed "
            f"in the last {SUSTAINED_FAILURE_WINDOW_MINUTES} minutes "
            f"({recent['operations']} paid, {recent['free_requests']} free). "
            "Check service logs for failure codes.</p>",
            dedupe_key="sustained-failures",
        )
    return signals


def _reconcile_all_accounts(db):
    accounts = db.scalars(select(M.CreditAccount.user_id)).all()
    db.rollback()
    for user_id in accounts:
        C.reconcile_account(db, user_id)


def _run_payment_reconciliation(db):
    # Issue #72: daily Stripe-to-ledger reconciliation. Guarded so a
    # job failure never breaks the maintenance loop.
    from app import payment_reconcile as PR
    PR.run_payment_reconciliation_if_due(db)


def run_once(*, reconcile=False):
    from app.db import SessionLocal
    from app.main import cleanup_pending_uploads
    _run_job(None, "cleanup_pending_uploads", lambda _db: cleanup_pending_uploads())
    with SessionLocal() as db:
        _run_job(db, "recover_expired_operations", C.recover_expired_operations)
        _run_job(db, "recover_free_requests", recover_free_requests)
        _run_job(db, "cleanup_results", cleanup_results)
        # Issue #70: abandoned checkouts must not sit pending forever.
        _run_job(db, "expire_stale_pending_purchases", C.expire_stale_pending_purchases)
        if reconcile:
            _run_job(db, "reconcile_accounts", _reconcile_all_accounts)
        _run_job(db, "payment_reconciliation", _run_payment_reconciliation)
        # Issue #58: ops signals alert the founder; never break the loop.
        _run_job(db, "ops_signals", check_ops_signals)


if __name__ == '__main__':
    run_once(reconcile=True)
