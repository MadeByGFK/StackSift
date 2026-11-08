"""Issue #164 Phase A: product purchase / entitlement engine.

Generic per-product dollar engine proven on the Investigation Report.
Settlement grants an Entitlement and nothing else — no credits, no
ledger rows, no consent rows, ever, on this path (Decision 5).

Redemption discipline (A1) mirrors the credit Operation machinery:
durable redemption rows, worker identity + lease generation fencing,
CAS transitions on the entitlement, restart recovery that releases
ONLY with executor-stop evidence (else 'stopped'), and a revocation
CAS that wins over any late complete/release (A5).
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app import models

logger = logging.getLogger(__name__)

LEASE_TTL = timedelta(minutes=5)
REDEMPTION_WINDOW_DAYS = 30  # F5: source expiry + 30 days


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_aware(dt):
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


class ProductError(Exception):
    pass


class DuplicateEntitlement(ProductError):
    """F1: buyer already holds a live entitlement for (buyer, source, sku)."""
    def __init__(self, entitlement):
        super().__init__("existing entitlement")
        self.entitlement = entitlement


class SettlementError(ProductError):
    """Product settlement cannot proceed; purchase fails closed (A4)."""


# ---------------------------------------------------------------------------
# Purchases
# ---------------------------------------------------------------------------

def live_entitlement(db: Session, user_id, source_result_id, sku, *, for_update: bool = False):
    """An available|reserved entitlement for (buyer, source, sku), or None.

    ``for_update`` takes a row lock where the caller is about to act on
    the check (checkout creation, P2-1): on PostgreSQL this serialises
    concurrent checkouts against an existing live entitlement. The
    hard guarantee against two live entitlements is the partial unique
    index ``ix_entitlements_live_unique`` (models/migration 0017);
    the lock narrows the window, the index closes it.
    """
    stmt = select(models.Entitlement).where(
        models.Entitlement.user_id == user_id,
        models.Entitlement.source_result_id == source_result_id,
        models.Entitlement.sku == sku,
        models.Entitlement.status.in_(("available", "reserved")),
    ).order_by(models.Entitlement.created_at.desc())
    if for_update:
        stmt = stmt.with_for_update()
    return db.execute(stmt).scalars().first()


def create_pending_product_purchase(db: Session, user_id, sku: str, source_result_id):
    """Create/reuse the pending product purchase (A7) with F1 blocking.

    Returns (purchase, reused). A retry of the same (user, source, sku)
    while a pending purchase with a live session exists returns that
    purchase. While a live entitlement exists, NO new purchase is
    created (F1) — DuplicateEntitlement is raised.
    """
    from app import stripe_billing
    entry = stripe_billing.get_product_sku(sku)
    if entry is None:
        raise ProductError(f"unknown product sku: {sku}")
    existing_ent = live_entitlement(db, user_id, source_result_id, sku,
                                    for_update=True)
    if existing_ent is not None:
        raise DuplicateEntitlement(existing_ent)
    pending = db.execute(
        select(models.ProductPurchase).where(
            models.ProductPurchase.user_id == user_id,
            models.ProductPurchase.source_result_id == source_result_id,
            models.ProductPurchase.sku == sku,
            models.ProductPurchase.status == "pending",
        ).order_by(models.ProductPurchase.created_at.desc()).with_for_update()
    ).scalars().first()
    if pending is not None:
        if _as_aware(pending.created_at) > _utcnow() - timedelta(hours=23):
            # Reuse the row so a retry never creates a second purchase
            # or a second session for the same action. This holds BOTH
            # when a live session id is recorded AND in the A7 timeout
            # case (Stripe may have created the session but the local
            # row has no stripe_session_id): the caller re-creates /
            # retrieves the session under THIS row's idempotency key
            # (checkout:product:{purchase_id}), so Stripe returns the
            # original session instead of minting a second one (P2-1).
            return pending, True
        # Stale pending row (session lifetime is 24h): close it out so
        # the partial unique pending index lets a fresh row be created.
        pending.status = "failed"
        db.flush()
    from app import credits as credits_helpers
    purchase = models.ProductPurchase(
        user_id=user_id, sku=sku, source_result_id=source_result_id,
        amount_cents=entry["amount_cents"], currency=entry["currency"],
        stripe_price_id=stripe_billing.product_price_id(sku),
        pricing_version=credits_helpers.PRICING_VERSION, status="pending",
    )
    db.add(purchase)
    try:
        with db.begin_nested():
            db.flush()
    except Exception:
        # Partial unique pending index (P2-1): a concurrent checkout
        # won the insert race for this (user, source, sku). Reuse the
        # winner's row instead of surfacing a 500 or a duplicate.
        winner = db.execute(
            select(models.ProductPurchase).where(
                models.ProductPurchase.user_id == user_id,
                models.ProductPurchase.source_result_id == source_result_id,
                models.ProductPurchase.sku == sku,
                models.ProductPurchase.status == "pending",
            ).order_by(models.ProductPurchase.created_at.desc())
        ).scalars().first()
        if winner is None:
            raise
        return winner, True
    return purchase, False


def settle_product_purchase(db: Session, purchase, *, stripe_event_id: str,
                            stripe_session_id: str, event_metadata: dict,
                            amount_cents, currency, payment_intent_id,
                            payment_status, session_status, mode,
                            session_price_id, livemode=None) -> str:
    """Settle one product purchase exactly once (A4 + F4). Strict facts.

    Grants ONLY on checkout.session.completed with payment_status=paid,
    status=complete, mode=payment. Any fact failure: SettlementError,
    purchase marked failed (permanent mismatch), no entitlement.
    Returns 'processed' or 'duplicate'.
    """
    from app import credits as credits_helpers
    locked = db.execute(
        select(models.ProductPurchase).where(
            models.ProductPurchase.id == purchase.id).with_for_update()
    ).scalar_one()
    if locked.status != "pending":
        logger.info("product webhook %s: purchase %s already %s",
                    stripe_event_id, purchase.id, locked.status)
        return "duplicate"

    def _fail(note: str):
        logger.error("product webhook %s: purchase %s failed: %s",
                     stripe_event_id, purchase.id, note)
        locked.status = "failed"
        locked.stripe_event_id = stripe_event_id
        db.flush()
        raise SettlementError(note)

    if payment_status != "paid" or session_status != "complete" or mode != "payment":
        _fail("session is not a completed paid payment session")
    if livemode is not None:
        import os
        key = os.environ.get("STRIPE_SECRET_KEY", "")
        if key.startswith(("sk_test_", "rk_test_")) and livemode:
            _fail("live-mode event against test-mode keys")
        if key.startswith(("sk_live_", "rk_live_")) and not livemode:
            _fail("test-mode event against live-mode keys")
    if event_metadata.get("kind") != "product":
        _fail("metadata kind is not product")
    if event_metadata.get("sku") != locked.sku:
        _fail("metadata sku does not match purchase")
    if str(event_metadata.get("user_id", "")) != str(locked.user_id):
        _fail("metadata user_id does not match purchase")
    try:
        meta_pid = uuid.UUID(str(event_metadata.get("purchase_id", "")))
    except (ValueError, TypeError):
        meta_pid = None
    if meta_pid != locked.id:
        _fail("metadata purchase_id does not match purchase")
    try:
        meta_version = int(event_metadata.get("pricing_version", -1))
    except (TypeError, ValueError):
        meta_version = -1
    if meta_version != locked.pricing_version:
        _fail("pricing_version does not match purchase snapshot")
    if not isinstance(amount_cents, int) or amount_cents != locked.amount_cents:
        _fail("amount_total does not match purchase snapshot")
    if currency != locked.currency:
        _fail("currency does not match catalog currency")
    # A4(e) is unconditional (P3-4): the retrieved session Price ID
    # must equal the checkout-time snapshot. A missing snapshot is a
    # defence-in-depth failure too, not a skip — route-created rows
    # always snapshot a price (creation fails closed otherwise), so a
    # null snapshot means a manually seeded / corrupt row.
    if session_price_id != locked.stripe_price_id:
        _fail("session price id does not match purchase snapshot")
    if locked.stripe_payment_intent_id and payment_intent_id != locked.stripe_payment_intent_id:
        _fail("payment intent does not match purchase")
    if not locked.stripe_session_id:
        locked.stripe_session_id = stripe_session_id
    elif locked.stripe_session_id != stripe_session_id:
        _fail("event session id does not match purchase session id")

    locked.status = "completed"
    locked.amount_cents = amount_cents
    locked.currency = currency
    locked.stripe_payment_intent_id = payment_intent_id
    locked.stripe_event_id = stripe_event_id
    locked.completed_at = _utcnow()

    source = db.get(models.Result, locked.source_result_id)
    deadline = None
    if source is not None and source.expires_at is not None:
        deadline = _as_aware(source.expires_at) + timedelta(days=REDEMPTION_WINDOW_DAYS)
    else:
        deadline = _utcnow() + timedelta(days=REDEMPTION_WINDOW_DAYS + 7)
    entitlement = models.Entitlement(
        user_id=locked.user_id, product_purchase_id=locked.id, sku=locked.sku,
        source_result_id=locked.source_result_id, status="available",
        redemption_deadline=deadline,
    )
    db.add(entitlement)
    db.flush()
    logger.info("product webhook %s: purchase %s completed; entitlement %s",
                stripe_event_id, purchase.id, entitlement.id)
    return "processed"


def fail_product_purchase(db: Session, purchase, *, reason: str,
                          stripe_event_id: str | None = None) -> bool:
    locked = db.execute(
        select(models.ProductPurchase).where(
            models.ProductPurchase.id == purchase.id).with_for_update()
    ).scalar_one()
    if locked.status != "pending":
        return False
    locked.status = "failed"
    if stripe_event_id:
        locked.stripe_event_id = stripe_event_id
    db.flush()
    logger.info("product purchase %s marked failed: %s", purchase.id, reason)
    return True


def expire_stale_pending_product_purchases(db: Session, *, older_than_hours: int = 24) -> int:
    cutoff = _utcnow() - timedelta(hours=older_than_hours)
    stale = db.execute(
        select(models.ProductPurchase).where(
            models.ProductPurchase.status == "pending",
            models.ProductPurchase.created_at < cutoff,
        ).with_for_update()
    ).scalars().all()
    for purchase in stale:
        purchase.status = "failed"
    db.flush()
    return len(stale)


# ---------------------------------------------------------------------------
# Revocation / reversals (A5 + F3)
# ---------------------------------------------------------------------------

def revoke_entitlement(db: Session, entitlement) -> bool:
    """CAS available|reserved -> revoked. Wins over late complete/release:
    those paths re-check the entitlement status under lock and fail."""
    locked = db.execute(
        select(models.Entitlement).where(
            models.Entitlement.id == entitlement.id).with_for_update()
    ).scalar_one()
    if locked.status in ("revoked", "redeemed", "refund_eligible"):
        return False
    locked.status = "revoked"
    locked.version += 1
    db.flush()
    return True


def apply_refund(db: Session, purchase, *, stripe_event_id: str,
                 refunded_cents: int, charge_amount_cents: int) -> str:
    """Record a charge.refunded against a product purchase (A5/F3).

    Partial refund: provenance only — the entitlement stays INTACT.
    Full refund: available/reserved entitlement revoked; a redeemed
    artifact is NOT clawed back and flags for founder manual review.
    A pending purchase that is fully refunded becomes terminal.
    """
    locked = db.execute(
        select(models.ProductPurchase).where(
            models.ProductPurchase.id == purchase.id).with_for_update()
    ).scalar_one()
    full = charge_amount_cents > 0 and refunded_cents >= charge_amount_cents
    locked.reversal_event_id = stripe_event_id
    locked.reversal_kind = "refund"
    locked.reversed_at = _utcnow()
    if not full:
        db.flush()
        return "partial_recorded"
    ent = db.execute(
        select(models.Entitlement).where(
            models.Entitlement.product_purchase_id == locked.id)
    ).scalar_one_or_none()
    # P3-5: a full refund is terminal from ANY non-terminal paid
    # state — including 'disputed' (dispute opened, then refunded):
    # leaving it 'disputed' after the money is gone would strand the
    # status machine inconsistent with the entitlement revocation.
    if locked.status in ("pending", "completed", "disputed"):
        locked.status = "refunded"
    if ent is not None:
        if ent.status == "redeemed":
            locked.needs_manual_review = True
        else:
            revoke_entitlement(db, ent)
    db.flush()
    return "refunded"


def apply_dispute(db: Session, purchase, *, stripe_event_id: str,
                  dispute_status: str | None) -> str:
    """Record charge.dispute.created|closed (A5/F3).

    Open: purchase disputed + provenance, entitlement untouched (the
    dispute is not final). Closed/lost: full-revocation semantics.
    Closed/won: recorded + founder-manual flag; NEVER auto-restores a
    revoked entitlement (F3).
    """
    locked = db.execute(
        select(models.ProductPurchase).where(
            models.ProductPurchase.id == purchase.id).with_for_update()
    ).scalar_one()
    locked.reversal_event_id = stripe_event_id
    locked.reversed_at = _utcnow()
    if dispute_status is None:  # dispute.created
        if locked.status == "completed":
            locked.status = "disputed"
        locked.reversal_kind = "dispute_open"
        db.flush()
        return "dispute_opened"
    if dispute_status == "lost":
        locked.reversal_kind = "dispute_lost"
        if locked.status in ("completed", "disputed"):
            locked.status = "disputed"
        ent = db.execute(
            select(models.Entitlement).where(
                models.Entitlement.product_purchase_id == locked.id)
        ).scalar_one_or_none()
        if ent is not None:
            if ent.status == "redeemed":
                locked.needs_manual_review = True
            else:
                revoke_entitlement(db, ent)
        db.flush()
        return "dispute_lost_revoked"
    if dispute_status == "won":
        locked.reversal_kind = "dispute_won"
        locked.needs_manual_review = True
        db.flush()
        return "dispute_won_recorded"
    locked.reversal_kind = "dispute_open"
    db.flush()
    return "dispute_recorded"


# ---------------------------------------------------------------------------
# Redemption (A1)
# ---------------------------------------------------------------------------

def lock_redemption(db: Session, redemption_id):
    """Lock order: entitlement row, then redemption row (FOR UPDATE)."""
    red = db.execute(
        select(models.EntitlementRedemption).where(
            models.EntitlementRedemption.id == redemption_id)
    ).scalar_one_or_none()
    if red is None:
        from app.credits import AdmissionError
        raise AdmissionError("redemption not found")
    ent = db.execute(
        select(models.Entitlement).where(
            models.Entitlement.id == red.entitlement_id)
        .with_for_update().execution_options(populate_existing=True)
    ).scalar_one()
    red = db.execute(
        select(models.EntitlementRedemption).where(
            models.EntitlementRedemption.id == redemption_id)
        .with_for_update().execution_options(populate_existing=True)
    ).scalar_one()
    return red, ent


def reserve_redemption(db: Session, entitlement, *, request_hash: str, worker_id: str):
    """CAS available -> reserved + insert the live redemption row.

    Both writes happen in this one transaction: 'reserved' is never
    set without its live redemption row (A1 projection rule). An
    entitlement past its F5 deadline transitions to refund_eligible
    instead and raises DeadlineLapsed.
    """
    from app.credits import AdmissionError
    locked = db.execute(
        select(models.Entitlement).where(
            models.Entitlement.id == entitlement.id)
        .with_for_update().execution_options(populate_existing=True)
    ).scalar_one()
    if locked.status != "available":
        raise AdmissionError(f"entitlement is {locked.status}")
    if locked.redemption_deadline is not None and _as_aware(locked.redemption_deadline) < _utcnow():
        locked.status = "refund_eligible"
        locked.version += 1
        db.flush()
        raise DeadlineLapsed("redemption window has lapsed")
    now = _utcnow()
    result = db.execute(
        update(models.Entitlement)
        .where(models.Entitlement.id == locked.id,
               models.Entitlement.status == "available",
               models.Entitlement.version == locked.version)
        .values(status="reserved", version=locked.version + 1)
    )
    if result.rowcount != 1:
        raise AdmissionError("entitlement reservation lost the CAS race")
    redemption = models.EntitlementRedemption(
        entitlement_id=locked.id, source_result_id=locked.source_result_id,
        request_hash=request_hash, worker_id=worker_id, lease_generation=1,
        lease_expires_at=now + LEASE_TTL, status="reserved",
    )
    db.add(redemption)
    db.flush()
    db.refresh(locked)
    return redemption


class DeadlineLapsed(ProductError):
    pass


def complete_redemption(db: Session, redemption_id, worker_id: str, result_id=None,
                        *, lease_generation: int = 1):
    """reserved -> redeemed, fenced by worker + lease generation.

    Fails (AdmissionError) when the entitlement was revoked mid-flight:
    revocation CAS wins and the artifact must not publish (A5).
    """
    from app.credits import AdmissionError
    red, ent = lock_redemption(db, redemption_id)
    if red.status == "completed":
        return red
    if red.status != "reserved":
        raise AdmissionError(f"redemption already {red.status}")
    if red.worker_id != worker_id or red.lease_generation != lease_generation:
        raise AdmissionError("worker ownership mismatch")
    if _as_aware(red.lease_expires_at) < _utcnow():
        raise AdmissionError("lease expired")
    if ent.status == "revoked":
        raise AdmissionError("entitlement revoked")
    if ent.status != "reserved":
        raise AdmissionError(f"entitlement is {ent.status}")
    red.status = "completed"
    red.result_id = result_id
    ent.status = "redeemed"
    ent.version += 1
    ent.redeemed_result_id = result_id
    ent.redeemed_at = _utcnow()
    db.flush()
    return red


def release_redemption(db: Session, redemption_id, worker_id: str, failure_code: str,
                       *, lease_generation: int = 1):
    """reserved -> released; entitlement returns to available (F2:
    a generation failure NEVER consumes the purchase). A revoked
    entitlement is never revived by a release (A5)."""
    from app.credits import AdmissionError
    red, ent = lock_redemption(db, redemption_id)
    if red.status in ("released",):
        return red
    if red.status != "reserved":
        raise AdmissionError(f"redemption already {red.status}")
    if red.worker_id != worker_id or red.lease_generation != lease_generation:
        raise AdmissionError("worker ownership mismatch")
    if ent.status == "revoked":
        raise AdmissionError("entitlement revoked")
    red.status = "released"
    red.failure_code = str(failure_code)[:50]
    red.lease_generation += 1  # late publication from this executor is rejected
    if ent.status == "reserved":
        ent.status = "available"
        ent.version += 1
    db.flush()
    return red


def recover_expired_redemptions(db: Session, batch_size: int = 100, *, executor_stopped=None) -> int:
    """Restart recovery mirroring recover_expired_operations (A1).

    Expired leases: a stored Result completes the redemption; executor-
    stop evidence releases it back to available; without evidence the
    redemption is marked 'stopped' and the entitlement stays out of
    circulation until retry_stopped_redemption gets evidence.
    """
    candidates = db.execute(
        select(models.EntitlementRedemption.id, models.EntitlementRedemption.worker_id,
               models.EntitlementRedemption.lease_generation).where(
            models.EntitlementRedemption.status == "reserved",
            models.EntitlementRedemption.lease_expires_at < _utcnow(),
        ).order_by(models.EntitlementRedemption.lease_expires_at).limit(batch_size)
    ).all()
    db.rollback()
    recovered = 0
    for red_id, worker_id, generation in candidates:
        stopped = executor_stopped is not None and executor_stopped(red_id, worker_id, generation)
        try:
            red, ent = lock_redemption(db, red_id)
            if (red.status != "reserved" or _as_aware(red.lease_expires_at) >= _utcnow()
                    or red.worker_id != worker_id or red.lease_generation != generation):
                db.rollback()
                continue
            result = db.execute(
                select(models.Result).where(
                    models.Result.product_redemption_id == red_id,
                    models.Result.deleted_at.is_(None))).scalar_one_or_none()
            if result is not None:
                if ent.status == "revoked":
                    db.rollback()
                    continue
                red.status = "completed"
                red.result_id = result.id
                ent.status = "redeemed"
                ent.version += 1
                ent.redeemed_result_id = result.id
                ent.redeemed_at = _utcnow()
            elif stopped:
                red.status = "released"
                red.failure_code = "expired"
                red.lease_generation += 1
                if ent.status == "reserved":
                    ent.status = "available"
                    ent.version += 1
            else:
                red.status = "stopped"
                red.failure_code = "executor_unconfirmed"
                logger.warning("Expired redemption %s awaits executor termination evidence", red_id)
            db.commit()
            recovered += 1
        except Exception:
            db.rollback()
            logger.exception("redemption recovery failed for %s", red_id)
    return recovered


def retry_stopped_redemption(db: Session, redemption_id, *, executor_stopped) -> bool:
    """Retry-after-stopped path (A1): with executor-stop evidence for
    the stopped generation, release the entitlement back to available."""
    red, ent = lock_redemption(db, redemption_id)
    if red.status != "stopped":
        return False
    if not executor_stopped(red.id, red.worker_id, red.lease_generation):
        return False
    red.status = "released"
    red.failure_code = "expired"
    red.lease_generation += 1
    if ent.status == "reserved":
        ent.status = "available"
        ent.version += 1
    db.flush()
    return True


def lapse_expired_entitlements(db: Session) -> int:
    """F5: available entitlements past deadline -> refund_eligible."""
    rows = db.execute(
        select(models.Entitlement).where(
            models.Entitlement.status == "available",
            models.Entitlement.redemption_deadline.isnot(None),
            models.Entitlement.redemption_deadline < _utcnow(),
        ).with_for_update()
    ).scalars().all()
    for ent in rows:
        ent.status = "refund_eligible"
        ent.version += 1
    db.flush()
    return len(rows)
