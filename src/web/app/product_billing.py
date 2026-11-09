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

def admission_lock_key(user_id, source_result_id, sku) -> str:
    return f"product-admission:{user_id}:{source_result_id}:{sku}"


def lock_product_admission(db: Session, user_id, source_result_id, sku):
    """Stable shared lock serialising checkout admission vs settlement
    (remediation2 P1-C).

    ``live_entitlement(for_update=True)`` cannot lock an ABSENT row:
    if settlement committed between checkout's entitlement lookup and
    its pending-purchase lookup, checkout created (and collected) a
    second purchase despite F1. Both sides therefore take this stable
    per-(user, source, sku) lock FIRST — a CapacityScope row via the
    house upsert-then-SELECT-FOR-UPDATE pattern (credits.
    _ensure_capacity_scope, the lock_global_paid_scope precedent) —
    so the entitlement lookup, the pending lookup, and the pending
    insert are atomic w.r.t. settlement's grant, and vice versa.
    Lock order: this scope precedes purchase/entitlement row locks on
    both sides. On SQLite FOR UPDATE is a no-op (house caveat); the
    PostgreSQL legs are the live evidence.
    """
    from app import credits as credits_helpers
    return credits_helpers._ensure_capacity_scope(
        db, admission_lock_key(user_id, source_result_id, sku), 1)


def _session_conclusively_expired(purchase) -> bool:
    """True only when Stripe CONFIRMS the purchase's session is dead
    (remediation2 P1-B). Local age alone never proves it: a session
    lives 24h from SESSION creation, which can postdate the row.

    - Session id recorded: ask the API. Only status 'expired' is
      conclusive; 'open'/'complete' mean the session can still (or
      did) take payment, and a retrieval failure is NOT evidence.
    - No session id recorded: a session, if Stripe created one at
      all, was created contemporaneously with the row (the only
      later-creation path — the checkout reuse branch — backfills
      the session id), so past 25h of row age every such session is
      conclusively past its 24h lifetime.
    """
    from app import stripe_billing
    if purchase.stripe_session_id:
        try:
            session = stripe_billing.fetch_checkout_session(
                purchase.stripe_session_id)
        except stripe_billing.CheckoutError:
            logger.warning(
                "product purchase %s: session state unconfirmed; "
                "treating as live", purchase.id)
            return False
        return session.get("status") == "expired"
    return _as_aware(purchase.created_at) <= _utcnow() - timedelta(hours=25)


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


def available_entitlement(db: Session, user_id, source_result_id, sku):
    """A live entitlement that can be redeemed RIGHT NOW, or None.

    Remediation4 (fixes 1+7): 'available' status inside the F5
    window (deadline at-or-after now, mirroring reserve_redemption's
    ``deadline < now`` lapse rule; a NULL deadline never lapses).
    Reserved/revoked/redeemed entitlements do not count — surfaces
    built on this helper must not offer a redemption that cannot
    proceed.
    """
    ent = live_entitlement(db, user_id, source_result_id, sku)
    if ent is None or ent.status != "available":
        return None
    if ent.redemption_deadline is not None and \
            _as_aware(ent.redemption_deadline) < _utcnow():
        return None
    return ent


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
    # P1-C: the stable admission lock is taken BEFORE either lookup,
    # and held (by the caller's transaction) across lookup + insert,
    # so settlement cannot commit an entitlement in between.
    lock_product_admission(db, user_id, source_result_id, sku)
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
        # Older than 23h: local age is NOT proof the session is dead
        # (P1-B — its 24h lifetime runs from session creation, which
        # can postdate this row). Retire the row ONLY when the
        # session is conclusively expired; otherwise reuse it, so a
        # payment on the original session still settles/grants
        # against this row instead of dying as a 'duplicate'.
        if not _session_conclusively_expired(pending):
            return pending, True
        pending.status = "failed"
        db.flush()
    from app import credits as credits_helpers
    purchase = models.ProductPurchase(
        user_id=user_id, sku=sku, source_result_id=source_result_id,
        amount_cents=entry["amount_cents"], currency=entry["currency"],
        stripe_price_id=stripe_billing.product_price_id(sku),
        pricing_version=credits_helpers.PRICING_VERSION, status="pending",
    )
    try:
        # P2-A: the savepoint is established BEFORE the purchase is
        # added/flushed. Adding first let the nested begin flush the
        # insert OUTSIDE the savepoint, so a pending-unique violation
        # aborted the OUTER transaction (PostgreSQL) and the winner
        # requery died with PendingRollbackError instead of reusing
        # the winner.
        with db.begin_nested():
            db.add(purchase)
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


def _coerce_stripe_timestamp(value):
    """Coerce a Stripe ``created`` value to an aware datetime.

    Accepts a datetime, unix seconds (int/float — the shape Stripe
    sends), or an ISO string; returns None for anything else.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return _as_aware(value)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        try:
            return _as_aware(datetime.fromisoformat(value))
        except ValueError:
            return None
    return None


def settle_product_purchase(db: Session, purchase, *, stripe_event_id: str,
                            stripe_session_id: str, event_metadata: dict,
                            amount_cents, currency, payment_intent_id,
                            payment_status, session_status, mode,
                            session_price_id, livemode=None,
                            stripe_charge_created_at=None) -> str:
    """Settle one product purchase exactly once (A4 + F4). Strict facts.

    Grants ONLY on checkout.session.completed with payment_status=paid,
    status=complete, mode=payment. Any fact failure: SettlementError,
    purchase marked failed (permanent mismatch), no entitlement.
    Returns 'processed' or 'duplicate'.
    """
    from app import credits as credits_helpers
    # P1-C: the SAME stable admission lock checkout takes, taken
    # BEFORE the purchase row lock (shared lock order), so a grant
    # cannot commit between a concurrent checkout's entitlement and
    # pending lookups.
    lock_product_admission(db, purchase.user_id, purchase.source_result_id,
                           purchase.sku)
    # Remediation3 P1: populate_existing=True — without it the
    # re-select returns the caller-loaded identity-map instance
    # WITHOUT refreshing its attributes, so a purchase whose row was
    # concurrently committed as 'refunded' (full refund of a pending
    # purchase) could still read stale status 'pending' here and be
    # settled, overwriting 'refunded' and granting an entitlement
    # for refunded money. Refresh under the row lock before testing.
    locked = db.execute(
        select(models.ProductPurchase).where(
            models.ProductPurchase.id == purchase.id).with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one()
    def _fail(note: str):
        logger.error("product webhook %s: purchase %s failed: %s",
                     stripe_event_id, purchase.id, note)
        locked.status = "failed"
        locked.stripe_event_id = stripe_event_id
        db.flush()
        raise SettlementError(note)

    def _validation_error():
        """The A4 strict-facts checks as a pure predicate: the
        failure note, or None when every fact checks out. Factored
        out of the grant path (remediation5 fix 2) so a purchase
        terminally reversed BEFORE completion can run the SAME
        validation before its payment facts are recorded for
        reconciliation — facts must never be recorded from an event
        settlement itself would have rejected."""
        if payment_status != "paid" or session_status != "complete" or mode != "payment":
            return "session is not a completed paid payment session"
        if livemode is not None:
            import os
            key = os.environ.get("STRIPE_SECRET_KEY", "")
            if key.startswith(("sk_test_", "rk_test_")) and livemode:
                return "live-mode event against test-mode keys"
            if key.startswith(("sk_live_", "rk_live_")) and not livemode:
                return "test-mode event against live-mode keys"
        if event_metadata.get("kind") != "product":
            return "metadata kind is not product"
        if event_metadata.get("sku") != locked.sku:
            return "metadata sku does not match purchase"
        if str(event_metadata.get("user_id", "")) != str(locked.user_id):
            return "metadata user_id does not match purchase"
        try:
            meta_pid = uuid.UUID(str(event_metadata.get("purchase_id", "")))
        except (ValueError, TypeError):
            meta_pid = None
        if meta_pid != locked.id:
            return "metadata purchase_id does not match purchase"
        try:
            meta_version = int(event_metadata.get("pricing_version", -1))
        except (TypeError, ValueError):
            meta_version = -1
        if meta_version != locked.pricing_version:
            return "pricing_version does not match purchase snapshot"
        if not isinstance(amount_cents, int) or amount_cents != locked.amount_cents:
            return "amount_total does not match purchase snapshot"
        if currency != locked.currency:
            return "currency does not match catalog currency"
        # A4(e) is unconditional (P3-4): the retrieved session Price ID
        # must equal the checkout-time snapshot. A missing snapshot is a
        # defence-in-depth failure too, not a skip — route-created rows
        # always snapshot a price (creation fails closed otherwise), so a
        # null snapshot means a manually seeded / corrupt row.
        if session_price_id != locked.stripe_price_id:
            return "session price id does not match purchase snapshot"
        if locked.stripe_payment_intent_id and payment_intent_id != locked.stripe_payment_intent_id:
            return "payment intent does not match purchase"
        if locked.stripe_session_id and locked.stripe_session_id != stripe_session_id:
            return "event session id does not match purchase session id"
        return None

    def _record_reversed_payment_facts():
        """Remediation5 (fix 2): a purchase terminally reversed
        BEFORE checkout.session.completed (full refund -> 'refunded',
        lost dispute -> 'disputed') never recorded completed_at or
        the charge anchor, so compute_reconciliation excluded it
        permanently while Stripe included its paid session — the
        payment AND the reversal were both invisible on the ledger
        side, and the session surfaced as a false
        stripe_session_without_purchase. When the completion event
        arrives for such a purchase, validate it exactly as
        settlement validates session facts and, only on success,
        record the payment facts (completed_at and/or the
        charge-creation anchor) WITHOUT granting an entitlement,
        changing the terminal status, or resurrecting the purchase,
        so reconciliation accounts for both sides. NULL-guarded:
        redelivery is idempotent and a settled purchase's recorded
        facts never move."""
        note = _validation_error()
        if note is not None:
            logger.warning("product webhook %s: purchase %s already "
                           "%s; completion facts NOT recorded (%s)",
                           stripe_event_id, purchase.id, locked.status,
                           note)
            return
        if locked.completed_at is None:
            locked.completed_at = _utcnow()
        _anchor = _coerce_stripe_timestamp(stripe_charge_created_at)
        if _anchor is not None and locked.stripe_charge_created_at is None:
            locked.stripe_charge_created_at = _anchor
        db.flush()

    if locked.status != "pending":
        if locked.status in ("refunded", "disputed"):
            _record_reversed_payment_facts()
        logger.info("product webhook %s: purchase %s already %s",
                    stripe_event_id, purchase.id, locked.status)
        return "duplicate"
    if locked.reversal_kind == "dispute_lost":
        # Remediation3 P2 (defence for rows recorded before the
        # apply_dispute fix, which left a lost-disputed PENDING
        # purchase pending): a recorded lost dispute is terminal —
        # settlement must never grant. Repair the row to the same
        # terminal 'disputed' state apply_dispute now writes.
        # Remediation5 (fix 2): the row is terminally reversed from
        # this point, so its validated payment facts are recorded
        # for reconciliation exactly as for a 'disputed' row above.
        locked.status = "disputed"
        _record_reversed_payment_facts()
        db.flush()
        logger.info("product webhook %s: purchase %s has a lost "
                    "dispute; settlement refused", stripe_event_id,
                    purchase.id)
        return "duplicate"

    _error = _validation_error()
    if _error is not None:
        _fail(_error)
    if not locked.stripe_session_id:
        locked.stripe_session_id = stripe_session_id

    locked.status = "completed"
    locked.amount_cents = amount_cents
    locked.currency = currency
    locked.stripe_payment_intent_id = payment_intent_id
    locked.stripe_event_id = stripe_event_id
    locked.completed_at = _utcnow()
    # Remediation4 (fix 6): persist the Stripe charge creation anchor
    # carried on the completed session object (its ``created``), so
    # reconciliation can bucket this purchase by charge creation
    # time — the day the Stripe charge fetch keys on — instead of
    # the local settlement-processing time (completed_at), which a
    # delayed webhook delivery can push across midnight. When no
    # usable timestamp is carried, the column stays NULL and
    # reconciliation falls back to completed_at (the pre-0020
    # behaviour, preserved for rows settled without the anchor).
    _anchor = _coerce_stripe_timestamp(stripe_charge_created_at)
    if _anchor is not None:
        locked.stripe_charge_created_at = _anchor

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
    # Remediation3 P1: populate_existing for the same stale-instance
    # hazard as settle_product_purchase (a caller-stale 'pending'
    # must not overwrite a concurrently committed terminal status).
    locked = db.execute(
        select(models.ProductPurchase).where(
            models.ProductPurchase.id == purchase.id).with_for_update()
        .execution_options(populate_existing=True)
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
    # P1-B: age alone never retires a row whose session may still
    # take payment — each candidate must be conclusively expired
    # (Stripe-confirmed for rows with a session id; see
    # _session_conclusively_expired). Unconfirmed rows stay pending
    # and are re-examined on the next maintenance pass.
    cutoff = _utcnow() - timedelta(hours=older_than_hours)
    stale = db.execute(
        select(models.ProductPurchase).where(
            models.ProductPurchase.status == "pending",
            models.ProductPurchase.created_at < cutoff,
        ).with_for_update()
    ).scalars().all()
    expired = 0
    for purchase in stale:
        if not _session_conclusively_expired(purchase):
            continue
        purchase.status = "failed"
        expired += 1
    db.flush()
    return expired


# ---------------------------------------------------------------------------
# Revocation / reversals (A5 + F3)
# ---------------------------------------------------------------------------

def revoke_entitlement(db: Session, entitlement) -> bool:
    """CAS available|reserved -> revoked. Wins over late complete/release:
    those paths re-check the entitlement status under lock and fail."""
    locked = db.execute(
        select(models.Entitlement).where(
            models.Entitlement.id == entitlement.id).with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one()
    if locked.status in ("revoked", "redeemed", "refund_eligible"):
        return False
    locked.status = "revoked"
    locked.version += 1
    db.flush()
    return True


def _locked_entitlement_for_purchase(db: Session, purchase_id):
    """The purchase's entitlement, re-read UNDER ITS ROW LOCK.

    Remediation4 (fix 4): the manual-review decision (redeemed ->
    founder review, otherwise revoke) must be made on the committed
    entitlement state, not on an instance or unlocked read that a
    concurrent redemption completion can invalidate between the
    check and the act. ``populate_existing`` forces the refresh, and
    callers additionally honour ``revoke_entitlement``'s return, so
    a redemption that lands despite the refresh still flags manual
    review instead of being silently treated as revoked.
    """
    return db.execute(
        select(models.Entitlement).where(
            models.Entitlement.product_purchase_id == purchase_id)
        .with_for_update().execution_options(populate_existing=True)
    ).scalar_one_or_none()


def _revoke_or_flag_manual_review(db: Session, locked_purchase, ent) -> None:
    """Full-reversal entitlement act, decided on the LOCKED row."""
    if ent is None:
        return
    if ent.status == "redeemed":
        locked_purchase.needs_manual_review = True
        return
    if not revoke_entitlement(db, ent):
        # Revocation refused: the refreshed row is in a terminal
        # state our read did not predict. A redeemed artifact is
        # never clawed back — it flags for founder manual review;
        # already-revoked / refund_eligible needs nothing further.
        refreshed = db.execute(
            select(models.Entitlement).where(
                models.Entitlement.id == ent.id)
            .execution_options(populate_existing=True)
        ).scalar_one_or_none()
        if refreshed is not None and refreshed.status == "redeemed":
            locked_purchase.needs_manual_review = True


def apply_refund(db: Session, purchase, *, stripe_event_id: str,
                 refunded_cents: int, charge_amount_cents: int) -> str:
    """Record a charge.refunded against a product purchase (A5/F3).

    Partial refund: provenance only — the entitlement stays INTACT.
    Full refund: available/reserved entitlement revoked; a redeemed
    artifact is NOT clawed back and flags for founder manual review.
    A pending purchase that is fully refunded becomes terminal.
    """
    # Remediation3 P1: populate_existing for the same stale-instance
    # hazard as settle (status and refunded_cents must be the
    # committed values under the row lock, not a caller-stale copy).
    locked = db.execute(
        select(models.ProductPurchase).where(
            models.ProductPurchase.id == purchase.id).with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one()
    locked.reversal_event_id = stripe_event_id
    locked.reversal_kind = "refund"
    locked.reversed_at = _utcnow()
    # P2-C: persist the refunded amount (Stripe's amount_refunded is
    # cumulative per charge, so the latest event's value replaces —
    # never adds). Partials previously recorded provenance only, so
    # reconciliation's ledger side excluded the amount while the
    # Stripe side subtracted it: a permanent false mismatch. F3
    # semantics are unchanged: a partial never touches the
    # entitlement (below, only the full branch acts on it).
    # Remediation3 P2: persist the MAXIMUM cumulative amount, never a
    # direct assignment — out-of-order delivery of distinct partial-
    # refund events (e.g. the 600¢ event processed before the 300¢
    # event) must not regress the persisted total to the older,
    # smaller cumulative value. ``refunded_at`` (migration 0019)
    # moves only when the maximum moves, and is a dedicated field
    # dispute processing never touches, so a later dispute cannot
    # erase or move the refund deduction in reconciliation.
    previous_refunded = locked.refunded_cents or 0
    if refunded_cents > previous_refunded or locked.refunded_cents is None:
        locked.refunded_at = _utcnow()
    locked.refunded_cents = max(previous_refunded, refunded_cents)
    full = charge_amount_cents > 0 and locked.refunded_cents >= charge_amount_cents
    if not full:
        db.flush()
        return "partial_recorded"
    ent = _locked_entitlement_for_purchase(db, locked.id)
    # P3-5: a full refund is terminal from ANY non-terminal paid
    # state — including 'disputed' (dispute opened, then refunded):
    # leaving it 'disputed' after the money is gone would strand the
    # status machine inconsistent with the entitlement revocation.
    if locked.status in ("pending", "completed", "disputed"):
        locked.status = "refunded"
    # Remediation4 (fix 4): decide on the entitlement re-read under
    # its lock above; a concurrently redeemed entitlement flags
    # manual review instead of being treated as revocable.
    _revoke_or_flag_manual_review(db, locked, ent)
    db.flush()
    return "refunded"


def _record_product_dispute(db: Session, locked_purchase, *,
                              dispute_id, dispute_status,
                              disputed_cents) -> None:
    """Upsert the per-dispute record (remediation5 fix 1).

    Keyed by the Stripe dispute ID (unique), so created/closed
    events and webhook redeliveries of the SAME dispute update one
    row — never double-counted — and a won dispute can never erase
    an earlier lost dispute's amount, which lives on its own row.
    Amount: the dispute's own amount, replaced when an event
    carries one (a fact about that dispute, equal on redelivery).
    Status: closed events carry the final status and overwrite;
    a created event (``dispute_status=None``) marks the record
    'open' but never downgrades a recorded terminal outcome —
    an out-of-order or redelivered created event must not
    resurrect a lost/won dispute into the open bucket.
    """
    if not isinstance(dispute_id, str) or not dispute_id:
        return
    record = db.execute(
        select(models.ProductPurchaseDispute).where(
            models.ProductPurchaseDispute.stripe_dispute_id == dispute_id)
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if record is None:
        record = models.ProductPurchaseDispute(
            product_purchase_id=locked_purchase.id,
            stripe_dispute_id=dispute_id)
        try:
            # Savepoint before the insert (the create_pending P2-A
            # pattern): a concurrent delivery of the same dispute
            # tripping the unique constraint must not abort the
            # outer transaction — re-read the winner instead.
            with db.begin_nested():
                db.add(record)
                db.flush()
        except Exception:
            record = db.execute(
                select(models.ProductPurchaseDispute).where(
                    models.ProductPurchaseDispute.stripe_dispute_id == dispute_id)
            ).scalar_one_or_none()
            if record is None:
                raise
    if disputed_cents is not None:
        try:
            record.amount_cents = int(disputed_cents)
        except (TypeError, ValueError):
            logger.warning("product purchase %s: unusable disputed "
                           "amount %r for dispute %s; not persisted",
                           locked_purchase.id, disputed_cents, dispute_id)
    if dispute_status is None:
        if record.status not in ("lost", "won"):
            record.status = "open"
    else:
        record.status = str(dispute_status)
    record.updated_at = _utcnow()
    db.flush()


def apply_dispute(db: Session, purchase, *, stripe_event_id: str,
                  dispute_status: str | None,
                  disputed_cents: int | None = None,
                  dispute_id: str | None = None) -> str:
    """Record charge.dispute.created|closed (A5/F3).

    Open: purchase disputed + provenance, entitlement untouched (the
    dispute is not final). Closed/lost: full-revocation semantics.
    Closed/won: recorded + founder-manual flag; NEVER auto-restores a
    revoked entitlement (F3).

    Remediation5 (fix 1): when the event carries the Stripe dispute
    ID, amount + outcome are ALSO persisted per dispute
    (``_record_product_dispute``) — the purchase row's
    ``disputed_cents`` below remains latest-event provenance, but
    reconciliation aggregates the per-dispute records, so several
    disputes on one charge are never collapsed into the last one.
    """
    # Remediation3 P1: populate_existing for the same stale-instance
    # hazard as settle/apply_refund (the status transitions below
    # must act on the committed status, not a caller-stale copy —
    # a stale 'completed' must not resurrect a 'refunded' purchase
    # to 'disputed').
    locked = db.execute(
        select(models.ProductPurchase).where(
            models.ProductPurchase.id == purchase.id).with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one()
    locked.reversal_event_id = stripe_event_id
    locked.reversed_at = _utcnow()
    # Remediation4 (fix 2): persist the disputed amount Stripe
    # reported, on ANY dispute event that carries one (created and
    # closed alike), so a partial lost dispute deducts only its own
    # amount in reconciliation. The amount is a fact about the
    # dispute, not a cumulative total, so the latest reported value
    # stands (equal on redelivery of the same dispute).
    if disputed_cents is not None:
        try:
            locked.disputed_cents = int(disputed_cents)
        except (TypeError, ValueError):
            logger.warning("product purchase %s: unusable disputed "
                           "amount %r; not persisted", locked.id,
                           disputed_cents)
    # Remediation5 (fix 1): the per-dispute record is the
    # reconciliation source of truth (see _record_product_dispute).
    _record_product_dispute(db, locked, dispute_id=dispute_id,
                            dispute_status=dispute_status,
                            disputed_cents=disputed_cents)
    if dispute_status is None:  # dispute.created
        if locked.status == "completed":
            locked.status = "disputed"
        locked.reversal_kind = "dispute_open"
        db.flush()
        return "dispute_opened"
    if dispute_status == "lost":
        locked.reversal_kind = "dispute_lost"
        if locked.status in ("pending", "completed", "disputed"):
            # Remediation3 P2: a lost dispute is TERMINAL for a
            # pending purchase too. Previously pending was left
            # pending (no entitlement exists to revoke yet), so a
            # checkout-completion event arriving afterwards settled
            # and granted an entitlement despite the lost dispute.
            # 'disputed' is terminal for settlement (settle grants
            # only from 'pending'), exactly as a full refund's
            # 'refunded' is terminal for a pending purchase.
            # dispute_lost_at (migration 0019) is the dedicated,
            # overwrite-proof record reconciliation keys on; it is
            # NOT set when the purchase is already 'refunded' /
            # 'failed' — the Stripe side caps a lost dispute's
            # portion at the unrefunded remainder (zero there), so
            # recording a second deduction would double-count.
            locked.status = "disputed"
            locked.dispute_lost_at = _utcnow()
        # Remediation4 (fix 4): decide on the entitlement re-read
        # under its lock; a concurrently redeemed entitlement flags
        # manual review instead of being treated as revocable.
        ent = _locked_entitlement_for_purchase(db, locked.id)
        _revoke_or_flag_manual_review(db, locked, ent)
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
