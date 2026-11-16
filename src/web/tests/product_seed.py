"""Issue #164 Phase A re-basing helper (A10 classification).

Seeds a completed product purchase + AVAILABLE entitlement for the
owner of a source Result, so legacy suites whose fixtures generated
the Analysis Report through the old 3-credit route can generate it
through the new dollar premise instead: POST /deep-dive redeems this
entitlement ($9 captured at checkout, in fixture terms) and touches
no credit rows. Idempotent: if a live entitlement already exists for
(buyer, source, sku) it is returned unchanged.
"""
from datetime import datetime, timedelta, timezone


def seed_entitlement_for_source(sessions, source_result_id):
    """sessions: zero-arg callable returning a DB session (the
    auth_env / route_env fixture pattern). Returns entitlement id."""
    from app import models
    db = sessions()
    try:
        source = db.get(models.Result, source_result_id)
        assert source is not None, f"no source Result {source_result_id}"
        user_id = source.user_id
        live = db.query(models.Entitlement).filter(
            models.Entitlement.user_id == user_id,
            models.Entitlement.source_result_id == source_result_id,
            models.Entitlement.sku == "investigation_report",
            models.Entitlement.status.in_(("available", "reserved")),
        ).first()
        if live is not None:
            return live.id
        now = datetime.now(timezone.utc)
        purchase = models.ProductPurchase(
            user_id=user_id, sku="investigation_report",
            source_result_id=source_result_id,
            amount_cents=900, currency="usd",
            stripe_price_id="price_test_investigation",
            pricing_version=1, status="completed", completed_at=now)
        db.add(purchase)
        db.flush()
        expires = source.expires_at
        if expires is not None and expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        ent = models.Entitlement(
            user_id=user_id, product_purchase_id=purchase.id,
            sku="investigation_report", source_result_id=source_result_id,
            status="available",
            redemption_deadline=(expires + timedelta(days=30))
            if expires is not None else None)
        db.add(ent)
        db.commit()
        return ent.id
    finally:
        db.close()
