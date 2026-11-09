"""Daily Stripe-to-ledger reconciliation (issue #72).

Compares Stripe completed payments against ledger credit grants for the
same UTC calendar day, per pack, to the cent. Refunds and disputes count
as negative entries on the Stripe side even when the ledger holds no
matching reversal — they are economics, and an unmatched one is the
anomaly the founder must see (GFK-013 §6).

The Stripe mode follows the configured key (``stripe_billing._secret_key``
accepts ``sk_test_``/``sk_live_`` and ``rk_test_``/``rk_live_`` keys;
issues #126, #154).

Join path (per models.py): Stripe payment <-> credit_purchases
(stripe_session_id) <-> credit_grants (purchase_id) <-> credit_ledger
(event_key). Pack identity on the Stripe side comes from the Checkout
Session metadata (pack_id); refund/dispute charges are attributed to a
pack through their payment intent's Checkout Session, falling back to
charge metadata[pack_id] (set by create_checkout_session since this
issue), then to the pack "unknown".

Scheduling: ``run_payment_reconciliation_if_due`` is called from the
credit-maintenance loop (~every minute); it reconciles yesterday (the
most recent complete UTC day) plus any earlier unreconciled days, bounded
to LOOKBACK_DAYS behind. 'error' days are retried. Final rows (clean /
mismatch / skipped) are never re-run directly, but the maintenance scan
re-runs them inside the provisional window (PROVISIONAL_WINDOW_DAYS)
via ``force=True``, so a late webhook can heal a row computed before it
landed; rows older than the window stay final forever.
"""

from __future__ import annotations

import logging
from datetime import date, datetime, timedelta, timezone

import httpx
from sqlalchemy import func, select

from app import models as M
from app import stripe_billing as sb

logger = logging.getLogger(__name__)

STRIPE_API_BASE = "https://api.stripe.com/v1"
PAGE_LIMIT = 100
LOOKBACK_DAYS = 31  # backfill bound for the first run
REFUND_ATTRIBUTION_LOOKBACK_DAYS = 60  # late refunds still find their pack
SETTLE_LOOKBACK_DAYS = 4  # a session created on day D can settle at most
# ~4 days later: Checkout Sessions expire 24h after creation and Stripe
# retries webhook delivery for up to ~3 days, so the prior-session fetch
# below covers the theoretical worst case with margin.
PROVISIONAL_WINDOW_DAYS = 7  # final rows inside this window are re-run
# by the maintenance scan (force=True); covers the 4-day worst-case
# settlement lag plus margin. Older rows stay final forever.
OPEN_DISPUTE_STATUSES = ("needs_response", "under_review",
                         "warning_needs_response", "warning_under_review",
                         "warning_closed")
ALERT_ENV = "RECON_ALERT_EMAIL"
UNKNOWN_PACK = "unknown"


class ReconcileError(Exception):
    """The reconciliation job itself failed (Stripe/DB); the day is retried."""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def day_bounds(day: date) -> tuple[datetime, datetime]:
    """UTC day -> (inclusive start, exclusive end), tz-aware."""
    start = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
    return start, start + timedelta(days=1)


def _stripe_list(key: str, path: str, start_ts: int, end_ts: int,
                 extra: dict | None = None) -> list[dict]:
    """Paginated Stripe list call over a created-timestamp window.

    Raises ReconcileError on transport or API failure — the day is
    recorded 'error' and retried, never silently dropped.
    """
    out: list[dict] = []
    params: dict = {
        "created[gte]": start_ts,
        "created[lte]": end_ts - 1,
        "limit": PAGE_LIMIT,
    }
    if extra:
        params.update(extra)
    starting_after: str | None = None
    try:
        while True:
            if starting_after:
                params["starting_after"] = starting_after
            resp = httpx.get(
                f"{STRIPE_API_BASE}{path}",
                params=params,
                auth=(key, ""),
                timeout=30.0,
            )
            if resp.status_code != 200:
                logger.error("Stripe %s returned HTTP %s", path, resp.status_code)
                raise ReconcileError(f"Stripe {path} returned HTTP {resp.status_code}")
            body = resp.json()
            items = body.get("data", [])
            out.extend(items)
            if not body.get("has_more") or not items:
                break
            starting_after = items[-1]["id"]
    except ReconcileError:
        raise
    except Exception as exc:
        logger.error("Stripe %s request failed (%s)", path, type(exc).__name__)
        raise ReconcileError(f"Stripe {path} request failed") from exc
    return out


def fetch_day_sessions(key: str, day: date) -> list[dict]:
    """Paid Checkout Sessions created on the UTC day."""
    start, end = day_bounds(day)
    # NOTE: payment_status is a Checkout Session response field, not a
    # list parameter for GET /v1/checkout/sessions — sending it makes
    # Stripe return 400. Paid+complete filtering stays client-side below.
    sessions = _stripe_list(
        key, "/checkout/sessions",
        int(start.timestamp()), int(end.timestamp()),
    )
    # Client-side guard: only completed, paid sessions count as gross.
    return [
        s for s in sessions
        if s.get("payment_status") == "paid" and s.get("status") == "complete"
    ]


def fetch_prior_sessions(key: str, day: date) -> list[dict]:
    """Paid Checkout Sessions created in the settlement-lookback window.

    Sessions created on [day - SETTLE_LOOKBACK_DAYS, day - 1] may have
    settled (webhook-processed) on ``day``; the join bucketing in
    ``compute_reconciliation`` pairs them with their purchase's
    ``completed_at`` day. Filtered paid+complete exactly as
    ``fetch_day_sessions`` does.
    """
    start = datetime(day.year, day.month, day.day, tzinfo=timezone.utc) \
        - timedelta(days=SETTLE_LOOKBACK_DAYS)
    end = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
    sessions = _stripe_list(
        key, "/checkout/sessions",
        int(start.timestamp()), int(end.timestamp()),
    )
    return [
        s for s in sessions
        if s.get("payment_status") == "paid" and s.get("status") == "complete"
    ]


def fetch_day_charges(key: str, day: date) -> list[dict]:
    """Charges created on the UTC day (refund/dispute source).

    NOTE: no ``expand[]=data.dispute`` here. The current Stripe Charges
    reference lists no ``dispute`` attribute on Charge (only the
    ``disputed`` boolean), and the code pins no Stripe-Version header,
    so an expansion the account's API version does not support would
    400 the whole charges fetch and error every day. Dispute status
    instead comes from the separate disputes fetch below (the spec's
    documented fallback), which cannot fail the charges call.
    """
    start, end = day_bounds(day)
    return _stripe_list(
        key, "/charges",
        int(start.timestamp()), int(end.timestamp()),
    )


def fetch_day_disputes(key: str, day: date) -> list[dict]:
    """Disputes created on or after the UTC day, up to now.

    The spec's literal fallback window was ``[day - 90 days, day]``,
    which would miss a dispute opened AFTER day-end for a day charge
    (the common late-dispute case). Disputes for a day's charges are
    necessarily created at or after day-start, so ``[day_start, now]``
    is exactly complete at run time, and the 7-day window re-run picks
    up disputes that open later. Paginated via ``_stripe_list``.
    """
    start, _ = day_bounds(day)
    now = _utcnow()
    return _stripe_list(
        key, "/disputes",
        int(start.timestamp()), int(now.timestamp()) + 1,
    )


def _aggregate_disputes(disputes: list[dict]) -> dict:
    """One synthetic Dispute dict for a charge with several disputes.

    Stripe documents that a payment can have multiple disputes, and
    its list APIs return reverse chronological order — so a naive
    last-wins join keeps the OLDEST dispute and can drop a newer lost
    one behind an older won one (Codex P2 on PR #108). Grouping is
    therefore mandatory, not cosmetic. Money rule: only non-won
    disputes subtract, and ``compute_reconciliation`` already caps
    the per-charge portion at the unrefunded remainder, so summing
    non-won amounts cannot double-count beyond the charge. Status
    rule: lost beats open beats won (a lost dispute's funds are
    gone; an open one's may still reverse, but the lost amount is
    final); among open disputes the newest (first in list order)
    supplies the displayed status. A charge whose disputes are all
    won/charge_refunded aggregates to won with amount 0.
    Open-component rule (Codex P2(b) on PR #108): a lost aggregate
    must NOT hide a still-open dispute — the aggregate also carries
    ``open_amount`` (summed open-dispute cents) and ``open_status``
    (newest open dispute's status), so ``compute_reconciliation``
    can warn about the outstanding dispute alongside the lost
    status instead of recording the group as fully resolved.
    """
    non_won = [d for d in disputes
               if (d.get("status") or "unknown")
               not in ("won", "charge_refunded")]
    if not non_won:
        return {"status": "won", "amount": 0,
                "open_amount": 0, "open_status": None}
    amount = sum(int(d.get("amount") or 0) for d in non_won)
    open_disputes = [d for d in non_won
                     if (d.get("status") or "unknown")
                     in OPEN_DISPUTE_STATUSES]
    open_amount = sum(int(d.get("amount") or 0) for d in open_disputes)
    # First open in list order = newest open dispute.
    open_status = open_disputes[0].get("status") or "unknown" \
        if open_disputes else None
    lost = [d for d in non_won if d.get("status") == "lost"]
    if lost:
        status = "lost"
    else:
        # First non-won in list order = newest open dispute.
        status = non_won[0].get("status") or "unknown"
    return {"status": status, "amount": amount,
            "open_amount": open_amount, "open_status": open_status}


def attach_disputes(charges: list[dict], disputes: list[dict]) -> None:
    """Attach fetched Dispute objects to their charges, in place.

    Joined by ``dispute.charge`` and grouped per charge (see
    ``_aggregate_disputes`` — a charge with several disputes gets
    one aggregated object, never a last-wins overwrite). A charge
    that already carries an expanded dispute dict (the test seam
    supplies these) is left alone; a charge whose ``dispute`` is a
    bare id string or absent gets the fetched object. Unknown
    charges are ignored.
    """
    by_charge: dict[str, list[dict]] = {}
    for d in disputes:
        charge_id = d.get("charge")
        if isinstance(charge_id, str) and charge_id:
            by_charge.setdefault(charge_id, []).append(d)
    for c in charges:
        if not c.get("disputed"):
            continue
        if isinstance(c.get("dispute"), dict):
            continue
        group = by_charge.get(c.get("id"))
        if not group:
            continue
        c["dispute"] = group[0] if len(group) == 1 \
            else _aggregate_disputes(group)


def _pack_for_charge(charge: dict, pi_to_pack: dict[str, str]) -> str:
    """Attribute a charge to a pack: charge metadata, then PI->session map."""
    meta = charge.get("metadata") or {}
    if meta.get("pack_id"):
        return meta["pack_id"]
    pi = charge.get("payment_intent")
    if isinstance(pi, dict):
        pi = pi.get("id")
    if pi and pi in pi_to_pack:
        return pi_to_pack[pi]
    return UNKNOWN_PACK


def _ledger_refund_economics(db, ledger_entry) -> tuple[str, int]:
    """(pack, refunded cents) for a cash_refund ledger entry, best effort.

    Money lives on the purchase, not the ledger row (ledger deltas are
    credits), so the refund is valued at the reversed purchase's
    amount_cents via the ledger_grants -> credit_grants -> credit_purchases
    chain. Returns (UNKNOWN_PACK, 0) when the chain cannot be resolved.
    """
    try:
        grant_ids = db.execute(
            select(M.LedgerGrant.grant_id).where(
                M.LedgerGrant.ledger_entry_id == ledger_entry.id
            )
        ).scalars().all()
        if grant_ids:
            purchase_id = db.execute(
                select(M.CreditGrant.purchase_id).where(
                    M.CreditGrant.id.in_(grant_ids)
                )
            ).scalars().first()
            if purchase_id:
                pack_id, amount_cents = db.execute(
                    select(M.CreditPurchase.pack_id,
                           M.CreditPurchase.amount_cents).where(
                        M.CreditPurchase.id == purchase_id
                    )
                ).first() or (None, None)
                if pack_id and amount_cents:
                    return pack_id, int(amount_cents)
    except Exception:
        logger.exception("ledger refund economics lookup failed")
    return UNKNOWN_PACK, 0


def compute_reconciliation(
    db,
    day: date,
    sessions: list[dict],
    charges: list[dict],
    wide_sessions: list[dict] | None = None,
    *,
    prior_sessions: list[dict] | None = None,
) -> dict:
    """Compare Stripe and ledger sides for one UTC day.

    Returns the aggregate result dict (also what gets stored on the row):
    totals, per_pack breakdown, and the identified differences.

    ``prior_sessions`` are paid+complete sessions created in the
    settlement-lookback window (see SETTLE_LOOKBACK_DAYS). A session
    counts on the day of its matched purchase's ``completed_at`` when a
    matched completed purchase exists; otherwise it counts on its
    ``created`` day (i.e. only day-fetch sessions without a match count
    here — prior sessions without a match belong to their created day).
    """
    start, end = day_bounds(day)

    # --- Stripe side ---
    pi_to_pack: dict[str, str] = {}
    for s in sessions:
        pi = s.get("payment_intent")
        if isinstance(pi, dict):
            pi = pi.get("id")
        pack = (s.get("metadata") or {}).get("pack_id") or UNKNOWN_PACK
        if pi:
            pi_to_pack[pi] = pack
    if wide_sessions:
        for s in wide_sessions:
            pi = s.get("payment_intent")
            if isinstance(pi, dict):
                pi = pi.get("id")
            pack = (s.get("metadata") or {}).get("pack_id") or UNKNOWN_PACK
            if pi and pi not in pi_to_pack:
                pi_to_pack[pi] = pack

    # --- Settlement-day join bucketing (Finding 1a) ---
    # session_id -> latest completed_at, for completed purchases only
    # (more than one completed purchase sharing a session id should not
    # occur; the latest wins defensively).
    day_ids = {s["id"] for s in sessions}
    prior_only = [s for s in (prior_sessions or [])
                  if s["id"] not in day_ids]
    matched_latest: dict[str, datetime] = {}
    all_ids = [s["id"] for s in sessions] + [s["id"] for s in prior_only]
    if all_ids:
        for sid, completed_at in db.execute(
            select(M.CreditPurchase.stripe_session_id,
                   M.CreditPurchase.completed_at).where(
                M.CreditPurchase.status == "completed",
                M.CreditPurchase.stripe_session_id.in_(all_ids),
            )
        ).all():
            if sid is None or completed_at is None:
                continue
            if sid not in matched_latest or completed_at > matched_latest[sid]:
                matched_latest[sid] = completed_at
        # Remediation2 P2-B: product purchases join the SAME
        # settlement-date bucketing BEFORE family partitioning.
        # Previously matched_latest was credit-only, so a product
        # session created before UTC midnight and settled after
        # counted on its creation day (orphan there, since the
        # product ledger gross keys on completed_at) and was missing
        # from its settlement day's prior_sessions pairing — false
        # mismatches on BOTH days. Product purchases whose current
        # status moved on to refunded/disputed still settled on
        # their completed_at, so they bucket identically.
        # Remediation4 (fix 6): the product bucketing anchor is the
        # persisted Stripe charge creation time when present (the
        # day the Stripe charge fetch keys on), falling back to
        # completed_at for pre-0020 rows — so a charge created
        # before midnight but settled after it counts on its
        # CHARGE day on both sides.
        for sid, _charge_created, completed_at in db.execute(
            select(M.ProductPurchase.stripe_session_id,
                   M.ProductPurchase.stripe_charge_created_at,
                   M.ProductPurchase.completed_at).where(
                M.ProductPurchase.status.in_(
                    ("completed", "refunded", "disputed")),
                M.ProductPurchase.completed_at.isnot(None),
                M.ProductPurchase.stripe_session_id.in_(all_ids),
            )
        ).all():
            if sid is None or completed_at is None:
                continue
            anchor_at = _charge_created if _charge_created is not None \
                else completed_at
            if sid not in matched_latest or anchor_at > matched_latest[sid]:
                matched_latest[sid] = anchor_at
    included: list[dict] = []
    for s in sessions:
        sid = s["id"]
        if sid in matched_latest and matched_latest[sid].date() != day:
            continue  # settled on another day: counts there, not here,
            # and must NOT appear as an orphan difference on this day
        included.append(s)
    for s in prior_only:
        sid = s["id"]
        if sid in matched_latest and matched_latest[sid].date() == day:
            included.append(s)  # cross-midnight settlement, paired here
        # else: belongs to its created day (or another settlement day)

    # Issue #164 (A8): partition by family ONCE at ingestion. Product
    # sessions never enter the pack buckets (previously they inflated
    # UNKNOWN_PACK); unknown stays a discrepancy, never absorbed.
    def _family_of(sess):
        meta = sess.get("metadata") or {}
        if meta.get("kind") == "product" or (meta.get("sku") and not meta.get("pack_id")):
            return "product"
        if meta.get("pack_id"):
            return "pack"
        return "unknown"
    product_included = [s for s in included if _family_of(s) == "product"]
    included = [s for s in included if _family_of(s) != "product"]
    stripe_gross: dict[str, int] = {}
    stripe_session_ids: set[str] = set()
    for s in included:
        pack = (s.get("metadata") or {}).get("pack_id") or UNKNOWN_PACK
        amount = int(s.get("amount_total") or 0)
        stripe_gross[pack] = stripe_gross.get(pack, 0) + amount
        stripe_session_ids.add(s["id"])
    product_stripe_gross = sum(int(s.get("amount_total") or 0) for s in product_included)
    product_stripe_session_ids = {s["id"] for s in product_included}

    # Issue #164 (A8/P2-2): charge-side family partition. A charge is
    # a PRODUCT charge when its own metadata says kind=product, OR
    # its PaymentIntent belongs to a product session (session/PI
    # metadata join — real Charge objects do NOT carry the PI's
    # metadata, so the charge-metadata check alone misses every real
    # product charge), OR its PI is snapshotted on a ProductPurchase
    # row. Product charges never enter the pack buckets (previously
    # they polluted UNKNOWN_PACK via _pack_for_charge).
    product_pis: set[str] = set()
    for _s in list(sessions) + list(wide_sessions or []):
        if _family_of(_s) == "product":
            _pi = _s.get("payment_intent")
            if isinstance(_pi, dict):
                _pi = _pi.get("id")
            if _pi:
                product_pis.add(_pi)
    _charge_pis = set()
    for _c in charges:
        _pi = _c.get("payment_intent")
        if isinstance(_pi, dict):
            _pi = _pi.get("id")
        if _pi:
            _charge_pis.add(_pi)
    if _charge_pis:
        for (_pi,) in db.execute(
            select(M.ProductPurchase.stripe_payment_intent_id).where(
                M.ProductPurchase.stripe_payment_intent_id.in_(_charge_pis))
        ).all():
            if _pi:
                product_pis.add(_pi)

    def _is_product_charge(c) -> bool:
        meta = c.get("metadata") or {}
        if meta.get("kind") == "product":
            return True
        pi = c.get("payment_intent")
        if isinstance(pi, dict):
            pi = pi.get("id")
        return bool(pi) and pi in product_pis

    stripe_refunds: dict[str, int] = {}
    stripe_disputes: dict[str, int] = {}
    refund_charges: list[dict] = []
    disputed_charges: list[dict] = []
    product_stripe_refunds = 0
    product_stripe_disputes = 0
    for c in charges:
        is_product = _is_product_charge(c)
        pack = _pack_for_charge(c, pi_to_pack)
        amount = int(c.get("amount") or 0)
        refunded = int(c.get("amount_refunded") or 0)
        if refunded > 0:
            if is_product:
                product_stripe_refunds += refunded
            else:
                stripe_refunds[pack] = stripe_refunds.get(pack, 0) + refunded
                refund_charges.append({"charge_id": c["id"], "pack": pack,
                                       "refunded_cents": refunded,
                                       "payment_intent": c.get("payment_intent")
                                       if isinstance(c.get("payment_intent"), str)
                                       else (c.get("payment_intent") or {}).get("id")})
        if c.get("disputed"):
            # Net lost amount per charge from the expanded dispute
            # object (Finding 2). A won or charge_refunded dispute
            # subtracts nothing; any other status subtracts at most
            # the unrefunded remainder, so a refunded+disputed charge
            # is never subtracted twice. Without an expanded object
            # the status is unknown and the full amount is subtracted
            # (the previous conservative behavior), flagged as such.
            dispute = c.get("dispute")
            if isinstance(dispute, dict):
                dispute_status = dispute.get("status") or "unknown"
                dispute_amount = int(dispute.get("amount") or amount)
            else:
                dispute_status = "unknown"
                dispute_amount = amount
            if dispute_status in ("won", "charge_refunded"):
                dispute_portion = 0
            else:
                dispute_portion = min(dispute_amount,
                                      max(0, amount - refunded))
            if dispute_portion > 0:
                if is_product:
                    # P2-2: product disputes count on the product
                    # Stripe side (previously product_stripe_disputes
                    # was initialised 0 and never populated) and never
                    # enter the pack disputed_charges differences.
                    product_stripe_disputes += dispute_portion
                    continue
                stripe_disputes[pack] = stripe_disputes.get(pack, 0) \
                    + dispute_portion
                entry = {"charge_id": c["id"], "pack": pack,
                         "disputed_cents": dispute_portion,
                         "status": dispute_status}
                # Aggregated groups only (single disputes carry the
                # raw Stripe object, which has no open_* keys): surface
                # a still-open component hidden behind a lost/unknown
                # aggregate status, so the difference note below can
                # warn about it (Codex P2(b) on PR #108). Codex P2 on
                # PR #112: open_amount is the GROSS summed open
                # amount, but disputed_cents is the capped deduction
                # — reporting the gross as the outstanding component
                # overstates what can reverse whenever the cap binds
                # (a refund, or open sums beyond the charge). Report
                # the reversible amount instead: the deduction minus
                # what would still deduct if every open dispute
                # resolved won. Keep the gross distinctly so no
                # information is lost.
                if isinstance(dispute, dict):
                    open_amount = int(dispute.get("open_amount") or 0)
                    if open_amount > 0:
                        unrefunded = max(0, amount - refunded)
                        still_deducted = min(dispute_amount - open_amount,
                                             unrefunded)
                        reversible = dispute_portion - still_deducted
                        # Codex P2 on PR #112 (zero-reversible case):
                        # when non-open disputes already exhaust the
                        # cap, reversible is 0 but the open dispute
                        # still needs attention — preserve its status
                        # and gross amount independently of positive
                        # reversible exposure, so the note below can
                        # warn about it without claiming the deduction
                        # may reverse.
                        entry["open_status"] = \
                            dispute.get("open_status") or "unknown"
                        if reversible > 0:
                            entry["open_disputed_cents"] = reversible
                        if open_amount != reversible:
                            entry["open_gross_disputed_cents"] = \
                                open_amount
                disputed_charges.append(entry)

    # --- Ledger side ---
    purchases = db.execute(
        select(M.CreditPurchase).where(
            M.CreditPurchase.status == "completed",
            M.CreditPurchase.completed_at >= start,
            M.CreditPurchase.completed_at < end,
        )
    ).scalars().all()
    ledger_gross: dict[str, int] = {}
    ledger_session_ids: set[str] = set()
    for p in purchases:
        ledger_gross[p.pack_id] = ledger_gross.get(p.pack_id, 0) + (p.amount_cents or 0)
        if p.stripe_session_id:
            ledger_session_ids.add(p.stripe_session_id)

    ledger_refunds: dict[str, int] = {}
    refund_entries = db.execute(
        select(M.CreditLedger).where(
            M.CreditLedger.reason == "cash_refund",
            M.CreditLedger.created_at >= start,
            M.CreditLedger.created_at < end,
        )
    ).scalars().all()
    for entry in refund_entries:
        pack, refund_cents = _ledger_refund_economics(db, entry)
        ledger_refunds[pack] = ledger_refunds.get(pack, 0) + refund_cents

    # --- Compare ---
    packs = sorted(set(stripe_gross) | set(stripe_refunds) | set(stripe_disputes)
                   | set(ledger_gross) | set(ledger_refunds))
    per_pack: dict[str, dict] = {}
    differences: list[dict] = []
    for pack in packs:
        sg = stripe_gross.get(pack, 0)
        sr = stripe_refunds.get(pack, 0)
        sd = stripe_disputes.get(pack, 0)
        lg = ledger_gross.get(pack, 0)
        lr = ledger_refunds.get(pack, 0)
        stripe_net = sg - sr - sd
        ledger_net = lg - lr
        diff = stripe_net - ledger_net
        per_pack[pack] = {
            "stripe_gross_cents": sg,
            "stripe_refund_cents": sr,
            "stripe_dispute_cents": sd,
            "ledger_gross_cents": lg,
            "ledger_refund_cents": lr,
            "stripe_net_cents": stripe_net,
            "ledger_net_cents": ledger_net,
            "diff_cents": diff,
        }
        if diff != 0:
            differences.append({
                "kind": "pack_total_mismatch",
                "pack": pack,
                "stripe_net_cents": stripe_net,
                "ledger_net_cents": ledger_net,
                "diff_cents": diff,
            })

    for s in included:
        if s["id"] not in ledger_session_ids:
            differences.append({
                "kind": "stripe_session_without_purchase",
                "stripe_session_id": s["id"],
                "pack": (s.get("metadata") or {}).get("pack_id") or UNKNOWN_PACK,
                "amount_cents": int(s.get("amount_total") or 0),
            })
    for p in purchases:
        if p.stripe_session_id and p.stripe_session_id not in stripe_session_ids:
            differences.append({
                "kind": "purchase_without_stripe_session",
                "purchase_id": str(p.id),
                "pack": p.pack_id,
                "amount_cents": p.amount_cents or 0,
            })
    for rc in refund_charges:
        differences.append({
            "kind": "stripe_refund",
            "charge_id": rc["charge_id"],
            "pack": rc["pack"],
            "refunded_cents": rc["refunded_cents"],
            "note": "negative entry; unmatched when the ledger has no cash_refund",
        })
    for dc in disputed_charges:
        # disputed_cents is the NET portion (capped at the unrefunded
        # remainder); won disputes append no entry at all (not an
        # anomaly). Open disputes may reverse — the 7-day re-run window
        # corrects the row if they later resolve to won. A mixed
        # lost+open group keeps status "lost" but must still warn
        # about its open component (Codex P2(b) on PR #108): the
        # open amount is still reversible and needs a response, so
        # recording the group as only "lost" would mislead the
        # founder alert.
        if dc["status"] in OPEN_DISPUTE_STATUSES:
            note = ("negative entry; dispute open (%s) — amount may "
                    "reverse" % dc["status"])
        else:
            if dc["status"] == "unknown":
                note = "negative entry; dispute status unknown"
            else:
                note = "negative entry; dispute status %s" % dc["status"]
            if dc.get("open_disputed_cents"):
                note += ("; also open dispute (%s, %s¢) still "
                         "outstanding — amount may reverse"
                         % (dc.get("open_status"),
                            dc["open_disputed_cents"]))
                if dc.get("open_gross_disputed_cents"):
                    note += (" (%s¢ gross open)"
                             % dc["open_gross_disputed_cents"])
            elif dc.get("open_gross_disputed_cents"):
                # Zero reversible exposure: the open dispute still
                # needs a response, but claiming the deduction may
                # reverse would be false — the cap is already
                # exhausted by other disputes.
                note += ("; also open dispute (%s, %s¢ gross open) "
                         "still outstanding — no amount reversible"
                         % (dc.get("open_status"),
                            dc["open_gross_disputed_cents"]))
        diff_entry = {
            "kind": "stripe_dispute",
            "charge_id": dc["charge_id"],
            "pack": dc["pack"],
            "disputed_cents": dc["disputed_cents"],
            "status": dc["status"],
            "note": note,
        }
        # Keep the open component structured, not just in the note:
        # the founder alert dumps the whole entry, and a later reader
        # should not have to parse the note to find the outstanding
        # amount. (Pure-open groups need no extra fields — their
        # status already says open.)
        if dc.get("open_disputed_cents"):
            diff_entry["open_disputed_cents"] = dc["open_disputed_cents"]
            diff_entry["open_status"] = dc.get("open_status")
            if dc.get("open_gross_disputed_cents"):
                diff_entry["open_gross_disputed_cents"] = \
                    dc["open_gross_disputed_cents"]
        elif dc.get("open_gross_disputed_cents"):
            diff_entry["open_status"] = dc.get("open_status")
            diff_entry["open_gross_disputed_cents"] = \
                dc["open_gross_disputed_cents"]
        differences.append(diff_entry)

    # --- Product family ledger side (A8) ---
    # Remediation4 (fix 6): product gross AND reversal membership
    # bucket by ONE shared anchor — the persisted Stripe charge
    # creation time (stripe_charge_created_at, migration 0020),
    # falling back to completed_at for pre-0020 rows. The Stripe
    # charge fetch keys on charge creation time, so a charge
    # created before midnight whose settlement was processed after
    # midnight must land on the charge day here too, not on the
    # local completed_at day.
    from sqlalchemy import and_ as _and, or_ as _or

    def _product_anchor_in_range():
        return _or(
            _and(M.ProductPurchase.stripe_charge_created_at.isnot(None),
                 M.ProductPurchase.stripe_charge_created_at >= start,
                 M.ProductPurchase.stripe_charge_created_at < end),
            _and(M.ProductPurchase.stripe_charge_created_at.is_(None),
                 M.ProductPurchase.completed_at >= start,
                 M.ProductPurchase.completed_at < end),
        )

    product_purchases = db.execute(
        select(M.ProductPurchase).where(
            M.ProductPurchase.status.in_(("completed", "refunded", "disputed")),
            _product_anchor_in_range(),
        )
    ).scalars().all()
    product_ledger_gross = sum(p.amount_cents or 0 for p in product_purchases)
    product_ledger_session_ids = {p.stripe_session_id for p in product_purchases if p.stripe_session_id}
    # Remediation2 P2-C: the product ledger refund total is the sum
    # of PERSISTED refunded amounts (product_purchases.refunded_cents,
    # migration 0018) — partial refunds included, at their partial
    # amount. Previously only status='refunded' rows counted, at
    # FULL amount, so a $3 partial on a $9 purchase left the ledger
    # net at 900 while the Stripe side netted 600: a permanent false
    # mismatch. Pre-0018 full-refund rows carry refunded_cents NULL
    # and fall back to their full amount_cents.
    # Remediation3 (findings 3+5): BOTH product reversal totals are
    # bucketed by the charge anchor — originally completed_at as the
    # ledger's proxy for the charge's creation day, which is exactly
    # where the Stripe charge loop above attributes amount_refunded
    # and dispute portions (it iterates charges CREATED this day).
    # The previous reversed_at (processing-day) bucketing counted a
    # refund processed days later on the processing day, where the
    # Stripe side never counts it: false mismatches on both days.
    # Remediation4 (fix 6) replaces the completed_at proxy with the
    # persisted charge creation time itself (see _product_anchor_
    # in_range above); pre-0020 rows still fall back to completed_at.
    # Membership is keyed on the DEDICATED reversal fields
    # (refunded_cents / refunded_at / dispute_lost_at, migrations
    # 0018+0019), never on reversal_kind/reversed_at alone: a later
    # dispute (or refund) event overwrites that provenance, and the
    # earlier deduction must survive the overwrite. Fallbacks keep
    # pre-0019 rows countable: refunded_cents set by the 0018-era
    # code, status='refunded' for pre-0018 full refunds, and
    # reversal_kind='dispute_lost' for pre-0019 lost disputes.
    product_refunded = db.execute(
        select(M.ProductPurchase).where(
            _product_anchor_in_range(),
            _or(M.ProductPurchase.refunded_at.isnot(None),
                M.ProductPurchase.refunded_cents.isnot(None),
                M.ProductPurchase.status == "refunded"),
        )
    ).scalars().all()
    product_ledger_refunds = sum(
        (p.refunded_cents if p.refunded_cents is not None
         else (p.amount_cents or 0) if p.status == "refunded" else 0)
        for p in product_refunded)
    # P2-2: product Stripe refunds/disputes were already partitioned
    # in the charge loop above via the PaymentIntent join (product_
    # stripe_refunds / product_stripe_disputes) — real charges do not
    # carry kind=product metadata on the charge object. The ledger
    # side of a lost dispute: purchases that EVER lost a dispute
    # (dedicated dispute_lost_at, or the pre-0019 provenance
    # fallback), bucketed by the charge anchor as above. The amount
    # is capped at the unrefunded remainder, mirroring the Stripe
    # side's per-charge cap, so a refunded-then-disputed (or
    # disputed-then-refunded) purchase is never deducted twice.
    # Remediation4 (fix 2): when the dispute's own amount was
    # persisted (disputed_cents, migration 0020), the deduction is
    # min(disputed_cents, amount - refunded) — a PARTIAL lost
    # dispute deducts only its amount, exactly as the Stripe side
    # caps it. Legacy rows without a persisted amount keep the
    # full-remainder behaviour as fallback.
    # Remediation5 (fix 1): disputed_cents holds only the LATEST
    # dispute event's amount, so a charge with several disputes was
    # still under-deducted (two lost disputes of 600 + 300 left
    # disputed_cents=300), and a won dispute could overwrite an
    # earlier lost one's amount. When per-dispute records exist
    # (product_purchase_disputes, migration 0021), the deduction is
    # min(SUM of that purchase's LOST dispute amounts, amount -
    # refunded) — the aggregate under the same cap, mirroring
    # _aggregate_disputes on the Stripe side. A lost record without
    # a persisted amount falls the whole purchase back to the
    # legacy computation below (its amount is unknowable here);
    # purchases with no records at all keep the legacy path
    # untouched (pre-0021 disputes, direct service-level calls).
    product_disputed = db.execute(
        select(M.ProductPurchase).where(
            _product_anchor_in_range(),
            _or(M.ProductPurchase.dispute_lost_at.isnot(None),
                M.ProductPurchase.reversal_kind == "dispute_lost"),
        )
    ).scalars().all()
    _dispute_records: dict = {}
    if product_disputed:
        for _rec in db.execute(
            select(M.ProductPurchaseDispute).where(
                M.ProductPurchaseDispute.product_purchase_id.in_(
                    [p.id for p in product_disputed]))
        ).scalars().all():
            _dispute_records.setdefault(_rec.product_purchase_id, []).append(_rec)

    def _ledger_dispute_cents(p) -> int:
        remainder = max(0, (p.amount_cents or 0) - (p.refunded_cents or 0))
        records = _dispute_records.get(p.id)
        if records:
            lost = [r for r in records if r.status == "lost"]
            if all(r.amount_cents is not None for r in lost):
                return min(sum(r.amount_cents for r in lost), remainder)
        if getattr(p, "disputed_cents", None) is not None:
            return min(p.disputed_cents, remainder)
        return remainder

    product_ledger_disputes = sum(
        _ledger_dispute_cents(p) for p in product_disputed)
    for s in product_included:
        if s["id"] not in product_ledger_session_ids:
            differences.append({
                "kind": "stripe_session_without_purchase", "family": "product",
                "stripe_session_id": s["id"],
                "amount_cents": int(s.get("amount_total") or 0),
            })
    for p in product_purchases:
        if p.stripe_session_id and p.stripe_session_id not in product_stripe_session_ids:
            differences.append({
                "kind": "purchase_without_stripe_session", "family": "product",
                "purchase_id": str(p.id),
                "amount_cents": p.amount_cents or 0,
            })
    # Per-family check: every completed product purchase has exactly
    # one entitlement, and vice versa — a money-clean day with a
    # missing entitlement alerts.
    for p in product_purchases:
        if p.status != "completed":
            continue
        count = db.execute(
            select(func.count()).select_from(M.Entitlement).where(
                M.Entitlement.product_purchase_id == p.id)
        ).scalar() or 0
        if count != 1:
            differences.append({
                "kind": "product_purchase_entitlement_mismatch",
                "family": "product", "purchase_id": str(p.id),
                "entitlement_count": count,
            })
    product_stripe_net = product_stripe_gross - product_stripe_refunds - product_stripe_disputes
    product_ledger_net = product_ledger_gross - product_ledger_refunds - product_ledger_disputes
    if product_stripe_net != product_ledger_net:
        differences.append({
            "kind": "family_total_mismatch", "family": "product",
            "stripe_net_cents": product_stripe_net,
            "ledger_net_cents": product_ledger_net,
            "diff_cents": product_stripe_net - product_ledger_net,
        })
    per_family = {
        "pack": {
            "stripe_gross_cents": sum(stripe_gross.values()),
            "ledger_gross_cents": sum(ledger_gross.values()),
        },
        "product": {
            "stripe_gross_cents": product_stripe_gross,
            "stripe_refund_cents": product_stripe_refunds,
            "stripe_dispute_cents": product_stripe_disputes,
            "ledger_gross_cents": product_ledger_gross,
            "ledger_refund_cents": product_ledger_refunds,
            "ledger_dispute_cents": product_ledger_disputes,
            "stripe_net_cents": product_stripe_net,
            "ledger_net_cents": product_ledger_net,
            "diff_cents": product_stripe_net - product_ledger_net,
        },
    }

    return {
        "per_family": per_family,
        "stripe_gross_cents": sum(stripe_gross.values()) + product_stripe_gross,
        # P2-2: headline refund/dispute totals extend across BOTH
        # families consistently (previously product amounts counted
        # in gross only, leaving refund/dispute headlines pack-only).
        "stripe_refund_cents": sum(stripe_refunds.values()) + product_stripe_refunds,
        "stripe_dispute_cents": sum(stripe_disputes.values()) + product_stripe_disputes,
        "ledger_gross_cents": sum(ledger_gross.values()) + product_ledger_gross,
        "ledger_refund_cents": sum(ledger_refunds.values()) + product_ledger_refunds,
        "per_pack": per_pack,
        "differences": differences,
    }


def _send_mismatch_alert(day: date, result: dict) -> bool:
    """Founder-visible alert email. Returns True when delivered."""
    import os
    from app import email as email_module

    to = os.environ.get(ALERT_ENV, "")
    if not to:
        logger.warning("reconciliation mismatch for %s: %s not set, alert pending",
                       day, ALERT_ENV)
        return False
    lines = [
        f"<p>StackSift payment reconciliation found a mismatch for {day} (UTC).</p>",
        "<table><tr><th>pack</th><th>stripe net ¢</th><th>ledger net ¢</th>"
        "<th>diff ¢</th></tr>",
    ]
    for pack, pp in sorted(result["per_pack"].items()):
        lines.append(
            f"<tr><td>{pack}</td><td>{pp['stripe_net_cents']}</td>"
            f"<td>{pp['ledger_net_cents']}</td><td>{pp['diff_cents']}</td></tr>"
        )
    lines.append("</table><p>Differing records:</p><ul>")
    for d in result["differences"]:
        lines.append(f"<li>{d['kind']}: {d}</li>")
    lines.append("</ul>")
    sent = email_module.send_email(
        to,
        f"[StackSift] Payment reconciliation mismatch — {day}",
        "".join(lines),
    )
    if not sent:
        logger.error("reconciliation mismatch alert email failed for %s", day)
    return sent


def reconcile_day(db, day: date, *, stripe_get=None,
                  force: bool = False) -> M.PaymentReconciliation:
    """Reconcile one UTC day; idempotent (final rows are never re-run
    unless ``force=True``).

    An existing 'error' row is replaced on success and updated in place
    on failure. It must NOT be deleted upfront: on a failure the handler
    rolls back, which would resurrect the deleted row, and re-inserting
    it then violates recon_date's uniqueness — aborting the whole job
    scan (later days, alert-pending retry) on every tick of an outage
    once error days are retried by the job.

    A re-run over an existing row — ``force=True`` on a final row, or
    a non-force retry of an 'error' row — UPDATES IT IN PLACE (same
    ``id`` and ``created_at``; status, totals, per_pack, differences
    overwritten; error_note cleared) so no migration is needed. This
    is load-bearing for alert history: the old non-force success path
    delete+inserted, so an error row that had already alerted (a
    window re-run that failed after the alert went out) lost
    ``alert_sent`` on recovery and sent the alert a second time.
    Alert rules on any re-run: a recomputed mismatch keeps a previous
    ``alert_sent=True`` without re-sending; a previous
    ``alert_pending=True`` attempts delivery as usual; a recomputed
    clean clears ``alert_pending`` but keeps the historical
    ``alert_sent``. Any status flip logs a warning naming the day and
    the old -> new status. The not-configured branch is the one
    exception: it still delete+inserts a 'skipped' row.
    """
    existing = db.execute(
        select(M.PaymentReconciliation).where(
            M.PaymentReconciliation.recon_date == day
        )
    ).scalar_one_or_none()
    if (not force and existing is not None
            and existing.status in ("clean", "mismatch", "skipped")):
        return existing
    if not sb.checkout_configured():
        if existing is not None:
            db.delete(existing)
            db.flush()
        run = M.PaymentReconciliation(
            recon_date=day, status="skipped",
            error_note="Stripe checkout not configured; no payments could exist",
        )
        db.add(run)
        db.commit()
        return run

    try:
        key = sb._secret_key()  # mode follows the configured key
        if stripe_get is not None:
            sessions = stripe_get("sessions", day)
            charges = stripe_get("charges", day)
            wide = stripe_get("wide_sessions", day)
            prior = stripe_get("prior_sessions", day)
        else:
            sessions = fetch_day_sessions(key, day)
            charges = fetch_day_charges(key, day)
            if any(c.get("disputed") for c in charges):
                # Dispute status via the separate disputes fetch (see
                # fetch_day_charges): one extra call, only when a
                # disputed charge exists, never on the charges call.
                attach_disputes(charges, fetch_day_disputes(key, day))
            prior = fetch_prior_sessions(key, day)
            wide = None
            if any(int(c.get("amount_refunded") or 0) > 0 or c.get("disputed")
                   for c in charges):
                # Late refunds/disputes need their pack: one wider session
                # fetch, only when there is something to attribute.
                back = day - timedelta(days=REFUND_ATTRIBUTION_LOOKBACK_DAYS)
                wide = _stripe_list(
                    key, "/checkout/sessions",
                    int(datetime(back.year, back.month, back.day,
                                 tzinfo=timezone.utc).timestamp()),
                    int(day_bounds(day)[0].timestamp()) - 1,
                )
        result = compute_reconciliation(db, day, sessions, charges, wide,
                                        prior_sessions=prior)
    except ReconcileError as exc:
        db.rollback()
        # Re-fetch after the rollback: the pre-existing error row (if any)
        # is still there; update it in place rather than inserting a
        # second row for the same day (recon_date is unique).
        row = db.execute(
            select(M.PaymentReconciliation).where(
                M.PaymentReconciliation.recon_date == day
            )
        ).scalar_one_or_none()
        if row is None:
            row = M.PaymentReconciliation(
                recon_date=day, status="error", error_note=str(exc)[:500])
            db.add(row)
        else:
            # Deliberately untouched: alert_sent / alert_pending.
            # A failed re-run of an already-alerted mismatch row must
            # keep its alert history, or the recovery re-sends it
            # (Codex Finding 2 on PR #108).
            row.status = "error"
            row.error_note = str(exc)[:500]
        db.commit()
        return row

    status = "clean" if not result["differences"] else "mismatch"
    if existing is not None:
        # Any re-run over an existing row updates in place, preserving
        # id, created_at, and alert history (see the docstring: the
        # old non-force branch delete+inserted here, which re-sent an
        # already-delivered alert when an error row recovered).
        prev_status = existing.status
        prev_alert_sent = existing.alert_sent
        existing.status = status
        existing.stripe_gross_cents = result["stripe_gross_cents"]
        existing.stripe_refund_cents = result["stripe_refund_cents"]
        existing.stripe_dispute_cents = result["stripe_dispute_cents"]
        existing.ledger_gross_cents = result["ledger_gross_cents"]
        existing.ledger_refund_cents = result["ledger_refund_cents"]
        existing.per_pack = result["per_pack"]
        existing.per_family = result.get("per_family")
        existing.schema_version = 2
        existing.differences = result["differences"]
        existing.error_note = None
        if status == "mismatch":
            if prev_alert_sent:
                # Founder was already told; do not re-send.
                existing.alert_sent = True
                existing.alert_pending = False
            else:
                sent = _send_mismatch_alert(day, result)
                existing.alert_sent = sent
                existing.alert_pending = not sent
        else:
            existing.alert_pending = False
            existing.alert_sent = prev_alert_sent
        if prev_status != status:
            logger.warning("payment reconciliation status flip for %s: "
                           "%s -> %s", day, prev_status, status)
        run = existing
        db.add(run)
        db.commit()
    else:
        # Fresh day: no existing row (final rows return early above
        # unless forced, and forced rows take the in-place branch).
        run = M.PaymentReconciliation(
            recon_date=day,
            status=status,
            stripe_gross_cents=result["stripe_gross_cents"],
            stripe_refund_cents=result["stripe_refund_cents"],
            stripe_dispute_cents=result["stripe_dispute_cents"],
            ledger_gross_cents=result["ledger_gross_cents"],
            ledger_refund_cents=result["ledger_refund_cents"],
            per_pack=result["per_pack"],
            per_family=result.get("per_family"),
            schema_version=2,
            differences=result["differences"],
        )
        alert_pending = False
        alert_sent = False
        if status == "mismatch":
            alert_sent = _send_mismatch_alert(day, result)
            alert_pending = not alert_sent
        run.alert_sent = alert_sent
        run.alert_pending = alert_pending
        db.add(run)
        db.commit()
    if status == "mismatch":
        logger.warning("payment reconciliation mismatch for %s: %d differences",
                       day, len(result["differences"]))
    return run


def reconcile_missing_days(db, *, stripe_get=None, today: date | None = None
                           ) -> list[M.PaymentReconciliation]:
    """Reconcile every unreconciled UTC day up to yesterday.

    Starts at the earliest day with a completed purchase (bounded to
    LOOKBACK_DAYS back) when no reconciliation exists yet.

    Error days are revisited, not skipped: the scan starts at the
    earliest 'error' row when one exists. The previous watermark
    (latest recorded day + 1) silently abandoned an error day once any
    later day was recorded — e.g. the 2026-10-24 run errored on Stripe
    and was never retried because later days already had rows.
    reconcile_day itself is idempotent for final rows, so rescanning
    from the earliest error day costs only a DB read per settled day.
    """
    today = today or _utcnow().date()
    earliest_error = db.execute(
        select(func.min(M.PaymentReconciliation.recon_date)).where(
            M.PaymentReconciliation.status == "error"
        )
    ).scalar()
    last = db.execute(
        select(func.max(M.PaymentReconciliation.recon_date))
    ).scalar()
    if earliest_error is not None:
        start_day = earliest_error
    elif last is not None:
        start_day = last + timedelta(days=1)
    else:
        earliest = db.execute(
            select(func.min(M.CreditPurchase.completed_at)).where(
                M.CreditPurchase.status == "completed"
            )
        ).scalar()
        # Remediation4 (fix 6): the product scan start is the
        # earliest product ANCHOR day (charge creation, falling back
        # to completed_at) — starting at completed_at would skip the
        # charge day of a first-ever cross-midnight settlement, and
        # that day would never be reconciled at all.
        _earliest_product = db.execute(
            select(func.min(func.coalesce(
                M.ProductPurchase.stripe_charge_created_at,
                M.ProductPurchase.completed_at))).where(
                M.ProductPurchase.status == "completed"
            )
        ).scalar()
        if _earliest_product is not None and (earliest is None or _earliest_product < earliest):
            earliest = _earliest_product
        if earliest is not None:
            start_day = earliest.date()
        else:
            start_day = today - timedelta(days=1)
        floor = today - timedelta(days=LOOKBACK_DAYS)
        if start_day < floor:
            start_day = floor

    # Pre-scan snapshot of final rows: the window pass below must
    # force-re-run exactly these rows inside the window. "Not already
    # computed by this scan's main loop" (Finding 1b) means not freshly
    # computed by the main loop — a final row the main loop merely
    # visits (reconcile_day without force returns it untouched) still
    # needs the window re-run. The previous `wday < start_day` filter
    # got this wrong when start_day was an earliest ERROR day: later
    # final rows inside the window were visited but never recomputed,
    # so a late-webhook row after a persistent error day never healed
    # until the error day cleared. Fresh rows created by this scan's
    # main loop are not in the snapshot, so they are correctly excluded.
    pre_scan_final = set(db.execute(
        select(M.PaymentReconciliation.recon_date).where(
            M.PaymentReconciliation.status.in_(("clean", "mismatch",
                                                "skipped")),
        )
    ).scalars().all())

    runs: list[M.PaymentReconciliation] = []
    day = start_day
    while day < today:
        runs.append(reconcile_day(db, day, stripe_get=stripe_get))
        day += timedelta(days=1)
    # Provisional re-run window (Finding 1b): pre-scan final rows
    # inside the window are re-run with force=True, so a late webhook
    # heals a row computed before it landed. Window re-runs are NOT
    # appended to `runs` (the scan contract is unchanged); they are
    # observable through row state. A re-run that itself fails follows
    # the ReconcileError path (row becomes 'error' in place, retried
    # on the next tick).
    window_start = today - timedelta(days=PROVISIONAL_WINDOW_DAYS)
    for wday in sorted(pre_scan_final):
        if window_start <= wday < today:
            reconcile_day(db, wday, stripe_get=stripe_get, force=True)
    # Retry alert delivery for pending mismatches whose address is now set.
    for run in db.execute(
        select(M.PaymentReconciliation).where(
            M.PaymentReconciliation.alert_pending.is_(True)
        )
    ).scalars().all():
        if _send_mismatch_alert(run.recon_date,
                                {"per_pack": run.per_pack or {},
                                 "differences": run.differences or []}):
            run.alert_pending = False
            run.alert_sent = True
            db.commit()
    return runs


def run_payment_reconciliation_if_due(db) -> list[M.PaymentReconciliation]:
    """Maintenance-loop entry point. Never raises into the loop."""
    try:
        return reconcile_missing_days(db)
    except Exception:
        logger.exception("payment reconciliation failed")
        return []
