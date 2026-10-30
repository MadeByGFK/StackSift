"""Daily Stripe-to-ledger reconciliation (issue #72).

Compares Stripe completed payments against ledger credit grants for the
same UTC calendar day, per pack, to the cent. Refunds and disputes count
as negative entries on the Stripe side even when the ledger holds no
matching reversal — they are economics, and an unmatched one is the
anomaly the founder must see (GFK-013 §6).

Test-mode ONLY: the Stripe key must start with ``sk_test_`` (enforced by
``stripe_billing._secret_key``); this module never touches live mode.

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
    """Charges created on the UTC day (refund/dispute source)."""
    start, end = day_bounds(day)
    return _stripe_list(
        key, "/charges",
        int(start.timestamp()), int(end.timestamp()),
        extra={"expand[]": "data.dispute"},
    )


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

    stripe_gross: dict[str, int] = {}
    stripe_session_ids: set[str] = set()
    for s in included:
        pack = (s.get("metadata") or {}).get("pack_id") or UNKNOWN_PACK
        amount = int(s.get("amount_total") or 0)
        stripe_gross[pack] = stripe_gross.get(pack, 0) + amount
        stripe_session_ids.add(s["id"])

    stripe_refunds: dict[str, int] = {}
    stripe_disputes: dict[str, int] = {}
    refund_charges: list[dict] = []
    disputed_charges: list[dict] = []
    for c in charges:
        pack = _pack_for_charge(c, pi_to_pack)
        amount = int(c.get("amount") or 0)
        refunded = int(c.get("amount_refunded") or 0)
        if refunded > 0:
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
                stripe_disputes[pack] = stripe_disputes.get(pack, 0) \
                    + dispute_portion
                disputed_charges.append({"charge_id": c["id"], "pack": pack,
                                         "disputed_cents": dispute_portion,
                                         "status": dispute_status})

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
        # corrects the row if they later resolve to won.
        if dc["status"] == "unknown":
            note = "negative entry; dispute status unknown"
        elif dc["status"] in OPEN_DISPUTE_STATUSES:
            note = ("negative entry; dispute open (%s) — amount may "
                    "reverse" % dc["status"])
        else:
            note = "negative entry; dispute status %s" % dc["status"]
        differences.append({
            "kind": "stripe_dispute",
            "charge_id": dc["charge_id"],
            "pack": dc["pack"],
            "disputed_cents": dc["disputed_cents"],
            "status": dc["status"],
            "note": note,
        })

    return {
        "stripe_gross_cents": sum(stripe_gross.values()),
        "stripe_refund_cents": sum(stripe_refunds.values()),
        "stripe_dispute_cents": sum(stripe_disputes.values()),
        "ledger_gross_cents": sum(ledger_gross.values()),
        "ledger_refund_cents": sum(ledger_refunds.values()),
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

    A ``force=True`` re-run of a final row UPDATES IT IN PLACE (same
    ``id`` and ``created_at``; status, totals, per_pack, differences
    overwritten; error_note cleared) so no migration is needed. Alert
    rules on a force re-run: a recomputed mismatch keeps a previous
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
        key = sb._secret_key()  # test-mode enforced here
        if stripe_get is not None:
            sessions = stripe_get("sessions", day)
            charges = stripe_get("charges", day)
            wide = stripe_get("wide_sessions", day)
            prior = stripe_get("prior_sessions", day)
        else:
            sessions = fetch_day_sessions(key, day)
            charges = fetch_day_charges(key, day)
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
            row.status = "error"
            row.error_note = str(exc)[:500]
        db.commit()
        return row

    status = "clean" if not result["differences"] else "mismatch"
    if existing is not None and force:
        # Force re-run: update in place, preserving id and created_at.
        prev_status = existing.status
        prev_alert_sent = existing.alert_sent
        existing.status = status
        existing.stripe_gross_cents = result["stripe_gross_cents"]
        existing.stripe_refund_cents = result["stripe_refund_cents"]
        existing.stripe_dispute_cents = result["stripe_dispute_cents"]
        existing.ledger_gross_cents = result["ledger_gross_cents"]
        existing.ledger_refund_cents = result["ledger_refund_cents"]
        existing.per_pack = result["per_pack"]
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
        if existing is not None:
            db.delete(existing)
            db.flush()
        run = M.PaymentReconciliation(
            recon_date=day,
            status=status,
            stripe_gross_cents=result["stripe_gross_cents"],
            stripe_refund_cents=result["stripe_refund_cents"],
            stripe_dispute_cents=result["stripe_dispute_cents"],
            ledger_gross_cents=result["ledger_gross_cents"],
            ledger_refund_cents=result["ledger_refund_cents"],
            per_pack=result["per_pack"],
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
