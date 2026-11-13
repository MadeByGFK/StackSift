"""D2 attribution instrumentation (issue #156, MVP).

First-party only: no third-party analytics, no fingerprinting, no log
content or PII in events. Attribution rides on the #62 funnel contract —
events are rows in ``funnel_events`` with ``anon_id`` carrying the
``d2_visitor_id`` cookie value; UTM/referrer attribution rides in
``meta`` under the funnel's banned-key / scalar-only rules.

Cookies (set by middleware in app.main, HTML GET responses only):

- ``d2_visitor_id``: uuid4, HttpOnly, SameSite=Lax, 180 days. Set when
  absent (a malformed value counts as absent and is replaced) AND the
  request carries any ``utm_*`` query param OR lands on ``/`` or
  ``/credits``. A present, valid value is never overwritten.
- ``d2_attribution``: first-touch JSON of the ``utm_*`` params (each
  truncated to 128 chars) plus the referrer HOST only. Set only when
  utm params are present and no attribution cookie exists yet.

Identity merge: signup / login / OAuth callback call ``link_visitor``,
which writes one ``d2_visitor_links`` row per visitor id. First merge
wins; rows are never rewritten.

Report: ``d2_summary(db, days)`` / ``python -m app.d2_attribution``.
Dedup key for uniques: the linked user_id if the visitor is linked,
else the anon_id (a linked visitor counts once across pre- and
post-merge events). Buyers are distinct users with a completed
purchase in the window; a buyer counts as exposed when their linked
visitor has an ``offer_viewed`` event at or before that purchase's
completion. When in doubt, the report undercounts.
"""

from __future__ import annotations

import argparse
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from sqlalchemy import func

from app import funnel, models

log = logging.getLogger(__name__)

VISITOR_COOKIE = "d2_visitor_id"
ATTRIBUTION_COOKIE = "d2_attribution"
COOKIE_MAX_AGE = 180 * 24 * 3600  # 180 days
ATTRIBUTION_VALUE_CAP = 128

UTM_KEYS = ("utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term")
REFERRER_KEY = "referrer_host"

# Premium-intent kinds (issue #156 spec §6). Client-posted
# premium_intent events may only carry one of these; anything else is
# dropped rather than trusted.
PREMIUM_INTENT_KINDS = frozenset(
    {"checkout_start", "export_unlock", "analysis_report"}
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --- cookie values -----------------------------------------------------------

def valid_visitor_id(value) -> str | None:
    """Return the canonical string form of a valid UUID cookie value,
    else None (absent and malformed are both treated as no visitor)."""
    if not value or not isinstance(value, str):
        return None
    try:
        return str(uuid.UUID(value))
    except (ValueError, AttributeError, TypeError):
        return None


def visitor_id_from_cookies(cookies) -> str | None:
    try:
        return valid_visitor_id(cookies.get(VISITOR_COOKIE))
    except Exception:
        return None


def build_attribution(query_params, referrer: str | None) -> dict:
    """First-touch attribution from a landing request's query params.

    UTM values are truncated to 128 chars; the referrer contributes
    its host only — the full referrer URL is never stored.
    """
    attribution: dict = {}
    for key in UTM_KEYS:
        value = query_params.get(key)
        if value:
            attribution[key] = str(value)[:ATTRIBUTION_VALUE_CAP]
    if referrer:
        try:
            host = urlparse(referrer).hostname
        except ValueError:
            host = None
        if host:
            attribution[REFERRER_KEY] = host[:ATTRIBUTION_VALUE_CAP]
    return attribution


def parse_attribution_cookie(raw) -> dict:
    """Parse the ``d2_attribution`` cookie into funnel-safe meta.

    Only the known attribution keys survive, values are re-truncated
    server-side, and anything malformed yields an empty dict — client
    supplied attribution beyond this cookie is never trusted (the
    cookie itself is only ever written by our middleware).
    """
    if not raw or not isinstance(raw, str):
        return {}
    try:
        data = json.loads(raw)
    except ValueError:
        return {}
    if not isinstance(data, dict):
        return {}
    clean: dict = {}
    for key in UTM_KEYS + (REFERRER_KEY,):
        value = data.get(key)
        if isinstance(value, str) and value:
            clean[key] = value[:ATTRIBUTION_VALUE_CAP]
    return clean


def attribution_meta_from_cookies(cookies) -> dict:
    try:
        return parse_attribution_cookie(cookies.get(ATTRIBUTION_COOKIE))
    except Exception:
        return {}


# --- identity merge ----------------------------------------------------------

def link_visitor(db, visitor_id, user_id) -> bool:
    """Link ``visitor_id`` to ``user_id`` (first merge wins).

    Returns True when the visitor is linked to this user after the
    call (new row flushed, or an idempotent same-user re-merge) and
    False when the visitor id is invalid or already linked to a
    DIFFERENT user (the link is never stolen or rewritten). The
    caller owns the transaction: flush only, never commit, so auth
    call sites can commit (or roll back) on their own schedule.
    """
    vid = valid_visitor_id(visitor_id)
    if vid is None or user_id is None:
        return False
    existing = db.query(models.D2VisitorLink).filter(
        models.D2VisitorLink.visitor_id == vid).first()
    if existing is not None:
        if str(existing.user_id) == str(user_id):
            return True
        log.debug("d2 visitor already linked to a different user; ignoring")
        return False
    now = _utcnow()
    db.add(models.D2VisitorLink(
        visitor_id=vid, user_id=user_id, first_seen_at=now, merged_at=now))
    db.flush()
    return True


def link_visitor_best_effort(db, visitor_id, user_id) -> None:
    """Auth-path wrapper: link + commit, swallowing every failure so
    telemetry can never block signup, login, or OAuth."""
    try:
        if link_visitor(db, visitor_id, user_id):
            db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        log.exception("d2 visitor link failed; continuing")


# --- server-side emission helpers ---------------------------------------------

def emit_premium_intent(request, user_id, kind: str) -> None:
    """Best-effort premium_intent at a premium attempt entry point.

    Observe-only: funnel.emit_standalone never raises and never
    touches charging, credit logic, status codes, or balances.
    """
    meta = {"kind": kind}
    meta.update(attribution_meta_from_cookies(request.cookies))
    funnel.emit_standalone(
        funnel.PREMIUM_INTENT,
        user_id=user_id,
        anon_id=visitor_id_from_cookies(request.cookies),
        meta=meta,
    )


def emit_analysis_run(request, user_id, anon_id, kind: str) -> None:
    """Best-effort analysis_run at a successful analysis completion."""
    meta = {"kind": kind}
    try:
        meta.update(attribution_meta_from_cookies(request.cookies))
    except Exception:
        pass
    funnel.emit_standalone(
        funnel.ANALYSIS_RUN,
        user_id=user_id,
        anon_id=visitor_id_from_cookies(request.cookies) or anon_id,
        meta=meta,
    )


# --- report --------------------------------------------------------------------

def _identity_key(event, links: dict):
    """Dedup key for one funnel event: the event's own authenticated
    user_id wins when present; the visitor link applies only to
    anonymous events (Codex P2, PR #157: two accounts sharing one
    browser must not collapse into the link's first account)."""
    if event.user_id is not None:
        return ("user", str(event.user_id))
    anon_id = event.anon_id
    if anon_id and anon_id in links:
        return ("user", str(links[anon_id]))
    if anon_id:
        return ("anon", anon_id)
    return None


def d2_summary(db, days: int = 30) -> dict:
    """D2 funnel report for the last ``days`` days.

    Issue #164 Phase C (C6b): LEGACY-PACK-ONLY after cutover. Buyer
    counts here derive from CreditPurchase (pack) records only;
    dollar buyers are counted by the product purchase records, and
    no report may claim this summary measures the dollar funnel.

    Counts are intent only, never demand evidence (GFK-013 §5.12).
    Conservative by construction: identity-less events are skipped
    for uniques, and exposure requires a linked visitor with an
    offer_viewed at or before purchase completion.
    """
    since = _utcnow() - timedelta(days=days)
    links = {
        row.visitor_id: row.user_id
        for row in db.query(models.D2VisitorLink).all()
    }

    report: dict = {"window_days": days}
    for event_name in (funnel.OFFER_VIEWED, funnel.ANALYSIS_RUN,
                       funnel.PREMIUM_INTENT):
        events = (
            db.query(models.FunnelEvent)
            .filter(models.FunnelEvent.event == event_name,
                    models.FunnelEvent.occurred_at >= since)
            .all()
        )
        uniques = {
            key for key in (_identity_key(e, links) for e in events)
            if key is not None
        }
        entry = {"total": len(events), "uniques": len(uniques)}
        if event_name == funnel.PREMIUM_INTENT:
            kinds: dict[str, int] = {}
            for e in events:
                kind = (e.meta or {}).get("kind")
                if isinstance(kind, str) and kind:
                    kinds[kind] = kinds.get(kind, 0) + 1
            entry["kinds"] = kinds
        report[event_name] = entry

    purchases = (
        db.query(models.CreditPurchase)
        .filter(models.CreditPurchase.status == "completed",
                func.coalesce(models.CreditPurchase.completed_at,
                              models.CreditPurchase.created_at) >= since)
        .all()
    )
    buyers = {str(p.user_id) for p in purchases}
    report["buyers_total"] = len(buyers)

    # Exposure: the buyer's linked visitor viewed the offer at or
    # before that purchase completed.
    links_by_user: dict[str, list[str]] = {}
    for visitor_id, user_id in links.items():
        links_by_user.setdefault(str(user_id), []).append(visitor_id)
    exposed_buyers: set[str] = set()
    for purchase in purchases:
        visitor_ids = links_by_user.get(str(purchase.user_id))
        if not visitor_ids:
            continue
        completed_at = purchase.completed_at or purchase.created_at
        viewed = (
            db.query(models.FunnelEvent.id)
            .filter(models.FunnelEvent.event == funnel.OFFER_VIEWED,
                    models.FunnelEvent.anon_id.in_(visitor_ids),
                    models.FunnelEvent.occurred_at <= completed_at,
                    # An offer_viewed recorded under a DIFFERENT
                    # authenticated account on the same browser is not
                    # this buyer's exposure (Codex P2, PR #157).
                    (models.FunnelEvent.user_id.is_(None))
                    | (models.FunnelEvent.user_id == purchase.user_id))
            .first()
        )
        if viewed is not None:
            exposed_buyers.add(str(purchase.user_id))
    report["buyers_from_exposed"] = len(exposed_buyers)
    return report


def render_text(report: dict) -> str:
    lines = [
        f"D2 attribution summary — last {report['window_days']} days "
        "(intent only, not demand evidence)",
        "",
        f"offer_viewed:   total={report['offer_viewed']['total']} "
        f"uniques={report['offer_viewed']['uniques']}",
        f"analysis_run:   total={report['analysis_run']['total']} "
        f"uniques={report['analysis_run']['uniques']}",
        f"premium_intent: total={report['premium_intent']['total']} "
        f"uniques={report['premium_intent']['uniques']}",
    ]
    for kind, count in sorted(report["premium_intent"].get("kinds", {}).items()):
        lines.append(f"  kind={kind}: {count}")
    lines += [
        f"buyers_total:        {report['buyers_total']}",
        f"buyers_from_exposed: {report['buyers_from_exposed']}",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="D2 attribution summary (issue #156)")
    parser.add_argument("--days", type=int, default=30,
                        help="lookback window in days")
    args = parser.parse_args(argv)
    from app.db import SessionLocal

    with SessionLocal() as db:
        print(render_text(d2_summary(db, days=args.days)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
