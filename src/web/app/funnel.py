"""Activation and purchase funnel instrumentation (issue #62).

Privacy contract (issue acceptance criteria):
- Events join by privacy-appropriate IDs only: the authenticated user_id,
  or a random anonymous session id for pre-account visitors.
- Log text, tokens, and filenames are NEVER recorded. ``record()`` enforces
  this with a denylist on meta keys and a scalar-only value rule.
- Capture counts are intent only — never demand evidence (GFK-013 §5.12).

Emission is best-effort: call sites use ``emit()``, which logs and swallows
failures so funnel telemetry can never break a money or analysis path.
``record()`` is the strict core used by tests.

The weekly-readable summary (``summary()`` / ``python -m app.funnel``) is
reviewed by the named reviewer below in the Goodfolk weekly marketing block
(operating process v1.1).
"""

from __future__ import annotations

import argparse
import logging
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from app import models

log = logging.getLogger(__name__)

# The named reviewer for the weekly funnel summary.
FUNNEL_REVIEWER = "Sunny — Goodfolk weekly marketing block (operating process v1.1)"

ANALYSIS_FIRST = "analysis_first"
EMAIL_VERIFIED = "email_verified"
EXPORT_INTENT = "export_intent"
PURCHASE_START = "purchase_start"
PURCHASE_SUCCESS = "purchase_success"
CREDIT_SPEND = "credit_spend"
REPEAT_PURCHASE = "repeat_purchase"

FUNNEL_EVENTS = frozenset(
    {
        ANALYSIS_FIRST,
        EMAIL_VERIFIED,
        EXPORT_INTENT,
        PURCHASE_START,
        PURCHASE_SUCCESS,
        CREDIT_SPEND,
        REPEAT_PURCHASE,
    }
)

# Ordered ladder for the weekly summary; each step's conversion is measured
# against the previous step.
FUNNEL_LADDER = (
    ANALYSIS_FIRST,
    EMAIL_VERIFIED,
    EXPORT_INTENT,
    PURCHASE_START,
    PURCHASE_SUCCESS,
    REPEAT_PURCHASE,
)

# Meta keys that must never be recorded: log content, auth material,
# filenames, network identifiers, and contact PII. Matching is
# case-insensitive. ``record()`` raises on any of these.
BANNED_META_KEYS = frozenset(
    {
        "log",
        "log_text",
        "logtext",
        "content",
        "token",
        "csrf",
        "csrf_token",
        "session_token",
        "filename",
        "file_name",
        "file",
        "filepath",
        "path",
        "ip",
        "ip_address",
        "email",
        "password",
        "secret",
        "api_key",
        "authorization",
    }
)

_SCALAR_TYPES = (str, int, float, bool)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _clean_meta(meta: dict | None) -> dict | None:
    if not meta:
        return None
    clean: dict = {}
    for key, value in meta.items():
        if not isinstance(key, str) or not key:
            raise ValueError("funnel meta keys must be non-empty strings")
        if key.lower() in BANNED_META_KEYS:
            raise ValueError(f"funnel meta forbids key {key!r}: privacy contract")
        if value is not None and not isinstance(value, _SCALAR_TYPES):
            raise ValueError(
                f"funnel meta value for {key!r} must be a scalar (str/int/float/bool)"
            )
        clean[key] = value
    return clean or None


def _identity_filter(query, user_id, anon_id):
    if user_id is not None:
        return query.filter(models.FunnelEvent.user_id == user_id)
    return query.filter(models.FunnelEvent.anon_id == anon_id)


def record(db, event: str, *, user_id=None, anon_id: str | None = None,
           meta: dict | None = None, once_per_identity: bool = False):
    """Insert one funnel event. Strict: raises on programmer errors.

    ``once_per_identity`` makes first-milestone events (analysis_first,
    email_verified) idempotent per identity: a second record for the same
    identity returns None instead of inserting.
    """
    if event not in FUNNEL_EVENTS:
        raise ValueError(f"unknown funnel event {event!r}")
    if user_id is None and not anon_id:
        raise ValueError("funnel event requires user_id or anon_id")
    clean = _clean_meta(meta)

    if once_per_identity:
        existing = _identity_filter(
            db.query(models.FunnelEvent.id).filter(models.FunnelEvent.event == event),
            user_id,
            anon_id,
        ).first()
        if existing is not None:
            return None

    row = models.FunnelEvent(
        id=uuid.uuid4(),
        user_id=user_id,
        anon_id=anon_id,
        event=event,
        occurred_at=_utcnow(),
        meta=clean,
    )
    db.add(row)
    db.flush()

    # A purchase that is not the user's first is also a repeat purchase.
    if event == PURCHASE_SUCCESS and user_id is not None:
        prior = (
            db.query(models.FunnelEvent.id)
            .filter(
                models.FunnelEvent.event == PURCHASE_SUCCESS,
                models.FunnelEvent.user_id == user_id,
                models.FunnelEvent.id != row.id,
            )
            .first()
        )
        if prior is not None:
            db.add(
                models.FunnelEvent(
                    id=uuid.uuid4(),
                    user_id=user_id,
                    anon_id=None,
                    event=REPEAT_PURCHASE,
                    occurred_at=_utcnow(),
                    meta=clean,
                )
            )
            db.flush()
    return row


def emit(db, event: str, **kwargs) -> None:
    """Best-effort emission for call sites: never raises.

    Funnel telemetry must not break analysis, auth, or money paths, so any
    failure is logged and swallowed here. Tests exercise ``record()``
    directly for the strict contract.
    """
    try:
        record(db, event, **kwargs)
    except Exception:
        log.exception("funnel event %s failed; continuing", event)


def emit_standalone(event: str, **kwargs) -> None:
    """Emit via a fresh session and commit. For call sites whose request
    transaction is read-only or may roll back (checkout, export intent,
    email verification): the funnel row must persist independently of the
    request's own transaction. Best-effort: never raises."""
    try:
        from app.db import SessionLocal

        with SessionLocal() as db:
            record(db, event, **kwargs)
            db.commit()
    except Exception:
        log.exception("funnel event %s failed; continuing", event)


def summary(db, days: int = 7) -> dict:
    """Weekly-readable funnel summary: counts and step-to-step conversion.

    Returns a plain dict; the CLI renders it as text for the named reviewer.
    """
    since = _utcnow() - timedelta(days=days)
    counts: dict[str, int] = {}
    for event in FUNNEL_EVENTS:
        counts[event] = (
            db.query(func.count(models.FunnelEvent.id))
            .filter(
                models.FunnelEvent.event == event,
                models.FunnelEvent.occurred_at >= since,
            )
            .scalar()
            or 0
        )
    ladder = []
    prev = None
    for event in FUNNEL_LADDER:
        count = counts[event]
        conv = (count / prev) if prev else None
        ladder.append({"event": event, "count": count, "conversion_from_prev": conv})
        prev = count
    spend_rows = (
        db.query(models.FunnelEvent.meta)
        .filter(
            models.FunnelEvent.event == CREDIT_SPEND,
            models.FunnelEvent.occurred_at >= since,
        )
        .all()
    )
    credits_spent = sum(
        (row[0] or {}).get("credits", 0)
        for row in spend_rows
        if isinstance((row[0] or {}).get("credits", 0), int)
    )
    return {
        "window_days": days,
        "reviewer": FUNNEL_REVIEWER,
        "counts": counts,
        "ladder": ladder,
        "credit_spend_events": counts[CREDIT_SPEND],
        "credits_spent": credits_spent,
    }


def render_text(report: dict) -> str:
    lines = [
        f"Funnel summary — last {report['window_days']} days (intent only, not demand evidence)",
        f"Reviewer: {report['reviewer']}",
        "",
        f"{'step':<18}{'count':>8}{'conv from prev':>16}",
    ]
    for step in report["ladder"]:
        conv = step["conversion_from_prev"]
        conv_s = f"{conv:>15.1%}" if conv is not None else f"{'—':>16}"
        lines.append(f"{step['event']:<18}{step['count']:>8}{conv_s}")
    lines += [
        "",
        f"credit_spend events: {report['credit_spend_events']}",
        f"credits spent:        {report['credits_spent']}",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Weekly funnel summary (issue #62)")
    parser.add_argument("--days", type=int, default=7, help="lookback window in days")
    args = parser.parse_args(argv)
    from app.db import SessionLocal

    with SessionLocal() as db:
        print(render_text(summary(db, days=args.days)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
