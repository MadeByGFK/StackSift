"""Operations alerting for paid-launch readiness (issue #58).

Founder-visible alert emails for conditions no customer should ever have to
report: sustained analysis failures, stuck credit reservations, and
maintenance-job failures. Ledger discrepancies are covered separately by
``payment_reconcile`` (issue #72).

All alerts go to OPS_ALERT_EMAIL via Resend (``app.email.send_email``). When
the address is unset, alerts are logged and dropped — the maintenance loop
never breaks over a missing address. The founder sets OPS_ALERT_EMAIL
alongside RECON_ALERT_EMAIL during the paid-launch checklist; it may be the
same address.
"""

from __future__ import annotations

import logging
import os
import time

logger = logging.getLogger(__name__)

ALERT_ENV = "OPS_ALERT_EMAIL"
# Minimum seconds between two alerts with the same dedupe key, per process.
# Deliberate and documented: the maintenance loop ticks every minute, and an
# unthrottled alert would page the owner every minute of an ongoing incident.
ALERT_MIN_INTERVAL_SECONDS = 3600

_last_sent: dict[str, float] = {}


def reset_alert_state() -> None:
    """Clear in-process alert throttle. Tests only."""
    _last_sent.clear()


def send_ops_alert(subject: str, html: str, *, dedupe_key: str | None = None) -> bool:
    """Send a founder-visible ops alert email. Returns True when delivered.

    Missing OPS_ALERT_EMAIL returns False; the condition is logged so the gap
    is visible in service logs. Repeated alerts for the same dedupe key are
    throttled to one per ALERT_MIN_INTERVAL_SECONDS per process.
    """
    from app import email as email_module

    key = dedupe_key or subject
    now = time.monotonic()
    last = _last_sent.get(key)
    if last is not None and now - last < ALERT_MIN_INTERVAL_SECONDS:
        logger.debug("ops alert throttled: %s", key)
        return False
    to = os.environ.get(ALERT_ENV, "")
    if not to:
        logger.warning("ops alert not sent (%s): %s not set", key, ALERT_ENV)
        return False
    sent = email_module.send_email(to, f"[StackSift] {subject}", html)
    if sent:
        _last_sent[key] = now
    else:
        logger.error("ops alert email failed: %s", key)
    return sent
