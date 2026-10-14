"""Email sending for StackSift Phase 1.

Uses Resend API (https://resend.com). In tests/dev, emails are logged
instead of sent if RESEND_API_KEY is not set.
"""

from __future__ import annotations

import logging
import os

import httpx

logger = logging.getLogger(__name__)

RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
FROM_EMAIL = os.environ.get("FROM_EMAIL", "noreply@goodfolkdigital.com")
APP_URL = os.environ.get("APP_URL", "https://stacksift.goodfolkdigital.com")


def send_email(to: str, subject: str, html: str) -> bool:
    """Send email via Resend. Returns True on success.

    If RESEND_API_KEY is not set, logs the email and returns True
    (dev/test mode — don't fail auth flows).
    """
    if not RESEND_API_KEY:
        logger.info("Email (not sent, no RESEND_API_KEY): to=%s subject=%s", to, subject)
        logger.info("Email body: %s", html)
        return True
    try:
        resp = httpx.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
            json={"from": FROM_EMAIL, "to": [to], "subject": subject, "html": html},
            timeout=10.0,
        )
        resp.raise_for_status()
        return True
    except httpx.HTTPError as e:
        logger.error("Failed to send email to %s: %s", to, e)
        return False


def send_verification_email(to: str, token: str) -> bool:
    """Send email verification link."""
    url = f"{APP_URL}/auth/verify?token={token}"
    html = f"""<p>Welcome to StackSift!</p>
<p>Please verify your email by clicking the link below:</p>
<p><a href="{url}">{url}</a></p>
<p>This link expires in 24 hours.</p>
<p>If you didn't create a StackSift account, ignore this email.</p>"""
    return send_email(to, "Verify your StackSift email", html)


def send_password_reset_email(to: str, token: str) -> bool:
    """Send password reset link."""
    url = f"{APP_URL}/auth/reset?token={token}"
    html = f"""<p>You requested a password reset for your StackSift account.</p>
<p>Click the link below to reset your password:</p>
<p><a href="{url}">{url}</a></p>
<p>This link expires in 1 hour.</p>
<p>If you didn't request this, ignore this email. Your password won't change.</p>"""
    return send_email(to, "Reset your StackSift password", html)
