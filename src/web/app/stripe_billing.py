"""Phase 3: Stripe Checkout for credit packs (issue #68).

Test-mode ONLY. The secret key MUST start with ``sk_test_`` — live keys are
refused outright and never touch the network. Live activation is a separate
founder gate (issues #69+); this module must never enable it.

Each pack maps to a Stripe Price created in the sandbox account
("StackSift", test mode). Price IDs reach the app through environment
variables so no Stripe IDs are hardcoded:

    STRIPE_PRICE_STARTER  $5  -> 10 credits
    STRIPE_PRICE_GROWTH   $10 -> 25 credits
    STRIPE_PRICE_POWER    $25 -> 75 credits

A pack whose price env var is unset is shown as "Coming soon" and its
checkout attempt fails closed with 503 — the page works before the sandbox
products exist.

Calls go to the Stripe REST API directly (httpx is already a pinned
dependency) so no new package is required. Webhook signature verification
is HMAC-SHA256 over the raw body (hashlib/hmac only) — no new package.

Settlement contract (issue #69): the session carries

    metadata[purchase_id]   local CreditPurchase id (authoritative join key)
    metadata[user_id], metadata[pack_id], metadata[credits],
    metadata[pricing_version], client_reference_id = user_id

The webhook looks the purchase up by metadata[purchase_id] and backfills
stripe_session_id from the event; metadata[user_id]/credits must agree with
the purchase row or settlement fails closed.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import time

import httpx

from app import credits as credits_helpers

logger = logging.getLogger(__name__)

STRIPE_API_BASE = "https://api.stripe.com/v1"

# Pack catalog: display copy + the env var holding the pack's Stripe Price ID.
# Amounts are informational (the Price object is authoritative); the tests
# assert the correct price ID is sent per pack.
PACKS: dict[str, dict] = {
    "starter": {
        "name": "Starter",
        "price_label": "$5",
        "credits": 10,
        "econ": "$0.50 per credit \u00b7 ~5 PDF exports",
        "tagline": "Perfect for trying premium",
        "highlight": False,
        "badge": None,
        "price_env": "STRIPE_PRICE_STARTER",
    },
    "growth": {
        "name": "Growth",
        "price_label": "$10",
        "credits": 25,
        "econ": "$0.40 per credit \u00b7 ~12 PDF exports",
        "tagline": "25% more credits per dollar",
        "highlight": True,
        "badge": None,
        "price_env": "STRIPE_PRICE_GROWTH",
    },
    "power": {
        "name": "Power",
        "price_label": "$25",
        "credits": 75,
        "econ": "$0.33 per credit \u00b7 ~37 PDF exports",
        "tagline": "50% more credits per dollar",
        "highlight": True,
        "badge": "Best Value",
        "price_env": "STRIPE_PRICE_POWER",
    },
}


class CheckoutError(Exception):
    """Checkout cannot proceed (misconfiguration or Stripe failure)."""


class CheckoutNotConfigured(CheckoutError):
    """Stripe is not configured yet — fail closed, no partial checkout."""


class LiveKeyRefused(CheckoutError):
    """A live secret key was presented; this build never uses live mode."""


class WebhookNotConfigured(CheckoutError):
    """STRIPE_WEBHOOK_SECRET is not set — webhooks fail closed."""


def get_pack(pack_id: str) -> dict | None:
    """Return the pack definition, or None for an unknown pack id."""
    return PACKS.get(pack_id)


def pack_price_id(pack_id: str) -> str | None:
    """Return the configured Stripe Price ID for a pack, or None if unset."""
    pack = PACKS.get(pack_id)
    if pack is None:
        return None
    return os.environ.get(pack["price_env"]) or None


def packs_for_display() -> list[dict]:
    """Pack catalog for the credits page, with per-pack checkout readiness."""
    out = []
    for pack_id, pack in PACKS.items():
        out.append(
            {
                "id": pack_id,
                "name": pack["name"],
                "price_label": pack["price_label"],
                "credits": pack["credits"],
                "econ": pack["econ"],
                "tagline": pack["tagline"],
                "highlight": pack["highlight"],
                "badge": pack["badge"],
                "ready": pack_price_id(pack_id) is not None,
            }
        )
    return out


def checkout_configured() -> bool:
    """True when at least one pack has a price ID configured."""
    return any(p["ready"] for p in packs_for_display())


def _secret_key() -> str:
    """Return the Stripe secret key, enforcing test mode.

    Raises CheckoutNotConfigured when unset, LiveKeyRefused for live keys,
    CheckoutError for anything that is not a test key.
    """
    key = os.environ.get("STRIPE_SECRET_KEY", "")
    if not key:
        raise CheckoutNotConfigured("STRIPE_SECRET_KEY is not set")
    if key.startswith("sk_live_"):
        raise LiveKeyRefused("live Stripe keys are never used by this build")
    if not key.startswith("sk_test_"):
        raise CheckoutError("unrecognized Stripe key format")
    return key


def _webhook_secret() -> str:
    """Return the Stripe webhook signing secret.

    Raises WebhookNotConfigured when unset, LiveKeyRefused when a live
    secret key is configured (this build never settles live payments;
    live activation is a separate founder gate).
    """
    secret = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
    if not secret:
        raise WebhookNotConfigured("STRIPE_WEBHOOK_SECRET is not set")
    key = os.environ.get("STRIPE_SECRET_KEY", "")
    if key.startswith("sk_live_"):
        raise LiveKeyRefused("live Stripe keys are never used by this build")
    return secret


_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _stripe_error_detail(resp) -> str:
    """Summarize a Stripe API error body for the server logs.

    Extracts the structured ``error`` fields Stripe documents (type, code,
    param, message) so a failed checkout self-diagnoses from the app logs —
    the 2026-10-23 staging E2E hit a bare HTTP 400 with no hint in our logs
    and required dashboard spelunking. The raw body is NEVER logged: it can
    carry account detail. Email-looking values are redacted from the message.
    Returns a short fallback string when the body is not a JSON error object.
    """
    try:
        body = resp.json()
    except Exception:
        return "unparseable-body"
    err = body.get("error") if isinstance(body, dict) else None
    if not isinstance(err, dict):
        return "unparseable-body"
    parts = []
    for key in ("type", "code", "param"):
        value = err.get(key)
        if value:
            parts.append(f"{key}={value}")
    message = err.get("message")
    if message:
        message = _EMAIL_RE.sub("[redacted-email]", str(message))
        parts.append(f"message={message}")
    return " ".join(parts) or "empty-error"


def verify_stripe_signature(
    payload: bytes,
    header: str | None,
    secret: str,
    tolerance: int = 300,
) -> bool:
    """Verify a Stripe webhook signature (Stripe-Signature header).

    Stripe signs ``f"{timestamp}.{payload}"`` with HMAC-SHA256 and sends
    ``t=<ts>,v1=<sig>[,v1=<sig>...]``. Any v1 may match (key rotation);
    the timestamp must be within ``tolerance`` seconds of now. Anything
    unsigned, malformed, stale, or mismatched returns False — the caller
    answers 400 and touches no database rows.
    """
    if not header or not secret:
        return False
    try:
        parts: dict[str, list[str]] = {}
        for item in header.split(","):
            name, _, value = item.partition("=")
            name, value = name.strip(), value.strip()
            if name and value:
                parts.setdefault(name, []).append(value)
        timestamps = parts.get("t", [])
        signatures = parts.get("v1", [])
        if not timestamps or not signatures:
            return False
        ts = int(timestamps[0])
    except (ValueError, IndexError):
        return False
    if abs(time.time() - ts) > tolerance:
        return False
    signed = str(ts).encode("ascii") + b"." + payload
    expected = hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(expected, sig) for sig in signatures)


def create_checkout_session(
    *,
    user_id,
    pack_id: str,
    purchase_id,
    success_url: str,
    cancel_url: str,
    receipt_email: str | None = None,
) -> tuple[str, str]:
    """Create a Stripe Checkout Session for a pack.

    Returns ``(session_url, session_id)``. One-time payment (mode=payment),
    quantity 1. The session carries the user, pack, and purchase identity in
    metadata + client_reference_id so settlement (issue #69) can grant
    deterministically via metadata[purchase_id].

    ``receipt_email`` (issue #71): the purchasing user's account email. When
    set, it is passed as ``payment_intent_data[receipt_email]`` so Stripe
    emails the payment receipt to the buyer. No PII beyond the account email
    the user already gave us reaches Stripe.
    """
    pack = PACKS.get(pack_id)
    if pack is None:
        raise CheckoutError(f"unknown pack: {pack_id}")
    price_id = pack_price_id(pack_id)
    if not price_id:
        raise CheckoutNotConfigured(f"price not configured for pack {pack_id}")
    key = _secret_key()

    # Per-minute idempotency: a retried POST collapses into one session,
    # but a deliberate repeat purchase a minute later still works.
    idempotency_key = f"checkout:{user_id}:{pack_id}:{int(time.time() // 60)}"

    data = {
        "mode": "payment",
        "line_items[0][price]": price_id,
        "line_items[0][quantity]": "1",
        "success_url": success_url,
        "cancel_url": cancel_url,
        "client_reference_id": str(user_id),
        "metadata[purchase_id]": str(purchase_id),
        "metadata[user_id]": str(user_id),
        "metadata[pack_id]": pack_id,
        "metadata[credits]": str(pack["credits"]),
        "metadata[pricing_version]": str(credits_helpers.PRICING_VERSION),
    }
    if receipt_email:
        # Issue #71: Stripe sends the payment receipt to this address.
        data["payment_intent_data[receipt_email]"] = receipt_email
    # Issue #72: join keys on the payment intent so refund/dispute charges
    # (which carry PI metadata, not session metadata) attribute to a pack.
    data["payment_intent_data[metadata][purchase_id]"] = str(purchase_id)
    data["payment_intent_data[metadata][pack_id]"] = pack_id
    data["payment_intent_data[metadata][pricing_version]"] = str(
        credits_helpers.PRICING_VERSION
    )
    try:
        resp = httpx.post(
            f"{STRIPE_API_BASE}/checkout/sessions",
            data=data,
            auth=(key, ""),
            headers={"Idempotency-Key": idempotency_key},
            timeout=20.0,
        )
    except Exception as exc:
        logger.error("Stripe checkout request failed (%s)", type(exc).__name__)
        raise CheckoutError("Stripe request failed") from exc
    if resp.status_code != 200:
        # Log the structured Stripe error (type/code/param/message), never
        # the raw body — it can carry account detail. The user-facing error
        # stays generic; the detail is for the server logs only.
        detail = _stripe_error_detail(resp)
        logger.error("Stripe checkout returned HTTP %s (%s)", resp.status_code, detail)
        raise CheckoutError("Stripe request failed")
    body = resp.json()
    url = body.get("url")
    session_id = body.get("id")
    if not url or not session_id:
        raise CheckoutError("Stripe returned an incomplete checkout session")
    return url, session_id
