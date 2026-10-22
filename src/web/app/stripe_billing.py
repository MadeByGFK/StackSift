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
dependency) so no new package is required. Settlement (webhook -> grant) is
issue #69; the metadata below is the contract it will settle on:

    metadata[user_id], metadata[pack_id], metadata[credits],
    metadata[pricing_version], client_reference_id = user_id
"""

from __future__ import annotations

import logging
import os
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


def create_checkout_session(
    *,
    user_id,
    pack_id: str,
    success_url: str,
    cancel_url: str,
) -> str:
    """Create a Stripe Checkout Session for a pack. Returns the session URL.

    One-time payment (mode=payment), quantity 1. The session carries the
    user and pack identity in metadata + client_reference_id so settlement
    (issue #69) can grant deterministically.
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
        "metadata[user_id]": str(user_id),
        "metadata[pack_id]": pack_id,
        "metadata[credits]": str(pack["credits"]),
        "metadata[pricing_version]": str(credits_helpers.PRICING_VERSION),
    }
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
        # Log the status only — Stripe error bodies can carry account detail.
        logger.error("Stripe checkout returned HTTP %s", resp.status_code)
        raise CheckoutError("Stripe request failed")
    url = resp.json().get("url")
    if not url:
        raise CheckoutError("Stripe returned no checkout URL")
    return url
