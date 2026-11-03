"""StackSift web — free log-file analyzer.

Thin slice: upload a log file, get an incident summary. No accounts or retained upload archive. Rate-limited free tier; auth + credits come later once usage proves
demand.

Phase 1: Accounts added — email/password auth, Google/GitHub OAuth, sessions.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, Request, UploadFile
from app.db import get_db
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.rate_limit import (
    BurstLimited,
    HourlyLimited,
    PostgresRateLimiter,
    RateLimiter,
)
from app.client_ip import client_ip as _client_ip
from app.sample_data import SAMPLE_FILENAME, SAMPLE_LOG
from app.service import (
    analyze_upload,
    render_text_report,
    classify_upload_size,
    count_original_lines,
    MAX_OVERSIZE_UPLOAD_BYTES,
    MAX_OVERSIZE_UPLOAD_LINES,
    _is_binary_content,
)

# Phase 1: Auth
from app.auth_routes import router as auth_router

BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(title="StackSift", docs_url=None, redoc_url=None)


@app.on_event("startup")
async def run_migrations():
    """Upgrade the configured account database; keep anonymous analysis available."""
    import logging
    import os
    if not os.environ.get("DATABASE_URL"):
        return
    try:
        from alembic.config import Config
        from alembic import command
        from app.db import engine

        # Use the application's normalized URL/driver, not Alembic's raw env URL.
        # Programmatic config avoids resetting application loggers via fileConfig.
        cfg = Config()
        cfg.set_main_option("script_location", str(BASE_DIR.parent / "alembic"))
        with engine.begin() as connection:
            cfg.attributes["connection"] = connection
            command.upgrade(cfg, "head")
    except Exception as exc:
        # Driver errors may contain credentials/URLs; log the exception type only.
        logging.getLogger(__name__).error(
            "Account migrations failed (%s); account routes are unavailable.",
            type(exc).__name__,
        )


@app.on_event("startup")
async def start_credit_maintenance():
    import asyncio
    if not os.environ.get("DATABASE_URL"):
        return
    async def loop():
        from app.credit_maintenance import run_once
        tick = 0
        while True:
            await asyncio.sleep(60)
            try:
                await asyncio.to_thread(run_once, reconcile=(tick % 60 == 0))
            except Exception:
                logging.getLogger(__name__).exception("Credit maintenance failed")
            tick += 1
    app.state.credit_maintenance = asyncio.create_task(loop())


@app.on_event("shutdown")
async def stop_credit_maintenance():
    import asyncio
    task = getattr(app.state, "credit_maintenance", None)
    if task:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")
templates.env.globals["new_request_id"] = lambda: __import__("uuid").uuid4().hex
# Issue #105: report.html renders its structured-export price from the
# single credits constant (global so every report.html render site —
# fresh analysis, replay, saved report — shows the same ruled price).
from app import credits as _credits_template_globals
templates.env.globals["structured_export_cost"] = _credits_template_globals.COST_STRUCTURED_EXPORT
# Issue #107: report.html renders its retention price/unit from the same
# single ruled constants ("Extend 90 days — 1 credit").
templates.env.globals["retention_extension_cost"] = _credits_template_globals.COST_RETENTION_EXTENSION
templates.env.globals["retention_extension_days"] = _credits_template_globals.RETENTION_EXTENSION_DAYS

# Phase 1: Auth routes (signup, login, OAuth, sessions, settings)
app.include_router(auth_router)

# Free tier: 10 analyses per hour per IP. Tune as usage data comes in.
limiter = RateLimiter(max_requests=10, window_seconds=3600)
burst_limiter = RateLimiter(max_requests=2, window_seconds=60)
# PR #28: shared enforcement for multi-process deployments. Replaces the
# in-memory limiters above whenever the database is configured.
shared_limiter = PostgresRateLimiter(
    burst_max=2, burst_window=60, hourly_max=10, hourly_window=3600
)
# ISSUE-68: checkout-session creation shares the Postgres-backed enforcement
# so the 5/hour/IP cap holds across processes, under its own bucket key
# ("c:" + IP — short prefix because rate_limit_buckets.trusted_ip is
# String(45)) so checkout attempts never consume analysis quota. The burst
# window is widened to the hourly window, so admit() enforces the hourly
# cap only — checkout sessions are money-adjacent, so the cap is tighter
# than the notify-me one this replaces.
checkout_limiter = PostgresRateLimiter(
    burst_max=5, burst_window=3600, hourly_max=5, hourly_window=3600
)
# ISSUE-107: public share-view abuse limiter (draft §7) — 30/min and
# 300/hr per trusted IP, in the isolated "s:" key namespace (see
# app.report_access.share_limit_key), called WITHOUT request_id so no
# replay bypass exists, and fail-closed (503) on database errors.
# Production sharing requires this shared DB enforcement; the in-memory
# pair below serves only the no-database demo path, mirroring the
# analysis limiters above.
share_limiter = PostgresRateLimiter(
    burst_max=30, burst_window=60, hourly_max=300, hourly_window=3600
)
_share_mem_burst = RateLimiter(max_requests=30, window_seconds=60)
_share_mem_hourly = RateLimiter(max_requests=300, window_seconds=3600)

# ISSUE-107: /s/* token-path log redaction (draft §6 launch requirement).
# Raw share tokens ride in request paths and would otherwise persist in
# access logs; the filter rewrites them at the logging layer. Edge/CDN
# log configuration is a separate deployment verification (see
# src/web/RETENTION_SHARING.md).
import logging as _logging
from app.report_access import SharePathRedactionFilter as _ShareRedactionFilter
for _logger_name in ("uvicorn.access", "uvicorn.error", __name__):
    _logger = _logging.getLogger(_logger_name)
    if not any(isinstance(f, _ShareRedactionFilter) for f in _logger.filters):
        _logger.addFilter(_ShareRedactionFilter())


def _use_shared_limiter() -> bool:
    """True when the database is configured (shared enforcement applies)."""
    import os

    return bool(os.environ.get("DATABASE_URL"))


def _db_session():
    """Return a new database session. Raises on connection failure."""
    from app.db import SessionLocal

    return SessionLocal()


def _remaining(ip: str) -> int:
    """Hourly quota remaining for ``ip``, shared across processes when possible.

    Fail-closed display: any database failure shows 0 remaining rather than
    promising quota that cannot be delivered (the /analyze path 503s then).
    """
    if not _use_shared_limiter():
        return limiter.remaining(ip)
    try:
        db = _db_session()
    except Exception:
        return 0
    try:
        return shared_limiter.remaining(db, ip)
    except Exception:
        return 0
    finally:
        db.close()


def _serve_replay(request: Request, file: UploadFile, content: bytes, request_id: str, output: str, ip: str):
    """Serve the stored result for an already-completed request_id.

    Contract (see PostgresRateLimiter.admit): a 'replay' verdict means the
    request already completed AND no quota was consumed. The caller must
    serve the existing result via the durable-result path — it must never
    silently rerun the analysis here.

    ``_durable_analysis`` (PR #17) re-looks-up the request and serves the
    stored result. If the durable path is unavailable (impossible when
    replays genuinely occur, since they require PR #17's tables), fail
    closed with 503.
    """
    durable = globals().get("_durable_analysis")
    if durable is not None:
        return durable(request, file.filename, content, request_id, output)
    _user, _csrf = _get_current_user_optional(request)
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "error": "This analysis was already completed, but its stored result "
            "is temporarily unavailable. Please try again shortly.",
            "remaining": _remaining(ip),
            "current_user": _user,
            "csrf_token": _csrf,
        },
        status_code=503,
        headers={"Retry-After": "60"},
    )


def _get_current_user_optional(request: Request):
    """Return the logged-in user or None. Safe when DB is unavailable."""
    import os
    if not os.environ.get("DATABASE_URL"):
        return None, ""
    try:
        from app.db import SessionLocal
        from app import auth as auth_helpers
        db = SessionLocal()
        try:
            session = auth_helpers.get_session_from_cookie(db, request)
            if session:
                return session.user, session.csrf_token
            return None, ""
        finally:
            db.close()
    except Exception:
        return None, ""

# NOTE: Global admission control REMOVED - does not work with
# blocking sync analysis in async endpoints. The event loop
# serializes requests, so the counter never reaches the limit.
# See Beta Readiness report for details and recommended fix.

MAX_BYTES = 10 * 1024 * 1024  # 10 MB
ALLOWED_SUFFIXES = {".log", ".txt", ".text"}


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


# Issue #104, trim T4: pre-multipart body guard, Content-Length variant.
# The framework spools multipart before the route runs, so a route-level
# guard cannot prevent spooling; this middleware rejects, before any
# handler runs, only POST /analyze requests whose DECLARED Content-Length
# exceeds the oversize ceiling plus 1 MiB of multipart overhead. It trusts
# the header only for this early reject — the route still enforces the
# real ceilings on actual bytes via bounded chunk reads, so chunked
# uploads without Content-Length are covered there. It cannot break
# existing uploads: every legitimate upload is far under this bound, and
# all other paths are untouched. The residual limitation (a hostile
# chunked body is spooled before the route's bounded read stops it) is
# recorded as a known limitation; the bounded read is the enforcement.
_OVERSIZE_GUARD_BYTES = MAX_OVERSIZE_UPLOAD_BYTES + 1024 * 1024


# Issue #103: batch pre-multipart body guard — 50 MiB of file data
# (5 files x the 10 MiB free ceiling) plus 1 MiB of multipart overhead.
_BATCH_GUARD_BYTES = 51 * 1024 * 1024


@app.middleware("http")
async def oversize_body_guard(request: Request, call_next):
    if (request.method == "POST" and request.url.path == "/batch"
            and request.headers.get("content-length")):
        try:
            declared_batch = int(request.headers["content-length"])
        except ValueError:
            declared_batch = 0
        if declared_batch > _BATCH_GUARD_BYTES:
            _user, _csrf = _get_current_user_optional(request)
            return templates.TemplateResponse(
                request,
                "batch.html",
                {"error": "Batch too large. A batch is at most 5 files of "
                          "10 MB each (50 MB total).",
                 "current_user": _user, "csrf_token": _csrf},
                status_code=413,
            )
    if (request.method == "POST" and request.url.path == "/analyze"
            and request.headers.get("content-length")):
        try:
            declared = int(request.headers["content-length"])
        except ValueError:
            declared = 0
        if declared > _OVERSIZE_GUARD_BYTES:
            _user, _csrf = _get_current_user_optional(request)
            return templates.TemplateResponse(
                request,
                "index.html",
                {"error": "File too large. Oversize analysis supports up to 100 MB.",
                 "remaining": _remaining(_client_ip(request)),
                 "current_user": _user, "csrf_token": _csrf},
                status_code=413,
            )
    return await call_next(request)




@app.get("/credits", response_class=HTMLResponse)
async def credits(request: Request):
    _user, _csrf = _get_current_user_optional(request)
    from app import stripe_billing

    packs = stripe_billing.packs_for_display()
    status = request.query_params.get("checkout", "")
    # ISSUE-71: the credits page shows the ledger-derived balance (never a
    # display-only number) so the post-purchase balance is visible without
    # the user hunting for it or hitting refresh.
    balance_summary = None
    latest_purchase = None
    if _user is not None:
        from app.db import SessionLocal
        from app import credits as credits_helpers
        from app.models import CreditPurchase

        db = SessionLocal()
        try:
            balance_summary = credits_helpers.get_balance_summary(db, _user.id)
            latest_purchase = (
                db.query(CreditPurchase)
                .filter(CreditPurchase.user_id == _user.id)
                .order_by(CreditPurchase.created_at.desc())
                .first()
            )
        finally:
            db.close()
    return templates.TemplateResponse(
        request,
        "pricing.html",
        {
            "current_user": _user,
            "csrf_token": _csrf,
            "packs": packs,
            "checkout_ready": any(p["ready"] for p in packs),
            "checkout_status": status if status in ("success", "cancelled") else "",
            "balance_summary": balance_summary,
            "latest_purchase": latest_purchase,
        },
    )


@app.get("/pricing", include_in_schema=False)
async def pricing_redirect():
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/credits", status_code=301)


# ISSUE-68: Stripe Checkout entry point. The billing module accepts test
# and live keys; the configured key determines the mode (issue #126).
# Anonymous users cannot buy: they get a 401 pointing at signup/login, and
# the credits page only renders buy forms for signed-in users.
@app.post("/credits/checkout")
async def credits_checkout(
    request: Request,
    pack_id: str = Form(...),
    csrf_token: str = Form(""),
    db=Depends(get_db),
):
    import hmac
    import logging
    import os as _os
    from fastapi import HTTPException
    from fastapi.responses import JSONResponse
    from app import auth as auth_helpers
    from app import stripe_billing

    if not _os.environ.get("DATABASE_URL"):
        raise HTTPException(503, "Credit purchases are unavailable right now.")

    _user, _ = _get_current_user_optional(request)
    if not _user:
        return JSONResponse({"error": "Log in or sign up to buy credits."}, status_code=401)

    # CSRF: session token, same pattern as the other authenticated POSTs.
    session = auth_helpers.get_session_from_cookie(db, request)
    expected = session.csrf_token if session else None
    if not expected or not isinstance(csrf_token, str) or not hmac.compare_digest(csrf_token, expected):
        raise HTTPException(403, "Invalid CSRF token. Reload the page and try again.")

    ip = _client_ip(request)
    if _use_shared_limiter():
        # Shared enforcement (same pattern as analysis admission): a fresh
        # session, because admit() manages its own transaction; database
        # failures fail closed with 503 rather than skipping the limit.
        try:
            rl_db = _db_session()
            try:
                checkout_limiter.admit(rl_db, f"c:{ip}")
            finally:
                rl_db.close()
        except (BurstLimited, HourlyLimited):
            # Identical windows/counts on checkout_limiter: both mean the
            # 5/hour cap for this IP is exhausted.
            raise HTTPException(429, "Too many attempts. Please try again later.")
        except Exception:
            raise HTTPException(503, "Rate limiting is temporarily unavailable. Please try again shortly.")
    else:
        auth_helpers.check_rate_limit("checkout", ip)

    pack = stripe_billing.get_pack(pack_id)
    if pack is None:
        return JSONResponse({"error": "Unknown credit pack."}, status_code=400)

    origin = str(request.base_url).rstrip("/")
    success_url = _os.environ.get("STRIPE_SUCCESS_URL") or f"{origin}/credits?checkout=success"
    cancel_url = _os.environ.get("STRIPE_CANCEL_URL") or f"{origin}/credits?checkout=cancelled"
    try:
        # Fail closed on configuration BEFORE touching the database, so the
        # purchases table only ever holds real checkout attempts.
        stripe_billing._secret_key()
        if stripe_billing.pack_price_id(pack_id) is None:
            raise stripe_billing.CheckoutNotConfigured(
                f"price not configured for pack {pack_id}")
        # ISSUE-69: record the purchase as pending BEFORE the Stripe call, so
        # a crash between Stripe and our DB cannot produce a paid session
        # with no local record. The purchase id rides in the session metadata
        # as the settlement join key.
        from app import credits as credits_helpers
        purchase = credits_helpers.create_pending_purchase(db, _user.id, pack_id)
        db.commit()
        try:
            checkout_url, session_id = stripe_billing.create_checkout_session(
                user_id=_user.id,
                pack_id=pack_id,
                purchase_id=purchase.id,
                success_url=success_url,
                cancel_url=cancel_url,
            )
        except Exception:
            # Stripe never saw a session (or we never got its id): the
            # pending row stays as an abandoned attempt for reconciliation.
            db.rollback()
            raise
        purchase.stripe_session_id = session_id
        db.commit()
    except stripe_billing.CheckoutNotConfigured:
        return JSONResponse(
            {"error": "Credit purchases are not available yet. Please try again later."},
            status_code=503,
        )
    except stripe_billing.CheckoutError:
        raise HTTPException(503, "Credit purchases are temporarily unavailable. Please try again shortly.")
    # Issue #62: purchase start — a Checkout session was created for this user.
    # Standalone session: this route is otherwise read-only and never commits.
    from app import funnel as funnel_helpers
    funnel_helpers.emit_standalone(funnel_helpers.PURCHASE_START, user_id=_user.id,
                                   meta={"pack_id": pack_id})
    return JSONResponse({"checkout_url": checkout_url})


# ISSUE-69: Stripe webhook — idempotent credit granting.
# Server-to-server: no user session and no CSRF token. The Stripe-Signature
# HMAC is the authentication; unsigned or mis-signed deliveries are answered
# 400 before any database row is touched. Stripe retries non-2xx, so every
# handler path below is idempotent.
@app.post("/credits/webhook")
async def credits_webhook(request: Request, db=Depends(get_db)):
    import json as _json
    from fastapi import HTTPException
    from fastapi.responses import JSONResponse
    from sqlalchemy.exc import IntegrityError
    from app import stripe_billing, models as _models
    from app import credits as credits_helpers

    log = logging.getLogger(__name__)
    try:
        webhook_secret = stripe_billing._webhook_secret()
    except stripe_billing.WebhookNotConfigured:
        raise HTTPException(503, "Credit purchases are unavailable right now.")

    raw = await request.body()
    if not stripe_billing.verify_stripe_signature(
        raw, request.headers.get("stripe-signature"), webhook_secret
    ):
        log.warning("webhook: invalid Stripe signature; ignoring")
        raise HTTPException(400, "Invalid webhook signature.")
    try:
        event = _json.loads(raw)
    except ValueError:
        raise HTTPException(400, "Invalid webhook payload.")
    event_id = event.get("id")
    event_type = event.get("type", "")
    if not event_id or not isinstance(event_id, str):
        raise HTTPException(400, "Invalid webhook payload.")

    # Idempotency gate: the PK on stripe_event_id makes redelivery collide
    # here, before any side effect. Roll back the failed insert and answer
    # 200 so Stripe stops retrying a delivery we already handled.
    webhook_event = _models.StripeWebhookEvent(
        stripe_event_id=event_id, event_type=event_type, outcome="ignored")
    db.add(webhook_event)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        log.info("webhook %s: redelivered event; granting nothing", event_id)
        return JSONResponse({"status": "duplicate"})

    if event_type != "checkout.session.completed" and event_type not in (
        "checkout.session.expired",
        "checkout.session.async_payment_failed",
        "payment_intent.payment_failed",
    ):
        db.commit()
        log.info("webhook %s: ignoring event type %s", event_id, event_type)
        return JSONResponse({"status": "ignored"})

    stripe_obj = event.get("data", {}).get("object", {}) or {}
    obj_metadata = stripe_obj.get("metadata", {}) or {}

    def _find_purchase():
        purchase = None
        purchase_ref = obj_metadata.get("purchase_id")
        if purchase_ref:
            try:
                purchase = db.get(_models.CreditPurchase, purchase_ref)
            except Exception:
                # Malformed purchase_id in verified metadata: data corruption,
                # not an attack — treat as unknown, never 500 (Stripe retries
                # non-2xx into a loop).
                log.warning("webhook %s: malformed metadata purchase_id %r",
                            event_id, purchase_ref)
                purchase = None
        if purchase is None and stripe_obj.get("id"):
            # Fallback join for sessions created before metadata[purchase_id]
            # existed; the session id is backfilled onto the purchase at
            # settlement.
            from sqlalchemy import select as _select
            purchase = db.execute(
                _select(_models.CreditPurchase).where(
                    _models.CreditPurchase.stripe_session_id == stripe_obj["id"])
            ).scalar_one_or_none()
        return purchase

    # ISSUE-70: terminal failure signals. An expired session (or a failed
    # async payment method) can never complete, so the pending purchase is
    # failed outright — no credits, no ledger grant, nothing stuck pending.
    # A failed card payment is NOT terminal: inside a Checkout session the
    # customer sees Stripe's decline message and can retry with another card,
    # so the purchase stays pending and a later completion still settles.
    if event_type in ("checkout.session.expired",
                      "checkout.session.async_payment_failed"):
        purchase = _find_purchase()
        if purchase is None:
            webhook_event.outcome = "ignored"
            webhook_event.note = "unknown purchase"
            db.commit()
            log.warning("webhook %s: no purchase for %s %s; ignoring",
                        event_id, event_type, stripe_obj.get("id"))
            return JSONResponse({"status": "ignored"})
        webhook_event.purchase_id = purchase.id
        reason = ("checkout session expired" if event_type == "checkout.session.expired"
                  else "async payment failed")
        transitioned = credits_helpers.fail_purchase(
            db, purchase, reason=reason, stripe_event_id=event_id)
        webhook_event.outcome = "processed"
        webhook_event.note = f"purchase {reason}" + ("" if transitioned else " (already terminal)")
        db.commit()
        return JSONResponse({"status": "processed"})

    if event_type == "payment_intent.payment_failed":
        purchase = _find_purchase()
        if purchase is None:
            webhook_event.outcome = "ignored"
            webhook_event.note = "unknown purchase"
            db.commit()
            log.warning("webhook %s: no purchase for payment intent %s; ignoring",
                        event_id, stripe_obj.get("id"))
            return JSONResponse({"status": "ignored"})
        webhook_event.purchase_id = purchase.id
        # Declined card: grant nothing. The purchase deliberately stays
        # pending — the customer retries inside the still-open Checkout
        # session; only expiry (above) or the stale-pending cleanup may
        # terminally fail it.
        webhook_event.outcome = "processed"
        webhook_event.note = "card declined; purchase left pending for in-session retry"
        db.commit()
        log.info("webhook %s: purchase %s card declined; still %s, granting nothing",
                 event_id, purchase.id, purchase.status)
        return JSONResponse({"status": "processed"})

    session_obj = stripe_obj
    metadata = obj_metadata
    purchase = _find_purchase()
    if purchase is None:
        webhook_event.outcome = "ignored"
        webhook_event.note = "unknown purchase"
        db.commit()
        log.warning("webhook %s: no purchase for session %s; ignoring",
                    event_id, session_obj.get("id"))
        return JSONResponse({"status": "ignored"})

    webhook_event.purchase_id = purchase.id
    try:
        outcome = credits_helpers.settle_purchase(
            db,
            purchase,
            stripe_event_id=event_id,
            stripe_session_id=session_obj.get("id") or "",
            event_metadata=metadata,
            amount_cents=session_obj.get("amount_total"),
            currency=session_obj.get("currency"),
            payment_intent_id=session_obj.get("payment_intent"),
        )
    except credits_helpers.SettlementError as exc:
        webhook_event.outcome = "failed"
        webhook_event.note = str(exc)[:250]
        db.commit()
        return JSONResponse({"status": "failed"})
    webhook_event.outcome = outcome
    db.commit()
    return JSONResponse({"status": outcome})

@app.get("/privacy", response_class=HTMLResponse, include_in_schema=False)
async def privacy(request: Request):
    _user, _csrf = _get_current_user_optional(request)
    return templates.TemplateResponse(
        request, "privacy.html", {"current_user": _user, "csrf_token": _csrf}
    )


@app.get("/terms", response_class=HTMLResponse, include_in_schema=False)
async def terms(request: Request):
    _user, _csrf = _get_current_user_optional(request)
    return templates.TemplateResponse(
        request, "terms.html", {"current_user": _user, "csrf_token": _csrf}
    )


@app.get("/support", response_class=HTMLResponse, include_in_schema=False)
async def support(request: Request):
    _user, _csrf = _get_current_user_optional(request)
    return templates.TemplateResponse(
        request, "support.html", {"current_user": _user, "csrf_token": _csrf}
    )


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    _user, _csrf = _get_current_user_optional(request)
    return templates.TemplateResponse(
        request, "index.html", {"error": None, "remaining": _remaining(_client_ip(request)), "current_user": _user, "csrf_token": _csrf}
    )


@app.get("/demo", response_class=HTMLResponse)
async def demo(request: Request):
    """One-click demo: analyze a canned incident log, no upload needed.

    Not rate-limited — the input is fixed and cheap to analyze, and this
    is the conversion path for new visitors.
    """
    data = analyze_upload(SAMPLE_FILENAME, SAMPLE_LOG.encode("utf-8"))
    data["is_demo"] = True
    _user, _csrf = _get_current_user_optional(request)
    data["current_user"] = _user
    data["csrf_token"] = _csrf
    return templates.TemplateResponse(request, "report.html", data)


@app.post("/analyze")
async def analyze(
    request: Request,
    file: UploadFile | None = File(None),
    output: str = Form("html"),
    request_id: str = Form(""),
):
    ip = _client_ip(request)

    def error(message: str, status: int = 400, headers: dict = None):
        _user, _csrf = _get_current_user_optional(request)
        return templates.TemplateResponse(
            request,
            "index.html",
            {"error": message, "remaining": _remaining(ip), "current_user": _user, "csrf_token": _csrf},
            status_code=status,
            headers=headers or {},
        )

    if not file or not file.filename:
        return error("Please choose a file first.")

    suffix = Path(file.filename).suffix.lower()
    if suffix not in ALLOWED_SUFFIXES:
        return error(
            f"Only {', '.join(sorted(ALLOWED_SUFFIXES))} files are supported "
            f"(got '{suffix or 'no extension'}')."
        )

    # Issue #104: bounded chunk reads (1 MiB chunks, stopping at the
    # oversize ceiling + 1 byte) instead of an unbounded file.read().
    # Chunk concatenation preserves exact bytes, so multi-byte characters
    # and CRLF pairs straddling a chunk boundary still count correctly.
    _read_limit = MAX_OVERSIZE_UPLOAD_BYTES + 1
    _buf = bytearray()
    while len(_buf) < _read_limit:
        _chunk = await file.read(min(1024 * 1024, _read_limit - len(_buf)))
        if not _chunk:
            break
        _buf.extend(_chunk)
    content = bytes(_buf)
    if not content.strip():
        return error("That file is empty — nothing to analyze.")
    if _is_binary_content(content):
        return error("This appears to be a binary file, not a text log. "
                     "StackSift analyzes text logs. If this is a log file, "
                     "ensure it's saved as plain text (UTF-8).")
    # Classification counts ORIGINAL decoded lines pre-redaction (T6) and
    # enforces bytes and lines independently, ceilings inclusive.
    _nbytes = len(content)
    _nlines = count_original_lines(content)
    _size_class = classify_upload_size(_nbytes, _nlines)
    if _size_class == "unsupported":
        if _nbytes > MAX_OVERSIZE_UPLOAD_BYTES:
            return error("File too large. Oversize analysis supports up to 100 MB.",
                         status=413)
        return error(f"Too many lines ({_nlines:,}). "
                     "Oversize analysis supports up to 500,000 lines.")
    if _size_class == "oversize":
        # Oversize never consumes free quota and never runs free: it goes
        # straight to paid consent for signed-in users, and anonymous
        # attempts get a 400 naming the exceeded free limit, with no
        # consent, pending upload, reservation, or confirm action.
        _user, _csrf = _get_current_user_optional(request)
        if _user is None:
            if _nbytes > MAX_BYTES:
                return error("That file is over the 10 MB free-tier limit. "
                             "Sign in to analyze files up to 100 MB / 500,000 lines "
                             "with Power-Up credits, or upload a smaller file.")
            return error("That file has more than 50,000 lines. "
                         "Sign in to analyze files up to 100 MB / 500,000 lines "
                         "with Power-Up credits, or upload a smaller file.")
        from app import credits as _credits_helpers
        try:
            return _paid_consent_page(request, file.filename, content, _user, _csrf, ip,
                                      operation="oversize_analysis",
                                      byte_count=_nbytes, line_count=_nlines)
        except _credits_helpers.InsufficientCredits:
            return _analysis_response(request, 402,
                                      message=OVERSIZE_INSUFFICIENT_MESSAGE,
                                      buy_credits=True)
        except _credits_helpers.AdmissionError as exc:
            return _analysis_response(request, 409, message=str(exc))
        except RuntimeError as exc:
            if "capacity" in str(exc):
                return error("Pending upload capacity exhausted. Please try again shortly.",
                             status=503, headers={"Retry-After": "60"})
            return error("Oversize analysis is temporarily unavailable. Please try again shortly.",
                         status=503, headers={"Retry-After": "60"})

    if _use_shared_limiter():
        # PR #28: shared rate limiting with replay detection, ahead of the
        # durable path. Burst violations hard-429 here (abuse protection);
        # hourly defers to _durable_analysis (paid offer for logged-in users);
        # replays serve the stored result with no quota consumed and no rerun;
        # any database failure fails closed with 503.
        verdict = None
        try:
            db = _db_session()
            try:
                verdict = shared_limiter.admit(db, ip, request_id=request_id or None)
            finally:
                db.close()
        except BurstLimited:
            return error(
                "Too many requests. Please wait a minute and try again.",
                status=429,
                headers={"Retry-After": "60"},
            )
        except HourlyLimited:
            pass  # _durable_analysis handles hourly quota + paid offer below
        except Exception:
            return error(
                "Rate limiting is temporarily unavailable. Please try again shortly.",
                status=503,
                headers={"Retry-After": "60"},
            )
        if verdict == "replay":
            return _serve_replay(request, file, content, request_id, output, ip)
        return _durable_analysis(request, file.filename, content, request_id or uuid_module.uuid4().hex, output)

    # Atomic check: verify both limits before recording either.
    # Prevents rejected requests from consuming quota in the other limiter.
    burst_ok = burst_limiter.check(ip)
    hourly_ok = limiter.check(ip)
    if not burst_ok:
        return error(
            "Too many requests. Please wait a minute and try again.",
            status=429,
            headers={"Retry-After": "60"},
        )
    if not hourly_ok:
        # Phase 2A: offer paid path if user is logged in (free-first per v11.1).
        _user, _csrf = _get_current_user_optional(request)
        if _user is not None:
            try:
                return _paid_consent_page(request, file.filename, content, _user, _csrf, ip)
            except Exception:
                pass  # fall through to free-tier error
        return error(
            "Free-tier limit reached (10 analyses/hour). Please try again later.",
            status=429,
            headers={"Retry-After": "3600"},
        )
    # Both pass: record in both limiters
    burst_limiter.record(ip)
    limiter.record(ip)

    # The upload is analyzed from a temp file and deleted immediately —
    # see app/service.py. The framework may also spool the raw upload to disk.
    data = analyze_upload(file.filename, content)

    # Handle error dicts from analyze_upload (binary, too many lines, timeout, etc.)
    if isinstance(data, dict) and "error" in data:
        return error(data.get("message", "Analysis failed."), status=400)

    if output == "txt":
        report = render_text_report(data)
        stem = Path(file.filename).stem
        return PlainTextResponse(
            report,
            headers={"Content-Disposition": f'attachment; filename="{stem}-stacksift.txt"'},
        )

    _user, _csrf = _get_current_user_optional(request)
    data["current_user"] = _user
    data["csrf_token"] = _csrf
    return templates.TemplateResponse(request, "report.html", data)


# ---------------------------------------------------------------------------
# Phase 2A: Paid analysis flow (free-first per v11.1 Section 6)
#
# When the free hourly quota is exhausted and the user is logged in:
#   1. /analyze returns a consent page quoting 1 credit.
#   2. User confirms -> POST /analyze/paid with consent_id + file.
#   3. Server re-checks free quota (T27), then atomically admits paid op.
# ---------------------------------------------------------------------------

import hashlib
import logging
import json
import os
import tempfile
import uuid as uuid_module
from datetime import datetime, timezone

# Temp file storage for consent flow (15-min TTL, keyed by content hash).
# Single-worker deployment; files deleted after use or expiry.
# Issue #104, trim T2: the aggregate pending budget is 256 MiB (a ceiling
# only, not an allocation — the old 64 MiB cap could not hold a 100 MiB
# input). Capacity checks and writes are serialized on _PENDING_LOCK, and
# at most one live oversize pending upload per user is allowed (enforced
# in _paid_consent_page via the live-consent check). Single-replica
# assumption (T3): a multi-replica finding blocks production promotion,
# not the staging merge.
_PAID_PENDING_DIR = os.environ.get("STACKSIFT_PAID_TMP", tempfile.gettempdir() + "/stacksift-paid")
_PAID_PENDING_TTL = 900  # 15 minutes
_PAID_PENDING_BUDGET = 256 * 1024 * 1024  # 256 MiB aggregate ceiling

import threading as _threading
# RLock: _paid_consent_page holds it across the live-consent check +
# consent creation + pending store (one-live-oversize enforcement), and
# _store_paid_pending re-acquires it for the budget check + write.
_PENDING_LOCK = _threading.RLock()

# Issue #104: exact insufficient-credits message (spec §4), with the
# /credits CTA rendered by _analysis_response(buy_credits=True).
OVERSIZE_INSUFFICIENT_MESSAGE = (
    "Oversize analysis costs 3 credits. You do not have enough eligible Power-Up credits."
)


def _paid_pending_path(file_hash: str) -> str:
    os.makedirs(_PAID_PENDING_DIR, exist_ok=True)
    # Only server-generated consent IDs may select a file; filenames/digests cannot.
    token = uuid_module.UUID(file_hash).hex
    return os.path.join(_PAID_PENDING_DIR, f"pending-{token}.bin")


def _paid_pending_meta_path(file_hash: str) -> str:
    token = uuid_module.UUID(file_hash).hex
    return os.path.join(_PAID_PENDING_DIR, f"pending-{token}.meta.json")


def _store_paid_pending(file_hash: str, filename: str, content: bytes, meta: dict | None = None) -> None:
    """Store a redacted pending upload (mode 0o600, exclusive creation).

    The aggregate-budget check and the write are serialized on
    _PENDING_LOCK (T2). Raises RuntimeError on storage exhaustion, with no
    reservation created; callers must roll back any uncommitted consent.
    Oversize metadata (server-measured byte/line counts) rides in a
    sidecar file so confirmation revalidates server-owned measurements,
    never client fields.
    """
    path = _paid_pending_path(file_hash)
    with _PENDING_LOCK:
        cleanup_pending_uploads()
        if _pending_usage_bytes() + len(content) > _PAID_PENDING_BUDGET:
            raise RuntimeError("Pending upload capacity exhausted")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(json.dumps(filename).encode("utf-8") + b"\n")
            f.write(content)
        if meta is not None:
            with open(_paid_pending_meta_path(file_hash), "w", encoding="utf-8") as f:
                json.dump(meta, f)


def _load_paid_pending(file_hash: str) -> tuple[str, bytes] | None:
    path = _paid_pending_path(file_hash)
    try:
        stat = os.stat(path)
        age = datetime.now(timezone.utc).timestamp() - stat.st_mtime
        if age > _PAID_PENDING_TTL:
            os.unlink(path)
            try:
                os.unlink(_paid_pending_meta_path(file_hash))
            except OSError:
                pass
            return None
        with open(path, "rb") as f:
            raw = f.read()
        nl = raw.index(b"\n")
        filename = json.loads(raw[:nl].decode("utf-8"))
        content = raw[nl + 1:]
        return filename, content
    except (OSError, ValueError):
        return None


def _load_paid_pending_meta(file_hash: str) -> dict | None:
    try:
        with open(_paid_pending_meta_path(file_hash), "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def cleanup_pending_uploads():
    cutoff = datetime.now(timezone.utc).timestamp() - _PAID_PENDING_TTL
    for path in Path(_PAID_PENDING_DIR).glob("pending-*.bin"):
        try:
            if path.stat().st_mtime < cutoff:
                path.unlink()
        except FileNotFoundError:
            pass
    for path in Path(_PAID_PENDING_DIR).glob("pending-*.meta.json"):
        try:
            if path.stat().st_mtime < cutoff:
                path.unlink()
        except FileNotFoundError:
            pass


def _pending_usage_bytes() -> int:
    """Aggregate size of live pending uploads, race-safe by construction.

    Issue #118: a pending file may be unlinked (worker completion,
    TTL expiry, cleanup) after the glob discovers it but before stat
    runs. A vanished file contributes 0 instead of raising
    FileNotFoundError into consent creation.
    """
    total = 0
    for p in Path(_PAID_PENDING_DIR).glob("pending-*.bin"):
        try:
            total += p.stat().st_size
        except FileNotFoundError:
            continue
    return total


def _delete_paid_pending(file_hash: str) -> None:
    # Issue #118: deletions are serialized on _PENDING_LOCK so they
    # cannot interleave with the budget scans in the _store_*_pending
    # functions, which hold the lock across glob + stat + write.
    with _PENDING_LOCK:
        try:
            os.unlink(_paid_pending_path(file_hash))
        except OSError:
            pass
        try:
            os.unlink(_paid_pending_meta_path(file_hash))
        except OSError:
            pass


# Issue #102: pair-pending storage for a comparison consent. The two
# redacted files share the consent's single pending file (the pending
# path is keyed by a UUID consent ID, so two separate stores are not
# possible): a JSON header line with both filenames, then an 8-byte
# big-endian length for A, then A's bytes, then B's bytes. The loader
# is compare-only; the single-file loader never parses a pair file.
# Budget and TTL handling mirror _store_paid_pending / _load_paid_pending.
def _store_compare_pending(consent_id: str, filename_a: str, content_a: bytes,
                           filename_b: str, content_b: bytes) -> None:
    path = _paid_pending_path(consent_id)
    with _PENDING_LOCK:
        cleanup_pending_uploads()
        if (_pending_usage_bytes()
                + len(content_a) + len(content_b) > _PAID_PENDING_BUDGET):
            raise RuntimeError("Pending upload capacity exhausted")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(json.dumps([filename_a, filename_b]).encode("utf-8") + b"\n")
            f.write(len(content_a).to_bytes(8, "big"))
            f.write(content_a)
            f.write(content_b)


def _load_compare_pending(consent_id: str) -> tuple[str, bytes, str, bytes] | None:
    path = _paid_pending_path(consent_id)
    try:
        stat = os.stat(path)
        if datetime.now(timezone.utc).timestamp() - stat.st_mtime > _PAID_PENDING_TTL:
            os.unlink(path)
            return None
        with open(path, "rb") as f:
            raw = f.read()
        nl = raw.index(b"\n")
        filename_a, filename_b = json.loads(raw[:nl].decode("utf-8"))
        len_a = int.from_bytes(raw[nl + 1:nl + 9], "big")
        content_a = raw[nl + 9:nl + 9 + len_a]
        content_b = raw[nl + 9 + len_a:]
        if len(content_a) != len_a:
            return None
        return filename_a, content_a, filename_b, content_b
    except (OSError, ValueError, IndexError):
        return None


def _compare_pair_hash(filename_a: str, content_a: bytes, filename_b: str, content_b: bytes) -> str:
    """Ordered-pair fingerprint binding a compare consent to both files.

    Direction matters: A (before) and B (after) are not interchangeable,
    so the hash is over the ordered pair of single-file fingerprints.
    """
    from app.analysis_admission import fingerprint as _fingerprint
    from app import credits as _credits_helpers
    return _credits_helpers.hash_input(
        (_fingerprint(filename_a, content_a) + "\0"
         + _fingerprint(filename_b, content_b)).encode("utf-8"))


def _paid_consent_page(request: Request, filename: str, content: bytes, user, csrf_token: str, ip: str,
                       *, operation: str = "additional_analysis",
                       byte_count: int | None = None, line_count: int | None = None,
                       filename_b: str | None = None, content_b: bytes | None = None):
    """Return a consent page offering a paid analysis. Raises on no DB.

    Generalized for issue #104 (trim T8): the operation policy is
    server-selected. ``additional_analysis`` keeps its byte-identical
    wording ("1 credit" / "Use 1 credit" / free-quota explanation);
    ``oversize_analysis`` quotes 3 credits with the draft §3 copy. The
    consent row binds user, operation type, redacted-content fingerprint,
    pricing version, and (oversize) server-measured byte/line counts.
    Issue #102 adds ``compare_logs``: both files are redacted, the
    consent binds the ORDERED pair hash (A = before, B = after), and
    the pair is stored with _store_compare_pending. Consent creation
    changes neither balance nor allocations, and creates no debit or
    operation. Raises InsufficientCredits when eligible credits are
    below the operation cost, so callers return HTTP 402.
    """
    import os as _os
    if not _os.environ.get("DATABASE_URL"):
        raise RuntimeError("no database")
    from app.db import SessionLocal
    from app import credits as credits_helpers
    from app import models as _models

    from app.analysis_admission import fingerprint
    from app.redact import redact_secrets
    # Finding 2: Redact secrets before fingerprinting and disk persistence.
    # Raw uploaded logs must never be written to disk; the consent flow
    # stores the file temporarily, so redaction happens here (not just
    # at analysis time). The fingerprint is of the redacted content, which
    # matches what _durable_analysis will load and verify.
    try:
        text = content.decode("utf-8", errors="replace")
        redacted_text = redact_secrets(text)
        content = redacted_text.encode("utf-8")
        if operation == "compare_logs":
            if content_b is None or filename_b is None:
                raise ValueError("compare consent requires both files")
            text_b = content_b.decode("utf-8", errors="replace")
            content_b = redact_secrets(text_b).encode("utf-8")
    except Exception:
        # GFD Finding 2: Fail closed. Never persist unredacted content.
        # If redaction fails, abort rather than writing raw logs to disk.
        from fastapi.responses import HTMLResponse
        return HTMLResponse(
            content="<h1>Upload processing error</h1><p>Could not securely process your file. Please try again.</p>",
            status_code=500,
        )
    if operation == "compare_logs":
        file_hash = _compare_pair_hash(filename, content, filename_b, content_b)
    else:
        file_hash = fingerprint(filename, content)
    if operation == "oversize_analysis":
        cost = credits_helpers.COST_OVERSIZE_ANALYSIS
    elif operation == "compare_logs":
        cost = credits_helpers.COST_COMPARE
    elif operation == "additional_analysis":
        cost = credits_helpers.COST_ADDITIONAL_ANALYSIS
    else:
        raise ValueError(f"unknown paid operation: {operation}")
    db = SessionLocal()
    try:
        with _PENDING_LOCK:
            if operation == "oversize_analysis":
                # T2: at most one live oversize pending upload per user.
                # A consent is live while unconsumed and unexpired; the
                # check, creation, and pending store run under one lock so
                # two concurrent uploads cannot both pass the check.
                now = datetime.now(timezone.utc)
                live = db.query(_models.Consent).filter(
                    _models.Consent.user_id == user.id,
                    _models.Consent.operation_type == "oversize_analysis",
                    _models.Consent.consumed_by_operation_id.is_(None),
                    _models.Consent.consumed_by_free_request_id.is_(None),
                    _models.Consent.expires_at > now,
                ).first()
                if live is not None:
                    raise credits_helpers.AdmissionError(
                        "You already have an oversize upload awaiting confirmation. "
                        "Confirm or wait for it to expire before uploading another oversize file.")
            # Check eligible credits
            summary = credits_helpers.get_balance_summary(db, user.id)
            if summary["eligible"] < cost:
                # BR-01: raise the domain exception so callers return
                # HTTP 402 (credit limit), not a generic 503.
                raise credits_helpers.InsufficientCredits("insufficient credits")
            # Create server-bound consent (flushed, not yet committed, so
            # a pending-store failure rolls it back: no dangling consent
            # and no reservation on storage exhaustion).
            consent = credits_helpers.create_consent(
                db, user.id, operation, file_hash, cost,
            )
            db.flush()
            consent_id = str(consent.id)
            # Store file for the paid endpoint (deleted after use).
            # Oversize metadata carries the SERVER-measured counts from
            # upload classification; confirmation revalidates from these,
            # never from client fields.
            meta = None
            if operation == "oversize_analysis":
                meta = {"operation_type": operation, "byte_count": byte_count,
                        "line_count": line_count, "user_id": str(user.id)}
            try:
                if operation == "compare_logs":
                    _store_compare_pending(consent_id, filename, content,
                                           filename_b, content_b)
                else:
                    _store_paid_pending(consent_id, filename, content, meta=meta)
            except Exception:
                db.rollback()
                raise
            db.commit()
    finally:
        db.close()

    if operation == "oversize_analysis":
        size_mb = (byte_count or 0) / (1024 * 1024)
        context = {
            "current_user": user,
            "csrf_token": csrf_token,
            "filename": filename,
            "file_hash": file_hash,
            "consent_id": consent_id,
            "cost": cost,
            "balance": summary["balance"],
            "eligible": summary["eligible"],
            "operation_type": operation,
            "heading": "Oversize analysis",
            "intro": "This file exceeds the free limits.",
            "size_line": f"{byte_count:,} bytes ({size_mb:.1f} MB) · {line_count:,} lines",
            "limits_line": "Analyze up to 100 MB / 500,000 lines.",
            "cost_label": "3 credits",
            "cost_sentence": "This run costs 3 credits.",
            "confirm_label": "Use 3 credits",
            "confirm_action": "/analyze/paid",
            "cancel_label": "Cancel",
            "note": "No charge if the analysis fails. Results are available for 7 days.",
        }
    elif operation == "compare_logs":
        # Spec trim C10: the consent page discloses that an identical
        # pair, or a comparison with no material differences, still
        # costs 3 credits. Consent creation itself charges nothing.
        context = {
            "current_user": user,
            "csrf_token": csrf_token,
            "filename": f"{filename} → {filename_b}",
            "file_hash": file_hash,
            "consent_id": consent_id,
            "cost": cost,
            "balance": summary["balance"],
            "eligible": summary["eligible"],
            "operation_type": operation,
            "heading": "Compare two logs",
            "intro": "Compare A (before) against B (after).",
            "size_line": None,
            "limits_line": "Free limits apply to both files (10 MB / 50,000 lines each).",
            "cost_label": "3 credits",
            "cost_sentence": ("This comparison costs 3 credits — even if the logs are "
                              "identical or show no material differences."),
            "confirm_label": "Use 3 credits",
            "confirm_action": "/compare/paid",
            "cancel_label": "Cancel",
            "note": "No charge if the comparison fails. Results are available for 7 days.",
        }
    else:
        context = {
            "current_user": user,
            "csrf_token": csrf_token,
            "filename": filename,
            "file_hash": file_hash,
            "consent_id": consent_id,
            "cost": cost,
            "balance": summary["balance"],
            "eligible": summary["eligible"],
            "operation_type": operation,
            "heading": "Free analyses used up",
            "intro": "You've used your 10 free analyses this hour. They reset automatically.",
            "size_line": None,
            "limits_line": None,
            "cost_label": "1 credit",
            "cost_sentence": "Continue this analysis now with a Power-Up credit",
            "confirm_label": "Use 1 credit",
            "confirm_action": "/analyze/paid",
            "cancel_label": "Wait for free",
            "note": "No charge if the analysis fails. Credits never expire. Results are available for 7 days.",
        }
    return templates.TemplateResponse(
        request,
        "paid_consent.html",
        context,
        status_code=402,  # Payment Required
    )


def _analysis_response(request, status, data=None, message=None, *, output="html", filename="analysis.log", report_id=None, buy_credits=False):
    """Render an analysis outcome.

    buy_credits=True marks the insufficient-credits (402) entry point: the
    page renders a "Buy credits" CTA linking to /credits (issue #68).
    """
    user, csrf = _get_current_user_optional(request)
    if data is None:
        return templates.TemplateResponse(request, "index.html", {
            "error": message, "remaining": limiter.remaining(_client_ip(request)),
            "current_user": user, "csrf_token": csrf,
            "buy_credits": buy_credits}, status_code=status)
    if output == "txt":
        return PlainTextResponse(render_text_report(data), headers={
            "Content-Disposition": f'attachment; filename="{Path(filename).stem}-stacksift.txt"'})
    data = dict(data, current_user=user, csrf_token=csrf)
    if report_id is not None:
        data["report_id"] = report_id
    return templates.TemplateResponse(request, "report.html", data, status_code=status)


def _execute_oversize(filename: str, content: bytes, *, original_byte_count: int | None = None) -> dict:
    """Run an oversize analysis via the supervised worker (issue #104).

    Module-level indirection so HTTP/ledger tests can keep the existing
    mocked-execution pattern (monkeypatch main._execute_oversize) while
    real-subprocess tests cover app.analysis_worker.run_supervised
    directly (trim T5).

    original_byte_count (PR #111 finding 6): the server-measured original
    byte count from consent metadata, forwarded to the worker so its byte
    ceiling is checked against the originals, not the redacted bytes.
    """
    from app.analysis_worker import run_supervised
    return run_supervised(filename, content, original_byte_count=original_byte_count)


def _durable_analysis(request, filename, content, key, output="html", *, consent_id=None, digest=None):
    from app.db import SessionLocal
    from app import auth, credits as C, models as M, analysis_admission as A
    from sqlalchemy import select
    import secrets
    user, _ = _get_current_user_optional(request)
    user_id = user.id if user else None
    anon = None
    cookie = None
    with SessionLocal() as db:
        if user_id is None:
            cookie = request.cookies.get("__Host-stacksift_analysis", "")
            known = len(cookie) == 64 and db.scalar(select(M.FreeRequest.request_id).where(
                M.FreeRequest.anonymous_session_hash == auth.hash_token(cookie)).limit(1))
            if not known:
                cookie = secrets.token_hex(32)
            anon = auth.hash_token(cookie)
        digest = digest or A.fingerprint(filename, content)
        if not key or len(key) > 255:
            return _analysis_response(request, 400, message="Invalid request identity.")
        # Issue #104: operation type and cost are derived from the
        # SERVER-side consent row only; no posted price or tier is ever
        # trusted. Unknown operation types are rejected outright.
        consent_operation = None
        if consent_id:
            _consent_row = db.get(M.Consent, consent_id, populate_existing=True)
            if _consent_row is None:
                return _analysis_response(request, 400, message="Invalid consent.")
            if _consent_row.operation_type not in ("additional_analysis", "oversize_analysis"):
                return _analysis_response(request, 400, message="Invalid consent.")
            consent_operation = _consent_row.operation_type
        paid_operation_type = None
        oversize_original_bytes = None
        try:
            if consent_operation == "oversize_analysis":
                # --- Oversize confirmation (direct paid admission) ---
                # Replay resolves BEFORE a consumed consent is rejected:
                # a matching completed/in-progress operation replays
                # without a new charge; only then is the consent validated.
                try:
                    _existing_op = C.find_operation(db, user_id, "oversize_analysis", key, digest)
                except C.AdmissionError as exc:
                    db.rollback()
                    return _analysis_response(request, 409, message=str(exc))
                if _existing_op is not None:
                    status, data, message = A.replay(db, _existing_op, user_id)
                    rid = None
                    if status == 200 and data is not None and getattr(_existing_op, "result_id", None):
                        rid = str(_existing_op.result_id)
                    return _analysis_response(request, status, data, message, output=output, filename=filename, report_id=rid)
                try:
                    C.validate_consent(db, consent_id, user_id, "oversize_analysis", digest,
                                       C.COST_OVERSIZE_ANALYSIS)
                except C.AdmissionError as exc:
                    db.rollback()
                    return _analysis_response(request, 409, message=str(exc))
                pending = _load_paid_pending(str(consent_id))
                if pending is None:
                    return _analysis_response(request, 410, message="Upload expired. Please upload the file again.")
                filename, content = pending
                if A.fingerprint(filename, content) != digest:
                    return _analysis_response(request, 409, message="Upload does not match your consent.")
                # Revalidate ceilings from SERVER-owned measurements
                # (consent-time metadata), never from client fields.
                meta = _load_paid_pending_meta(str(consent_id))
                if meta is not None:
                    if meta.get("byte_count", 0) > MAX_OVERSIZE_UPLOAD_BYTES:
                        return _analysis_response(request, 413, message="File too large. Oversize analysis supports up to 100 MB.")
                    if meta.get("line_count", 0) > MAX_OVERSIZE_UPLOAD_LINES:
                        return _analysis_response(request, 400, message="Too many lines. Oversize analysis supports up to 500,000 lines.")
                    # PR #111 finding 6: carry the server-owned original
                    # byte count to the worker so it does not re-apply
                    # the byte ceiling to the redacted bytes it receives
                    # (redaction can expand a near-ceiling file past
                    # 100 MB). A missing/invalid count falls back to the
                    # worker's len(content) check, which is the old
                    # (safe, fail-closed) behavior.
                    if isinstance(meta.get("byte_count"), int):
                        oversize_original_bytes = meta["byte_count"]
                worker = uuid_module.uuid4().hex
                try:
                    # Direct admit_paid_operation: the free-quota branch
                    # of analysis_admission.admit() must NEVER convert an
                    # oversize run into a free run. Slice 1 (T3): worker
                    # pool size 1 via the global:oversize scope, existing
                    # user/global permits, explicit 30/hour rate policy.
                    item = C.admit_paid_operation(db, user_id, "oversize_analysis", key, digest,
                                                  C.COST_OVERSIZE_ANALYSIS, consent_id, worker,
                                                  input_manifest=_client_ip(request),
                                                  extra_scopes=[("global:oversize", 1)])
                except C.InsufficientCredits:
                    db.rollback()
                    return _analysis_response(request, 402, message=OVERSIZE_INSUFFICIENT_MESSAGE,
                                              buy_credits=True)
                except C.AdmissionError as exc:
                    db.rollback()
                    return _analysis_response(request, 409 if "409" in str(exc) else 429, message=str(exc))
                paid = True
                paid_operation_type = "oversize_analysis"
                identity = item.id
                created = (item.worker_id == worker)
                db.commit()
                if not created:
                    status, data, message = A.replay(db, item, user_id)
                    rid = None
                    if status == 200 and data is not None and getattr(item, "result_id", None):
                        rid = str(item.result_id)
                    return _analysis_response(request, status, data, message, output=output, filename=filename, report_id=rid)
            else:
                existing = A.lookup(db, user_id, anon, key, digest, _client_ip(request))
                if existing:
                    status, data, message = A.replay(db, existing, user_id)
                    rid = None
                    if status == 200 and data is not None and user_id is not None and getattr(existing, "result_id", None):
                        rid = str(existing.result_id)
                    return _analysis_response(request, status, data, message, output=output, filename=filename, report_id=rid)
                if consent_id:
                    C.validate_consent(db, consent_id, user_id, "additional_analysis", digest, 1)
                    pending = _load_paid_pending(str(consent_id))
                    if pending is None:
                        return _analysis_response(request, 410, message="Upload expired. Please upload the file again.")
                    filename, content = pending
                    if A.fingerprint(filename, content) != digest:
                        return _analysis_response(request, 409, message="Upload does not match your consent.")
                worker = uuid_module.uuid4().hex
                item, created = A.admit(db, user_id, anon, key, digest, _client_ip(request), worker, consent_id)
                if item is None:
                    db.rollback()
                    if user:
                        return _paid_consent_page(request, filename, content, user, _get_current_user_optional(request)[1], _client_ip(request))
                    return _analysis_response(request, 429, message="Free-tier limit reached (10 analyses/hour). Please try again later.")
                paid = isinstance(item, M.Operation)
                identity = item.id if paid else item.request_id
                db.commit()
                if not created:
                    status, data, message = A.replay(db, item, user_id)
                    rid = None
                    if status == 200 and data is not None and user_id is not None and getattr(item, "result_id", None):
                        rid = str(item.result_id)
                    return _analysis_response(request, status, data, message, output=output, filename=filename, report_id=rid)
        except C.InsufficientCredits:
            db.rollback()
            return _analysis_response(request, 402, message="Insufficient Power-Up credits.", buy_credits=True)
        except C.AdmissionError as exc:
            db.rollback()
            return _analysis_response(request, 409 if '409' in str(exc) else 429, message=str(exc))
        except Exception:
            db.rollback()
            logging.getLogger(__name__).exception("Analysis admission failed")
            return _analysis_response(request, 503, message="Could not start analysis. Please retry this request.")
    result_id = None
    try:
        if paid_operation_type == "oversize_analysis":
            # T5: oversize runs in the supervised subprocess with its own
            # deadline; the standard path keeps in-process SIGALRM below.
            # A worker error dict settles exactly like an in-process
            # failure: full reservation reversal, no result published.
            data = _execute_oversize(filename, content,
                                     original_byte_count=oversize_original_bytes)
        else:
            data = analyze_upload(filename, content)
        failure = data.get("message", "Analysis failed.") if isinstance(data, dict) and "error" in data else None
        with SessionLocal() as db:
            if paid:
                if failure:
                    C.release_operation(db, identity, worker, "analysis_failed")
                else:
                    result = C.store_result(db, user_id, identity, data)
                    C.complete_operation(db, identity, worker, result.id)
                    result_id = result.id
            else:
                settled = A.finish_free(db, identity, data, failure)
                if settled is not None:
                    result_id = settled.id
            if not failure and result_id is not None:
                # Issue #62: first successful own-log analysis. The /demo route
                # never reaches this path, so everything here is a user upload.
                # Identity is the user, or the anonymous session hash for
                # pre-account visitors (privacy-appropriate: no PII).
                from app import funnel as funnel_helpers
                funnel_helpers.emit(db, funnel_helpers.ANALYSIS_FIRST,
                                    user_id=user_id, anon_id=anon,
                                    once_per_identity=True)
            db.commit()
    except Exception:
        logging.getLogger(__name__).exception("Analysis execution or settlement failed")
        # Execution has returned/stopped here. Completion is never reversed.
        try:
            with SessionLocal() as db:
                if paid:
                    C.release_operation(db, identity, worker, "execution_failed")
                else:
                    A.finish_free(db, identity, failure="execution_failed")
                db.commit()
        except Exception:
            logging.getLogger(__name__).exception("Analysis settlement needs recovery")
        return _analysis_response(request, 503, message="Analysis could not be delivered. Retry this request to check its outcome.")
    finally:
        if consent_id:
            _delete_paid_pending(str(consent_id))
    response = _analysis_response(request, 400 if failure else 200, None if failure else data,
        failure, output=output, filename=filename,
        report_id=str(result_id) if (result_id is not None and user_id is not None and not failure) else None)
    if cookie:
        response.set_cookie("__Host-stacksift_analysis", cookie, secure=True, httponly=True, samesite="lax", max_age=7*86400)
    response.headers["X-Analysis-Request-ID"] = key
    return response


@app.post("/analyze/paid", response_class=HTMLResponse)
async def analyze_paid(request: Request, consent_id: str = Form(...), file_hash: str = Form(...),
                       idempotency_key: str = Form(...), csrf_token: str = Form("")):
    from app.db import SessionLocal
    from app import auth, models as M
    import asyncio
    import hmac
    with SessionLocal() as db:
        session = auth.get_session_from_cookie(db, request)
        if not session:
            return _analysis_response(request, 401, message="Please log in to use Power-Up credits.")
        if not csrf_token or not hmac.compare_digest(csrf_token, session.csrf_token):
            return _analysis_response(request, 403, message="Invalid request. Please try again.")
    try:
        consent_uuid = uuid_module.UUID(consent_id)
    except ValueError:
        return _analysis_response(request, 400, message="Invalid consent.")
    # Issue #104 follow-up (P1): the oversize execution waits up to 60s
    # on a supervised subprocess, which must not block the async event
    # loop on a single-worker deployment. Oversize never arms SIGALRM
    # (child use_alarm=False, parent subprocess timeout), so running
    # its _durable_analysis in a worker thread is safe. The
    # additional_analysis path stays on the event loop: its 25s SIGALRM
    # only works in the main thread, and that path is unchanged.
    is_oversize = False
    with SessionLocal() as db:
        _consent_row = db.get(M.Consent, consent_uuid)
        is_oversize = _consent_row is not None and _consent_row.operation_type == "oversize_analysis"
    if is_oversize:
        return await asyncio.to_thread(
            _durable_analysis, request, "", b"", idempotency_key,
            consent_id=consent_uuid, digest=file_hash)
    return _durable_analysis(request, "", b"", idempotency_key, consent_id=consent_uuid, digest=file_hash)


@app.post("/analyze/paid/cancel", response_class=HTMLResponse)
async def analyze_paid_cancel(request: Request, consent_id: str = Form(...),
                              csrf_token: str = Form("")):
    """Cancel a paid consent (issue #104 follow-up, PR #111 finding 5).

    The oversize consent page's Cancel control previously only navigated
    to "/", while _paid_consent_page's one-live-oversize check blocked
    any second oversize upload until the first consent expired (up to
    15 minutes). Cancel now actually releases that lockout: with a valid
    session + CSRF token, an unconsumed consent owned by the caller is
    expired and its pending files are deleted, so a fresh oversize upload
    quotes immediately. Consumed consents are left untouched (their
    pending files were already deleted on settlement). Unknown or
    other-user consent IDs redirect without any change, so the endpoint
    does not leak consent existence or ownership. No balance, operation,
    or reservation is touched: cancel happens before any charge.
    """
    from app.db import SessionLocal
    from app import auth, credits as C, models as M
    import hmac
    from fastapi.responses import RedirectResponse
    with SessionLocal() as db:
        session = auth.get_session_from_cookie(db, request)
        if not session:
            return _analysis_response(request, 401, message="Please log in to use Power-Up credits.")
        if not csrf_token or not hmac.compare_digest(csrf_token, session.csrf_token):
            return _analysis_response(request, 403, message="Invalid request. Please try again.")
        try:
            consent_uuid = uuid_module.UUID(consent_id)
        except ValueError:
            return _analysis_response(request, 400, message="Invalid consent.")
        consent = db.get(M.Consent, consent_uuid)
        if consent is None or consent.user_id != session.user.id:
            return RedirectResponse("/", status_code=303)
        if consent.consumed_by_operation_id is None and consent.consumed_by_free_request_id is None:
            # Expire now: validate_consent rejects expires_at < now, and
            # the one-live check only counts consents with expires_at > now.
            consent.expires_at = C._utcnow()
            db.commit()
        _delete_paid_pending(str(consent_uuid))
    return RedirectResponse("/", status_code=303)


# ---------------------------------------------------------------------------
# Issue #102: Compare two logs (paid, 3 credits)
# ---------------------------------------------------------------------------

COMPARE_INSUFFICIENT_MESSAGE = (
    "Comparing two logs costs 3 credits. You do not have enough eligible Power-Up credits."
)


def _comparison_response(request, status, data=None, message=None, *, report_id=None):
    """Render a comparison outcome: the comparison report on success,
    the compare form with an error otherwise."""
    user, csrf = _get_current_user_optional(request)
    if data is None:
        return templates.TemplateResponse(request, "compare.html", {
            "error": message, "current_user": user, "csrf_token": csrf},
            status_code=status)
    data = dict(data, current_user=user, csrf_token=csrf)
    if report_id is not None:
        data["report_id"] = report_id
    data.setdefault("elapsed", 0.0)
    return templates.TemplateResponse(request, "compare_report.html", data, status_code=status)


def _execute_compare(filename_a: str, content_a: bytes, filename_b: str, content_b: bytes):
    """Run both analyses via the supervised worker (spec trim C1: compare
    REUSES the #104 worker, it does not build a second one).

    Module-level indirection so HTTP/ledger tests can keep the mocked-
    execution pattern (monkeypatch main._execute_compare) while real
    subprocess behavior is covered for run_supervised directly. Both
    inputs were already validated against the FREE limits at POST
    /compare (trim C7: oversize + compare is out of v1 scope); the
    worker's oversize ceilings therefore never widen a comparison.
    Returns (result_a, result_b) in analyze_upload wrapper shape.
    """
    from app.analysis_worker import run_supervised
    return (
        run_supervised(filename_a, content_a, collect_comparison_evidence=True),
        run_supervised(filename_b, content_b, collect_comparison_evidence=True),
    )


def _durable_compare(request, key, *, consent_id, digest):
    """Confirm a comparison consent: replay, admit (-3), run, settle.

    Mirrors _durable_analysis's oversize branch: one reservation covers
    both analyzer runs, the diff, and persistence (reserve -3, complete
    on success, full reversal on any failure); a committed result is
    never reversed on delivery disconnect (replay returns it).
    """
    from app.db import SessionLocal
    from app import auth, credits as C, models as M, analysis_admission as A
    from app.compare_service import compare_results
    user, _ = _get_current_user_optional(request)
    user_id = user.id if user else None
    if user_id is None:
        return _comparison_response(request, 401, message="Please log in to compare logs.")
    item = None
    worker = uuid_module.uuid4().hex
    with SessionLocal() as db:
        try:
            existing = C.find_operation(db, user_id, "compare_logs", key, digest)
        except C.AdmissionError as exc:
            db.rollback()
            return _comparison_response(request, 409, message=str(exc))
        if existing is not None:
            status, data, message = A.replay(db, existing, user_id)
            rid = str(existing.result_id) if (status == 200 and existing.result_id) else None
            return _comparison_response(request, status, data, message, report_id=rid)
        try:
            C.validate_consent(db, consent_id, user_id, "compare_logs", digest, C.COST_COMPARE)
        except C.AdmissionError as exc:
            db.rollback()
            return _comparison_response(request, 409, message=str(exc))
        pair = _load_compare_pending(str(consent_id))
        if pair is None:
            return _comparison_response(request, 410, message="Upload expired. Please upload the files again.")
        filename_a, content_a, filename_b, content_b = pair
        if _compare_pair_hash(filename_a, content_a, filename_b, content_b) != digest:
            return _comparison_response(request, 409, message="Upload does not match your consent.")
        try:
            item = C.admit_paid_operation(db, user_id, "compare_logs", key, digest,
                                          C.COST_COMPARE, consent_id, worker,
                                          input_manifest=_client_ip(request))
        except C.InsufficientCredits:
            db.rollback()
            return _comparison_response(request, 402, message=COMPARE_INSUFFICIENT_MESSAGE)
        except C.AdmissionError as exc:
            db.rollback()
            return _comparison_response(request, 409 if "409" in str(exc) else 429, message=str(exc))
        db.commit()
        if item.worker_id != worker:
            status, data, message = A.replay(db, item, user_id)
            rid = str(item.result_id) if (status == 200 and item.result_id) else None
            return _comparison_response(request, status, data, message, report_id=rid)
    result_id = None
    try:
        data_a, data_b = _execute_compare(filename_a, content_a, filename_b, content_b)
        failure = None
        for data in (data_a, data_b):
            if isinstance(data, dict) and "error" in data:
                failure = data.get("message", "Comparison failed.")
                break
        with SessionLocal() as db:
            if failure:
                C.release_operation(db, item.id, worker, "analysis_failed")
            else:
                a_result = dict(data_a["results"])
                b_result = dict(data_b["results"])
                # The analyzer saw temp paths; the stored payload names
                # the user's files (compare_service derives display names
                # from result["file"]).
                a_result["file"] = filename_a
                b_result["file"] = filename_b
                payload = compare_results(a_result, b_result)
                result = C.store_result(db, user_id, item.id, payload,
                                        result_type="comparison", severity=None)
                C.complete_operation(db, item.id, worker, result.id)
                result_id = result.id
            db.commit()
    except Exception:
        logging.getLogger(__name__).exception("Comparison execution or settlement failed")
        try:
            with SessionLocal() as db:
                C.release_operation(db, item.id, worker, "execution_failed")
                db.commit()
        except Exception:
            logging.getLogger(__name__).exception("Comparison settlement needs recovery")
        return _comparison_response(request, 503, message="Comparison could not be delivered. Retry this request to check its outcome.")
    finally:
        _delete_paid_pending(str(consent_id))
    if failure:
        return _comparison_response(request, 400, message=failure)
    # Re-read the stored payload so the rendered report is exactly what
    # persistence holds (integrity-checked, like the historical view).
    with SessionLocal() as db:
        result = db.get(M.Result, result_id)
        payload = C.result_payload(result, user_id=user_id, operation_id=item.id,
                                   free_request_id=result.free_request_id)
    return _comparison_response(request, 200, payload, report_id=str(result_id))


@app.get("/compare", response_class=HTMLResponse)
async def compare_form(request: Request):
    """Comparison upload form (paid feature: login required)."""
    from fastapi.responses import RedirectResponse
    from app import auth as auth_helpers
    from app.db import SessionLocal
    # Load session.user INSIDE the session: it is a lazy relationship and
    # accessing it after close raises DetachedInstanceError.
    with SessionLocal() as db:
        session = auth_helpers.get_session_from_cookie(db, request)
        _user = session.user if session else None
        _csrf = session.csrf_token if session else ""
    if not session:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "compare.html", {
        "current_user": _user, "csrf_token": _csrf})


@app.post("/compare", response_class=HTMLResponse)
async def compare_upload(request: Request, file_a: UploadFile | None = File(None),
                         file_b: UploadFile | None = File(None)):
    """Validate BOTH uploads before any analysis or reservation (approved
    spec §5), then quote 3 credits on the generalized consent page.

    Trim C7: both files are subject to the FREE limits even though
    oversize has shipped — an oversize file is rejected here, never
    routed into an oversize comparison. Consent creation charges nothing.
    """
    from fastapi.responses import RedirectResponse
    from app.db import SessionLocal
    from app import auth as auth_helpers
    from app import credits as _credits_helpers
    # Load session.user INSIDE the session (see compare_form).
    with SessionLocal() as db:
        session = auth_helpers.get_session_from_cookie(db, request)
        _user = session.user if session else None
        _csrf = session.csrf_token if session else ""
    if not session:
        return RedirectResponse("/login", status_code=303)

    def error(message: str, status: int = 400):
        return templates.TemplateResponse(request, "compare.html", {
            "error": message, "current_user": _user, "csrf_token": _csrf},
            status_code=status)

    if not file_a or not file_a.filename or not file_b or not file_b.filename:
        return error("Please choose two files: A (before) and B (after).")
    contents = []
    for label, upload in (("A", file_a), ("B", file_b)):
        suffix = Path(upload.filename).suffix.lower()
        if suffix not in ALLOWED_SUFFIXES:
            return error(
                f"File {label}: only {', '.join(sorted(ALLOWED_SUFFIXES))} files are supported "
                f"(got '{suffix or 'no extension'}').")
        buf = bytearray()
        read_limit = MAX_OVERSIZE_UPLOAD_BYTES + 1
        while len(buf) < read_limit:
            chunk = await upload.read(min(1024 * 1024, read_limit - len(buf)))
            if not chunk:
                break
            buf.extend(chunk)
        content = bytes(buf)
        if not content.strip():
            return error(f"File {label} is empty — nothing to compare.")
        if _is_binary_content(content):
            return error(f"File {label} appears to be a binary file, not a text log.")
        # Free limits only (C7): oversize or unsupported in either file
        # rejects the whole pair before any analysis runs.
        if classify_upload_size(len(content), count_original_lines(content)) != "standard":
            return error(
                f"File {label} exceeds the free limits (10 MB / 50,000 lines). "
                "Oversize comparison is not available yet.", status=413)
        contents.append((upload.filename, content))
    try:
        return _paid_consent_page(request, contents[0][0], contents[0][1], _user, _csrf,
                                  _client_ip(request), operation="compare_logs",
                                  filename_b=contents[1][0], content_b=contents[1][1])
    except _credits_helpers.InsufficientCredits:
        return _comparison_response(request, 402, message=COMPARE_INSUFFICIENT_MESSAGE)
    except _credits_helpers.AdmissionError as exc:
        return _comparison_response(request, 409, message=str(exc))
    except RuntimeError as exc:
        if "capacity" in str(exc):
            return error("Pending upload capacity exhausted. Please try again shortly.", status=503)
        raise


@app.post("/compare/paid", response_class=HTMLResponse)
async def compare_paid(request: Request, consent_id: str = Form(...), file_hash: str = Form(...),
                       idempotency_key: str = Form(...), csrf_token: str = Form("")):
    """Confirm a comparison consent (CSRF-protected, like /analyze/paid).

    Runs in a worker thread: the supervised worker's subprocess wait must
    not block the async event loop on a single-worker deployment.
    """
    from app.db import SessionLocal
    from app import auth, models as M
    import asyncio
    import hmac
    with SessionLocal() as db:
        session = auth.get_session_from_cookie(db, request)
        if not session:
            return _comparison_response(request, 401, message="Please log in to use Power-Up credits.")
        if not csrf_token or not hmac.compare_digest(csrf_token, session.csrf_token):
            return _comparison_response(request, 403, message="Invalid request. Please try again.")
    try:
        consent_uuid = uuid_module.UUID(consent_id)
    except ValueError:
        return _comparison_response(request, 400, message="Invalid consent.")
    return await asyncio.to_thread(
        _durable_compare, request, idempotency_key,
        consent_id=consent_uuid, digest=file_hash)


# ---------------------------------------------------------------------------
# Issue #103: Batch analysis (paid) — 2-5 files, ONE combined report.
#
# Pricing (founder-ruled, trim B1): total = (0 if the first file can use
# the free hourly allowance else 1) + (N-1) x 1 credits. One reservation,
# one completion, full release on any failure; an admitted first-file
# free attempt is NOT restored on failure (trim B8). Execution reuses
# the #104 supervised worker (trim B3) under a batch-specific 150s
# outer wall deadline; per-file limits are the FREE limits (trim B9).
# ---------------------------------------------------------------------------

from app.batch_service import MAX_BATCH_FILES as _MAX_BATCH_FILES
from app.batch_service import MIN_BATCH_FILES as _MIN_BATCH_FILES

BATCH_OUTER_DEADLINE_SECONDS = 150


def _batch_insufficient_message(file_count: int, total: int) -> str:
    return (f"This {file_count}-file batch costs {total} credits. "
            "Insufficient eligible Power-Up credits.")


def _batch_response(request, status, data=None, message=None, *, report_id=None,
                    buy_credits=False):
    """Render a batch outcome: the combined report on success, the batch
    form with an error otherwise."""
    user, csrf = _get_current_user_optional(request)
    if data is None:
        return templates.TemplateResponse(request, "batch.html", {
            "error": message, "current_user": user, "csrf_token": csrf,
            "buy_credits": buy_credits}, status_code=status)
    data = dict(data, current_user=user, csrf_token=csrf)
    if report_id is not None:
        data["report_id"] = report_id
    data.setdefault("elapsed", 0.0)
    return templates.TemplateResponse(request, "batch_report.html", data, status_code=status)


def _batch_bundle_hash(files) -> str:
    """Ordered bundle fingerprint binding a batch consent to its files.

    Deterministic serialization of (ordinal, display filename, redacted
    content digest) per file; duplicate filenames stay distinct by
    ordinal, and reordering changes the hash.
    """
    from app.analysis_admission import fingerprint as _fingerprint
    from app import credits as _credits_helpers
    manifest = [[ordinal, filename, _fingerprint(filename, content)]
                for ordinal, filename, content in files]
    return _credits_helpers.hash_input(json.dumps(manifest).encode("utf-8"))


def _store_batch_pending(consent_id: str, files, counts) -> None:
    """Store the versioned ordinal-indexed bundle envelope.

    Layout under the existing pending dir, keyed by the consent UUID
    (same path/mode/TTL discipline as _store_paid_pending): one JSON
    header line {version, files:[{ordinal, filename, length,
    byte_count, line_count}]} followed by the redacted contents in
    upload order. ``counts`` carries the SERVER-measured original
    byte/line counts per file for confirmation-time revalidation.
    Never routed through the single-file pending loader.
    """
    header = {
        "version": 1,
        "files": [
            {"ordinal": ordinal, "filename": filename, "length": len(content),
             "byte_count": counts[i][0], "line_count": counts[i][1]}
            for i, (ordinal, filename, content) in enumerate(files)
        ],
    }
    envelope_size = len(json.dumps(header).encode("utf-8")) + 1 + sum(
        len(content) for _, _, content in files)
    path = _paid_pending_path(consent_id)
    with _PENDING_LOCK:
        cleanup_pending_uploads()
        if (_pending_usage_bytes()
                + envelope_size > _PAID_PENDING_BUDGET):
            raise RuntimeError("Pending upload capacity exhausted")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(json.dumps(header).encode("utf-8") + b"\n")
            for _, _, content in files:
                f.write(content)


def _load_batch_pending(consent_id: str):
    """Load a bundle envelope; None on missing/expired/corrupt.

    Returns a list of (ordinal, filename, content, byte_count,
    line_count) in upload order.
    """
    path = _paid_pending_path(consent_id)
    try:
        stat = os.stat(path)
        if datetime.now(timezone.utc).timestamp() - stat.st_mtime > _PAID_PENDING_TTL:
            os.unlink(path)
            return None
        with open(path, "rb") as f:
            raw = f.read()
        nl = raw.index(b"\n")
        header = json.loads(raw[:nl].decode("utf-8"))
        if not isinstance(header, dict) or header.get("version") != 1:
            return None
        entries = header["files"]
        pos = nl + 1
        out = []
        for entry in entries:
            length = int(entry["length"])
            content = raw[pos:pos + length]
            if len(content) != length:
                return None
            pos += length
            out.append((int(entry["ordinal"]), entry["filename"], content,
                        int(entry["byte_count"]), int(entry["line_count"])))
        if pos != len(raw):
            return None
        return out
    except (OSError, ValueError, KeyError, TypeError):
        return None


def _batch_consent_page(request: Request, validated, user, csrf_token: str, ip: str,
                        *, quote=None):
    """Quote a batch and return the generalized consent page (402).

    ``validated`` is a list of dicts {ordinal, filename, content,
    byte_count, line_count} holding the ORIGINAL uploads (already
    validated against the free limits). Redaction happens here, before
    fingerprinting and disk persistence — raw logs are never written.
    Consent creation charges nothing, claims no allowance, and creates
    no reservation. Raises InsufficientCredits (eligible < total),
    RuntimeError on pending-capacity exhaustion.
    """
    import os as _os
    if not _os.environ.get("DATABASE_URL"):
        raise RuntimeError("no database")
    from app.db import SessionLocal
    from app import credits as credits_helpers
    from app import batch_admission
    from app.redact import redact_secrets

    files = []
    counts = []
    try:
        for entry in validated:
            text = entry["content"].decode("utf-8", errors="replace")
            redacted = redact_secrets(text).encode("utf-8")
            files.append((entry["ordinal"], entry["filename"], redacted))
            counts.append((entry["byte_count"], entry["line_count"]))
    except Exception:
        from fastapi.responses import HTMLResponse
        return HTMLResponse(
            content="<h1>Upload processing error</h1><p>Could not securely process your files. Please try again.</p>",
            status_code=500,
        )
    n = len(files)
    file_hash = _batch_bundle_hash(files)
    db = SessionLocal()
    try:
        if quote is None:
            total, first_cost, free_available = batch_admission.batch_price(db, ip, n)
        else:
            total, first_cost, free_available = quote
        summary = credits_helpers.get_balance_summary(db, user.id)
        if summary["eligible"] < total:
            raise credits_helpers.InsufficientCredits("insufficient credits")
        with _PENDING_LOCK:
            consent = credits_helpers.create_consent(
                db, user.id, "batch", file_hash, total)
            db.flush()
            consent_id = str(consent.id)
            try:
                _store_batch_pending(consent_id, files, counts)
            except Exception:
                db.rollback()
                raise
            db.commit()
    finally:
        db.close()

    first_line = ("free hourly allowance" if free_available
                  else "1 credit (free allowance used)")
    total_bytes = sum(c[0] for c in counts)
    context = {
        "current_user": user,
        "csrf_token": csrf_token,
        "filename": f"Batch \u2014 {n} files",
        "file_list": [f"{ordinal}. {filename}" for ordinal, filename, _ in files],
        "file_hash": file_hash,
        "consent_id": consent_id,
        "cost": total,
        "balance": summary["balance"],
        "eligible": summary["eligible"],
        "operation_type": "batch",
        "heading": "Batch analysis",
        "intro": (f"{n} files. First file: {first_line}. "
                  f"{n - 1} additional file{'s' if n - 1 != 1 else ''} "
                  f"\u00d7 1 credit. Total: {total} credits."),
        "size_line": f"{total_bytes:,} bytes across {n} files, in upload order",
        "limits_line": "Free limits apply to every file (10 MB / 50,000 lines each). Duplicate filenames are separate files, told apart by their number.",
        "cost_label": f"{total} credit{'s' if total != 1 else ''}",
        "cost_sentence": "This batch produces one combined report.",
        "confirm_label": f"Analyze {n} files \u2014 use {total} credits",
        "confirm_action": "/batch/paid",
        "cancel_label": "Cancel",
        "note": ("All credits are released if the batch fails, but an admitted "
                 "first-file free attempt is counted even if the batch fails and "
                 "is not restored. This consent screen consumes no allowance. "
                 "Results are available for 7 days. PDF export of the combined "
                 "report costs 2 credits once, not per file."),
    }
    return templates.TemplateResponse(
        request, "paid_consent.html", context, status_code=402)


def _execute_batch(files):
    """Run the batch sequentially in upload order via the shared
    supervised worker (trim B3: #104's run_supervised, NOT a new
    worker), under the batch-specific 150-second outer wall deadline.

    ``files`` is a list of (ordinal, filename, content). Returns one
    analyze_upload-shaped dict per file, in order; a file whose worker
    run fails carries an error dict, and a blown outer deadline turns
    the current file into a timeout error so settlement releases the
    whole reservation.
    """
    import time as _time
    from app.analysis_worker import run_supervised
    start = _time.monotonic()
    results = []
    for ordinal, filename, content in files:
        remaining = BATCH_OUTER_DEADLINE_SECONDS - (_time.monotonic() - start)
        if remaining <= 0:
            results.append({
                "error": "analysis_timeout",
                "message": f"Batch exceeded the {BATCH_OUTER_DEADLINE_SECONDS}s "
                           "outer deadline before this file finished.",
                "filename": filename,
            })
            break
        results.append(run_supervised(
            filename, content, timeout=max(1, min(60, int(remaining)))))
    return results


def _durable_batch(request, key, *, consent_id, digest):
    """Confirm a batch consent: replay, re-quote check, admit once
    (reservation + free-first claim in one transaction), run, settle.

    Mirrors the compare/oversize settlement discipline: replay before
    consent validation, one reservation for the whole bundle, full
    reversal on any failure/exception, a committed result never
    reversed.
    """
    from app.db import SessionLocal
    from app import credits as C, models as M, analysis_admission as A
    from app import batch_admission, batch_service
    user, csrf = _get_current_user_optional(request)
    if user is None:
        return _batch_response(request, 401, message="Please log in to use Power-Up credits.")
    user_id = user.id
    ip = _client_ip(request)
    worker = uuid_module.uuid4().hex
    operation_id = None
    total_cost = None
    first_cost = None
    bundle = None
    with SessionLocal() as db:
        try:
            existing = C.find_operation(db, user_id, "batch", key, digest)
        except C.AdmissionError as exc:
            db.rollback()
            return _batch_response(request, 409, message=str(exc))
        if existing is not None:
            status, data, message = A.replay(db, existing, user_id)
            rid = str(existing.result_id) if (status == 200 and existing.result_id) else None
            return _batch_response(request, status, data, message, report_id=rid)
        consent_row = db.get(M.Consent, consent_id, populate_existing=True)
        quoted_total = consent_row.max_cost if consent_row is not None else None
        bundle = _load_batch_pending(str(consent_id))
        if bundle is None:
            return _batch_response(request, 410, message="Upload expired. Please upload the files again.")
        files = [(ordinal, filename, content) for ordinal, filename, content, _, _ in bundle]
        if _batch_bundle_hash(files) != digest:
            return _batch_response(request, 409, message="Upload does not match your consent.")
        # Revalidate every free limit from the SERVER-owned counts
        # recorded at intake, never from client fields (trim B9).
        for ordinal, filename, content, byte_count, line_count in bundle:
            problem = None
            if Path(filename).suffix.lower() not in ALLOWED_SUFFIXES:
                problem = "unsupported file type"
            elif not content.strip():
                problem = "file is empty"
            elif _is_binary_content(content):
                problem = "file appears to be binary, not a text log"
            elif byte_count > MAX_BYTES:
                problem = "exceeds the 10 MB free limit"
            elif line_count > 50_000:
                problem = "exceeds the 50,000-line free limit"
            if problem:
                return _batch_response(
                    request, 400,
                    message=f"File {ordinal} ({filename}): {problem}. "
                            "No files were analyzed and no credits were reserved.")
        # Consent validation as its own step (the oversize pattern):
        # owner/type/hash/expiry/consumption failures are 409 here,
        # before quota or ledger admission maps its own errors.
        try:
            C.validate_consent(db, consent_id, user_id, "batch", digest,
                               quoted_total if quoted_total is not None else 0)
        except C.AdmissionError as exc:
            db.rollback()
            return _batch_response(request, 409, message=str(exc))
        try:
            item = batch_admission.admit_batch_operation(
                db, user_id, key, digest, consent_id, worker, ip, len(bundle))
        except batch_admission.RequoteRequired as rq:
            db.rollback()
            # Invalidate the old quote, then issue a replacement consent
            # at the recomputed total for the same bundle; run nothing.
            with SessionLocal() as db2:
                stale = db2.get(M.Consent, consent_id)
                if stale is not None:
                    stale.expires_at = C._utcnow()
                    db2.commit()
            _delete_paid_pending(str(consent_id))
            validated = [
                {"ordinal": ordinal, "filename": filename, "content": content,
                 "byte_count": byte_count, "line_count": line_count}
                for ordinal, filename, content, byte_count, line_count in bundle
            ]
            try:
                return _batch_consent_page(request, validated, user, csrf, ip)
            except C.InsufficientCredits:
                return _analysis_response(
                    request, 402,
                    message=_batch_insufficient_message(len(bundle), rq.new_total),
                    buy_credits=True)
            except RuntimeError:
                return _batch_response(
                    request, 503,
                    message="Pending upload capacity exhausted. Please try again shortly.")
        except C.InsufficientCredits:
            db.rollback()
            return _analysis_response(
                request, 402,
                message=_batch_insufficient_message(
                    len(bundle), quoted_total if quoted_total is not None else 0),
                buy_credits=True)
        except C.AdmissionError as exc:
            db.rollback()
            return _batch_response(request, 409 if "409" in str(exc) else 429,
                                   message=str(exc))
        except Exception:
            db.rollback()
            logging.getLogger(__name__).exception("Batch admission failed")
            return _batch_response(request, 503, message="Could not start the batch. Please try again shortly.")
        operation_id = item.id
        total_cost = item.cost
        first_cost = 0 if item.free_allowance_claim else C.COST_ADDITIONAL_ANALYSIS
        created = (item.worker_id == worker)
        db.commit()
        if not created:
            status, data, message = A.replay(db, item, user_id)
            rid = str(item.result_id) if (status == 200 and item.result_id) else None
            return _batch_response(request, status, data, message, report_id=rid)
    result_id = None
    failure = None
    try:
        payloads = _execute_batch(
            [(ordinal, filename, content) for ordinal, filename, content, _, _ in bundle])
        if len(payloads) != len(bundle):
            failure = "Batch execution stopped before every file was analyzed."
        else:
            for (ordinal, filename, *_), payload in zip(bundle, payloads):
                if isinstance(payload, dict) and "error" in payload:
                    failure = (f"File {ordinal} ({filename}): "
                               f"{payload.get('message', 'Analysis failed.')}")
                    break
        with SessionLocal() as db:
            if failure:
                C.release_operation(db, operation_id, worker, "analysis_failed")
            else:
                payload = batch_service.build_batch_payload(
                    [(ordinal, filename, payload)
                     for (ordinal, filename, *_), payload in zip(bundle, payloads)],
                    pricing={"file_count": len(bundle),
                             "first_file_cost": first_cost,
                             "additional_file_cost": C.COST_BATCH_ADDITIONAL_FILE,
                             "total_cost": total_cost})
                result = C.store_result(
                    db, user_id, operation_id, payload, result_type="analysis",
                    severity=batch_service.batch_severity(
                        payload["summary"]["level_counts"]))
                C.complete_operation(db, operation_id, worker, result.id)
                result_id = result.id
            db.commit()
    except Exception:
        logging.getLogger(__name__).exception("Batch execution or settlement failed")
        try:
            with SessionLocal() as db:
                C.release_operation(db, operation_id, worker, "execution_failed")
                db.commit()
        except Exception:
            logging.getLogger(__name__).exception("Batch settlement needs recovery")
        return _batch_response(request, 503, message="Batch could not be delivered. Retry this request to check its outcome.")
    finally:
        _delete_paid_pending(str(consent_id))
    if failure:
        return _batch_response(request, 400, message=failure)
    with SessionLocal() as db:
        result = db.get(M.Result, result_id)
        payload = C.result_payload(result, user_id=user_id, operation_id=operation_id,
                                   free_request_id=result.free_request_id)
    return _batch_response(request, 200, payload, report_id=str(result_id))


@app.get("/batch", response_class=HTMLResponse)
async def batch_form(request: Request):
    """Batch upload form (paid feature: login required)."""
    from fastapi.responses import RedirectResponse
    from app import auth as auth_helpers
    from app.db import SessionLocal
    with SessionLocal() as db:
        session = auth_helpers.get_session_from_cookie(db, request)
        _user = session.user if session else None
        _csrf = session.csrf_token if session else ""
    if not session:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "batch.html", {
        "current_user": _user, "csrf_token": _csrf})


@app.post("/batch", response_class=HTMLResponse)
async def batch_intake(request: Request, files: list[UploadFile] = File(...),
                       csrf_token: str = Form("")):
    """Validate ALL uploads before any analysis or reservation, then
    quote the batch total on the generalized consent page.

    Anonymous POSTs get 401 (no consent, pending bundle, or reservation).
    Any invalid file rejects the WHOLE batch with 400 naming its
    ordinal/name; no analyzer call, reservation, quota claim, result,
    or pending artifact survives a validation failure.
    """
    from app.db import SessionLocal
    from app import auth as auth_helpers
    from app import credits as _credits_helpers
    from app import batch_admission
    with SessionLocal() as db:
        session = auth_helpers.get_session_from_cookie(db, request)
        _user = session.user if session else None
        _csrf = session.csrf_token if session else ""
    if not session:
        return _batch_response(request, 401, message="Please log in to analyze a batch.")

    def error(message: str, status: int = 400):
        return templates.TemplateResponse(request, "batch.html", {
            "error": message, "current_user": _user, "csrf_token": _csrf},
            status_code=status)

    no_charge = " No files were analyzed and no credits were reserved."
    if files is None or len(files) < _MIN_BATCH_FILES:
        return error(f"A batch needs at least {_MIN_BATCH_FILES} files. "
                     "For one file, use the single-file upload on the home page." + no_charge)
    if len(files) > _MAX_BATCH_FILES:
        return error(f"A batch is at most {_MAX_BATCH_FILES} files; "
                     f"you selected {len(files)}." + no_charge)
    validated = []
    for ordinal, upload in enumerate(files, start=1):
        filename = upload.filename or ""
        if not filename:
            return error(f"File {ordinal}: please choose a file." + no_charge)
        suffix = Path(filename).suffix.lower()
        if suffix not in ALLOWED_SUFFIXES:
            return error(
                f"File {ordinal} ({filename}): only "
                f"{', '.join(sorted(ALLOWED_SUFFIXES))} files are supported "
                f"(got '{suffix or 'no extension'}')." + no_charge)
        buf = bytearray()
        read_limit = MAX_BYTES + 1
        while len(buf) < read_limit:
            chunk = await upload.read(min(1024 * 1024, read_limit - len(buf)))
            if not chunk:
                break
            buf.extend(chunk)
        content = bytes(buf)
        if not content.strip():
            return error(f"File {ordinal} ({filename}): file is empty \u2014 nothing to analyze." + no_charge)
        if _is_binary_content(content):
            return error(f"File {ordinal} ({filename}): this appears to be a binary file, not a text log." + no_charge)
        if len(content) > MAX_BYTES:
            return error(f"File {ordinal} ({filename}): exceeds the 10 MB free limit "
                         f"({MAX_BYTES // (1024 * 1024)} MB per file)." + no_charge)
        line_count = count_original_lines(content)
        if line_count > 50_000:
            return error(f"File {ordinal} ({filename}): exceeds the 50,000-line limit." + no_charge)
        validated.append({"ordinal": ordinal, "filename": filename,
                          "content": content, "byte_count": len(content),
                          "line_count": line_count})
    ip = _client_ip(request)
    try:
        with SessionLocal() as db:
            quote = batch_admission.batch_price(db, ip, len(validated))
    except Exception:
        return error("Batch analysis is temporarily unavailable. Please try again shortly.",
                     status=503)
    total = quote[0]
    try:
        return _batch_consent_page(request, validated, _user, _csrf, ip, quote=quote)
    except _credits_helpers.InsufficientCredits:
        return _analysis_response(
            request, 402, message=_batch_insufficient_message(len(validated), total),
            buy_credits=True)
    except _credits_helpers.AdmissionError as exc:
        return _batch_response(request, 409, message=str(exc))
    except RuntimeError as exc:
        if "capacity" in str(exc):
            return error("Pending upload capacity exhausted. Please try again shortly.",
                         status=503)
        return error("Batch analysis is temporarily unavailable. Please try again shortly.",
                     status=503)


@app.post("/batch/paid", response_class=HTMLResponse)
async def batch_paid(request: Request, consent_id: str = Form(...), file_hash: str = Form(...),
                     idempotency_key: str = Form(...), csrf_token: str = Form("")):
    """Confirm a batch consent (CSRF-protected, like /analyze/paid).

    Runs in a worker thread: the supervised worker's subprocess wait
    must not block the async event loop on a single-worker deployment.
    """
    from app.db import SessionLocal
    from app import auth
    import asyncio
    import hmac
    with SessionLocal() as db:
        session = auth.get_session_from_cookie(db, request)
        if not session:
            return _batch_response(request, 401, message="Please log in to use Power-Up credits.")
        if not csrf_token or not hmac.compare_digest(csrf_token, session.csrf_token):
            return _batch_response(request, 403, message="Invalid request. Please try again.")
    try:
        consent_uuid = uuid_module.UUID(consent_id)
    except ValueError:
        return _batch_response(request, 400, message="Invalid consent.")
    return await asyncio.to_thread(
        _durable_batch, request, idempotency_key,
        consent_id=consent_uuid, digest=file_hash)


@app.get("/credits/balance")
async def credits_balance(request: Request):
    """JSON API: current user's credit balance summary."""
    from fastapi.responses import JSONResponse
    import os as _os
    if not _os.environ.get("DATABASE_URL"):
        return JSONResponse({"error": "credits unavailable"}, status_code=503)
    _user, _ = _get_current_user_optional(request)
    if not _user:
        return JSONResponse({"error": "login required"}, status_code=401)
    from app.db import SessionLocal
    from app import credits as credits_helpers
    db = SessionLocal()
    try:
        summary = credits_helpers.get_balance_summary(db, _user.id)
        return JSONResponse(summary)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Phase 2B: Report history + PDF export
# ---------------------------------------------------------------------------

@app.get("/reports", response_class=HTMLResponse)
async def reports_list(request: Request, page: int = 1, db=Depends(get_db)):
    """List the current user's analysis reports (7-day retention). Paginated: 20 per page."""
    from fastapi.responses import RedirectResponse
    from app import auth as auth_helpers
    session = auth_helpers.get_session_from_cookie(db, request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    _user = session.user
    _csrf = session.csrf_token
    from app import models
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    per_page = 20
    page = max(1, page)
    offset = (page - 1) * per_page
    # Issue #102: comparison reports (type "comparison") list alongside
    # analyses; PDF-only results stay excluded.
    base_q = db.query(models.Result).filter(
        models.Result.user_id == _user.id,
        models.Result.type.in_(["analysis", "comparison"]),
        models.Result.expires_at > now,
        models.Result.deleted_at.is_(None),
    )
    total = base_q.count()
    results = base_q.order_by(models.Result.created_at.desc()).offset(offset).limit(per_page).all()
    total_pages = max(1, (total + per_page - 1) // per_page)
    reports = []
    for r in results:
        try:
            manifest = json.loads(r.storage_manifest)
            filename = manifest.get("filename", "Unknown file")
        except (json.JSONDecodeError, TypeError):
            filename = "Unknown file"
        from app.credits import _as_aware
        reports.append({
            "id": str(r.id),
            "filename": filename,
            "severity": r.severity,  # 'ok' | 'warnings' | 'errors' | None (pre-#49 rows)
            "created_at": r.created_at,
            "expires_at": r.expires_at,
            "days_left": max(0, (_as_aware(r.expires_at) - now).days),
        })
    return templates.TemplateResponse(request, "reports.html", {
        "reports": reports,
        "current_user": _user,
        "csrf_token": _csrf,
        "page": page,
        "total_pages": total_pages,
        "total": total,
    })


@app.get("/reports/{result_id}", response_class=HTMLResponse)
async def report_view(request: Request, result_id: str, db=Depends(get_db)):
    """View a specific past analysis report (ownership-checked, analysis only)."""
    import uuid as _uuid
    from fastapi.responses import RedirectResponse, JSONResponse
    from app import auth as auth_helpers
    from app import credits as credits_helpers
    session = auth_helpers.get_session_from_cookie(db, request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    _user = session.user
    _csrf = session.csrf_token
    from app import models
    from datetime import datetime, timezone
    try:
        rid = _uuid.UUID(result_id)
    except ValueError:
        return JSONResponse({"error": "Invalid report ID"}, status_code=400)
    # Issue #102: report_kind dispatch — a comparison result renders the
    # comparison template; report.html itself is unchanged.
    result = db.query(models.Result).filter(
        models.Result.id == rid,
        models.Result.user_id == _user.id,
        models.Result.type.in_(["analysis", "comparison"]),
        models.Result.deleted_at.is_(None),
    ).first()
    if not result:
        return JSONResponse({"error": "Report not found"}, status_code=404)
    if credits_helpers._as_aware(result.expires_at) < datetime.now(timezone.utc):
        return JSONResponse({"error": "Report has expired"}, status_code=410)
    try:
        data = credits_helpers.result_payload(
            result, user_id=_user.id,
            operation_id=result.operation_id,
            free_request_id=result.free_request_id,
        )
    except credits_helpers.AdmissionError:
        return JSONResponse({"error": "Report data corrupted"}, status_code=500)
    data["current_user"] = _user
    data["csrf_token"] = _csrf
    data["report_id"] = str(result.id)
    data["is_historical"] = True
    # Issue #105: existing structured-export artifacts for this source get
    # free re-download links on the report page (artifact's own expiry,
    # validated on the download route itself).
    if result.type == "analysis" and not data.get("report_kind"):
        from datetime import datetime as _dt, timezone as _tz
        _arts = db.query(models.Result).filter(
            models.Result.user_id == _user.id,
            models.Result.type == "structured_export",
            models.Result.deleted_at.is_(None),
            models.Result.expires_at > _dt.now(_tz.utc),
        ).order_by(models.Result.created_at.desc()).all()
        _links = []
        for _art in _arts:
            try:
                _m = json.loads(_art.storage_manifest)
            except (ValueError, TypeError):
                continue
            if _m.get("source_result_id") == str(result.id) and _m.get("format") in ("csv", "json"):
                _links.append({"id": str(_art.id), "format": _m["format"]})
        data["structured_exports"] = _links
    data.setdefault("structured_exports", [])
    # Issue #107: owner controls on report.html — retention state and
    # sharing state for THIS report, plus fresh per-render action keys
    # (a deliberately new key is a new purchase/rotation; a replayed key
    # is fenced server-side by ReportAction identity).
    if result.type == "analysis":
        from datetime import timedelta as _td
        _expires = credits_helpers._as_aware(result.expires_at)
        _ceiling = credits_helpers._as_aware(result.ready_at) + _td(
            days=credits_helpers.RETENTION_MAX_DAYS)
        data["report_expires_at"] = _expires
        data["retention_at_cap"] = (
            _expires + _td(days=credits_helpers.RETENTION_EXTENSION_DAYS) > _ceiling)
        data["retention_next_expiry"] = _expires + _td(
            days=credits_helpers.RETENTION_EXTENSION_DAYS)
        data["retention_key"] = uuid_module.uuid4().hex
        data["share_create_key"] = uuid_module.uuid4().hex
        data["share_rotate_key"] = uuid_module.uuid4().hex
        data["share_revoke_key"] = uuid_module.uuid4().hex
        _sharing = db.query(models.ReportSharing).filter(
            models.ReportSharing.result_id == result.id).first()
        data["share_active"] = bool(
            _sharing and _sharing.token_hash and _sharing.revoked_at is None)
    # Older manifests predate the elapsed field; the template requires it.
    data.setdefault("elapsed", 0.0)
    if result.type == "comparison":
        return templates.TemplateResponse(request, "compare_report.html", data)
    # Issue #103: a batch result is type "analysis" with a batch
    # discriminator in its manifest; only it dispatches to the batch
    # template — report.html itself is unchanged.
    if data.get("report_kind") == "batch":
        return templates.TemplateResponse(request, "batch_report.html", data)
    return templates.TemplateResponse(request, "report.html", data)


def _safe_download_filename(filename: str) -> str:
    """Header-safe download name: HTTP headers are latin-1, so a report
    filename containing non-ASCII characters (a comparison filename
    contains "→") would raise UnicodeEncodeError on download. The stored
    filename is untouched; only the header value is sanitized."""
    safe = "".join(ch if (ch.isascii() and (ch.isalnum() or ch in "._-")) else "-"
                   for ch in filename)
    return safe or "report"


@app.post("/reports/{result_id}/pdf")
async def report_export_pdf(request: Request, result_id: str, db=Depends(get_db)):
    """Export a report as PDF. Costs 2 credits (COST_PDF)."""
    import uuid as _uuid
    import hmac
    import base64 as _b64
    from fastapi.responses import JSONResponse, Response
    from app import auth as auth_helpers
    from app import credits as credits_helpers
    from app import models
    from datetime import datetime, timezone

    session = auth_helpers.get_session_from_cookie(db, request)
    if not session:
        return JSONResponse({"error": "Login required"}, status_code=401)
    user = session.user

    form = await request.form()
    csrf_token = form.get("csrf_token", "")
    if not csrf_token or not hmac.compare_digest(csrf_token, session.csrf_token):
        return JSONResponse({"error": "Invalid CSRF token"}, status_code=403)

    try:
        rid = _uuid.UUID(result_id)
    except ValueError:
        return JSONResponse({"error": "Invalid report ID"}, status_code=400)

    # Issue #102: PDF export also serves comparison reports (2 credits,
    # standard price); the renderer branches on the result type below.
    result = db.query(models.Result).filter(
        models.Result.id == rid,
        models.Result.user_id == user.id,
        models.Result.type.in_(["analysis", "comparison"]),
        models.Result.deleted_at.is_(None),
    ).first()
    if not result:
        return JSONResponse({"error": "Report not found"}, status_code=404)
    if credits_helpers._as_aware(result.expires_at) < datetime.now(timezone.utc):
        return JSONResponse({"error": "Report has expired"}, status_code=410)

    # Issue #62: export intent — an authenticated user with a real, unexpired
    # report asked for a PDF export. Standalone session: intent counts whether
    # or not credits suffice, and the 402 path rolls the request transaction
    # back.
    from app import funnel as funnel_helpers
    funnel_helpers.emit_standalone(funnel_helpers.EXPORT_INTENT, user_id=user.id)

    base_idempotency_key = f"pdf-{result_id}"
    request_hash = result.integrity_digest
    existing_op = db.query(models.Operation).filter(
        models.Operation.user_id == user.id,
        models.Operation.type == "pdf",
        models.Operation.idempotency_key == base_idempotency_key,
    ).first()
    # For failed/expired operations, use a new idempotency key so the retry
    # gets a fresh operation identity (the old credits were released).
    # The unique constraint on (user_id, type, idempotency_key) ensures safety.
    idempotency_key = base_idempotency_key
    if existing_op and existing_op.status in ("failed", "expired"):
        idempotency_key = f"{base_idempotency_key}-retry-{_uuid.uuid4().hex[:8]}"
        existing_op = None  # Force fresh admission with new key
    if existing_op:
        if existing_op.status == "completed" and existing_op.result_id:
            # Validate the saved PDF result before replaying (integrity, ownership, expiry)
            pdf_result = db.get(models.Result, existing_op.result_id)
            if pdf_result:
                try:
                    manifest = credits_helpers.result_payload(
                        pdf_result, user_id=user.id, operation_id=existing_op.id,
                    )
                    pdf_bytes = _b64.b64decode(manifest["pdf_base64"])
                    filename = manifest.get("filename", "report")
                    return Response(
                        content=pdf_bytes,
                        media_type="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="stacksift-report-{_safe_download_filename(filename)}.pdf"'},
                    )
                except (credits_helpers.AdmissionError, KeyError, ValueError):
                    # Stored PDF is invalid or expired; don't attempt to reuse the
                    # completed operation's idempotency key. Return a controlled error.
                    return JSONResponse(
                        {"error": "Previously generated PDF is no longer available. Please generate a new export."},
                        status_code=410,
                    )
        elif existing_op.status == "reserved":
            # Another request is already generating this PDF; don't hijack its operation
            return JSONResponse(
                {"error": "PDF export already in progress. Please wait and try again."},
                status_code=409,
            )
        # For failed/expired operations, fall through to admit a fresh one

    consent = credits_helpers.create_consent(
        db, user_id=user.id, operation_type="pdf",
        input_hash=request_hash, max_cost=credits_helpers.COST_PDF,
    )
    db.flush()

    worker_id = f"pdf-export-{_uuid.uuid4().hex[:8]}"
    try:
        op = credits_helpers.admit_paid_operation(
            db, user_id=user.id, operation_type="pdf",
            idempotency_key=idempotency_key, request_hash=request_hash,
            cost=credits_helpers.COST_PDF, consent_id=consent.id,
            worker_id=worker_id,
        )
        db.commit()
    except credits_helpers.InsufficientCredits:
        db.rollback()
        return JSONResponse({"error": "Insufficient credits. PDF export costs 2 credits.",
                             "purchase_url": "/credits"}, status_code=402)
    except credits_helpers.AdmissionError as e:
        db.rollback()
        return JSONResponse({"error": str(e)}, status_code=409)

    from app.pdf_export import generate_report_pdf, generate_comparison_pdf, generate_batch_pdf
    try:
        # Validate source result integrity before generating PDF
        manifest_data = credits_helpers.result_payload(
            result, user_id=user.id,
            operation_id=result.operation_id,
            free_request_id=result.free_request_id,
        )
        filename = manifest_data.get("filename", "report")
        if manifest_data.get("report_kind") == "batch":
            # Issue #103 (trim B5): ONE 2-credit export for the whole
            # combined artifact — the charge above is the standard
            # single COST_PDF admission for this operation.
            pdf_bytes = generate_batch_pdf(result.storage_manifest, filename)
        elif result.type == "comparison":
            pdf_bytes = generate_comparison_pdf(result.storage_manifest, filename)
        else:
            pdf_bytes = generate_report_pdf(result.storage_manifest, filename)
    except Exception as e:
        try:
            credits_helpers.release_operation(db, op.id, worker_id, str(e)[:200])
            db.commit()
        except Exception:
            db.rollback()
        return JSONResponse({"error": "PDF generation failed"}, status_code=500)

    try:
        pdf_result = credits_helpers.store_pdf_result(db, user.id, op.id, pdf_bytes, filename)
        credits_helpers.complete_operation(
            db, op.id, worker_id, result_id=pdf_result.id,
            lease_generation=op.lease_generation,
        )
        db.commit()
    except Exception as e:
        db.rollback()
        try:
            credits_helpers.release_operation(db, op.id, worker_id, str(e)[:200])
            db.commit()
        except Exception:
            pass
        return JSONResponse({"error": "Failed to store PDF"}, status_code=500)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="stacksift-report-{_safe_download_filename(filename)}.pdf"'},
    )



# ---------------------------------------------------------------------------
# Issue #105: Structured export (CSV/JSON) — uniform 2 credits per format
# (founder batched ruling 2026-11-01: COST_STRUCTURED_EXPORT for every
# format). Reserve -> generate from the validated snapshot -> store +
# complete in ONE settlement; full release on any failure.
# ---------------------------------------------------------------------------


def _structured_export_response(export_bytes, manifest):
    from fastapi.responses import Response
    return Response(
        content=export_bytes,
        media_type=manifest["media_type"],
        headers={
            "Content-Disposition": f'attachment; filename="{manifest["filename"]}"',
            "Cache-Control": "private, no-store",
            "X-Export-Download-URL": f"/exports/{manifest['_artifact_id']}",
        },
    )


@app.post("/reports/{result_id}/exports/{export_format}")
async def report_export_structured(request: Request, result_id: str, export_format: str, db=Depends(get_db)):
    """Export a stored single-file report as CSV or JSON.

    Costs COST_STRUCTURED_EXPORT credits on first generation per format;
    replays of the same format/source/schema are free.
    """
    import uuid as _uuid
    import hmac
    from fastapi.responses import JSONResponse
    from sqlalchemy import select as _select
    from app import auth as auth_helpers
    from app import credits as credits_helpers
    from app import models
    from app import structured_export as se
    from datetime import datetime, timezone

    # Format gate first: reject anything but csv/json before any
    # reservation (and before auth/CSRF work that could mask it).
    if export_format not in se.EXPORT_FORMATS:
        return JSONResponse({"error": "Unsupported export format"}, status_code=400)

    session = auth_helpers.get_session_from_cookie(db, request)
    if not session:
        return JSONResponse({"error": "Login required"}, status_code=401)
    user = session.user

    form = await request.form()
    csrf_token = form.get("csrf_token", "")
    if not csrf_token or not hmac.compare_digest(csrf_token, session.csrf_token):
        return JSONResponse({"error": "Invalid CSRF token"}, status_code=403)

    try:
        rid = _uuid.UUID(result_id)
    except ValueError:
        return JSONResponse({"error": "Invalid report ID"}, status_code=400)

    # PR #125 finding 4: comparison reports are stored with
    # type="comparison" (credits.store_result result_type="comparison");
    # they must be found here so they flow through integrity validation
    # and the report-kind gate (422 before charge), not 404.
    source = db.query(models.Result).filter(
        models.Result.id == rid,
        models.Result.user_id == user.id,
        models.Result.type.in_(("analysis", "comparison")),
        models.Result.deleted_at.is_(None),
    ).first()
    if not source:
        return JSONResponse({"error": "Report not found"}, status_code=404)
    if credits_helpers._as_aware(source.expires_at) <= datetime.now(timezone.utc):
        return JSONResponse({"error": "Report has expired"}, status_code=410)

    # Validate ALL source prerequisites BEFORE reservation (spec §5),
    # including integrity via result_payload (owner/origin/expiry/digest).
    try:
        payload = credits_helpers.result_payload(
            source, user_id=user.id,
            operation_id=source.operation_id,
            free_request_id=source.free_request_id,
        )
    except credits_helpers.AdmissionError:
        return JSONResponse({"error": "Report data corrupted"}, status_code=500)
    except Exception:
        return JSONResponse({"error": "Report data corrupted"}, status_code=500)

    # Report-kind gate (§7): compare/batch/unknown fail closed before charge.
    try:
        se.check_report_kind(payload)
    except se.UnsupportedReportKind:
        return JSONResponse(
            {"error": "Structured export is not yet supported for this report type"},
            status_code=422,
        )

    # Serialization validation also happens BEFORE reservation: a CSV
    # contradiction (422) or a non-finite JSON payload must never debit.
    # PR #125 finding 3: validation is separated from generation —
    # validate_exportable performs the full serialization validation
    # WITHOUT calling generate_export, so the 402 and completed-replay
    # paths below never run the generator. Bytes are generated only
    # after replay discovery + successful admission, from this same
    # validated snapshot.
    try:
        se.validate_exportable(payload, export_format)
    except se.UnsupportedReportKind:
        return JSONResponse(
            {"error": "Structured export is not yet supported for this report type"},
            status_code=422,
        )
    except se.StructuredExportError:
        return JSONResponse({"error": "Report cannot be exported"}, status_code=422)

    cost = credits_helpers.COST_STRUCTURED_EXPORT
    base_key = f"structured-{rid}-{export_format}-v1"
    request_hash = credits_helpers.hash_input(json.dumps(
        {
            "source_result_id": str(rid),
            "source_integrity_digest": source.integrity_digest,
            "format": export_format,
            "schema_version": se.SCHEMA_VERSION,
        },
        sort_keys=True, separators=(",", ":"),
    ).encode())

    # PR #125 finding 1: serialize discovery + retry-key creation for
    # the whole base-key chain. Lock the global:paid capacity scope
    # (same first scope admit_paid_operation locks) BEFORE discovery
    # and hold it, in this transaction, through the admission commit
    # below. A concurrent POST blocks on that row until the first
    # reservation commits, then its discovery sees the reserved /
    # completed operation instead of inventing a second retry key.
    # Every early return after this point rolls back to release it.
    credits_helpers.lock_global_paid_scope(db)

    # Replay discovery (§5): find the LATEST matching attempt — the base
    # key or any server-created retry suffix — never just the base key
    # (that is the PDF retry-discovery gap, designed out here).
    attempts = db.execute(
        _select(models.Operation).where(
            models.Operation.user_id == user.id,
            models.Operation.type == "structured_export",
        )
    ).scalars().all()
    matching = [
        op for op in attempts
        if op.idempotency_key == base_key
        or op.idempotency_key.startswith(base_key + "-retry-")
    ]
    # In-progress anywhere in the chain blocks a second generator/debit.
    if any(op.status == "reserved" for op in matching):
        db.rollback()
        return JSONResponse(
            {"error": "Structured export already in progress. Please wait and try again."},
            status_code=409,
        )
    completed = [op for op in matching if op.status == "completed" and op.result_id]
    if completed:
        # Latest completed attempt wins (retries are created later).
        latest = max(completed, key=lambda op: (op.created_at, str(op.id)))
        artifact = db.get(models.Result, latest.result_id)
        if artifact is not None:
            try:
                manifest = credits_helpers.result_payload(
                    artifact, user_id=user.id, operation_id=latest.id,
                )
                export_bytes, manifest = se.decode_artifact(
                    manifest, expected_format=export_format, expected_source_id=rid,
                    expected_source_integrity_digest=source.integrity_digest,
                )
            except Exception:
                db.rollback()
                return JSONResponse(
                    {"error": "Previously generated export is no longer available."},
                    status_code=410,
                )
            manifest = dict(manifest, _artifact_id=str(artifact.id))
            db.rollback()
            return _structured_export_response(export_bytes, manifest)
        db.rollback()
        return JSONResponse(
            {"error": "Previously generated export is no longer available."},
            status_code=410,
        )

    has_failed = any(op.status in ("failed", "expired") for op in matching)
    idempotency_key = (
        f"{base_key}-retry-{_uuid.uuid4().hex[:8]}" if has_failed else base_key
    )

    # Eligible-vs-total gate (§9.6): a spend-restricted user can hold a
    # positive total balance yet have zero eligible credits — that is a
    # 402 with the dynamic price, not an admission conflict, and it runs
    # no generator and leaves no reservation/artifact.
    if credits_helpers.get_eligible_credits(db, user.id) < cost:
        db.rollback()
        return JSONResponse(
            {"error": f"Insufficient credits. Structured export costs {cost} credit{'s' if cost != 1 else ''}.",
             "purchase_url": "/credits"},
            status_code=402,
        )

    consent = credits_helpers.create_consent(
        db, user_id=user.id, operation_type="structured_export",
        input_hash=request_hash, max_cost=cost,
    )
    db.flush()

    worker_id = f"structured-export-{_uuid.uuid4().hex[:8]}"
    try:
        op = credits_helpers.admit_paid_operation(
            db, user_id=user.id, operation_type="structured_export",
            idempotency_key=idempotency_key, request_hash=request_hash,
            cost=cost, consent_id=consent.id,
            worker_id=worker_id,
        )
        # Never execute an operation this request does not own: a replay
        # returned by admission (lost race) is handled without generating.
        if op.worker_id != worker_id or op.status != "reserved":
            db.rollback()
            if op.status == "completed":
                return JSONResponse(
                    {"error": "Structured export already completed. Please try again to download it."},
                    status_code=409,
                )
            return JSONResponse(
                {"error": "Structured export already in progress. Please wait and try again."},
                status_code=409,
            )
        db.commit()
    except credits_helpers.InsufficientCredits:
        db.rollback()
        return JSONResponse(
            {"error": f"Insufficient credits. Structured export costs {cost} credit{'s' if cost != 1 else ''}.",
             "purchase_url": "/credits"},
            status_code=402,
        )
    except credits_helpers.AdmissionError as e:
        db.rollback()
        return JSONResponse({"error": str(e)}, status_code=409)

    # Reserve committed. Generate from the validated snapshot, then store
    # + complete in ONE settlement transaction; full release on failure.
    # PR #125 finding 2: Operation.failure_code is String(50); storing
    # str(exception)[:200] overflowed it on PostgreSQL, the release
    # flush failed and the reversal rolled back, leaving the op stuck
    # reserved. Store only a short stable code (<=50 chars) and log the
    # full exception detail separately.
    def _release(failure_code, exc=None):
        import logging as _logging
        if exc is not None:
            _logging.getLogger(__name__).exception(
                "Structured export failed (%s)", failure_code,
                exc_info=(type(exc), exc, exc.__traceback__))
        bounded = str(failure_code)[:50]
        try:
            credits_helpers.release_operation(db, op.id, worker_id, bounded)
            db.commit()
        except Exception:
            db.rollback()

    try:
        export_bytes = se.generate_export(payload, export_format)
    except Exception as e:
        _release("generation_failed", e)
        return JSONResponse({"error": "Structured export generation failed"}, status_code=500)

    filename = se.safe_download_name(payload.get("filename"), rid, export_format)
    media_type = se.MEDIA_TYPES[export_format]
    try:
        artifact = credits_helpers.store_structured_export_result(
            db, user.id, op.id, export_bytes,
            export_format=export_format, filename=filename, media_type=media_type,
            source_result_id=rid, source_integrity_digest=source.integrity_digest,
        )
        credits_helpers.complete_operation(
            db, op.id, worker_id, result_id=artifact.id,
            lease_generation=op.lease_generation,
        )
        db.commit()
    except Exception as e:
        db.rollback()
        _release("storage_failed", e)
        return JSONResponse({"error": "Failed to store structured export"}, status_code=500)

    manifest = {
        "media_type": media_type,
        "filename": filename,
        "_artifact_id": str(artifact.id),
    }
    return _structured_export_response(export_bytes, manifest)


@app.get("/exports/{export_id}")
async def structured_export_download(request: Request, export_id: str, db=Depends(get_db)):
    """Free re-download of a generated structured export (spec §6).

    Owner-authenticated only; validates the artifact's own origin,
    manifest and content integrity/expiry. Works even after the SOURCE
    report expires — the artifact has its own 7-day life — and never
    generates, charges, or refreshes expiry.
    """
    import uuid as _uuid
    from fastapi.responses import JSONResponse, RedirectResponse
    from app import auth as auth_helpers
    from app import credits as credits_helpers
    from app import models
    from app import structured_export as se

    session = auth_helpers.get_session_from_cookie(db, request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    user = session.user

    try:
        eid = _uuid.UUID(export_id)
    except ValueError:
        return JSONResponse({"error": "Invalid export ID"}, status_code=400)

    artifact = db.query(models.Result).filter(
        models.Result.id == eid,
        models.Result.user_id == user.id,
        models.Result.type == "structured_export",
        models.Result.deleted_at.is_(None),
    ).first()
    if not artifact:
        return JSONResponse({"error": "Export not found"}, status_code=404)
    try:
        manifest = credits_helpers.result_payload(
            artifact, user_id=user.id, operation_id=artifact.operation_id,
        )
        export_bytes, manifest = se.decode_artifact(manifest)
        # PR #125 finding 5: bind provenance to the originating
        # operation. The source may be expired/gone on GET, so recompute
        # the POST route's request hash from the manifest's provenance
        # fields (exactly the POST canonical construction) and compare
        # it to the originating Operation's request_hash. Missing or
        # mismatched operation fails closed (410).
        if not artifact.operation_id:
            raise ValueError("artifact has no originating operation")
        origin_op = db.get(models.Operation, artifact.operation_id)
        if origin_op is None or origin_op.type != "structured_export":
            raise ValueError("originating operation missing")
        expected_hash = credits_helpers.hash_input(json.dumps(
            {
                "source_result_id": manifest["source_result_id"],
                "source_integrity_digest": manifest["source_integrity_digest"],
                "format": manifest["format"],
                "schema_version": manifest["schema_version"],
            },
            sort_keys=True, separators=(",", ":"),
        ).encode())
        if expected_hash != origin_op.request_hash:
            raise ValueError("artifact provenance does not match operation")
    except Exception:
        return JSONResponse({"error": "Export has expired or is no longer available"}, status_code=410)
    manifest = dict(manifest, _artifact_id=str(artifact.id))
    return _structured_export_response(export_bytes, manifest)


# ---------------------------------------------------------------------------
# Issue #107: Retention extension + shareable report links.
#
# Retention: POST /reports/{id}/retention — 1 credit per +90 days from
# the CURRENT expires_at, stackable to ready_at + 365 days, full-unit
# only (409 past the ceiling, no debit), settled atomically as
# reserve -> extend -> receipt -> complete in ONE transaction under the
# global:paid lock (the same row cleanup_results locks, so extension
# and cleanup cannot race).
#
# Sharing is FREE (trim T1): create/rotate/revoke never charge, never
# create a consent or a paid operation. Tokens are 256-bit, stored
# hash-only, revealed once; rotation is the lost-token recovery.
# ---------------------------------------------------------------------------

_SHARE_CSP = (
    "default-src 'none'; style-src 'self'; img-src 'self'; "
    "font-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
    "form-action 'none'"
)


def _share_csp(nonce: str | None = None) -> str:
    """CSP for shared pages. With a per-response nonce (Finding 4),
    ONLY the shared report page's single nonced <style> block is
    additionally allowed; 'unsafe-inline' is never added and every
    other directive is unchanged. Without a nonce the original
    policy is returned verbatim (identical-404 / PDF routes)."""
    if not nonce:
        return _SHARE_CSP
    return _SHARE_CSP.replace(
        "style-src 'self'", f"style-src 'self' 'nonce-{nonce}'")


def _share_headers(extra: dict | None = None,
                   nonce: str | None = None) -> dict:
    headers = {
        "Cache-Control": "private, no-store",
        "Referrer-Policy": "no-referrer",
        "X-Robots-Tag": "noindex, nofollow, noarchive",
        "Content-Security-Policy": _share_csp(nonce),
    }
    if extra:
        headers.update(extra)
    return headers


def _share_chart_style(projection: dict) -> tuple[str, dict]:
    """Build CSP-nonced dynamic chart dimensions (Finding 4).

    Returns (css_text, class_map): css_text holds one generated rule
    per dynamic height/width, to be emitted inside the shared page's
    single ``<style nonce=...>`` block; class_map maps a stable key
    for each chart element to its generated class name, which the
    template adds alongside the static classes. No inline style=
    attributes are used, so style-src 'self' (plus the nonce) is
    honoured without weakening the CSP. Percentages replicate the
    template's former inline computations exactly.
    """
    rules: list[str] = []
    classes: dict = {"timeline": {}, "severity": {}, "service": {}}

    def _pct(num, den):
        try:
            return (num / den * 100) if den else 0
        except Exception:
            return 0

    def _fmt(v):
        return f"{v:.6g}"

    timeline = projection.get("timeline") or []
    if isinstance(timeline, list) and len(timeline) > 1:
        try:
            tmax = max((b.get("total") or 0) for b in timeline)
        except Exception:
            tmax = 0
        for i, b in enumerate(timeline):
            if not isinstance(b, dict):
                continue
            issues = (b.get("warn") or 0) + (b.get("error") or 0) \
                + (b.get("critical") or 0)
            entry = {}
            cls = f"ss-dyn-tl-{i}"
            rules.append(f".{cls}{{height:{_fmt(_pct(issues, tmax))}%}}")
            entry["stack"] = cls
            for seg, key in (("critical", "critical"),
                             ("error", "error"), ("warn", "warn")):
                val = b.get(key) or 0
                if val > 0:
                    scls = f"ss-dyn-tl-{i}-{seg}"
                    rules.append(
                        f".{scls}{{height:{_fmt(_pct(val, issues))}%}}")
                    entry[seg] = scls
            classes["timeline"][i] = entry

    results = projection.get("results") or {}
    if isinstance(results, dict):
        level_counts = results.get("level_counts") or {}
        if level_counts:
            counts = [level_counts.get(k, 0) for k in
                      ("CRITICAL", "ERROR", "WARN", "INFO")]
            max_count = max(counts) if counts else 0
            for level in ("CRITICAL", "ERROR", "WARN", "INFO"):
                count = level_counts.get(level, 0)
                cls = f"ss-dyn-sev-{level.lower()}"
                rules.append(
                    f".{cls}{{width:{_fmt(_pct(count, max_count))}%}}")
                classes["severity"][level] = cls
        service_counts = results.get("service_counts") or {}
        total_lines = results.get("total_lines") or 0
        if isinstance(service_counts, dict):
            for idx, svc in enumerate(
                    sorted(service_counts, key=lambda k: service_counts[k],
                           reverse=True)):
                cls = f"ss-dyn-svc-{idx}"
                rules.append(
                    f".{cls}{{width:"
                    f"{_fmt(_pct(service_counts[svc], total_lines))}%}}")
                classes["service"][svc] = cls
    return "\n".join(rules), classes


def _share_unavailable():
    """The ONE public failure response (draft §6 identical-404 discipline).

    Unknown, malformed, tampered, revoked, rotated, expired, deleted
    and corrupt tokens all render exactly this status, body and
    headers; rate-limit/service errors are the only exceptions and are
    independent of token validity.
    """
    from fastapi.responses import HTMLResponse
    return HTMLResponse(
        content="<h1>This report is unavailable.</h1>",
        status_code=404,
        headers=_share_headers(),
    )


def _share_rate_limited(request: Request):
    """Apply the public abuse limiter; return an error response or None.

    Fail-closed: any limiter/database failure is a 503, never a skip.
    """
    from fastapi.responses import HTMLResponse
    from app.rate_limit import RateLimitUnavailable
    from app import report_access as _ra
    ip = _client_ip(request)
    key = _ra.share_limit_key(ip)
    if _use_shared_limiter():
        try:
            rl_db = _db_session()
            try:
                share_limiter.admit(rl_db, key)
            finally:
                rl_db.close()
        except (BurstLimited, HourlyLimited):
            return HTMLResponse(
                content="<h1>Too many requests.</h1>", status_code=429,
                headers=_share_headers({"Retry-After": "60"}))
        except Exception:
            return HTMLResponse(
                content="<h1>Service temporarily unavailable.</h1>",
                status_code=503,
                headers=_share_headers({"Retry-After": "60"}))
        return None
    # No-database demo path: paired in-memory limiters, atomic check.
    if not _share_mem_burst.check(key) or not _share_mem_hourly.check(key):
        return HTMLResponse(
            content="<h1>Too many requests.</h1>", status_code=429,
            headers=_share_headers({"Retry-After": "60"}))
    _share_mem_burst.record(key)
    _share_mem_hourly.record(key)
    return None


async def _check_owner_csrf(request: Request, session, db):
    import hmac
    from fastapi.responses import JSONResponse
    form = await request.form()
    csrf_token = form.get("csrf_token", "")
    if not csrf_token or not hmac.compare_digest(csrf_token, session.csrf_token):
        return None, JSONResponse({"error": "Invalid CSRF token"}, status_code=403)
    return form, None


def _find_owned_report(db, user, result_id: str, types):
    import uuid as _uuid
    from app import models
    try:
        rid = _uuid.UUID(result_id)
    except ValueError:
        return None, 400
    result = db.query(models.Result).filter(
        models.Result.id == rid,
        models.Result.user_id == user.id,
        models.Result.type.in_(list(types)),
        models.Result.deleted_at.is_(None),
    ).first()
    if not result:
        return None, 404
    return result, None


@app.post("/reports/{result_id}/retention")
async def report_extend_retention(request: Request, result_id: str, db=Depends(get_db)):
    """Extend a report's retention by +90 days for 1 credit (trim T2)."""
    import uuid as _uuid
    from fastapi.responses import JSONResponse
    from sqlalchemy import select as _select
    from app import auth as auth_helpers
    from app import credits as credits_helpers
    from app import models
    from app import report_access as _ra
    from datetime import timedelta

    session = auth_helpers.get_session_from_cookie(db, request)
    if not session:
        return JSONResponse({"error": "Login required"}, status_code=401)
    user = session.user
    form, err = await _check_owner_csrf(request, session, db)
    if err is not None:
        return err
    idempotency_key = str(form.get("idempotency_key") or _uuid.uuid4().hex)

    # Serialize against cleanup + other extensions on the global:paid
    # row for the WHOLE transaction (cleanup locks the same row).
    credits_helpers.lock_global_paid_scope(db)
    source, status = _find_owned_report(db, user, result_id,
                                         ("analysis", "comparison"))
    if status == 400:
        db.rollback()
        return JSONResponse({"error": "Invalid report ID"}, status_code=400)
    if source is None:
        db.rollback()
        return JSONResponse({"error": "Report not found"}, status_code=404)
    # Authoritative re-read under the lock.
    source = db.execute(
        _select(models.Result).where(models.Result.id == source.id)
        .with_for_update().execution_options(populate_existing=True)
    ).scalar_one()

    request_hash = _ra.action_request_hash(source, "retention_extension")

    # Replay fence (permanent ReportAction identity): same key returns
    # the stored outcome with no charge — even after the receipt
    # Result's payload has been cleaned up, and regardless of balance.
    prior = db.execute(
        _select(models.ReportAction).where(
            models.ReportAction.owner_user_id == user.id,
            models.ReportAction.result_id == source.id,
            models.ReportAction.action_kind == "retention_extension",
            models.ReportAction.idempotency_key == idempotency_key,
        )
    ).scalar_one_or_none()
    if prior is not None:
        db.rollback()
        if prior.request_hash != request_hash:
            return JSONResponse(
                {"error": "Idempotency key reused with different input"},
                status_code=409)
        return JSONResponse({
            "status": "extended",
            "result_id": str(source.id),
            "expires_at": credits_helpers._as_aware(
                prior.resulting_expiry).isoformat()
            if prior.resulting_expiry else None,
            "cost": credits_helpers.COST_RETENTION_EXTENSION,
            "replayed": True,
        })

    if credits_helpers._as_aware(source.expires_at) <= credits_helpers._utcnow():
        db.rollback()
        return JSONResponse({"error": "Report has expired"}, status_code=410)
    try:
        credits_helpers.result_payload(
            source, user_id=user.id,
            operation_id=source.operation_id,
            free_request_id=source.free_request_id,
        )
    except credits_helpers.AdmissionError:
        db.rollback()
        return JSONResponse({"error": "Report data corrupted"}, status_code=500)

    cost = credits_helpers.COST_RETENTION_EXTENSION
    if credits_helpers.get_eligible_credits(db, user.id) < cost:
        db.rollback()
        return JSONResponse(
            {"error": f"Retention extension costs {cost} credit. "
                      "Insufficient eligible credits.",
             "purchase_url": "/credits"},
            status_code=402)

    previous_expiry = credits_helpers._as_aware(source.expires_at)
    new_expiry = previous_expiry + timedelta(
        days=credits_helpers.RETENTION_EXTENSION_DAYS)
    ceiling = credits_helpers._as_aware(source.ready_at) + timedelta(
        days=credits_helpers.RETENTION_MAX_DAYS)
    if new_expiry > ceiling:
        db.rollback()
        return JSONResponse(
            {"error": "Retention extension would exceed the maximum "
                      "retention for this report."},
            status_code=409)

    consent = credits_helpers.create_consent(
        db, user_id=user.id, operation_type="retention_extension",
        input_hash=request_hash, max_cost=cost,
    )
    db.flush()
    worker_id = f"retention-{_uuid.uuid4().hex[:8]}"
    try:
        op = credits_helpers.admit_paid_operation(
            db, user_id=user.id, operation_type="retention_extension",
            idempotency_key=idempotency_key, request_hash=request_hash,
            cost=cost, consent_id=consent.id, worker_id=worker_id,
        )
        if op.worker_id != worker_id or op.status != "reserved":
            db.rollback()
            return JSONResponse(
                {"error": "Retention extension already in progress. "
                          "Please wait and try again."},
                status_code=409)
        # Atomic settlement in THIS transaction: extend -> receipt ->
        # action identity -> complete. Any failure rolls the whole
        # transaction back, restoring expiry and credits together.
        source.expires_at = new_expiry
        db.flush()
        receipt = credits_helpers.store_report_action_receipt(
            db, user.id, op.id, {
                "action_kind": "retention_extension",
                "target_result_id": str(source.id),
                "previous_expiry": previous_expiry.isoformat(),
                "new_expiry": new_expiry.isoformat(),
            })
        db.add(models.ReportAction(
            owner_user_id=user.id, result_id=source.id,
            action_kind="retention_extension",
            idempotency_key=idempotency_key, request_hash=request_hash,
            resulting_expiry=new_expiry, operation_id=op.id,
        ))
        db.flush()
        credits_helpers.complete_operation(
            db, op.id, worker_id, result_id=receipt.id,
            lease_generation=op.lease_generation,
        )
        db.commit()
    except credits_helpers.InsufficientCredits:
        db.rollback()
        return JSONResponse(
            {"error": f"Retention extension costs {cost} credit. "
                      "Insufficient eligible credits.",
             "purchase_url": "/credits"},
            status_code=402)
    except credits_helpers.AdmissionError as e:
        db.rollback()
        return JSONResponse({"error": str(e)}, status_code=409)
    except Exception:
        db.rollback()
        logging.getLogger(__name__).exception(
            "Retention extension settlement failed")
        return JSONResponse(
            {"error": "Retention extension failed"}, status_code=500)
    return JSONResponse({
        "status": "extended",
        "result_id": str(source.id),
        "expires_at": new_expiry.isoformat(),
        "cost": cost,
    })


def _share_action_replay(db, user, source, action_kind, idempotency_key,
                         request_hash):
    """Return (prior_action, error_response) for a free share action."""
    from fastapi.responses import JSONResponse
    from sqlalchemy import select as _select
    from app import models
    prior = db.execute(
        _select(models.ReportAction).where(
            models.ReportAction.owner_user_id == user.id,
            models.ReportAction.result_id == source.id,
            models.ReportAction.action_kind == action_kind,
            models.ReportAction.idempotency_key == idempotency_key,
        )
    ).scalar_one_or_none()
    if prior is not None and prior.request_hash != request_hash:
        return None, JSONResponse(
            {"error": "Idempotency key reused with different input"},
            status_code=409)
    return prior, None


def _record_share_action(db, user, source, action_kind, idempotency_key,
                         request_hash, generation):
    from app import models
    db.add(models.ReportAction(
        owner_user_id=user.id, result_id=source.id,
        action_kind=action_kind, idempotency_key=idempotency_key,
        request_hash=request_hash, generation=generation,
    ))
    db.flush()


def _share_url(request: Request, raw_token: str) -> str:
    """Share URL for the once-only reveal. Built from the trusted
    configured app origin (APP_BASE_URL) when one is set — never from
    an arbitrary request Host; without a configured origin the
    path-only URL is returned and the client resolves it against the
    origin it is already talking to."""
    origin = os.environ.get("APP_BASE_URL", "").rstrip("/")
    return f"{origin}/s/{raw_token}"


async def _share_owner_gate(request: Request, result_id: str, db):
    """Session + CSRF + owned single-type report for share actions."""
    import uuid as _uuid
    from fastapi.responses import JSONResponse
    from app import auth as auth_helpers
    from app import credits as credits_helpers
    session = auth_helpers.get_session_from_cookie(db, request)
    if not session:
        return None, None, None, None, JSONResponse(
            {"error": "Login required"}, status_code=401)
    user = session.user
    form, err = await _check_owner_csrf(request, session, db)
    if err is not None:
        return None, None, None, None, err
    source, status = _find_owned_report(
        db, user, result_id, ("analysis", "comparison"))
    if status == 400:
        return None, None, None, None, JSONResponse(
            {"error": "Invalid report ID"}, status_code=400)
    if source is None:
        return None, None, None, None, JSONResponse(
            {"error": "Report not found"}, status_code=404)
    idempotency_key = str(form.get("idempotency_key") or _uuid.uuid4().hex)
    return session, user, form, (source, idempotency_key), None


def _share_source_gate(db, user, source):
    """Expiry/integrity/kind gates for share CREATE (before any creation).

    Returns an error JSONResponse or None. Compare/batch/unknown kinds
    are rejected with a controlled 422 BEFORE link creation (trim T4).
    """
    from fastapi.responses import JSONResponse
    from app import credits as credits_helpers
    from app import report_access as _ra
    from datetime import datetime, timezone
    if source.type != "analysis":
        return JSONResponse(
            {"error": "Sharing is not yet supported for this report type"},
            status_code=422)
    if credits_helpers._as_aware(source.expires_at) <= datetime.now(timezone.utc):
        return JSONResponse({"error": "Report has expired"}, status_code=410)
    try:
        payload = credits_helpers.result_payload(
            source, user_id=user.id,
            operation_id=source.operation_id,
            free_request_id=source.free_request_id,
        )
    except credits_helpers.AdmissionError:
        return JSONResponse({"error": "Report data corrupted"}, status_code=500)
    if not _ra.is_single_file_payload(payload):
        return JSONResponse(
            {"error": "Sharing is not yet supported for this report type"},
            status_code=422)
    return None


@app.post("/reports/{result_id}/share")
async def report_share_create(request: Request, result_id: str, db=Depends(get_db)):
    """Create a share link — FREE (trim T1). Reveals the token once."""
    from fastapi.responses import JSONResponse
    from sqlalchemy import select as _select
    from app import auth as auth_helpers
    from app import credits as credits_helpers
    from app import models
    from app import report_access as _ra

    session, user, form, ctx, err = await _share_owner_gate(request, result_id, db)
    if err is not None:
        return err
    source, idempotency_key = ctx
    request_hash = _ra.action_request_hash(source, "share_create")
    # Finding 2: lock the share:actions bucket BEFORE the replay
    # lookup and hold it through settlement, so the lookup below is
    # authoritative under the lock (concurrent same-key requests
    # serialize; replays never consume rate and never 429/500).
    credits_helpers.lock_share_rate_bucket(db, str(user.id))
    prior, err = _share_action_replay(
        db, user, source, "share_create", idempotency_key, request_hash)
    if err is not None:
        db.rollback()
        return err
    if prior is not None:
        db.rollback()
        return JSONResponse({
            "status": "already_shared",
            "message": "This report already has a share link. "
                       "Rotate the link to get a new copyable URL.",
        })
    gate = _share_source_gate(db, user, source)
    if gate is not None:
        db.rollback()
        return gate
    try:
        credits_helpers._consume_rate(db, "share:actions", str(user.id))
    except credits_helpers.AdmissionError:
        db.rollback()
        return JSONResponse(
            {"error": "Too many share actions. Please try again later."},
            status_code=429)
    sharing = db.execute(
        _select(models.ReportSharing).where(
            models.ReportSharing.result_id == source.id)
        .with_for_update().execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if sharing is not None and sharing.token_hash and sharing.revoked_at is None:
        # Finding 1: record this no-op create outcome (with the
        # existing active sharing's generation) in the SAME
        # transaction as the rate consumption, so replaying this
        # key hits _share_action_replay and returns already_shared
        # without consuming rate or — if the owner revoked in the
        # meantime — creating a new active link.
        _record_share_action(db, user, source, "share_create",
                             idempotency_key, request_hash,
                             sharing.generation)
        db.commit()
        return JSONResponse({
            "status": "already_shared",
            "message": "This report already has a share link. "
                       "Rotate the link to get a new copyable URL.",
        })
    raw_token = auth_helpers.generate_token()
    if sharing is None:
        sharing = models.ReportSharing(
            result_id=source.id, owner_user_id=user.id,
            token_hash=auth_helpers.hash_token(raw_token), generation=1,
        )
        db.add(sharing)
    else:
        sharing.token_hash = auth_helpers.hash_token(raw_token)
        sharing.generation += 1
        sharing.revoked_at = None
    db.flush()
    _record_share_action(db, user, source, "share_create", idempotency_key,
                         request_hash, sharing.generation)
    db.commit()
    return JSONResponse({
        "status": "created",
        "share_url": _share_url(request, raw_token),
    })


@app.post("/reports/{result_id}/share/rotate")
async def report_share_rotate(request: Request, result_id: str, db=Depends(get_db)):
    """Replace the active token — FREE. The lost-token recovery path."""
    from fastapi.responses import JSONResponse
    from sqlalchemy import select as _select
    from app import auth as auth_helpers
    from app import credits as credits_helpers
    from app import models
    from app import report_access as _ra

    session, user, form, ctx, err = await _share_owner_gate(request, result_id, db)
    if err is not None:
        return err
    source, idempotency_key = ctx
    request_hash = _ra.action_request_hash(source, "share_rotate")
    # Finding 2: lock before the authoritative replay lookup (see
    # report_share_create).
    credits_helpers.lock_share_rate_bucket(db, str(user.id))
    prior, err = _share_action_replay(
        db, user, source, "share_rotate", idempotency_key, request_hash)
    if err is not None:
        db.rollback()
        return err
    if prior is not None:
        db.rollback()
        return JSONResponse({
            "status": "already_rotated",
            "message": "That rotation already happened. Rotate again "
                       "for a new copyable URL.",
        })
    gate = _share_source_gate(db, user, source)
    if gate is not None:
        db.rollback()
        return gate
    try:
        credits_helpers._consume_rate(db, "share:actions", str(user.id))
    except credits_helpers.AdmissionError:
        db.rollback()
        return JSONResponse(
            {"error": "Too many share actions. Please try again later."},
            status_code=429)
    sharing = db.execute(
        _select(models.ReportSharing).where(
            models.ReportSharing.result_id == source.id)
        .with_for_update().execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if sharing is None:
        db.commit()
        return JSONResponse(
            {"error": "This report has no share link to rotate"},
            status_code=409)
    raw_token = auth_helpers.generate_token()
    sharing.token_hash = auth_helpers.hash_token(raw_token)
    sharing.generation += 1
    sharing.revoked_at = None
    db.flush()
    _record_share_action(db, user, source, "share_rotate", idempotency_key,
                         request_hash, sharing.generation)
    db.commit()
    return JSONResponse({
        "status": "rotated",
        "share_url": _share_url(request, raw_token),
    })


@app.post("/reports/{result_id}/share/revoke")
async def report_share_revoke(request: Request, result_id: str, db=Depends(get_db)):
    """Revoke the active token — FREE and idempotent; always available
    regardless of balance or spend restrictions (draft §5)."""
    from fastapi.responses import JSONResponse
    from sqlalchemy import select as _select
    from app import credits as credits_helpers
    from app import models
    from app import report_access as _ra

    session, user, form, ctx, err = await _share_owner_gate(request, result_id, db)
    if err is not None:
        return err
    source, idempotency_key = ctx
    request_hash = _ra.action_request_hash(source, "share_revoke")
    # Finding 2: lock before the authoritative replay lookup (see
    # report_share_create).
    credits_helpers.lock_share_rate_bucket(db, str(user.id))
    prior, err = _share_action_replay(
        db, user, source, "share_revoke", idempotency_key, request_hash)
    if err is not None:
        db.rollback()
        return err
    if prior is not None:
        db.rollback()
        return JSONResponse({"status": "revoked"})
    try:
        credits_helpers._consume_rate(db, "share:actions", str(user.id))
    except credits_helpers.AdmissionError:
        db.rollback()
        return JSONResponse(
            {"error": "Too many share actions. Please try again later."},
            status_code=429)
    sharing = db.execute(
        _select(models.ReportSharing).where(
            models.ReportSharing.result_id == source.id)
        .with_for_update().execution_options(populate_existing=True)
    ).scalar_one_or_none()
    generation = 0
    if sharing is not None:
        if sharing.token_hash is not None or sharing.revoked_at is None:
            sharing.token_hash = None
            sharing.revoked_at = credits_helpers._utcnow()
            sharing.generation += 1
        generation = sharing.generation
        db.flush()
    _record_share_action(db, user, source, "share_revoke", idempotency_key,
                         request_hash, generation)
    db.commit()
    return JSONResponse({"status": "revoked"})


@app.get("/s/{token}", response_class=HTMLResponse)
async def shared_report_view(request: Request, token: str, db=Depends(get_db)):
    """Public read-only shared report. Bearer capability, not a session:
    sets no cookies, loads no owner identity, mutates nothing."""
    from app import report_access as _ra
    limited = _share_rate_limited(request)
    if limited is not None:
        return limited
    found = _ra.lookup_shared(db, token)
    if found is None:
        return _share_unavailable()
    sharing, result, payload = found
    # Recheck the CURRENT generation/revocation on fresh state just
    # before publication (draft §6): a revoke that committed while this
    # request was rendering must not be served from a stale snapshot.
    db.expire_all()
    again = _ra.lookup_shared(db, token)
    if again is None or again[0].id != sharing.id:
        return _share_unavailable()
    projection = _ra.public_projection(payload)
    # Finding 4: per-response CSP nonce for the dynamic chart rules.
    import secrets as _secrets
    nonce = _secrets.token_urlsafe(16)
    chart_css, chart_classes = _share_chart_style(projection)
    projection = {**projection, "csp_nonce": nonce,
                  "chart_css": chart_css, "chart_classes": chart_classes}
    response = templates.TemplateResponse(
        request, "shared_report.html", projection)
    for key, value in _share_headers(nonce=nonce).items():
        response.headers[key] = value
    return response


@app.get("/s/{token}/pdf")
async def shared_report_pdf(request: Request, token: str, db=Depends(get_db)):
    """PDF through a share link — ONLY a paid, unexpired PDF (trim T3).

    Any other case (no PDF ever paid for, PDF expired, token invalid)
    is the same identical 404 as the text route. CSV/JSON are not
    shared in v1 and have no route here.
    """
    from fastapi.responses import Response
    from app import report_access as _ra
    limited = _share_rate_limited(request)
    if limited is not None:
        return limited
    found = _ra.lookup_shared(db, token)
    if found is None:
        return _share_unavailable()
    sharing, result, payload = found
    pdf = _ra.find_shareable_pdf(db, result)
    if pdf is None:
        return _share_unavailable()
    pdf_result, pdf_bytes = pdf
    db.expire_all()
    if _ra.lookup_shared(db, token) is None:
        return _share_unavailable()
    filename = payload.get("filename", "report")
    headers = _share_headers({
        "Content-Disposition": f'attachment; filename="stacksift-report-{_safe_download_filename(str(filename))}.pdf"',
    })
    return Response(content=pdf_bytes, media_type="application/pdf",
                    headers=headers)
