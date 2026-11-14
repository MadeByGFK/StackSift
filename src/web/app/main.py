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
# Issue #106 Stage 2: the Analysis Report price renders from the same
# single ruled constant everywhere.
templates.env.globals["analysis_report_cost"] = _credits_template_globals.COST_DEEP_DIVE

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


@app.middleware("http")
async def d2_attribution_cookies(request: Request, call_next):
    """Issue #156: first-party D2 attribution cookies.

    HTML GET responses only. ``d2_visitor_id`` is set when absent (a
    malformed value counts as absent and is replaced) AND the request
    carries any ``utm_*`` query param OR lands on ``/`` or
    ``/credits``; a present valid value is never overwritten.
    ``d2_attribution`` (first-touch UTM + referrer host only) is set
    only when utm params are present and no attribution cookie exists
    yet. Best-effort: cookie work can never break a response.
    """
    response = await call_next(request)
    try:
        if request.method != "GET":
            return response
        if "text/html" not in response.headers.get("content-type", ""):
            return response
        import json as _json
        import uuid as _uuid

        from app import d2_attribution as _d2

        query_params = request.query_params
        has_utm = any(key.startswith("utm_") for key in query_params.keys())
        existing = request.cookies.get(_d2.VISITOR_COOKIE)
        if _d2.valid_visitor_id(existing) is None and (
            has_utm or request.url.path in ("/", "/credits")
        ):
            response.set_cookie(
                _d2.VISITOR_COOKIE, str(_uuid.uuid4()),
                httponly=True, samesite="lax", path="/",
                max_age=_d2.COOKIE_MAX_AGE,
            )
        if has_utm and not request.cookies.get(_d2.ATTRIBUTION_COOKIE):
            attribution = _d2.build_attribution(
                query_params, request.headers.get("referer"))
            if attribution:
                response.set_cookie(
                    _d2.ATTRIBUTION_COOKIE,
                    _json.dumps(attribution, separators=(",", ":")),
                    httponly=True, samesite="lax", path="/",
                    max_age=_d2.COOKIE_MAX_AGE,
                )
    except Exception:
        pass
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


# Issue #163 (Amendment A8(a)): the branding upload route joins the
# Content-Length pre-guard pattern with a 1 MiB declared-length
# ceiling -> 413 before the handler. Per the #104 precedent this is an
# early reject only (framework spooling precedes it); the authoritative
# bound is the route's bounded chunked read of the logo part.
_BRANDING_GUARD_BYTES = 1024 * 1024


@app.middleware("http")
async def oversize_body_guard(request: Request, call_next):
    if (request.method == "POST"
            and request.url.path.startswith("/reports/")
            and request.url.path.endswith("/branding")
            and request.headers.get("content-length")):
        try:
            declared_branding = int(request.headers["content-length"])
        except ValueError:
            declared_branding = 0
        if declared_branding > _BRANDING_GUARD_BYTES:
            from fastapi.responses import JSONResponse
            return JSONResponse(
                {"error": "Branding submission too large."},
                status_code=413)
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
    """Issue #164 Phase C (Decision 8): the dollar Pricing page.

    This route's one job is pricing. It renders the four ruled dollar
    prices from products_for_display() (fail-closed "Coming soon"
    when a Price env is unset). Phase C retired, on this page: the
    pack grid and its buy forms, the balance banner/strip, the
    /credits/balance poll, and the latest-CreditPurchase return
    banners (C6c) — product returns keep their own purchase-bound
    authority (/reports/{rid} and /products/return). The /pricing
    301 and the D2 first-touch cookie behaviour on /credits are
    preserved (C6b); the offer_viewed observer is retargeted to the
    dollar offer cards in pricing.html.
    """
    _user, _csrf = _get_current_user_optional(request)
    from app import stripe_billing

    products = stripe_billing.products_for_display()
    return templates.TemplateResponse(
        request,
        "pricing.html",
        {
            "current_user": _user,
            "csrf_token": _csrf,
            "products": products,
            "pay_now_promise": stripe_billing.PAY_NOW_PROMISE,
        },
    )


@app.get("/pricing", include_in_schema=False)
async def pricing_redirect():
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/credits", status_code=301)


@app.post("/events/d2")
async def d2_client_event(request: Request):
    """Issue #156: client beacon endpoint for D2 funnel events.

    Accepts ONLY ``offer_viewed`` and ``premium_intent`` from clients;
    ``analysis_run`` is server-emitted only, so a client POST claiming
    it is ignored (no row — prevents funnel forgery). Identity is the
    session user and/or the ``d2_visitor_id`` cookie; with neither,
    nothing is recorded (conservative undercount). Attribution meta is
    read server-side from the ``d2_attribution`` cookie — the request
    body can never inject attribution or meta. Always 204, including
    for malformed JSON: the endpoint is no oracle, and recording is
    best-effort so it can never break the page that sent the beacon.
    """
    from fastapi.responses import Response

    try:
        payload = await request.json()
    except Exception:
        return Response(status_code=204)
    if not isinstance(payload, dict):
        return Response(status_code=204)
    event = payload.get("event")
    if event not in ("offer_viewed", "premium_intent"):
        return Response(status_code=204)
    from app import d2_attribution as _d2
    from app import funnel as funnel_helpers

    _user, _ = _get_current_user_optional(request)
    anon_id = _d2.visitor_id_from_cookies(request.cookies)
    if _user is None and not anon_id:
        return Response(status_code=204)
    meta = _d2.attribution_meta_from_cookies(request.cookies)
    if event == "premium_intent":
        kind = payload.get("kind")
        if isinstance(kind, str) and kind in _d2.PREMIUM_INTENT_KINDS:
            meta = {"kind": kind, **meta}
    funnel_helpers.emit_standalone(
        event,
        user_id=_user.id if _user is not None else None,
        anon_id=anon_id,
        meta=meta or None,
    )
    return Response(status_code=204)


# ISSUE-68: Stripe Checkout entry point. The billing module accepts test
# and live keys; the configured key determines the mode (issue #126).
# Anonymous users cannot buy: they get a 401 pointing at signup/login, and
# the credits page only renders buy forms for signed-in users.
@app.post("/credits/checkout")
async def credits_checkout(request: Request):
    """Issue #164 Phase C (Decision 1): credit-pack sales are CLOSED.

    Fails closed for every pack_id, before any Stripe call and before
    any purchase row is written: 410 with the honest retirement
    message. Pack SETTLEMENT stays live on the shared webhook below
    for late/duplicate events on the historical purchase family.
    """
    from fastapi.responses import JSONResponse
    return JSONResponse(
        {"error": "Credit packs are retired. StackSift now sells "
                  "individual reports — see Pricing for the dollar prices."},
        status_code=410,
    )


# ISSUE-69: Stripe webhook — idempotent credit granting.
# Server-to-server: no user session and no CSRF token. The Stripe-Signature
# HMAC is the authentication; unsigned or mis-signed deliveries are answered
# 400 before any database row is touched. Stripe retries non-2xx, so every
# handler path below is idempotent.
@app.post("/reports/{result_id}/investigation-checkout")
async def investigation_checkout(
    request: Request,
    result_id: str,
    csrf_token: str = Form(...),
    db=Depends(get_db),
):
    """Issue #164 Phase A (A7): product checkout for the Investigation
    Report, on the Report surface. Creates/reuses the pending product
    purchase FIRST; the Stripe idempotency key binds to that one row.
    Success/cancel URLs never grant or redeem — webhook settlement only.
    """
    import hmac
    import os as _os
    import uuid as _uuid
    from fastapi import HTTPException
    from fastapi.responses import JSONResponse
    from app import auth as auth_helpers
    from app import stripe_billing
    from app import credits as credits_helpers
    from app import product_billing as pb
    from app import models
    from app import deep_dive as dd
    from datetime import datetime, timezone, timedelta

    # P3-6: fail-closed parity with the pack checkout route — the
    # previous dead `pass` here claimed a gate that did not exist.
    if not _os.environ.get("DATABASE_URL"):
        raise HTTPException(503, "Investigation Report purchases are unavailable right now.")
    _user, _ = _get_current_user_optional(request)
    if not _user:
        return JSONResponse({"error": "Log in or sign up to buy the Investigation Report."}, status_code=401)
    session = auth_helpers.get_session_from_cookie(db, request)
    expected = session.csrf_token if session else None
    if not expected or not isinstance(csrf_token, str) or not hmac.compare_digest(csrf_token, expected):
        raise HTTPException(403, "Invalid CSRF token. Reload the page and try again.")
    from app import d2_attribution as _d2
    _d2.emit_premium_intent(request, _user.id, "checkout_start")
    ip = _client_ip(request)
    if _use_shared_limiter():
        try:
            rl_db = _db_session()
            try:
                checkout_limiter.admit(rl_db, f"c:{ip}")
            finally:
                rl_db.close()
        except (BurstLimited, HourlyLimited):
            raise HTTPException(429, "Too many attempts. Please try again later.")
        except Exception:
            raise HTTPException(503, "Rate limiting is temporarily unavailable. Please try again shortly.")
    else:
        auth_helpers.check_rate_limit("checkout", ip)

    try:
        rid = _uuid.UUID(result_id)
    except ValueError:
        return JSONResponse({"error": "Invalid report ID"}, status_code=400)
    source = db.query(models.Result).filter(
        models.Result.id == rid,
        models.Result.user_id == _user.id,
        models.Result.deleted_at.is_(None),
    ).first()
    if not source:
        return JSONResponse({"error": "Report not found"}, status_code=404)
    # A6(1): checkout requires the same eligibility gates as redemption.
    if source.type != "analysis":
        return JSONResponse({"error": "Analysis Reports are not available for this report type"}, status_code=422)
    if credits_helpers._as_aware(source.expires_at) <= datetime.now(timezone.utc):
        return JSONResponse({"error": "Report has expired"}, status_code=410)
    try:
        payload = credits_helpers.result_payload(
            source, user_id=_user.id,
            operation_id=source.operation_id,
            free_request_id=source.free_request_id,
            product_redemption_id=source.product_redemption_id,
        )
    except credits_helpers.AdmissionError:
        return JSONResponse({"error": "Report data corrupted"}, status_code=500)
    try:
        dd.check_eligibility(payload)
    except dd.UnsupportedReportKind:
        return JSONResponse({"error": "Analysis Reports are not available for this report type"}, status_code=422)
    except dd.InsufficientEvidence as exc:
        return JSONResponse({"error": str(exc)}, status_code=422)

    sku = "investigation_report"
    # F1: a live entitlement blocks a second checkout entirely.
    existing_ent = pb.live_entitlement(db, _user.id, rid, sku)
    if existing_ent is not None:
        db.rollback()
        return JSONResponse({
            "error": "You already hold an entitlement for this report's Investigation Report.",
            "existing_entitlement_id": str(existing_ent.id),
            "entitlement_status": existing_ent.status,
            "redemption_deadline": existing_ent.redemption_deadline.isoformat() if existing_ent.redemption_deadline else None,
        }, status_code=409)

    origin = str(request.base_url).rstrip("/")
    success_url = _os.environ.get("STRIPE_SUCCESS_URL") or f"{origin}/reports/{rid}?checkout=success"
    cancel_url = _os.environ.get("STRIPE_CANCEL_URL") or f"{origin}/reports/{rid}?checkout=cancelled"
    try:
        stripe_billing._secret_key()
        if stripe_billing.product_price_id(sku) is None:
            raise stripe_billing.CheckoutNotConfigured(f"price not configured for product {sku}")
        purchase, reused = pb.create_pending_product_purchase(db, _user.id, sku, rid)
        db.commit()
        # Issue #164 idempotency-supersede fix: session creation goes
        # through pb.attempt_product_checkout_session — on a Stripe
        # idempotency_error for this row's key it applies the §2
        # safety gates (return the row's own open session; create
        # nothing when it already completed; supersede ONCE only for
        # a session-less row or a conclusively-expired session) and
        # retries ONCE under the replacement row. Every other failure
        # keeps the exact behaviour below (generic CheckoutError ->
        # the existing 503, row stays pending).
        try:
            attempt = pb.attempt_product_checkout_session(
                db, purchase.id,
                create_session=lambda pur: stripe_billing.create_product_checkout_session(
                    user_id=_user.id, sku=sku, purchase_id=pur.id,
                    success_url=success_url, cancel_url=cancel_url))
        except Exception:
            db.rollback()
            raise
        purchase = attempt.purchase
        checkout_url, session_id = attempt.checkout_url, attempt.session_id
        if attempt.state == "already_complete":
            # The original session already paid; settlement is
            # webhook-only and the status surface already reflects
            # it. Create nothing, backfill nothing.
            return JSONResponse({
                "checkout_url": checkout_url, "purchase_id": str(purchase.id),
                "session_status": "complete",
                "redemption_deadline": (credits_helpers._as_aware(source.expires_at) + timedelta(days=30)).isoformat(),
                "promise": stripe_billing.PAY_NOW_PROMISE,
            })
        # Remediation R1 (I2): coordinated backfill — the admission
        # lock + FOR-UPDATE pending re-check live in
        # pb.backfill_product_purchase_session (the attempt already
        # applied it; this re-application is idempotent and supplies
        # the price snapshot). No unlocked write of the session id
        # remains on this route.
        pb.backfill_product_purchase_session(
            db, purchase.id, session_id=session_id,
            price_id=stripe_billing.product_price_id(sku))
        db.commit()
        if reused and not attempt.superseded:
            # Session-retrieval retry (A7/P2-1): the pending row was
            # reused and the session re-created/retrieved under THIS
            # row's idempotency key — Stripe returns the original
            # session for the same key+params, including the timeout
            # case where the local row never recorded a session id.
            return JSONResponse({
                "checkout_url": checkout_url, "purchase_id": str(purchase.id),
                "redemption_deadline": (credits_helpers._as_aware(source.expires_at) + timedelta(days=30)).isoformat(),
                "promise": stripe_billing.PAY_NOW_PROMISE,
            })
    except pb.DuplicateEntitlement as dup:
        db.rollback()
        return JSONResponse({
            "error": "You already hold an entitlement for this report's Investigation Report.",
            "existing_entitlement_id": str(dup.entitlement.id),
            "entitlement_status": dup.entitlement.status,
        }, status_code=409)
    except stripe_billing.CheckoutNotConfigured:
        db.rollback()
        return JSONResponse({"error": "Investigation Report purchases are not available yet. Please try again later."}, status_code=503)
    except stripe_billing.CheckoutError:
        raise HTTPException(503, "Investigation Report purchases are temporarily unavailable. Please try again shortly.")
    from app import funnel as funnel_helpers
    funnel_helpers.emit_standalone(funnel_helpers.PURCHASE_START, user_id=_user.id,
                                   meta={"sku": sku, "kind": "product"})
    return JSONResponse({
        "checkout_url": checkout_url, "purchase_id": str(purchase.id),
        "redemption_deadline": (credits_helpers._as_aware(source.expires_at) + timedelta(days=30)).isoformat(),
        "promise": stripe_billing.PAY_NOW_PROMISE,
    })


@app.get("/reports/{result_id}/investigation-status")
async def investigation_status(request: Request, result_id: str, db=Depends(get_db)):
    """Issue #164 Phase A (A7/P3-2): purchase-status polling for the
    checkout return page. Read-only, owner-checked; grants nothing —
    settlement is webhook-only. The report page polls this after
    ?checkout=success until the entitlement lands (or tries run out).
    """
    import uuid as _uuid
    from fastapi.responses import JSONResponse
    from app import product_billing as pb
    from app import models
    _user, _ = _get_current_user_optional(request)
    if not _user:
        return JSONResponse({"error": "Login required"}, status_code=401)
    try:
        rid = _uuid.UUID(result_id)
    except ValueError:
        return JSONResponse({"error": "Invalid report ID"}, status_code=400)
    source = db.query(models.Result).filter(
        models.Result.id == rid,
        models.Result.user_id == _user.id,
        models.Result.deleted_at.is_(None),
    ).first()
    if not source:
        return JSONResponse({"error": "Report not found"}, status_code=404)
    ent = pb.live_entitlement(db, _user.id, rid, "investigation_report")
    if ent is not None:
        return JSONResponse({
            "entitlement_status": ent.status,
            "redemption_deadline": ent.redemption_deadline.isoformat() if ent.redemption_deadline else None,
        })
    purchase = db.query(models.ProductPurchase).filter(
        models.ProductPurchase.user_id == _user.id,
        models.ProductPurchase.source_result_id == rid,
        models.ProductPurchase.sku == "investigation_report",
    ).order_by(models.ProductPurchase.created_at.desc()).first()
    return JSONResponse({
        "entitlement_status": None,
        "purchase_status": purchase.status if purchase else None,
    })


# Issue #164 Phase B: operation type <-> digest SKU mapping. The
# three migrated flows are dollar-only for new runs from ship
# (Decision 1); their SKUs bind to a content digest, not a source.
PRODUCT_SKU_BY_OPERATION = {
    "oversize_analysis": "large_file_analysis",
    "compare_logs": "compare",
    "batch": "batch",
}


@app.post("/products/checkout")
async def product_checkout(
    request: Request,
    sku: str = Form(...),
    content_digest: str = Form(...),
    csrf_token: str = Form(...),
    db=Depends(get_db),
):
    """Issue #164 Phase B: product checkout for the digest-bound SKUs
    (compare / batch / large_file_analysis), started from the flow's
    quote/consent step on the Analyze surface.

    Mirrors the Phase A investigation checkout gates (auth, CSRF,
    rate limit, fail-closed price env, F1 duplicate block, pending
    row BEFORE the session, session idempotency bound to the row).
    Settlement is webhook-only; success/cancel URLs grant nothing.
    """
    import hmac
    import os as _os
    from fastapi import HTTPException
    from fastapi.responses import JSONResponse
    from app import auth as auth_helpers
    from app import stripe_billing
    from app import product_billing as pb

    if not _os.environ.get("DATABASE_URL"):
        raise HTTPException(503, "Purchases are unavailable right now.")
    _user, _ = _get_current_user_optional(request)
    if not _user:
        return JSONResponse({"error": "Log in or sign up to continue."}, status_code=401)
    session = auth_helpers.get_session_from_cookie(db, request)
    expected = session.csrf_token if session else None
    if not expected or not isinstance(csrf_token, str) or not hmac.compare_digest(csrf_token, expected):
        raise HTTPException(403, "Invalid CSRF token. Reload the page and try again.")
    if sku not in stripe_billing.DIGEST_SKUS:
        return JSONResponse({"error": "Unknown product."}, status_code=400)
    if not isinstance(content_digest, str) or len(content_digest) != 64:
        return JSONResponse({"error": "Invalid content digest."}, status_code=400)
    from app import d2_attribution as _d2
    _d2.emit_premium_intent(request, _user.id, "checkout_start")
    ip = _client_ip(request)
    if _use_shared_limiter():
        try:
            rl_db = _db_session()
            try:
                checkout_limiter.admit(rl_db, f"c:{ip}")
            finally:
                rl_db.close()
        except (BurstLimited, HourlyLimited):
            raise HTTPException(429, "Too many attempts. Please try again later.")
        except Exception:
            raise HTTPException(503, "Rate limiting is temporarily unavailable. Please try again shortly.")
    else:
        auth_helpers.check_rate_limit("checkout", ip)

    entry = stripe_billing.get_product_sku(sku)
    origin = str(request.base_url).rstrip("/")
    try:
        stripe_billing._secret_key()
        if stripe_billing.product_price_id(sku) is None:
            raise stripe_billing.CheckoutNotConfigured(f"price not configured for product {sku}")
        purchase, reused = pb.create_pending_product_purchase(
            db, _user.id, sku, content_digest=content_digest)
        db.commit()
        # PR #182 finding 4: bind the return landing to THIS checkout's
        # purchase. The success/cancel URLs are built only once the
        # pending purchase row exists, and carry its id so
        # /products/return resolves consent/purchase/entitlement by
        # the purchase's content_digest — never by whatever consent
        # happens to be the buyer's latest (a newer quote opened in
        # another tab must not hijack the landing). An env override
        # still wins as the base URL; the purchase parameter is
        # appended query-string-aware (any stale purchase parameter
        # on the override is replaced, not duplicated).
        from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

        def _purchase_bound_url(override, default_query, purchase_id):
            base = override or f"{origin}/products/return?{default_query}"
            parts = urlsplit(base)
            query = [(k, v) for k, v in
                     parse_qsl(parts.query, keep_blank_values=True)
                     if k != "purchase"]
            query.append(("purchase", str(purchase_id)))
            return urlunsplit(parts._replace(query=urlencode(query)))

        def _create_session_for(pur):
            # PR #182 finding 2: the return landing is the
            # settlement-aware /products/return surface, NOT the
            # plain home page (which ignored the parameter and
            # dead-ended a buyer who had paid). The URLs are built
            # per purchase row, so a superseded replacement row's
            # session binds its return landing to the NEW purchase
            # (§5), never to the poisoned row.
            success_url = _purchase_bound_url(
                _os.environ.get("STRIPE_SUCCESS_URL"),
                f"product_checkout=success&sku={sku}", pur.id)
            cancel_url = _purchase_bound_url(
                _os.environ.get("STRIPE_CANCEL_URL"),
                f"product_checkout=cancelled&sku={sku}", pur.id)
            return stripe_billing.create_product_checkout_session(
                user_id=_user.id, sku=sku, purchase_id=pur.id,
                success_url=success_url, cancel_url=cancel_url,
                content_digest=content_digest)

        # Issue #164 idempotency-supersede fix: same §2 gated
        # supersede-once path as the Investigation Report checkout
        # (see pb.attempt_product_checkout_session); every other
        # failure keeps the existing generic 503 / pending-row
        # behaviour.
        try:
            attempt = pb.attempt_product_checkout_session(
                db, purchase.id, create_session=_create_session_for)
        except Exception:
            db.rollback()
            raise
        purchase = attempt.purchase
        checkout_url, session_id = attempt.checkout_url, attempt.session_id
        if attempt.state == "already_complete":
            return JSONResponse({
                "checkout_url": checkout_url, "purchase_id": str(purchase.id),
                "session_status": "complete",
                "promise": stripe_billing.PAY_NOW_PROMISE,
            })
        # Remediation R1 (I2): coordinated backfill, as on the
        # Investigation Report route — see
        # pb.backfill_product_purchase_session. No unlocked write of
        # the session id remains on this route.
        pb.backfill_product_purchase_session(
            db, purchase.id, session_id=session_id,
            price_id=stripe_billing.product_price_id(sku))
        db.commit()
    except pb.DuplicateEntitlement as dup:
        db.rollback()
        return JSONResponse({
            "error": f"You already hold an entitlement for this {entry['name']}.",
            "existing_entitlement_id": str(dup.entitlement.id),
            "entitlement_status": dup.entitlement.status,
        }, status_code=409)
    except stripe_billing.CheckoutNotConfigured:
        db.rollback()
        return JSONResponse({"error": f"{entry['name']} purchases are not available yet. Please try again later."}, status_code=503)
    except stripe_billing.CheckoutError:
        raise HTTPException(503, "Purchases are temporarily unavailable. Please try again shortly.")
    from app import funnel as funnel_helpers
    funnel_helpers.emit_standalone(funnel_helpers.PURCHASE_START, user_id=_user.id,
                                   meta={"sku": sku, "kind": "product"})
    # No redemption_deadline is quoted here: the digest window runs
    # 30 days from SETTLEMENT (B-11), which has not happened yet.
    return JSONResponse({
        "checkout_url": checkout_url, "purchase_id": str(purchase.id),
        "promise": stripe_billing.PAY_NOW_PROMISE,
    })


PRODUCT_OPERATION_BY_SKU = {sku: op for op, sku in PRODUCT_SKU_BY_OPERATION.items()}

_PRODUCT_RETURN_ACTIONS = {
    "compare_logs": ("/compare/paid", "Run comparison — already paid", "/compare"),
    "batch": ("/batch/paid", "Run batch analysis — already paid", "/batch"),
    "oversize_analysis": ("/analyze/paid", "Run oversize analysis — already paid", "/"),
}


@app.get("/products/return", response_class=HTMLResponse)
async def product_return(request: Request):
    """Issue #164 Phase B (PR #182 finding 2): settlement-aware
    landing for a digest-SKU checkout return.

    Settlement is webhook-only — this page grants nothing. It reads
    the buyer's own state for the SKU and renders exactly one honest
    state: ``ready`` (a settled entitlement + the still-pending
    consent for the same files + the pending payload actually
    loaded: the Run form, never a second checkout prompt — PR #182
    finding 5: without the payload the Run form would 410, so that
    case renders ``no_consent`` instead), ``settling`` (payment received, webhook not landed yet:
    check-again link, no checkout prompt), ``no_consent`` (entitlement
    held but the pending upload is gone: re-upload the same files and
    the quote step offers Run), ``cancelled``, or ``missing``.
    The pending consent identity (consent_id + file_hash) is resolved
    server-side from the buyer's latest unconsumed consent for the
    SKU's operation, so the Run form re-confirms the SAME files the
    buyer paid for.

    PR #182 finding 4: when the return URL carries a ``purchase``
    parameter (minted by /products/checkout since that fix), the
    landing binds STRICTLY to that purchase: the purchase must belong
    to this buyer and SKU, and consent/entitlement are resolved by
    the purchase's content_digest — never by the latest-consent pick
    (a newer quote in another tab must not hijack the landing). A
    purchase parameter that does not resolve to such a purchase
    binds to NOTHING: the landing renders ``missing`` rather than
    falling back to some other consent on the account. URLs without
    the parameter (minted before the fix) keep the latest-consent
    behaviour above.
    """
    from fastapi.responses import RedirectResponse
    from app import stripe_billing as _sb
    sku = request.query_params.get("sku", "")
    outcome = request.query_params.get("product_checkout", "success")
    if sku not in _sb.DIGEST_SKUS:
        return HTMLResponse(
            content="<h1>Unknown product</h1><p>This checkout link is not valid.</p>",
            status_code=400)
    _user, _csrf = _get_current_user_optional(request)
    if not _user:
        return RedirectResponse("/login", status_code=303)
    operation = PRODUCT_OPERATION_BY_SKU[sku]
    confirm_action, run_label, start_path = _PRODUCT_RETURN_ACTIONS[operation]
    entry = _sb.get_product_sku(sku) or {}
    context = {
        "current_user": _user, "csrf_token": _csrf,
        # S6/S7 port (A3): the return template scopes its new
        # presentation by operation — Batch/Compare only.
        "operation": operation, "sku": sku,
        "product_name": entry.get("name", sku),
        "state": "missing", "filename": None,
        "consent_id": None, "file_hash": None,
        "confirm_action": confirm_action, "run_label": run_label,
        "start_path": start_path,
        "return_url": f"/products/return?product_checkout=success&sku={sku}",
    }
    from app.db import SessionLocal
    from app import models as _M
    from app import product_billing as _pb

    def _load_pending_filename(consent):
        """Fill the display filename from the consent's pending
        payload. Returns True only when the payload actually loaded
        (a loader returning None, or raising, counts as NOT loaded —
        PR #182 finding 5 gates the Run action on this)."""
        try:
            if operation == "compare_logs":
                pair = _load_compare_pending(str(consent.id))
                if pair is not None:
                    context["filename"] = f"{pair[0]} → {pair[2]}"
                    return True
            elif operation == "batch":
                bundle = _load_batch_pending(str(consent.id))
                if bundle is not None:
                    context["filename"] = f"Batch — {len(bundle)} files"
                    return True
            else:
                pending = _load_paid_pending(str(consent.id))
                if pending is not None:
                    context["filename"] = pending[0]
                    return True
        except Exception:
            context["filename"] = None
        return False

    # PR #182 finding 4: a purchase-bound return URL keeps its
    # binding in the settling state's Check-again link.
    purchase_param = request.query_params.get("purchase", "")
    if purchase_param:
        from urllib.parse import quote as _urlquote
        context["return_url"] = (
            f"/products/return?product_checkout=success&sku={sku}"
            f"&purchase={_urlquote(purchase_param, safe='')}")
    pending_loaded = False
    with SessionLocal() as db:
        consent = None
        entitlement = None
        purchase = None
        if purchase_param:
            # Finding 4, bound branch: resolve ONLY the named
            # purchase (this buyer, this SKU) and bind strictly to
            # its content_digest. No latest-consent fallback here —
            # that fallback is exactly the hijack being fixed. An
            # unresolvable parameter leaves consent/entitlement/
            # purchase all None, so the landing renders "missing":
            # the safest honest state (it neither claims a payment is
            # settling nor offers another purchase's files to run).
            import uuid as _uuid
            try:
                purchase_id = _uuid.UUID(purchase_param)
            except (ValueError, AttributeError, TypeError):
                purchase_id = None
            if purchase_id is not None:
                purchase = db.query(_M.ProductPurchase).filter(
                    _M.ProductPurchase.id == purchase_id,
                    _M.ProductPurchase.user_id == _user.id,
                    _M.ProductPurchase.sku == sku,
                ).first()
            if purchase is not None:
                digest = purchase.content_digest
                consent = db.query(_M.Consent).filter(
                    _M.Consent.user_id == _user.id,
                    _M.Consent.operation_type == operation,
                    _M.Consent.sku == sku,
                    _M.Consent.input_hash == digest,
                    _M.Consent.consumed_by_operation_id.is_(None),
                    _M.Consent.consumed_by_free_request_id.is_(None),
                    _M.Consent.expires_at > datetime.now(timezone.utc),
                ).order_by(_M.Consent.created_at.desc()).first()
                entitlement = _pb.available_entitlement(
                    db, _user.id, None, sku, content_digest=digest)
                if consent is not None:
                    context["consent_id"] = str(consent.id)
                    context["file_hash"] = consent.input_hash
                    pending_loaded = _load_pending_filename(consent)
        else:
            consent = db.query(_M.Consent).filter(
                _M.Consent.user_id == _user.id,
                _M.Consent.operation_type == operation,
                _M.Consent.sku == sku,
                _M.Consent.consumed_by_operation_id.is_(None),
                _M.Consent.consumed_by_free_request_id.is_(None),
                _M.Consent.expires_at > datetime.now(timezone.utc),
            ).order_by(_M.Consent.created_at.desc()).first()
            if consent is not None:
                context["consent_id"] = str(consent.id)
                context["file_hash"] = consent.input_hash
                entitlement = _pb.available_entitlement(
                    db, _user.id, None, sku,
                    content_digest=consent.input_hash)
                purchase = db.query(_M.ProductPurchase).filter(
                    _M.ProductPurchase.user_id == _user.id,
                    _M.ProductPurchase.sku == sku,
                    _M.ProductPurchase.content_digest == consent.input_hash,
                ).order_by(_M.ProductPurchase.created_at.desc()).first()
                pending_loaded = _load_pending_filename(consent)
            else:
                # No live consent: an entitlement for ANY digest of
                # this SKU still means "already paid — re-upload".
                entitlement = db.query(_M.Entitlement).filter(
                    _M.Entitlement.user_id == _user.id,
                    _M.Entitlement.sku == sku,
                    _M.Entitlement.status == "available",
                ).order_by(_M.Entitlement.created_at.desc()).first()
                if entitlement is not None and not _pb.available_entitlement(
                        db, _user.id, None, sku,
                        content_digest=entitlement.content_digest):
                    entitlement = None  # lapsed window: not redeemable
                purchase = db.query(_M.ProductPurchase).filter(
                    _M.ProductPurchase.user_id == _user.id,
                    _M.ProductPurchase.sku == sku,
                ).order_by(_M.ProductPurchase.created_at.desc()).first()
    if purchase_param and purchase is None:
        # Finding 4: an unresolvable purchase binding renders the
        # honest "missing" state — never another consent's state,
        # and never a "settling" claim for an unknown purchase.
        context["state"] = "missing"
    elif (entitlement is not None and consent is not None
            and pending_loaded):
        context["state"] = "ready"
    elif entitlement is not None and consent is not None:
        # PR #182 finding 5: entitlement + consent exist but the
        # pending payload did NOT load (temp storage lost) — the Run
        # form would necessarily 410 at the paid handler, so render
        # the re-upload recovery state instead of "ready". (Falls
        # into the no_consent branch below on purpose.)
        context["state"] = "no_consent"
    elif entitlement is not None:
        context["state"] = "no_consent"
    elif outcome == "cancelled":
        context["state"] = "cancelled"
    elif purchase is not None or consent is not None:
        context["state"] = "settling"
    return templates.TemplateResponse(request, "product_return.html", context)


# ISSUE-69 + #164 (A3): Stripe webhook — family dispatch by kind.
# Server-to-server: no user session and no CSRF token. The Stripe-Signature
# HMAC is the authentication; unsigned or mis-signed deliveries are answered
# 400 before any database row is touched. Stripe retries non-2xx, so every
# handler path below is idempotent. Dispatch order (A3): signature verify
# -> event-PK insert (exactly once) -> kind classification -> family lookup.
# Absent kind is deterministically PACK; a present kind that contradicts
# the resolved family, or an unknown kind, fails closed with no fallback.
@app.post("/credits/webhook")
async def credits_webhook(request: Request, db=Depends(get_db)):
    import json as _json
    from fastapi import HTTPException
    from fastapi.responses import JSONResponse
    from sqlalchemy.exc import IntegrityError
    from app import stripe_billing, models as _models
    from app import credits as credits_helpers
    from app import product_billing as _pb

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

    webhook_event = _models.StripeWebhookEvent(
        stripe_event_id=event_id, event_type=event_type, outcome="ignored")
    db.add(webhook_event)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        # P3-1 disposition: the A3(5) 'transient:' supersede branch
        # that previously sat here was dead code — no path ever wrote
        # a 'transient:' note. It is REMOVED. Effective transient
        # behaviour is the mechanism the handlers actually use:
        # settlement exceptions roll back (the event row is never
        # committed) and return HTTP 500, so Stripe redelivery enters
        # through a fresh event row. Any COMMITTED row is a true
        # duplicate and grants nothing twice.
        log.info("webhook %s: redelivered event; granting nothing", event_id)
        return JSONResponse({"status": "duplicate"})

    stripe_obj = event.get("data", {}).get("object", {}) or {}
    obj_metadata = stripe_obj.get("metadata", {}) or {}
    kind = obj_metadata.get("kind")
    if kind is not None and kind not in ("pack", "product"):
        webhook_event.outcome = "failed"
        webhook_event.note = f"unknown kind {kind!r}"
        db.commit()
        return JSONResponse({"status": "failed"})

    def _find_pack_purchase():
        purchase = None
        purchase_ref = obj_metadata.get("purchase_id")
        if purchase_ref:
            try:
                purchase = db.get(_models.CreditPurchase, purchase_ref)
            except Exception:
                log.warning("webhook %s: malformed metadata purchase_id %r", event_id, purchase_ref)
                purchase = None
        if purchase is None and stripe_obj.get("id"):
            from sqlalchemy import select as _select
            purchase = db.execute(
                _select(_models.CreditPurchase).where(
                    _models.CreditPurchase.stripe_session_id == stripe_obj["id"])
            ).scalar_one_or_none()
        return purchase

    def _find_product_purchase():
        purchase = None
        purchase_ref = obj_metadata.get("purchase_id")
        if purchase_ref:
            try:
                purchase = db.get(_models.ProductPurchase, purchase_ref)
            except Exception:
                log.warning("webhook %s: malformed metadata purchase_id %r", event_id, purchase_ref)
                purchase = None
        if purchase is None and stripe_obj.get("id"):
            from sqlalchemy import select as _select
            purchase = db.execute(
                _select(_models.ProductPurchase).where(
                    _models.ProductPurchase.stripe_session_id == stripe_obj["id"])
            ).scalar_one_or_none()
        if purchase is None and stripe_obj.get("payment_intent"):
            from sqlalchemy import select as _select
            purchase = db.execute(
                _select(_models.ProductPurchase).where(
                    _models.ProductPurchase.stripe_payment_intent_id == stripe_obj["payment_intent"])
            ).scalar_one_or_none()
        return purchase

    def _find_product_by_charge():
        # Refund/dispute join (A5): charge -> PI metadata purchase_id +
        # kind=product, else the purchase row's snapshotted PI id.
        purchase = None
        purchase_ref = obj_metadata.get("purchase_id")
        if purchase_ref:
            try:
                purchase = db.get(_models.ProductPurchase, purchase_ref)
            except Exception:
                purchase = None
        if purchase is None:
            pi = stripe_obj.get("payment_intent")
            if isinstance(pi, dict):
                pi = pi.get("id")
            if pi:
                from sqlalchemy import select as _select
                purchase = db.execute(
                    _select(_models.ProductPurchase).where(
                        _models.ProductPurchase.stripe_payment_intent_id == pi)
                ).scalar_one_or_none()
        return purchase

    def _resolve_product_by_charge():
        """Local join, then Stripe-API resolution (remediation2 P1-A).

        Returns (purchase, retryable). Both local joins miss when a
        reversal webhook precedes checkout.session.completed
        settlement: real Charge objects carry no purchase metadata,
        and the purchase row's PI snapshot is only written AT
        settlement. The PaymentIntent carries the purchase metadata
        from session creation, so retrieve it and join on that. A
        charge with NO product relation at all is genuinely unknown
        (retryable=False -> caller may ignore it); a charge the API
        ties to the product family whose purchase cannot be resolved
        yet, or whose resolution itself failed transiently, is
        retryable (retryable=True -> caller rolls back and answers
        500, committing NO event row, so redelivery can repair the
        ordering once settlement lands). A purchase RESOLVED here
        while still pending is processed normally: a full refund of
        a pending purchase is terminal in apply_refund, and the
        later settlement then grants nothing (duplicate).
        """
        purchase = _find_product_by_charge()
        if purchase is not None:
            return purchase, False
        pi = stripe_obj.get("payment_intent")
        if isinstance(pi, dict):
            pi = pi.get("id")
        if not pi:
            return None, False
        try:
            pi_metadata = stripe_billing.fetch_payment_intent_metadata(pi)
        except stripe_billing.CheckoutError:
            log.warning("webhook %s: PI resolution failed transiently; "
                        "asking Stripe to redeliver", event_id)
            return None, True
        if pi_metadata.get("kind") != "product":
            return None, False  # not a product charge at all
        purchase_ref = pi_metadata.get("purchase_id")
        resolved = None
        if purchase_ref:
            try:
                resolved = db.get(_models.ProductPurchase, purchase_ref)
            except Exception:
                resolved = None
        if resolved is not None:
            return resolved, False
        log.warning("webhook %s: product charge for unresolved purchase "
                    "%r; asking Stripe to redeliver", event_id, purchase_ref)
        return None, True

    # F4: async success is NOT a grant route in Phase A.
    if event_type == "checkout.session.async_payment_succeeded":
        webhook_event.outcome = "ignored"
        webhook_event.note = "async success grants nothing in Phase A (F4)"
        db.commit()
        return JSONResponse({"status": "ignored"})

    # A5: refund / dispute machinery for the product family. Charges
    # without a resolvable product join are ignored here (pack charges
    # keep their existing reconciliation-only handling).
    if event_type in ("charge.refunded", "charge.dispute.created", "charge.dispute.closed"):
        if kind == "pack":
            webhook_event.outcome = "ignored"
            webhook_event.note = "pack reversal handled by reconciliation"
            db.commit()
            return JSONResponse({"status": "ignored"})
        purchase, retryable = _resolve_product_by_charge()
        if purchase is None and retryable:
            # P1-A: never consume the event id for a product reversal
            # we cannot resolve yet — roll back (no committed event
            # row) and answer 500 so Stripe redelivers after the
            # settlement ordering repairs itself.
            db.rollback()
            raise HTTPException(500, "transient settlement failure")
        if purchase is None:
            webhook_event.outcome = "ignored"
            webhook_event.note = "unknown purchase"
            db.commit()
            return JSONResponse({"status": "ignored"})
        if kind is not None and kind != "product":
            webhook_event.outcome = "failed"
            webhook_event.note = "kind contradicts product purchase"
            db.commit()
            return JSONResponse({"status": "failed"})
        webhook_event.product_purchase_id = purchase.id
        try:
            if event_type == "charge.refunded":
                outcome = _pb.apply_refund(
                    db, purchase, stripe_event_id=event_id,
                    refunded_cents=int(stripe_obj.get("amount_refunded") or 0),
                    charge_amount_cents=int(stripe_obj.get("amount") or 0))
            elif event_type == "charge.dispute.created":
                outcome = _pb.apply_dispute(db, purchase, stripe_event_id=event_id, dispute_status=None,
                                            disputed_cents=stripe_obj.get("amount"),
                                            dispute_id=stripe_obj.get("id"))
            else:
                outcome = _pb.apply_dispute(db, purchase, stripe_event_id=event_id,
                                            dispute_status=stripe_obj.get("status"),
                                            disputed_cents=stripe_obj.get("amount"),
                                            dispute_id=stripe_obj.get("id"))
        except Exception:
            db.rollback()
            raise HTTPException(500, "transient settlement failure")
        webhook_event.outcome = "processed"
        webhook_event.note = outcome[:250]
        db.commit()
        return JSONResponse({"status": "processed"})

    if event_type != "checkout.session.completed" and event_type not in (
        "checkout.session.expired",
        "checkout.session.async_payment_failed",
        "payment_intent.payment_failed",
    ):
        db.commit()
        log.info("webhook %s: ignoring event type %s", event_id, event_type)
        return JSONResponse({"status": "ignored"})

    # Family classification for session/PI events: kind=product routes
    # to the product family ONLY; kind absent or 'pack' routes to pack
    # ONLY (legacy). A kind that contradicts the resolved family fails
    # closed — no cross-family fallback, ever (A3).
    if kind == "product":
        purchase = _find_product_purchase()
        if purchase is None:
            # The id may resolve in the pack family — that is a
            # contradiction, not an unknown purchase.
            if _find_pack_purchase() is not None:
                webhook_event.outcome = "failed"
                webhook_event.note = "kind=product contradicts pack purchase"
                db.commit()
                return JSONResponse({"status": "failed"})
            webhook_event.outcome = "ignored"
            webhook_event.note = "unknown purchase"
            db.commit()
            return JSONResponse({"status": "ignored"})
        webhook_event.product_purchase_id = purchase.id
        if event_type in ("checkout.session.expired", "checkout.session.async_payment_failed"):
            reason = ("checkout session expired" if event_type == "checkout.session.expired"
                      else "async payment failed")
            transitioned = _pb.fail_product_purchase(db, purchase, reason=reason, stripe_event_id=event_id)
            webhook_event.outcome = "processed"
            webhook_event.note = f"purchase {reason}" + ("" if transitioned else " (already terminal)")
            db.commit()
            return JSONResponse({"status": "processed"})
        if event_type == "payment_intent.payment_failed":
            webhook_event.outcome = "processed"
            webhook_event.note = "card declined; purchase left pending for in-session retry"
            db.commit()
            return JSONResponse({"status": "processed"})
        # checkout.session.completed — strict product settlement (A4/F4).
        # P1-1: a real checkout.session.completed event carries
        # NEITHER line_items nor a price id on the session object.
        # Retrieve the line items from the Stripe API (test-mode key
        # pattern via stripe_billing) and take the Price ID from the
        # retrieval — never from the event payload. A retrieval
        # failure is transient: roll back (the event row is not
        # committed) and answer 500 so Stripe redelivers.
        try:
            session_price_id = stripe_billing.fetch_session_line_item_price_id(
                stripe_obj.get("id") or "")
        except stripe_billing.CheckoutError:
            db.rollback()
            raise HTTPException(500, "transient settlement failure")
        try:
            outcome = _pb.settle_product_purchase(
                db, purchase,
                stripe_event_id=event_id,
                stripe_session_id=stripe_obj.get("id") or "",
                event_metadata=obj_metadata,
                amount_cents=stripe_obj.get("amount_total"),
                currency=stripe_obj.get("currency"),
                payment_intent_id=stripe_obj.get("payment_intent"),
                payment_status=stripe_obj.get("payment_status"),
                session_status=stripe_obj.get("status"),
                mode=stripe_obj.get("mode"),
                session_price_id=session_price_id,
                livemode=event.get("livemode"),
                # Remediation4 (fix 6): the completed session
                # object's ``created`` is the Stripe charge/session
                # creation anchor reconciliation keys on (the event
                # object's own ``created`` is the fallback — both
                # are carried on data already in hand here, no extra
                # Stripe retrieval).
                stripe_charge_created_at=stripe_obj.get("created") or event.get("created"),
            )
        except _pb.SettlementError as exc:
            webhook_event.outcome = "failed"
            webhook_event.note = str(exc)[:250]
            db.commit()
            return JSONResponse({"status": "failed"})
        except Exception:
            db.rollback()
            raise HTTPException(500, "transient settlement failure")
        webhook_event.outcome = outcome
        db.commit()
        return JSONResponse({"status": outcome})

    # Pack family (kind absent = legacy, or kind=pack).
    purchase = _find_pack_purchase()
    if purchase is None and kind == "pack":
        if _find_product_purchase() is not None:
            webhook_event.outcome = "failed"
            webhook_event.note = "kind=pack contradicts product purchase"
            db.commit()
            return JSONResponse({"status": "failed"})
    if event_type in ("checkout.session.expired",
                      "checkout.session.async_payment_failed"):
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
        if purchase is None:
            webhook_event.outcome = "ignored"
            webhook_event.note = "unknown purchase"
            db.commit()
            log.warning("webhook %s: no purchase for payment intent %s; ignoring",
                        event_id, stripe_obj.get("id"))
            return JSONResponse({"status": "ignored"})
        webhook_event.purchase_id = purchase.id
        webhook_event.outcome = "processed"
        webhook_event.note = "card declined; purchase left pending for in-session retry"
        db.commit()
        log.info("webhook %s: purchase %s card declined; still %s, granting nothing",
                 event_id, purchase.id, purchase.status)
        return JSONResponse({"status": "processed"})

    session_obj = stripe_obj
    metadata = obj_metadata
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
    # PR #182 finding 2 (legacy landings): checkout sessions created
    # before the /products/return surface existed still carry the old
    # "/?product_checkout=...&sku=..." success URL — consume the
    # parameter here by handing off to that surface instead of
    # dead-ending the buyer on the plain home page.
    _pc = request.query_params.get("product_checkout")
    _sku = request.query_params.get("sku", "")
    if _pc in ("success", "cancelled") and _sku:
        from fastapi.responses import RedirectResponse
        from urllib.parse import quote as _q
        return RedirectResponse(
            f"/products/return?product_checkout={_pc}&sku={_q(_sku)}",
            status_code=303)
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


# ---------------------------------------------------------------------------
# Issue #159: public sample Investigation Report.
#
# One immutable cache value — {raw artifact JSON (private, never in a
# response), public projection, PDF bytes, build metadata} — published
# under a lock ONLY after analyze -> build_deep_dive -> validate_artifact
# -> public_projection -> generate_deep_dive_pdf ALL succeed. Any stage
# failure publishes nothing, the request returns a plain 500, and the
# next request retries the full genuine pipeline (no failure caching).
# Execution is synchronous in the handler on the main thread:
# analyze_upload() arms SIGALRM, which is never safe off the main thread
# (the /demo precedent). The cache is per-process — it builds once per
# process and no cross-replica claim is made. The handlers resolve NO
# per-user context at all, so the served page is identical for anonymous
# and signed-in visitors, and they contain no event, admission, grant,
# or checkout code.
# ---------------------------------------------------------------------------
import threading as _sample_threading

_SAMPLE_CACHE = None
_SAMPLE_CACHE_LOCK = _sample_threading.Lock()
_SAMPLE_BANNER = "SAMPLE — generated by StackSift from a sample incident log"


def _reset_sample_cache():
    """Drop the cached sample value (test support; also process restart)."""
    global _SAMPLE_CACHE
    with _SAMPLE_CACHE_LOCK:
        _SAMPLE_CACHE = None


def _build_sample_cache():
    """Run the genuine pipeline end to end; raise on any stage failure."""
    import json as _json

    from app import deep_dive as _dd
    from app import pdf_export as _pdf_export

    payload = analyze_upload(SAMPLE_FILENAME, SAMPLE_LOG.encode("utf-8"))
    if not isinstance(payload, dict) or "error" in payload:
        raise RuntimeError("sample analysis failed")
    artifact = _dd.build_deep_dive(payload)
    validated = _dd.validate_artifact(artifact)
    projection = _dd.public_projection(validated)
    raw_json = _json.dumps(validated)
    # Issue #163 (Decision 8 / Amendment A5): the sample renders under
    # the WellInstance constant profile — a server-side constant, NOT
    # the owner machinery (the sample has no Result/owner). The PDF
    # report_title remains the existing SAMPLE label.
    from app import branding as _branding_sample
    pdf_bytes = _pdf_export.generate_deep_dive_pdf(
        raw_json,
        filename="sample-analysis-report",
        branding=_branding_sample.sample_branding_dict(),
    )
    return {
        "raw_artifact_json": raw_json,
        "projection": projection,
        "pdf_bytes": pdf_bytes,
        "branding_web": _branding_sample.sample_web_branding(),
        "metadata": {
            "generator_version": _dd.GENERATOR_VERSION,
            "sample_filename": SAMPLE_FILENAME,
        },
    }


def _get_sample_cache():
    """Return the published sample value, building it atomically once."""
    global _SAMPLE_CACHE
    if _SAMPLE_CACHE is not None:
        return _SAMPLE_CACHE
    with _SAMPLE_CACHE_LOCK:
        if _SAMPLE_CACHE is None:
            _SAMPLE_CACHE = _build_sample_cache()
        return _SAMPLE_CACHE


def _sample_build_failed():
    _logging.getLogger(__name__).error(
        "Sample report build failed; serving plain 500 and leaving the "
        "sample cache unpublished so the next request retries.")
    return PlainTextResponse(
        "Sample report temporarily unavailable.", status_code=500)


@app.get("/sample-report", response_class=HTMLResponse)
async def sample_report(request: Request):
    """Public sample Investigation Report (issue #159).

    No login, no per-user context, no charges, no events: renders the
    cached genuine pipeline projection with is_sample=True only.
    """
    try:
        cache = _get_sample_cache()
    except Exception:
        return _sample_build_failed()
    return templates.TemplateResponse(
        request,
        "deep_dive_report.html",
        {
            "analysis_projection": cache["projection"],
            "filename": cache["projection"].get("filename") or SAMPLE_FILENAME,
            "is_sample": True,
            # A5: brand header from the constant profile; no form, no
            # per-user context (is_sample gating is unchanged).
            "branding": cache.get("branding_web"),
        },
    )


@app.get("/sample-report/pdf")
async def sample_report_pdf(request: Request):
    """Public sample PDF (issue #159): the cached bytes from the exact
    sample invocation of generate_deep_dive_pdf (page-1 SAMPLE header
    label only). No export-unlock check and no credit path."""
    from fastapi.responses import Response

    try:
        cache = _get_sample_cache()
    except Exception:
        return _sample_build_failed()
    return Response(
        content=cache["pdf_bytes"],
        media_type="application/pdf",
        headers={"Content-Disposition":
                 'attachment; filename="sample-analysis-report.pdf"'},
    )


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
                             "with Large-File Analysis ($5), or upload a smaller file.")
            return error("That file has more than 50,000 lines. "
                         "Sign in to analyze files up to 100 MB / 500,000 lines "
                         "with Large-File Analysis ($5), or upload a smaller file.")
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

    # Issue #156: analysis_run on successful completion of the
    # no-database single-file path too (the durable path emits in
    # _durable_analysis). Best-effort: with no database configured the
    # standalone emit simply has nowhere to write and is swallowed.
    from app import d2_attribution as _d2
    _d2_user, _ = _get_current_user_optional(request)
    _d2.emit_analysis_run(request, _d2_user.id if _d2_user else None,
                          None, "free")

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
    "Oversize analysis costs $5. Complete the purchase from the "
    "quote step to run this file."
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


def _product_quote(request, *, operation: str, sku: str, file_hash: str, user,
                     store_pending):
    """Issue #164 Phase B: the dollar quote step for a migrated flow.

    Returns (consent_id, entitlement) on success — entitlement is the
    buyer's live available entitlement for (user, sku, digest) when
    one exists (the page then renders the redemption "Run" path,
    B-7's F1 surface), else None (the page renders the $5 checkout
    path). Returns an HTMLResponse when the SKU's price env is unset:
    the fail-closed "Coming soon" pattern (Decision 4) — no consent,
    no pending store, no purchase row, no Stripe call, and NO credit
    fallback. ``store_pending(consent_id)`` persists the pending
    upload inside the same transaction as consent creation.
    """
    import os as _os
    if not _os.environ.get("DATABASE_URL"):
        raise RuntimeError("no database")
    from fastapi.responses import HTMLResponse
    from app.db import SessionLocal
    from app import credits as credits_helpers
    from app import models as _models
    from app import product_billing as _pb
    from app import stripe_billing as _sb

    if _sb.product_price_id(sku) is None:
        return HTMLResponse(
            content=("<h1>Coming soon</h1><p>This feature is not "
                     "available yet. Please check back shortly.</p>"),
            status_code=503)
    db = SessionLocal()
    try:
        with _PENDING_LOCK:
            if operation == "oversize_analysis":
                # One live oversize pending per user (existing rule);
                # a re-quote of the SAME digest is not a second
                # pending — it is the redemption route after checkout.
                now = datetime.now(timezone.utc)
                live = db.query(_models.Consent).filter(
                    _models.Consent.user_id == user.id,
                    _models.Consent.operation_type == "oversize_analysis",
                    _models.Consent.input_hash != file_hash,
                    _models.Consent.consumed_by_operation_id.is_(None),
                    _models.Consent.consumed_by_free_request_id.is_(None),
                    _models.Consent.expires_at > now,
                ).first()
                if live is not None:
                    raise credits_helpers.AdmissionError(
                        "You already have an oversize upload awaiting confirmation. "
                        "Confirm or wait for it to expire before uploading another oversize file.")
            entitlement = _pb.available_entitlement(
                db, user.id, None, sku, content_digest=file_hash)
            consent = credits_helpers.create_product_consent(
                db, user.id, operation, file_hash, sku)
            db.flush()
            consent_id = str(consent.id)
            try:
                store_pending(consent_id)
            except Exception:
                db.rollback()
                raise
            db.commit()
    finally:
        db.close()
    return consent_id, entitlement


def _product_consent_context(*, user, csrf_token, filename, file_hash,
                             consent_id, entitlement, sku, heading, intro,
                             size_line, limits_line, cost_sentence,
                             confirm_action, run_label, note_extra="",
                             lead_in="", footnote="", note_text=None):
    """Shared dollar consent-page context (Decision 9 copy rules):
    $5, success-only, exports included, 90-day retention, and the
    Phase A PAY_NOW_PROMISE pinned verbatim on the checkout path.

    S6/S7 port additions (presentation only): ``lead_in`` is the
    design's post-cost-block lead-in and ``footnote`` the per-operation
    redemption footnote (amendment A4: NEW disclosure composed from
    the billing contract — redemption binds to the original filenames,
    plus upload order for Batch, and the 30-day window runs from the
    SETTLED purchase); both are supplied only by the Batch/Compare
    callers, so the Oversize render is unchanged apart from the
    CALL-3 confirm label. ``note_text`` replaces the composed bottom
    note outright when a caller has retired its facts into the
    lead-in (CALL-1: no sentence renders twice)."""
    from app import stripe_billing as _sb
    redeem = entitlement is not None
    return {
        "current_user": user,
        "csrf_token": csrf_token,
        "filename": filename,
        "file_hash": file_hash,
        "consent_id": consent_id,
        "cost": 0,
        "balance": None,
        "eligible": None,
        "product_mode": True,
        "product_checkout": not redeem,
        "product_sku": sku,
        "promise": _sb.PAY_NOW_PROMISE,
        "heading": heading,
        "intro": intro,
        "size_line": size_line,
        "limits_line": limits_line,
        "cost_label": "$5",
        "cost_sentence": cost_sentence,
        "confirm_label": run_label if redeem else "Pay $5",
        "confirm_action": confirm_action,
        "cancel_label": "Cancel",
        "lead_in": lead_in,
        "footnote": footnote,
        "note": (note_text if note_text is not None else
                 "Exports are included. Results are available for 90 days. "
                 + note_extra),
    }


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
    _sku = PRODUCT_SKU_BY_OPERATION.get(operation)
    if _sku is not None:
        # Issue #164 Phase B (Decisions 1/5, B-7): migrated flows
        # quote in dollars only — a zero-cost product consent, never
        # a credit consent, and no balance check.
        def _store(consent_id):
            if operation == "compare_logs":
                _store_compare_pending(consent_id, filename, content,
                                       filename_b, content_b)
            else:
                meta = None
                if operation == "oversize_analysis":
                    meta = {"operation_type": operation,
                            "byte_count": byte_count,
                            "line_count": line_count,
                            "user_id": str(user.id)}
                _store_paid_pending(consent_id, filename, content, meta=meta)
        quoted = _product_quote(request, operation=operation, sku=_sku,
                                file_hash=file_hash, user=user,
                                store_pending=_store)
        if not isinstance(quoted, tuple):
            return quoted  # fail-closed response (price env unset)
        consent_id, entitlement = quoted
        if operation == "oversize_analysis":
            size_mb = (byte_count or 0) / (1024 * 1024)
            context = _product_consent_context(
                user=user, csrf_token=csrf_token, filename=filename,
                file_hash=file_hash, consent_id=consent_id,
                entitlement=entitlement, sku=_sku,
                heading="Oversize analysis",
                intro="This file exceeds the free limits.",
                size_line=f"{byte_count:,} bytes ({size_mb:.1f} MB) · {line_count:,} lines",
                limits_line="Analyze up to 100 MB / 500,000 lines.",
                cost_sentence="This run costs $5. No charge if the analysis fails.",
                confirm_action="/analyze/paid",
                run_label="Run oversize analysis — already paid")
            context["operation_type"] = operation
        else:  # compare_logs
            context = _product_consent_context(
                user=user, csrf_token=csrf_token,
                filename=f"{filename} → {filename_b}",
                file_hash=file_hash, consent_id=consent_id,
                entitlement=entitlement, sku=_sku,
                heading="Compare two logs",
                intro="Compare A (before) against B (after).",
                size_line=None,
                limits_line="Free limits apply to both files (10 MB / 50,000 lines each).",
                cost_sentence=("This comparison costs $5 — even if the logs are "
                               "identical or show no material differences. "
                               "No charge if the comparison fails."),
                confirm_action="/compare/paid",
                run_label="Run comparison — already paid",
                lead_in=("Comparison costs $5, paid by card at checkout. "
                         "Exports are included, and the comparison is kept "
                         "for 90 days."),
                footnote=("You have 30 days from the settled purchase to run "
                          "this comparison; re-uploading the same two files, "
                          "with the same filenames, redeems your purchase."),
                note_text="")
            # S6/S7 port (spec §8.3, the one named context addition):
            # the design's per-file chips need the A/B file list; both
            # names are already in hand here — no new computation.
            context["file_list"] = [f"A — {filename}", f"B — {filename_b}"]
            context["operation_type"] = operation
        return templates.TemplateResponse(
            request, "paid_consent.html", context, status_code=402)
    if operation == "additional_analysis":
        # Issue #164 Phase C (C1, CALL-1 hard cap): no consent is
        # minted for additional analyses any more. The free allowance
        # (10/hour) is a hard cap — refuse honestly with the reset
        # guidance and NO purchase route.
        return templates.TemplateResponse(
            request, "index.html",
            {"error": "Free-tier limit reached (10 analyses/hour). "
                      "Your free analyses reset within the hour — "
                      "please try again later. Additional analyses "
                      "are not sold.",
             "remaining": limiter.remaining(ip),
             "current_user": user, "csrf_token": csrf_token},
            status_code=429)
    if operation == "oversize_analysis":
        cost = credits_helpers.COST_OVERSIZE_ANALYSIS
    elif operation == "compare_logs":
        cost = credits_helpers.COST_COMPARE
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
            "cost_sentence": "Continue this analysis now with a credit",
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
    if report_id is not None and user is not None:
        # Issue #106 Stage 2 (PR #149 Codex P2): the fresh-response
        # render must carry the same Analysis action state the
        # saved-report page sets, or Actions -> Analysis opens a
        # popup with an empty message and only a Cancel button.
        # Eligibility comes from the retained-evidence contract over
        # this render's own payload; a completed generation (e.g. on
        # an idempotent replay) links straight to the derived report.
        from app import deep_dive as _dd_fresh
        data["analysis_eligible"], data["analysis_reason"] = \
            _dd_fresh.eligibility_state(data)
        data["analysis_result_id"] = None
        try:
            _fresh_rid = uuid_module.UUID(report_id)
        except (ValueError, AttributeError, TypeError):
            _fresh_rid = None
        if _fresh_rid is not None:
            from app.db import SessionLocal as _SL_fresh
            from app import credits as _credits_fresh
            with _SL_fresh() as _db:
                _done_fresh = _credits_fresh.completed_analysis_result_id(
                    _db, user.id, _fresh_rid)
            data["analysis_result_id"] = (
                str(_done_fresh) if _done_fresh else None)
        # Issue #164 (P2-3/P3-3): same product display state as the
        # saved-report page — "Coming soon" when the Price env is
        # unset, and the F5 redemption deadline for this report.
        from app import stripe_billing as _sb_fresh
        data["product_ready"] = (
            _sb_fresh.product_price_id("investigation_report") is not None)
        # Remediation4 (fix 7): same entitlement-aware flag as the
        # saved-report view, so a fresh render does not strand a
        # redemption when new sales are disabled.
        data["entitlement_available"] = False
        if _fresh_rid is not None:
            from app.db import SessionLocal as _SL_fresh_ent
            from app import product_billing as _pb_fresh
            with _SL_fresh_ent() as _db_ent:
                data["entitlement_available"] = \
                    _pb_fresh.available_entitlement(
                        _db_ent, user.id, _fresh_rid,
                        "investigation_report") is not None
        _fresh_src = None
        if _fresh_rid is not None:
            from app.db import SessionLocal as _SL_fresh2
            from app import models as _models_fresh
            with _SL_fresh2() as _db2:
                _fresh_src = _db2.get(_models_fresh.Result, _fresh_rid)
                if _fresh_src is not None:
                    _db2.expunge(_fresh_src)
        if _fresh_src is not None and _fresh_src.expires_at is not None:
            from datetime import timedelta as _td_fresh
            data["redemption_deadline"] = (
                _credits_fresh._as_aware(_fresh_src.expires_at)
                + _td_fresh(days=30)).strftime("%Y-%m-%d")
        if _fresh_src is not None:
            from app import fidelity as _fidelity_fresh
            data["ss_id"] = getattr(_fresh_src, "ss_id", None) or \
                _fidelity_fresh.derive_ss_id(
                    _fresh_src.id, _fresh_src.ready_at)
            if not data.get("analysis_timestamp"):
                data["analysis_timestamp"] = \
                    _fidelity_fresh.analysis_timestamp_label(
                        _fresh_src.ready_at)
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
    from datetime import timedelta
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
                # Issue #164 Phase B: billing mode from the consent
                # row — a product consent admits via the entitlement
                # engine; an unadmitted legacy credit consent is
                # refused (B-12 class 2). Replay above still serves
                # admitted pre-ship runs on their original terms.
                if _consent_row.sku is None:
                    db.rollback()
                    return _analysis_response(request, 409, message=LEGACY_CONSENT_MESSAGE)
                # Consent validation precedes the pending load (the
                # credit-era order): consumed/expired/owner errors
                # are 409, a missing pending file is 410.
                try:
                    C.validate_consent(db, consent_id, user_id,
                                       "oversize_analysis", digest, 0,
                                       sku="large_file_analysis")
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
                    # Product admission (B-8): the free-quota branch of
                    # analysis_admission.admit() must NEVER convert an
                    # oversize run into a free run. Lock order (B-4):
                    # digest product-admission scope first (inside
                    # admit_product_operation), then this flow's
                    # capacity scopes (global:oversize before
                    # global:paid, sorted), then the entitlement row.
                    # Worker pool size 1 via the global:oversize scope,
                    # existing user/global permits, explicit 30/hour
                    # rate policy (consumed inside admission).
                    from app import product_billing as _pb_over
                    item = _pb_over.admit_product_operation(
                        db, user_id, "oversize_analysis",
                        "large_file_analysis", key, digest,
                        consent_id, worker,
                        input_manifest=_client_ip(request),
                        extra_scopes=[("global:oversize", 1)])
                except _pb_over.EntitlementRequired:
                    db.rollback()
                    return _analysis_response(request, 402, message=OVERSIZE_INSUFFICIENT_MESSAGE)
                except _pb_over.DeadlineLapsed:
                    db.commit()  # refund_eligible transition stands (B-11)
                    return _analysis_response(request, 410, message="This purchase's 30-day redemption window has lapsed. It is now refund-eligible — contact disputes@goodfolkdigital.com.")
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
                    # Issue #164 Phase C (C1b): an additional-analysis
                    # consent minted before cutover can no longer admit
                    # or debit after it. Replay of an already-admitted
                    # operation was resolved by A.lookup above; a bare
                    # unconsumed consent is refused, no charge.
                    db.rollback()
                    return _analysis_response(
                        request, 429,
                        message="Free-tier limit reached (10 analyses/hour). "
                                "Additional analyses are not sold — please "
                                "try again after your free allowance resets.")
                    pending = _load_paid_pending(str(consent_id))
                    if pending is None:
                        return _analysis_response(request, 410, message="Upload expired. Please upload the file again.")
                    filename, content = pending
                    if A.fingerprint(filename, content) != digest:
                        return _analysis_response(request, 409, message="Upload does not match your consent.")
                worker = uuid_module.uuid4().hex
                item, created = A.admit(db, user_id, anon, key, digest, _client_ip(request), worker, consent_id)
                if item is None:
                    # Issue #164 Phase C (C1a/e): hard cap — refusal
                    # carrying the reset time (oldest in-window free
                    # request + 1h), no consent, no purchase route,
                    # for anonymous and signed-in users alike.
                    _oldest = db.scalar(
                        select(M.FreeRequest.created_at).where(
                            M.FreeRequest.quota_bucket_trusted_ip == _client_ip(request),
                            M.FreeRequest.created_at > C._utcnow() - timedelta(hours=1),
                        ).order_by(M.FreeRequest.created_at.asc()).limit(1))
                    db.rollback()
                    _reset = ""
                    if _oldest is not None:
                        _reset_at = C._as_aware(_oldest) + timedelta(hours=1)
                        _reset = f" Your allowance resets at {_reset_at.strftime('%H:%M UTC')}."
                    return _analysis_response(
                        request, 429,
                        message="Free-tier limit reached (10 analyses/hour)." + _reset + " Additional analyses are not sold.")
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
            return _analysis_response(request, 402, message="Insufficient credits.", buy_credits=True)
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
            if not failure and result_id is not None:
                # Issue #156: analysis_run on EVERY successful completion
                # of the single-file flow (free and paid alike; replays
                # return earlier and never reach this point). Standalone
                # session: the settlement transaction above has already
                # committed, and telemetry must never break delivery.
                # Identity prefers the d2 visitor cookie; the anonymous
                # session hash is the fallback anon identity.
                from app import d2_attribution as _d2
                _d2.emit_analysis_run(
                    request, user_id, anon,
                    paid_operation_type or ("paid" if paid else "free"))
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
            return _analysis_response(request, 401, message="Please log in to continue.")
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
            return _analysis_response(request, 401, message="Please log in to use credits.")
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
    "Comparing two logs costs $5. Complete the purchase from the "
    "quote step to run this comparison."
)

LEGACY_CONSENT_MESSAGE = (
    "This confirmation was created under the previous credit pricing "
    "and can no longer be used. Upload the files again to see the "
    "current $5 price — no credits were charged."
)


def _export_unlocked_for(user, report_id) -> bool:
    """Export-unlock display state for a fresh compare/batch render:
    unlocked by a prior credit unlock OR product-paid (B-9 — exports
    are free for dollar-paid artifacts, decided by the B-8 helper)."""
    if user is None or report_id is None:
        return False
    try:
        import uuid as _uuid
        from app.db import SessionLocal
        from app import credits as _C
        from app import models as _M
        with SessionLocal() as db:
            result = db.get(_M.Result, _uuid.UUID(str(report_id)))
            if result is None:
                return False
            return bool(_C.is_export_unlocked(db, user.id, result.id)
                        or _C.is_product_paid_result(db, result))
    except Exception:
        return False


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
        data.setdefault("export_unlocked", _export_unlocked_for(user, report_id))
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
        # Issue #164 Phase B: billing mode is decided by the consent
        # row. A product consent (sku set) admits through the
        # entitlement engine; an unadmitted legacy CREDIT consent is
        # refused (B-12 class 2) — no charge, no run, route to the
        # dollar quote. Replay above still serves admitted runs.
        _consent_row = db.get(M.Consent, consent_id, populate_existing=True)
        if _consent_row is not None and _consent_row.sku is None:
            db.rollback()
            return _comparison_response(request, 409, message=LEGACY_CONSENT_MESSAGE)
        pair = _load_compare_pending(str(consent_id))
        if pair is None:
            return _comparison_response(request, 410, message="Upload expired. Please upload the files again.")
        filename_a, content_a, filename_b, content_b = pair
        if _compare_pair_hash(filename_a, content_a, filename_b, content_b) != digest:
            return _comparison_response(request, 409, message="Upload does not match your consent.")
        if _consent_row is not None:
            # Product admission (B-8). Lock order (B-4): digest
            # product-admission scope first (inside
            # admit_product_operation), then this flow's capacity
            # scopes (global:paid + user), then the entitlement row.
            # Consent validation as its own step first (the oversize
            # pattern): owner/type/hash/expiry/mode failures are 409
            # here; admission re-validates authoritatively under lock.
            try:
                C.validate_consent(db, consent_id, user_id, "compare_logs",
                                   digest, 0, sku="compare")
            except C.AdmissionError as exc:
                db.rollback()
                return _comparison_response(request, 409, message=str(exc))
            from app import product_billing as _pb
            try:
                item = _pb.admit_product_operation(
                    db, user_id, "compare_logs", "compare", key, digest,
                    consent_id, worker, input_manifest=_client_ip(request))
            except _pb.EntitlementRequired:
                db.rollback()
                return _comparison_response(request, 402, message=COMPARE_INSUFFICIENT_MESSAGE)
            except _pb.DeadlineLapsed:
                db.commit()  # refund_eligible transition stands (B-11)
                return _comparison_response(request, 410, message="This purchase's 30-day redemption window has lapsed. It is now refund-eligible — contact disputes@goodfolkdigital.com.")
            except C.AdmissionError as exc:
                db.rollback()
                return _comparison_response(request, 409 if "409" in str(exc) else 429, message=str(exc))
        else:
            try:
                C.validate_consent(db, consent_id, user_id, "compare_logs", digest, C.COST_COMPARE)
            except C.AdmissionError as exc:
                db.rollback()
                return _comparison_response(request, 409, message=str(exc))
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
            return _comparison_response(request, 401, message="Please log in to continue.")
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
            "Insufficient eligible credits.")


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
        data.setdefault("export_unlocked", _export_unlocked_for(user, report_id))
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
    # Issue #164 Phase B (Decision 3, B-7/B-19): flat $5 per batch run
    # of 2-5 files. No formula quote, no free-first claim, no balance
    # check — a zero-cost product consent only. (The ``quote`` param
    # is retained for call-site compatibility and ignored.)
    quoted = _product_quote(
        request, operation="batch", sku="batch", file_hash=file_hash,
        user=user,
        store_pending=lambda consent_id: _store_batch_pending(
            consent_id, files, counts))
    if not isinstance(quoted, tuple):
        return quoted  # fail-closed response (price env unset)
    consent_id, entitlement = quoted
    total_bytes = sum(c[0] for c in counts)
    context = _product_consent_context(
        user=user, csrf_token=csrf_token,
        filename=f"Batch \u2014 {n} files",
        file_hash=file_hash, consent_id=consent_id,
        entitlement=entitlement, sku="batch",
        heading="Batch analysis",
        intro="One combined report, in upload order.",
        size_line=f"{total_bytes:,} bytes across {n} files, in upload order",
        limits_line="Free limits apply to every file (10 MB / 50,000 lines each). Duplicate filenames are separate files, told apart by their number.",
        cost_sentence=("This batch costs $5 — one flat price for all files "
                       "in the set. No charge if the batch fails."),
        confirm_action="/batch/paid",
        run_label=f"Analyze {n} files \u2014 already paid",
        lead_in=("Batch analysis costs $5, paid by card at checkout. "
                 "Exports are included, and the combined report is kept "
                 "for 90 days."),
        footnote=("You have 30 days from the settled purchase to run this "
                  "batch; re-uploading the same files, with the same "
                  "filenames in the same upload order, redeems your "
                  "purchase."),
        note_text="PDF export of the combined report is included.")
    context["file_list"] = [f"{ordinal}. {filename}" for ordinal, filename, _ in files]
    context["operation_type"] = "batch"
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
        return _batch_response(request, 401, message="Please log in to continue.")
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
                            "No files were analyzed and nothing was charged.")
        # Issue #164 Phase B: billing mode from the consent row.
        if consent_row is not None and consent_row.sku is None:
            # B-12 class 2: unadmitted legacy credit consent refused.
            db.rollback()
            return _batch_response(request, 409, message=LEGACY_CONSENT_MESSAGE)
        product_batch = consent_row is not None and consent_row.sku is not None
        item = None
        if product_batch:
            # Consent validation as its own step (the oversize
            # pattern): failures are 409 here, before admission
            # re-validates authoritatively under lock.
            try:
                C.validate_consent(db, consent_id, user_id, "batch",
                                   digest, 0, sku="batch")
            except C.AdmissionError as exc:
                db.rollback()
                return _batch_response(request, 409, message=str(exc))
            # Product admission (B-8/B-19). Lock order (B-4): digest
            # product-admission scope first (inside
            # admit_product_operation), then this flow's capacity
            # scopes (global:batch before global:paid, sorted), then
            # the entitlement row. No requote, no free claim, no
            # RateLimitHit for a dollar batch.
            from app import product_billing as _pb
            try:
                item = _pb.admit_product_operation(
                    db, user_id, "batch", "batch", key, digest,
                    consent_id, worker, input_manifest=ip,
                    extra_scopes=[("global:batch", 1)])
            except _pb.EntitlementRequired:
                db.rollback()
                return _batch_response(
                    request, 402,
                    message="Batch analysis costs $5. Complete the purchase from the quote step to run this batch.")
            except _pb.DeadlineLapsed:
                db.commit()  # refund_eligible transition stands (B-11)
                return _batch_response(
                    request, 410,
                    message="This purchase's 30-day redemption window has lapsed. It is now refund-eligible — contact disputes@goodfolkdigital.com.")
            except C.AdmissionError as exc:
                db.rollback()
                return _batch_response(request, 409 if "409" in str(exc) else 429,
                                       message=str(exc))
        else:
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
                    # B-15: product-paid batches snapshot a DOLLAR
                    # pricing shape; legacy snapshots are unchanged.
                    pricing=({"sku": "batch", "amount_cents": 500}
                             if product_batch else
                             {"file_count": len(bundle),
                              "first_file_cost": first_cost,
                              "additional_file_cost": C.COST_BATCH_ADDITIONAL_FILE,
                              "total_cost": total_cost}))
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

    no_charge = " No files were analyzed and nothing was charged."
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
            return _batch_response(request, 401, message="Please log in to continue.")
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
    """Issue #164 Phase C (C3): RETIRED with its last consumer (the
    pricing page's unsettled-pack poll, removed with the pack grid).
    Answers honestly — 410, no stale JSON served."""
    from fastapi.responses import JSONResponse
    return JSONResponse(
        {"error": "Credit balances are retired. See /credits for pricing."},
        status_code=410,
    )


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
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    per_page = 20
    page = max(1, page)
    offset = (page - 1) * per_page
    # Issue #102: comparison reports (type "comparison") list alongside
    # analyses; PDF-only results stay excluded. Issue #106 Stage 2:
    # Analysis Reports (type "deep_dive") list as their own rows too.
    # Remediation4 (fix 1): an EXPIRED source is still listed when it
    # carries a live (available, in-window) entitlement — flagged
    # redemption-only in the row build below — because otherwise the
    # holder has no surface from which to redeem inside the F5
    # window. All other expired sources stay excluded, as before.
    from sqlalchemy import exists as _exists, or_ as _or
    _live_ent_exists = _exists().where(
        models.Entitlement.source_result_id == models.Result.id,
        models.Entitlement.user_id == _user.id,
        models.Entitlement.status == "available",
        _or(models.Entitlement.redemption_deadline.is_(None),
            models.Entitlement.redemption_deadline >= now),
    )
    base_q = db.query(models.Result).filter(
        models.Result.user_id == _user.id,
        models.Result.type.in_(["analysis", "comparison", "deep_dive"]),
        _or(models.Result.expires_at > now, _live_ent_exists),
        models.Result.deleted_at.is_(None),
    )
    total = base_q.count()
    results = base_q.order_by(models.Result.created_at.desc()).offset(offset).limit(per_page).all()
    total_pages = max(1, (total + per_page - 1) // per_page)
    from app import credits as _credits_for_list
    reports = []
    for r in results:
        _manifest_data = None
        try:
            manifest = json.loads(r.storage_manifest)
            _manifest_data = manifest
            filename = manifest.get("filename", "Unknown file")
            report_kind = manifest.get("report_kind")
        except (json.JSONDecodeError, TypeError):
            filename = "Unknown file"
            report_kind = None
        # Issue #106 Stage 2: row Analysis state — eligibility comes
        # from the retained-evidence contract; a completed generation
        # links straight to the derived report instead of re-charging.
        _analysis_eligible, _analysis_reason = (False, None)
        _analysis_result_id = None
        if r.type == "analysis" and _manifest_data is not None:
            from app import deep_dive as _dd_for_list
            _analysis_eligible, _analysis_reason = \
                _dd_for_list.eligibility_state(_manifest_data)
            _done = _credits_for_list.completed_analysis_result_id(
                db, _user.id, r.id)
            _analysis_result_id = str(_done) if _done else None
        from app.credits import _as_aware
        _sharing_rows = db.query(models.ReportSharing).filter(
            models.ReportSharing.result_id == r.id).all()
        # Remediation4 (fixes 1+7): per-row entitlement state — an
        # expired row present only via the entitlement EXISTS above
        # is redemption-only, and ANY row (expired or not) holding an
        # available entitlement must offer redemption even when new
        # product sales are disabled (product_ready false).
        from app import product_billing as _pb_for_list
        _ent_for_row = _pb_for_list.available_entitlement(
            db, _user.id, r.id, "investigation_report") \
            if r.type == "analysis" else None
        _row_expired = _as_aware(r.expires_at) <= now
        # Fidelity S3-C1 (rides S1-C2): SS-ID + honest format label
        # for the report-cell subline. Format comes from the stored
        # manifest's detected_format where present.
        from app import fidelity as _fidelity_list
        _row_format = None
        if _manifest_data is not None:
            _row_format = _manifest_data.get("detected_format")
        reports.append({
            "id": str(r.id),
            "ss_id": getattr(r, "ss_id", None) or
                _fidelity_list.derive_ss_id(r.id, r.ready_at),
            "format_label": _fidelity_list.honest_format_label(_row_format)
                if _row_format else None,
            "filename": filename,
            "severity": r.severity,  # 'ok' | 'warnings' | 'errors' | None (pre-#49 rows)
            "created_at": r.created_at,
            "expires_at": r.expires_at,
            "days_left": max(0, (_as_aware(r.expires_at) - now).days),
            # Issue #129 + founder UI amendment: row action row is
            # View / Export (dropdown) / Share / Extend. Each row gets
            # fresh per-render action keys and its unlock/share state
            # for the confirmation copy.
            "type": r.type,
            # PR #132 finding 4: the row template needs the same
            # discriminator the report page uses (report.html hides
            # CSV/JSON when report_kind is set) so batch rows — type
            # "analysis" with report_kind "batch", whose structured
            # exports the route rejects with 422 — do not offer
            # CSV/JSON controls that can only fail.
            "report_kind": report_kind,
            "retention_key": uuid_module.uuid4().hex,
            "share_create_key": uuid_module.uuid4().hex,
            "share_rotate_key": uuid_module.uuid4().hex,
            "share_revoke_key": uuid_module.uuid4().hex,
            "export_unlocked": _credits_for_list.is_export_unlocked(
                db, _user.id, r.id) or _credits_for_list.is_product_paid_result(db, r),
            "share_active": any(
                row.token_hash and row.revoked_at is None
                for row in _sharing_rows),
            # Issue #135: formats that already have an active link,
            # so the Share popup can mark them per format.
            "share_formats": [
                (row.share_format or "txt") for row in _sharing_rows
                if row.token_hash and row.revoked_at is None],
            # Founder UI amendment (2026-11-03): row actions are
            # View / Export / Analysis / Share / Extend.
            "analysis_eligible": _analysis_eligible,
            "analysis_reason": _analysis_reason,
            "analysis_result_id": _analysis_result_id,
            # Issue #164 (P3-3/F5): the redemption deadline for a
            # purchase from this row = source expiry + 30 days,
            # shown in the purchase modal before purchase.
            "redemption_deadline": (
                _credits_for_list._as_aware(r.expires_at)
                + timedelta(days=30)).strftime("%Y-%m-%d")
            if r.type == "analysis" else None,
            # Remediation4 (fix 1): expired-but-redeemable rows are
            # flagged so the template suppresses viewing-era actions
            # (Export/Share/Extend would 410) and labels the row.
            "redemption_only": bool(_row_expired and _ent_for_row is not None),
            # Remediation4 (fix 7): entitlement-aware flag threaded
            # into the row's Analysis button / shared modal JS.
            "entitlement_available": _ent_for_row is not None,
        })
    from app import stripe_billing as _sb_for_list
    return templates.TemplateResponse(request, "reports.html", {
        "reports": reports,
        "current_user": _user,
        "csrf_token": _csrf,
        "page": page,
        "total_pages": total_pages,
        "total": total,
        # Issue #164 (P2-3): product fail-closed display state for the
        # Analysis purchase modal ("Coming soon" when Price unset).
        "product_ready": _sb_for_list.product_price_id("investigation_report") is not None,
    })


# ---------------------------------------------------------------------------
# Issue #163: per-report branding helpers (owned deep_dive reports only).
# ---------------------------------------------------------------------------

def _branding_row_for(db, result_id):
    from app import models as _models
    return db.query(_models.ReportBranding).filter(
        _models.ReportBranding.result_id == result_id).first()


def _generate_deep_dive_pdf_branded(db, result, filename):
    """Generate a deep_dive PDF with the report's stored branding.

    The branding dict is assembled server-side from the stored row
    only; stored logo bytes are materialised to a server-owned temp
    file for the render and unlinked afterwards (A8(f)). With no row,
    generation is exactly the pre-#163 unbranded call.
    """
    from app import branding as _branding_mod
    from app.pdf_export import generate_deep_dive_pdf as _gen
    row = _branding_row_for(db, result.id)
    with _branding_mod.branding_dict_with_temp_logo(row) as _bdict:
        if _bdict:
            return _gen(result.storage_manifest, filename, branding=_bdict)
        return _gen(result.storage_manifest, filename)


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
        models.Result.type.in_(["analysis", "comparison", "deep_dive"]),
        models.Result.deleted_at.is_(None),
    ).first()
    if not result:
        return JSONResponse({"error": "Report not found"}, status_code=404)
    if credits_helpers._as_aware(result.expires_at) < datetime.now(timezone.utc):
        # Remediation4 (fix 1): an expired source whose owner holds
        # an available entitlement inside the F5 window gets a
        # REDEMPTION-ONLY page — the Analysis generate action, with
        # NO report payload or viewing — instead of a dead 410, so
        # the entitlement is actually reachable from the browser.
        # Every other expired case keeps the 410 exactly.
        _redeem_ent = None
        if result.type == "analysis":
            from app import product_billing as _pb_expired
            _redeem_ent = _pb_expired.available_entitlement(
                db, _user.id, result.id, "investigation_report")
        if _redeem_ent is not None:
            try:
                _exp_payload = credits_helpers.result_payload(
                    result, user_id=_user.id,
                    operation_id=result.operation_id,
                    free_request_id=result.free_request_id,
                    product_redemption_id=result.product_redemption_id,
                    allow_expired=True)
            except credits_helpers.AdmissionError:
                return JSONResponse({"error": "Report has expired"}, status_code=410)
            from app import deep_dive as _dd_expired
            _eligible, _reason = _dd_expired.eligibility_state(_exp_payload)
            _filename = "Unknown file"
            try:
                _filename = json.loads(result.storage_manifest).get(
                    "filename") or "Unknown file"
            except (ValueError, TypeError, AttributeError):
                pass
            from app import stripe_billing as _sb_expired
            return templates.TemplateResponse(request, "redemption_only.html", {
                "current_user": _user,
                "csrf_token": _csrf,
                "report_id": str(result.id),
                "filename": _filename,
                "redemption_only": True,
                "entitlement_available": True,
                "analysis_eligible": _eligible,
                "analysis_reason": _reason,
                "product_ready": (
                    _sb_expired.product_price_id("investigation_report") is not None),
                "redemption_deadline": (
                    credits_helpers._as_aware(_redeem_ent.redemption_deadline).strftime("%Y-%m-%d")
                    if _redeem_ent.redemption_deadline else None),
            })
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
    # Issue #170 fidelity: SS-ID (stored, or deterministic legacy
    # derivation) + head-meta analysis timestamp (payload value from
    # generation time, falling back to the Result's ready_at).
    from app import fidelity as _fidelity_view
    data["ss_id"] = getattr(result, "ss_id", None) or \
        _fidelity_view.derive_ss_id(result.id, result.ready_at)
    if not data.get("analysis_timestamp"):
        data["analysis_timestamp"] = \
            _fidelity_view.analysis_timestamp_label(result.ready_at)
    # Issue #106 Stage 2: an Analysis Report renders its own template
    # from the public projection only (no internal refs/digests).
    if result.type == "deep_dive":
        from app import deep_dive as _dd_view
        try:
            _artifact = _dd_view.validate_artifact(data)
            data["analysis_projection"] = _dd_view.public_projection(_artifact)
        except _dd_view.AnalysisError:
            return JSONResponse({"error": "Report data corrupted"}, status_code=500)
        data["export_unlocked"] = credits_helpers.is_export_unlocked(
            db, _user.id, result.id) or credits_helpers.is_product_paid_result(db, result)
        # Issue #163: branded header band + branding form state for
        # THIS report only (per-report, never per-account).
        from app import branding as _branding_view
        _brow = _branding_row_for(db, result.id)
        data["branding"] = _branding_view.web_branding_from_row(
            _brow, result.id)
        # Nullable row fields normalize to "" — a partial save or the
        # retained cleared row must never render the literal string
        # "None" into the form (Codex P2 on PR #169).
        data["branding_values"] = {
            "business_name": (_brow.business_name or "") if _brow else "",
            "client_name": (_brow.client_name or "") if _brow else "",
            "report_title": (_brow.report_title or "") if _brow else "",
            "accent": (_brow.accent or "") if _brow else "",
            "has_logo": bool(_brow and _brow.logo_bytes),
        }
        # Issue #160: the designed header block shows when this report
        # was generated (the artifact Result's ready_at) — display only.
        if result.ready_at:
            data["report_generated_at"] = credits_helpers._as_aware(
                result.ready_at).strftime("%Y-%m-%d %H:%M UTC")
        return templates.TemplateResponse(
            request, "deep_dive_report.html", data)
    # Issue #105: existing structured-export artifacts for this source get
    # free re-download links on the report page (artifact's own expiry,
    # validated on the download route itself).
    if (result.type == "analysis" and not data.get("report_kind")) or result.type == "deep_dive":
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
        _sharings = db.query(models.ReportSharing).filter(
            models.ReportSharing.result_id == result.id).all()
        data["share_active"] = any(
            row.token_hash and row.revoked_at is None for row in _sharings)
        data["share_formats"] = [
            (row.share_format or "txt") for row in _sharings
            if row.token_hash and row.revoked_at is None]
        # Issue #129: the report page's Export confirm copy reflects
        # the per-report unlock state (2 credits once, then free).
        data["export_unlocked"] = credits_helpers.is_export_unlocked(
            db, _user.id, result.id) or credits_helpers.is_product_paid_result(db, result)
        # Issue #106 Stage 2: Analysis action state (founder placement
        # amendment: report page is Export / Analysis / Share). Legacy
        # reports explain unavailability before any charge; a completed
        # generation links to the derived report.
        from app import deep_dive as _dd_page
        data["analysis_eligible"], data["analysis_reason"] = \
            _dd_page.eligibility_state(data)
        _done_id = credits_helpers.completed_analysis_result_id(
            db, _user.id, result.id)
        data["analysis_result_id"] = str(_done_id) if _done_id else None
        # Issue #162 (Amendment A1 / P2-6): version-aware discovery.
        # A completed artifact from an OLDER generator version still
        # serves free on its own GET view, but it must not make a new
        # Brief-bearing purchase unreachable: when the completed
        # artifact's generator version differs from the current one,
        # the source page offers the purchase popup again (stating it
        # is a new purchase) instead of only linking the old artifact.
        # Issue #164 (P2-3/P3-2/P3-3): product display state for the
        # purchase surfaces on this page — "Coming soon" fail-closed
        # state when the Price env is unset, the F5 redemption
        # deadline (source expiry + 30 days) shown before purchase,
        # and the checkout-return polling flag (A7).
        from app import stripe_billing as _sb_view
        data["product_ready"] = (
            _sb_view.product_price_id("investigation_report") is not None)
        # Remediation4 (fix 7): an available entitlement offers the
        # Generate/Confirm redemption action even when product_ready
        # is false — generation needs no Price; "Coming soon" gates
        # only NEW purchases.
        from app import product_billing as _pb_view
        data["entitlement_available"] = _pb_view.available_entitlement(
            db, _user.id, result.id, "investigation_report") is not None
        from datetime import timedelta as _td_deadline
        data["redemption_deadline"] = (
            credits_helpers._as_aware(result.expires_at)
            + _td_deadline(days=30)).strftime("%Y-%m-%d")
        data["checkout_poll"] = (
            request.query_params.get("checkout") == "success")
        data["analysis_prior_exists"] = False
        if _done_id is not None:
            _prior_row = db.get(models.Result, _done_id)
            _prior_version = None
            if _prior_row is not None:
                try:
                    _prior_version = json.loads(
                        _prior_row.storage_manifest or "{}").get(
                            "generator_version")
                except (ValueError, TypeError, AttributeError):
                    _prior_version = None
            if _prior_version != _dd_page.GENERATOR_VERSION:
                data["analysis_prior_exists"] = True
                data["analysis_result_id"] = None
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
    """Export a report as PDF.

    Issue #129: costs 2 credits (COST_PDF) only when this generation is
    the report's first export in ANY format (the single per-report
    unlock charge); once unlocked, PDF downloads are free.
    """
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
    # Issue #106 Stage 2: Analysis Reports export under the SAME #129
    # per-report unlock (no separate Analysis PDF price).
    result = db.query(models.Result).filter(
        models.Result.id == rid,
        models.Result.user_id == user.id,
        models.Result.type.in_(["analysis", "comparison", "deep_dive"]),
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
    # Issue #156: premium intent at the same attempt point (the export
    # unlock is a premium action, including when it ends in a 402).
    # Observe-only, standalone like the export-intent emit above.
    # Issue #164 Phase C (C7): the export_unlock premium-intent emit is
    # REMOVED — exports are free for all reports, so an export attempt
    # is not a paid upsell and must not be recorded as one.

    # PR #132 finding 5: build the operation key from the PARSED
    # canonical UUID (rid), never the raw URL segment — an uppercase
    # or unhyphenated first PDF export must create the same canonical
    # key unlock discovery searches for, or a later CSV/JSON export
    # would charge a second 2 credits and bypass the cross-format
    # reservation fence. The retry key below derives from this base,
    # so it is canonical too.
    base_idempotency_key = f"pdf-{rid}"
    request_hash = result.integrity_digest
    # Issue #129: serialize cross-format unlock discovery under the
    # global:paid lock (the first scope admit_paid_operation locks) and
    # hold it through the admission commit below, so a concurrent CSV/
    # JSON first generation for the same report cannot race this route
    # into a second 2-credit charge. Every early return after this
    # point rolls back to release the lock.
    credits_helpers.lock_global_paid_scope(db)
    # Issue #163 (Amendment A3): for a deep_dive Result, ANY
    # report_branding row (set OR cleared-state) defeats the stored-PDF
    # replay below — the route then falls through to the unlocked
    # fresh-generation path (no charge, no new Operation). Reports
    # that never had branding keep today's replay behaviour exactly.
    _has_branding_row = False
    if result.type == "deep_dive":
        _has_branding_row = _branding_row_for(db, rid) is not None
    existing_op = db.query(models.Operation).filter(
        models.Operation.user_id == user.id,
        models.Operation.type == "pdf",
        models.Operation.idempotency_key == base_idempotency_key,
    ).first()
    if existing_op is None:
        # PR #132 finding 5: an operation stored before key
        # canonicalization (raw uppercase/unhyphenated URL segment in
        # its key) must still be found here — otherwise its completed
        # PDF could not replay and its reserved state would not fence
        # this request. Canonical-tolerant match over this user's PDF
        # operations, preferring completed, then reserved, then the
        # latest attempt.
        _legacy = [
            _op for _op in db.query(models.Operation).filter(
                models.Operation.user_id == user.id,
                models.Operation.type == "pdf",
            ).all()
            if credits_helpers.export_key_belongs_to(
                _op.idempotency_key, rid)
        ]
        if _legacy:
            _rank = {"completed": 0, "reserved": 1}
            existing_op = max(
                _legacy,
                key=lambda _op: (
                    -_rank.get(_op.status, 2),
                    _op.created_at or datetime.min.replace(
                        tzinfo=timezone.utc),
                    str(_op.id),
                ),
            )
    # For failed/expired operations, use a new idempotency key so the retry
    # gets a fresh operation identity (the old credits were released).
    # The unique constraint on (user_id, type, idempotency_key) ensures safety.
    idempotency_key = base_idempotency_key
    if existing_op and existing_op.status in ("failed", "expired"):
        idempotency_key = f"{base_idempotency_key}-retry-{_uuid.uuid4().hex[:8]}"
        existing_op = None  # Force fresh admission with new key
    if existing_op:
        if existing_op.status == "completed" and existing_op.result_id \
                and not _has_branding_row:
            # Validate the saved PDF result before replaying (integrity, ownership, expiry)
            pdf_result = db.get(models.Result, existing_op.result_id)
            if pdf_result:
                try:
                    manifest = credits_helpers.result_payload(
                        pdf_result, user_id=user.id, operation_id=existing_op.id,
                    )
                    pdf_bytes = _b64.b64decode(manifest["pdf_base64"])
                    filename = manifest.get("filename", "report")
                    db.rollback()
                    return Response(
                        content=pdf_bytes,
                        media_type="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="stacksift-report-{_safe_download_filename(filename)}.pdf"'},
                    )
                except (credits_helpers.AdmissionError, KeyError, ValueError):
                    # Stored PDF is invalid or expired; don't attempt to reuse the
                    # completed operation's idempotency key. Return a controlled error.
                    db.rollback()
                    return JSONResponse(
                        {"error": "Previously generated PDF is no longer available. Please generate a new export."},
                        status_code=410,
                    )
        elif existing_op.status == "reserved":
            # Another request is already generating this PDF; don't hijack its operation
            db.rollback()
            return JSONResponse(
                {"error": "PDF export already in progress. Please wait and try again."},
                status_code=409,
            )
        # For failed/expired operations, fall through to admit a fresh one

    # Issue #129: per-report export unlock. Any completed export
    # operation for this report (a CSV/JSON first generation included)
    # unlocks the PDF for free; any reserved export operation in any
    # format fences this request so two formats cannot both charge.
    _unlocked, _in_progress = credits_helpers.export_unlock_state(
        db, user.id, rid)
    # Issue #164 (A9(c)): a dollar-paid report's exports are free,
    # decided from the Result origin BEFORE any consent/admission.
    if credits_helpers.is_product_paid_result(db, result):
        _unlocked = True
    if _in_progress:
        db.rollback()
        return JSONResponse(
            {"error": "PDF export already in progress. Please wait and try again."},
            status_code=409,
        )
    if _unlocked:
        db.rollback()
        # Unlocked: generate and serve with NO charge and no new
        # operation. A generation failure charges 0 and leaves the
        # unlock (already paid for) untouched.
        from app.pdf_export import generate_report_pdf as _gen_pdf
        from app.pdf_export import generate_comparison_pdf as _gen_cmp_pdf
        from app.pdf_export import generate_batch_pdf as _gen_batch_pdf
        from app.pdf_export import generate_deep_dive_pdf as _gen_dd_pdf
        try:
            _manifest_data = credits_helpers.result_payload(
                result, user_id=user.id,
                operation_id=result.operation_id,
                free_request_id=result.free_request_id,
            )
            _filename = _manifest_data.get("filename", "report")
            if result.type == "deep_dive":
                # Issue #163: fresh generation carries stored branding.
                _pdf_bytes = _generate_deep_dive_pdf_branded(
                    db, result, _filename)
            elif _manifest_data.get("report_kind") == "batch":
                _pdf_bytes = _gen_batch_pdf(result.storage_manifest, _filename)
            elif result.type == "comparison":
                _pdf_bytes = _gen_cmp_pdf(result.storage_manifest, _filename)
            else:
                _pdf_bytes = _gen_pdf(result.storage_manifest, _filename)
        except Exception:
            return JSONResponse({"error": "PDF generation failed"}, status_code=500)
        return Response(
            content=_pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="stacksift-report-{_safe_download_filename(_filename)}.pdf"'},
        )

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

    from app.pdf_export import generate_report_pdf, generate_comparison_pdf, generate_batch_pdf, generate_deep_dive_pdf
    try:
        # Validate source result integrity before generating PDF
        manifest_data = credits_helpers.result_payload(
            result, user_id=user.id,
            operation_id=result.operation_id,
            free_request_id=result.free_request_id,
        )
        filename = manifest_data.get("filename", "report")
        if result.type == "deep_dive":
            # Issue #163: the admitted first-export generation also
            # carries stored branding (same cost as unbranded).
            pdf_bytes = _generate_deep_dive_pdf_branded(
                db, result, filename)
        elif manifest_data.get("report_kind") == "batch":
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
# Issue #129 (founder ruling 2026-11-03): that charge is now the
# per-report export UNLOCK — the first successful generation in any
# format (PDF included) charges 2 credits once per report; every later
# format generation/download for that report is free (see the unlock
# branch in the route below).
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

    Issue #129: costs COST_STRUCTURED_EXPORT credits only when this
    generation is the report's first export in ANY format (the single
    per-report unlock charge); replays and all later formats are free.
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
        models.Result.type.in_(("analysis", "comparison", "deep_dive")),
        models.Result.deleted_at.is_(None),
    ).first()
    if not source:
        return JSONResponse({"error": "Report not found"}, status_code=404)
    if credits_helpers._as_aware(source.expires_at) <= datetime.now(timezone.utc):
        return JSONResponse({"error": "Report has expired"}, status_code=410)

    # Issue #156: premium intent at the same attempt point as the PDF
    # route (Codex P2, PR #157: a CSV/JSON first export performs the
    # same paid per-report unlock, so the attempt must record
    # identically or the funnel depends on the chosen format).
    # Observe-only, best-effort; counts whether or not credits suffice.
    # Issue #164 Phase C (C7): export_unlock premium-intent emit
    # removed (exports are free; see the PDF route note).

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
        if source.type == "comparison":
            # Issue #164 Phase C (C2): the format matrix keys off the
            # report's kind, and a comparison report IS a comparison
            # report by its stored type — a payload that lost (or never
            # carried) the report_kind discriminator must not slip a
            # comparison CSV/JSON past this gate now that the free
            # path no longer stops at a charge. Fail closed, as §7
            # requires, independent of the payload discriminator.
            raise se.UnsupportedReportKind(
                "Structured export is not yet supported for this report type")
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

    # Issue #129: per-report export unlock. A completed export
    # operation in ANY format (a PDF first generation included) unlocks
    # this format: generate and serve with NO charge, no consent and
    # no new operation (a generation failure here charges 0 and leaves
    # the unlock untouched). A reserved export operation in another
    # format fences this request (409) so two formats racing a locked
    # report cannot both charge — the global:paid lock held since
    # discovery makes this check authoritative on PostgreSQL.
    _unlocked, _any_in_progress = credits_helpers.export_unlock_state(
        db, user.id, rid)
    if credits_helpers.is_product_paid_result(db, source):
        _unlocked = True  # #164: free exports for the dollar-paid report
    if _any_in_progress:
        db.rollback()
        return JSONResponse(
            {"error": "Structured export already in progress. Please wait and try again."},
            status_code=409,
        )
    if _unlocked:
        db.rollback()
        try:
            export_bytes = se.generate_export(payload, export_format)
        except Exception:
            return JSONResponse(
                {"error": "Structured export generation failed"},
                status_code=500)
        from fastapi.responses import Response as _Response
        return _Response(
            content=export_bytes,
            media_type=se.MEDIA_TYPES[export_format],
            headers={
                "Content-Disposition": f'attachment; filename="{se.safe_download_name(payload.get("filename"), rid, export_format)}"',
                "Cache-Control": "private, no-store",
            },
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
# Issue #106 Stage 2: Analysis Report generation.
#
# POST /reports/{id}/deep-dive — 3 credits (COST_DEEP_DIVE), charged on
# SUCCESS only: reserve -> generate from the retained-evidence snapshot
# -> store + complete in one settlement; full release on any failure.
# Canonical identity is owner + source UUID/digest + grouping/evidence/
# generator/schema versions; the same identity replays the saved
# artifact free and never re-charges. Legacy (pre-evidence) sources,
# comparisons, batches and Analysis Reports themselves reject with 422
# BEFORE any reservation. The derived report is a distinct Result of
# type "deep_dive" with its own 7-day retention and its own #129
# export unlock; the source report is never modified.
# ---------------------------------------------------------------------------

@app.post("/reports/{result_id}/deep-dive")
async def report_deep_dive(request: Request, result_id: str, db=Depends(get_db)):
    """Generate the Investigation Report for a completed owned report.

    Issue #164 Phase A: NEW purchases are dollar-only ($9). Payment was
    captured at checkout (F2); this route redeems an available
    entitlement under the A1 reserve/complete/release discipline. A
    generation failure NEVER consumes the purchase. Canonical replay
    (either origin) is free and consumes nothing. With no entitlement
    the response is 402 directing to the product checkout — never a
    credit charge. Legacy credit-purchased artifacts keep their
    existing replay terms untouched.
    """
    import uuid as _uuid
    from fastapi.responses import JSONResponse
    from sqlalchemy import select as _select
    from app import auth as auth_helpers
    from app import credits as credits_helpers
    from app import product_billing as pb
    from app import models
    from app import deep_dive as dd
    from datetime import datetime, timezone

    session = auth_helpers.get_session_from_cookie(db, request)
    if not session:
        return JSONResponse({"error": "Login required"}, status_code=401)
    user = session.user
    form, err = await _check_owner_csrf(request, session, db)
    if err is not None:
        return err

    try:
        rid = _uuid.UUID(result_id)
    except ValueError:
        return JSONResponse({"error": "Invalid report ID"}, status_code=400)

    source = db.query(models.Result).filter(
        models.Result.id == rid,
        models.Result.user_id == user.id,
        models.Result.deleted_at.is_(None),
    ).first()
    if not source:
        return JSONResponse({"error": "Report not found"}, status_code=404)
    if source.type != "analysis":
        return JSONResponse(
            {"error": "Analysis Reports are not available for this report type"},
            status_code=422)
    source_expired = credits_helpers._as_aware(source.expires_at) <= datetime.now(timezone.utc)
    # F5: an available entitlement whose window is still open redeems
    # against an expired source (cleanup preserved its prerequisites);
    # every other caller keeps the pre-money 410 gate, including POST
    # replay against an expired source (A6).
    _window_ent = None
    if source_expired:
        _window_ent = pb.live_entitlement(db, user.id, rid, "investigation_report")
        # P3-3 / F5 boundary: redemption AT the deadline proceeds
        # ("at or before the deadline"); refuse only strictly past
        # it — matching reserve_redemption's `deadline < now` lapse.
        if _window_ent is None or _window_ent.status != "available" or (
            _window_ent.redemption_deadline is not None
            and credits_helpers._as_aware(_window_ent.redemption_deadline) < datetime.now(timezone.utc)
        ):
            return JSONResponse({"error": "Report has expired"}, status_code=410)
    try:
        payload = credits_helpers.result_payload(
            source, user_id=user.id,
            operation_id=source.operation_id,
            free_request_id=source.free_request_id,
            product_redemption_id=source.product_redemption_id,
            allow_expired=source_expired,
        )
    except credits_helpers.AdmissionError:
        return JSONResponse({"error": "Report data corrupted"}, status_code=500)

    try:
        dd.check_eligibility(payload)
    except dd.UnsupportedReportKind:
        return JSONResponse(
            {"error": "Analysis Reports are not available for this report type"},
            status_code=422)
    except dd.InsufficientEvidence as exc:
        return JSONResponse({"error": str(exc)}, status_code=422)

    from app import d2_attribution as _d2
    _d2.emit_premium_intent(request, user.id, "analysis_report")

    request_hash = dd.analysis_request_hash(source, payload)

    credits_helpers.lock_global_paid_scope(db)
    # In-flight fence across BOTH origins: a reserved legacy operation
    # or a reserved product redemption for this source 409s.
    attempts = credits_helpers.analysis_operations(db, user.id, rid)
    if any(op.status == "reserved" for op in attempts):
        db.rollback()
        return JSONResponse(
            {"error": "Analysis Report generation already in progress. "
                      "Please wait and try again."},
            status_code=409)
    live_reds = db.execute(
        _select(models.EntitlementRedemption).join(
            models.Entitlement, models.Entitlement.id == models.EntitlementRedemption.entitlement_id,
        ).where(
            models.Entitlement.user_id == user.id,
            models.EntitlementRedemption.source_result_id == rid,
            models.EntitlementRedemption.status == "reserved",
        )
    ).scalars().all()
    if live_reds:
        db.rollback()
        return JSONResponse(
            {"error": "Analysis Report generation already in progress. "
                      "Please wait and try again."},
            status_code=409)

    # Canonical replay BEFORE any entitlement is consumed (A2/A6):
    # legacy credit completions first (unchanged code path semantics),
    # then product completions.
    completed = [op for op in attempts
                 if op.status == "completed" and op.result_id
                 and op.request_hash == request_hash]
    if completed:
        latest = max(completed, key=lambda op: (op.created_at, str(op.id)))
        artifact = db.get(models.Result, latest.result_id)
        if artifact is not None:
            try:
                manifest = credits_helpers.result_payload(
                    artifact, user_id=user.id, operation_id=latest.id)
                dd.validate_artifact(
                    manifest, expected_source_id=rid,
                    expected_source_integrity_digest=source.integrity_digest)
            except Exception:
                db.rollback()
                return JSONResponse(
                    {"error": "Previously generated Analysis Report is "
                              "no longer available."},
                    status_code=410)
            db.rollback()
            return JSONResponse({
                "status": "completed",
                "analysis_result_id": str(artifact.id),
                "report_url": f"/reports/{artifact.id}",
                "cost": credits_helpers.COST_DEEP_DIVE,
                "replayed": True,
            })
        db.rollback()
        return JSONResponse(
            {"error": "Previously generated Analysis Report is no longer available."},
            status_code=410)
    done_reds = [r for r in credits_helpers.product_analysis_completions(db, user.id, rid)
                 if r.request_hash == request_hash]
    if done_reds:
        latest_red = max(done_reds, key=lambda r: (r.created_at, str(r.id)))
        artifact = db.get(models.Result, latest_red.result_id)
        if artifact is not None:
            try:
                manifest = credits_helpers.result_payload(
                    artifact, user_id=user.id,
                    product_redemption_id=latest_red.id)
                dd.validate_artifact(
                    manifest, expected_source_id=rid,
                    expected_source_integrity_digest=source.integrity_digest)
            except Exception:
                db.rollback()
                return JSONResponse(
                    {"error": "Previously generated Analysis Report is "
                              "no longer available."},
                    status_code=410)
            db.rollback()
            return JSONResponse({
                "status": "completed",
                "analysis_result_id": str(artifact.id),
                "report_url": f"/reports/{artifact.id}",
                "price_cents": 900,
                "replayed": True,
            })
        db.rollback()
        return JSONResponse(
            {"error": "Previously generated Analysis Report is no longer available."},
            status_code=410)

    # Dollar redemption (A1): reserve under the lock, generate outside
    # the admission transaction, settle store+complete in one commit.
    entitlement = pb.live_entitlement(db, user.id, rid, "investigation_report")
    if entitlement is None or entitlement.status != "available":
        db.rollback()
        return JSONResponse(
            {"error": "Investigation Report costs $9. Payment is captured at checkout; "
                      "if generation fails your purchase is never consumed and you can retry.",
             "checkout_url": f"/reports/{rid}/investigation-checkout",
             "purchase_url": f"/reports/{rid}/investigation-checkout",
             "price_cents": 900},
            status_code=402)
    worker_id = f"deep-dive-{_uuid.uuid4().hex[:8]}"
    try:
        redemption = pb.reserve_redemption(
            db, entitlement, request_hash=request_hash, worker_id=worker_id)
        db.commit()
    except pb.DeadlineLapsed:
        db.commit()  # the refund_eligible transition is the record
        return JSONResponse(
            {"error": "The redemption window for this purchase has lapsed. "
                      "It is refund-eligible: contact disputes@goodfolkdigital.com.",
             "refund_eligible": True},
            status_code=410)
    except credits_helpers.AdmissionError as e:
        db.rollback()
        return JSONResponse({"error": str(e)}, status_code=409)

    def _release(failure_code, exc=None):
        import logging as _logging
        if exc is not None:
            _logging.getLogger(__name__).exception(
                "Analysis Report failed (%s)", failure_code,
                exc_info=(type(exc), exc, exc.__traceback__))
        try:
            pb.release_redemption(db, redemption.id, worker_id, str(failure_code)[:50])
            db.commit()
        except Exception:
            db.rollback()

    try:
        artifact_data = dd.build_deep_dive(
            payload, source_result_id=rid,
            source_integrity_digest=source.integrity_digest)
    except Exception as e:
        _release("generation_failed", e)
        return JSONResponse(
            {"error": "Analysis Report generation failed"}, status_code=500)

    try:
        artifact = credits_helpers.store_product_result(
            db, user.id, redemption.id, artifact_data, result_type="deep_dive",
            severity=source.severity if source.severity is not None
            else "__default__", retention_days=90)
        pb.complete_redemption(
            db, redemption.id, worker_id, result_id=artifact.id,
            lease_generation=redemption.lease_generation)
        db.commit()
    except Exception as e:
        db.rollback()
        _release("storage_failed", e)
        return JSONResponse(
            {"error": "Failed to store Analysis Report"}, status_code=500)

    return JSONResponse({
        "status": "completed",
        "analysis_result_id": str(artifact.id),
        "report_url": f"/reports/{artifact.id}",
        "price_cents": 900,
    })


# ---------------------------------------------------------------------------
# Issue #163: branding routes — POST set, POST clear, GET logo.
#
# Included with the paid Analysis Report: these routes create NO
# Operation, Consent or CreditLedger rows, never touch the deep-dive
# canonical identity/digest, and never change the #129 unlock state.
# Branding text/bytes are never logged.
# ---------------------------------------------------------------------------

def _branding_target_under_lock(db, user, result_id: str):
    """Lock (global:paid, the same scope cleanup uses — A2) and
    re-read the branding target Result under the lock.

    Returns (result, None) or (None, error_response). Semantics mirror
    the deep-dive route, with the A2/A8(g) re-check under the lock:
    unknown/non-owner -> 404; non-deep_dive -> 422; expired OR
    soft-deleted -> 410 (an upload committing after cleanup selected
    the report must not resurrect branding on it).
    """
    import uuid as _uuid
    from fastapi.responses import JSONResponse
    from sqlalchemy import select as _select
    from app import credits as credits_helpers
    from app import models
    from datetime import datetime, timezone
    try:
        rid = _uuid.UUID(result_id)
    except ValueError:
        return None, JSONResponse(
            {"error": "Invalid report ID"}, status_code=400)
    credits_helpers.lock_global_paid_scope(db)
    found = db.query(models.Result).filter(
        models.Result.id == rid,
        models.Result.user_id == user.id,
    ).first()
    if not found:
        db.rollback()
        return None, JSONResponse(
            {"error": "Report not found"}, status_code=404)
    result = db.execute(
        _select(models.Result).where(models.Result.id == found.id)
        .with_for_update().execution_options(populate_existing=True)
    ).scalar_one()
    if result.deleted_at is not None or \
            credits_helpers._as_aware(result.expires_at) <= \
            datetime.now(timezone.utc):
        db.rollback()
        return None, JSONResponse(
            {"error": "Report has expired"}, status_code=410)
    if result.type != "deep_dive":
        db.rollback()
        return None, JSONResponse(
            {"error": "Branding is only available for Analysis Reports"},
            status_code=422)
    return result, None


@app.post("/reports/{result_id}/branding")
async def report_branding_set(request: Request, result_id: str,
                              db=Depends(get_db)):
    """Set/replace the branding on an owned paid Analysis Report."""
    from fastapi.responses import JSONResponse
    from app import auth as auth_helpers
    from app import branding as branding_mod
    from app import models

    session = auth_helpers.get_session_from_cookie(db, request)
    if not session:
        return JSONResponse({"error": "Login required"}, status_code=401)
    user = session.user
    form, err = await _check_owner_csrf(request, session, db)
    if err is not None:
        return err

    # A8(b): exactly one file part, named "logo"; any other file part
    # is a 400. Text fields are byte-capped raw before trim/length.
    # NOTE: form parts are Starlette UploadFile instances; FastAPI's
    # UploadFile is a SUBCLASS of it, so the isinstance check must use
    # the Starlette base class or every upload is silently missed.
    from starlette.datastructures import UploadFile as _StarletteUploadFile
    file_parts = [(key, value) for key, value in form.multi_items()
                  if isinstance(value, _StarletteUploadFile)]
    if len(file_parts) > 1 or any(key != "logo" for key, _ in file_parts):
        return JSONResponse(
            {"error": "Submit exactly one logo file."}, status_code=400)
    raw_fields = {}
    for field in ("business_name", "client_name", "report_title", "accent"):
        value = form.get(field)
        if value is not None and not isinstance(value, str):
            return JSONResponse(
                {"error": "Branding fields must be plain text."},
                status_code=400)
        if isinstance(value, str) and len(
                value.encode("utf-8", "surrogatepass")) > \
                branding_mod.MAX_TEXT_FIELD_BYTES:
            return JSONResponse(
                {"error": "A branding field is too long."},
                status_code=400)
        raw_fields[field] = value

    # A8(a): bounded chunked read of the logo part — abort past
    # 512 KiB. No file part OR a 0-byte file part = keep existing logo.
    logo_data = None
    if file_parts:
        upload = file_parts[0][1]
        if upload.filename:
            buffer = bytearray()
            while True:
                chunk = await upload.read(64 * 1024)
                if not chunk:
                    break
                buffer.extend(chunk)
                if len(buffer) > branding_mod.MAX_LOGO_BYTES:
                    return JSONResponse(
                        {"error": "Logo is too large. Logos are at "
                                  "most 512 KB."},
                        status_code=400)
            if buffer:
                logo_data = bytes(buffer)
    remove_logo = str(form.get("remove_logo") or "").lower() in (
        "1", "true", "on", "yes")

    # A8(c) ATOMICITY: ALL validation (text + logo, A1 full decode +
    # canonical re-encode) completes before any write, and before the
    # lock — an invalid replacement rejects the WHOLE update and the
    # prior row stays byte-for-byte untouched.
    try:
        business_name = branding_mod.clean_text_field(
            raw_fields["business_name"], label="Business name",
            max_chars=branding_mod.BUSINESS_NAME_MAX)
        client_name = branding_mod.clean_text_field(
            raw_fields["client_name"], label="Client name",
            max_chars=branding_mod.CLIENT_NAME_MAX)
        report_title = branding_mod.clean_text_field(
            raw_fields["report_title"], label="Report title",
            max_chars=branding_mod.REPORT_TITLE_MAX)
        accent = branding_mod.validate_accent(raw_fields["accent"])
        canonical_logo = None
        if logo_data is not None:
            canonical_logo = branding_mod.validate_and_canonicalize_logo(
                logo_data)
    except branding_mod.BrandingError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)

    # A2/A8(g): serialize with cleanup on global:paid and re-read the
    # Result under the lock immediately before commit.
    result, err = _branding_target_under_lock(db, user, result_id)
    if err is not None:
        return err
    row = _branding_row_for(db, result.id)
    if row is None:
        row = models.ReportBranding(result_id=result.id)
        db.add(row)
    row.business_name = business_name
    row.client_name = client_name
    row.report_title = report_title
    row.accent = accent
    if remove_logo:
        row.logo_bytes = None
        row.logo_media_type = None
        row.logo_sha256 = None
        row.logo_width = None
        row.logo_height = None
    elif canonical_logo is not None:
        stored, media_type, width, height = canonical_logo
        row.logo_bytes = stored
        row.logo_media_type = media_type
        row.logo_sha256 = branding_mod.logo_sha256(stored)
        row.logo_width = width
        row.logo_height = height
    # else: no/empty file part — keep the existing logo untouched.
    row.updated_at = _utcnow_for_branding()
    db.commit()
    return JSONResponse({
        "status": "branding_updated", "result_id": str(result.id)})


def _utcnow_for_branding():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc)


@app.post("/reports/{result_id}/branding/clear")
async def report_branding_clear(request: Request, result_id: str,
                                db=Depends(get_db)):
    """Clear branding (A8(e)): nulls all fields but RETAINS the row
    with a bumped updated_at — the cleared-state row is what makes
    A3's replay rule survive a clear. Only lifecycle cleanup (A2)
    deletes the row."""
    from fastapi.responses import JSONResponse
    from app import auth as auth_helpers
    from app import models

    session = auth_helpers.get_session_from_cookie(db, request)
    if not session:
        return JSONResponse({"error": "Login required"}, status_code=401)
    user = session.user
    form, err = await _check_owner_csrf(request, session, db)
    if err is not None:
        return err
    result, err = _branding_target_under_lock(db, user, result_id)
    if err is not None:
        return err
    row = _branding_row_for(db, result.id)
    if row is None:
        row = models.ReportBranding(result_id=result.id)
        db.add(row)
    row.business_name = None
    row.client_name = None
    row.report_title = None
    row.accent = None
    row.logo_bytes = None
    row.logo_media_type = None
    row.logo_sha256 = None
    row.logo_width = None
    row.logo_height = None
    row.updated_at = _utcnow_for_branding()
    db.commit()
    return JSONResponse({
        "status": "branding_cleared", "result_id": str(result.id)})


@app.get("/reports/{result_id}/branding/logo")
async def report_branding_logo(request: Request, result_id: str,
                               db=Depends(get_db)):
    """Serve the stored logo for the OWNER only.

    Content-Type comes from the stored validated type, with nosniff
    and private no-store. Non-owner/unknown -> 404; anonymous -> 401.
    Expiry/deleted state is re-checked at read time (A2). Nothing
    about the bytes is logged.
    """
    import uuid as _uuid
    from fastapi.responses import JSONResponse, Response
    from app import auth as auth_helpers
    from app import credits as credits_helpers
    from datetime import datetime, timezone

    session = auth_helpers.get_session_from_cookie(db, request)
    if not session:
        return JSONResponse({"error": "Login required"}, status_code=401)
    user = session.user
    try:
        rid = _uuid.UUID(result_id)
    except ValueError:
        return JSONResponse({"error": "Report not found"}, status_code=404)
    from app import models
    result = db.query(models.Result).filter(
        models.Result.id == rid,
        models.Result.user_id == user.id,
    ).first()
    if not result:
        return JSONResponse({"error": "Report not found"}, status_code=404)
    # A8 lifecycle contract (Codex P2 on PR #169): an OWNED target that
    # is expired OR soft-deleted answers 410 on logo-read too, matching
    # set/clear — cleanup_results() setting deleted_at must not change
    # the owner's answer from 410 to 404. Unknown/non-owner stays 404.
    if result.deleted_at is not None or \
            credits_helpers._as_aware(result.expires_at) <= \
            datetime.now(timezone.utc):
        return JSONResponse({"error": "Report has expired"}, status_code=410)
    row = _branding_row_for(db, result.id)
    if row is None or not row.logo_bytes:
        return JSONResponse({"error": "No logo stored"}, status_code=404)
    return Response(
        content=row.logo_bytes,
        media_type=row.logo_media_type or "application/octet-stream",
        headers={
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "private, no-store",
        },
    )


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

    # Issue #164 Phase B (B-13): product-paid artifacts already carry
    # 90-day retention and are never sold an extension — server
    # refusal is the contract (no ReportAction row, no charge).
    if credits_helpers.is_product_paid_result(db, source):
        db.rollback()
        return JSONResponse(
            {"error": "Paid reports include 90-day retention and can't be extended"},
            status_code=409)

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

    # Issue #164 Phase C (Decision 5 / C5): retention extensions are
    # no longer sold. This refusal sits AFTER the ReportAction replay
    # fence above, so a completed pre-cutover extension still returns
    # its recorded replay response; every NEW admission refuses
    # honestly — no charge, no date change. Expiries already in force
    # keep running to their recorded dates.
    db.rollback()
    return JSONResponse(
        {"error": "Retention extensions are no longer sold; paid "
                  "reports include 90 days of retention."},
        status_code=410)

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
                         request_hash, share_format=None):
    """Return (prior_action, error_response) for a free share action.

    PR #138 remediation (finding 4): a stored hash also matches when
    it is the pre-#135 legacy representation and the current action's
    format carries the legacy txt semantics — see
    report_access.action_hash_matches for the exact scheme."""
    from fastapi.responses import JSONResponse
    from sqlalchemy import select as _select
    from app import models
    from app import report_access as _ra
    prior = db.execute(
        _select(models.ReportAction).where(
            models.ReportAction.owner_user_id == user.id,
            models.ReportAction.result_id == source.id,
            models.ReportAction.action_kind == action_kind,
            models.ReportAction.idempotency_key == idempotency_key,
        )
    ).scalar_one_or_none()
    if prior is not None and not _ra.action_hash_matches(
            prior.request_hash, source, action_kind, request_hash,
            share_format=share_format):
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


def _find_sharing(db, source_id, share_format):
    """The sharing row for (report, format) — #135: one per format."""
    from sqlalchemy import select as _select
    from app import models
    from app import report_access as _ra
    rows = db.execute(
        _select(models.ReportSharing).where(
            models.ReportSharing.result_id == source_id)
    ).scalars().all()
    for row in rows:
        if _ra.share_format_of(row) == share_format:
            return row
    return None


def _active_sharings(db, source_id):
    from sqlalchemy import select as _select
    from app import models
    return [row for row in db.execute(
        _select(models.ReportSharing).where(
            models.ReportSharing.result_id == source_id)
    ).scalars().all()
        if row.token_hash and row.revoked_at is None]


@app.post("/reports/{result_id}/share")
async def report_share_create(request: Request, result_id: str, db=Depends(get_db)):
    """Create a share link for ONE format — FREE (trim T1).

    Issue #135: the popup's format choice (pdf/txt/json/csv; missing
    defaults to txt) is bound into the link. TXT is always free.
    pdf/json/csv require the report's #129 export unlock: pre-unlock
    creation is refused 402 (no charge, no link, no action row beyond
    the rate/replay bookkeeping below) — the unlock itself is bought
    through the export routes, never through sharing. Post-unlock
    creation charges nothing beyond that unlock."""
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
    share_format = _ra.normalize_share_format(
        form.get("format") or form.get("share_format"))
    if share_format is None:
        return JSONResponse(
            {"error": "Share format must be one of PDF, TXT, JSON, CSV."},
            status_code=400)
    request_hash = _ra.action_request_hash(
        source, "share_create", share_format=share_format)
    # Finding 2: lock the share:actions bucket BEFORE the replay
    # lookup and hold it through settlement, so the lookup below is
    # authoritative under the lock (concurrent same-key requests
    # serialize; replays never consume rate and never 429/500).
    credits_helpers.lock_share_rate_bucket(db, str(user.id))
    prior, err = _share_action_replay(
        db, user, source, "share_create", idempotency_key, request_hash,
        share_format=share_format)
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
    # Issue #164 Phase C (Decision 4 / C2): the #135 format gate is
    # REMOVED. Exports are free for all reports, so pdf/json/csv share
    # links are created on the link's own authority — no unlock
    # consult, no 402. Format eligibility itself is unchanged
    # (single-file payloads only; batch/comparison/deep_dive stay
    # excluded in report_access).
    try:
        credits_helpers._consume_rate(db, "share:actions", str(user.id))
    except credits_helpers.AdmissionError:
        db.rollback()
        return JSONResponse(
            {"error": "Too many share actions. Please try again later."},
            status_code=429)
    sharing = _find_sharing(db, source.id, share_format)
    if sharing is not None:
        sharing = db.execute(
            _select(models.ReportSharing).where(
                models.ReportSharing.id == sharing.id)
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
            "message": "This report already has a share link for that "
                       "format. Rotate the link to get a new copyable URL.",
            "format": share_format,
        })
    raw_token = auth_helpers.generate_token()
    if sharing is None:
        sharing = models.ReportSharing(
            result_id=source.id, owner_user_id=user.id,
            token_hash=auth_helpers.hash_token(raw_token), generation=1,
            share_format=share_format, raw_token=raw_token,
        )
        db.add(sharing)
    else:
        sharing.token_hash = auth_helpers.hash_token(raw_token)
        sharing.raw_token = raw_token
        sharing.share_format = share_format
        sharing.generation += 1
        sharing.revoked_at = None
    db.flush()
    _record_share_action(db, user, source, "share_create", idempotency_key,
                         request_hash, sharing.generation)
    db.commit()
    return JSONResponse({
        "status": "created",
        "share_url": _share_url(request, raw_token),
        "format": share_format,
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
    # Issue #135: rotate targets ONE format's link. An explicit format
    # names it; without one, the report's sole active link (or its txt
    # link) is the unambiguous target.
    _rotate_fmt_raw = form.get("format") or form.get("share_format")
    _rotate_fmt = _ra.normalize_share_format(_rotate_fmt_raw) \
        if _rotate_fmt_raw else None
    if _rotate_fmt_raw and _rotate_fmt is None:
        return JSONResponse(
            {"error": "Share format must be one of PDF, TXT, JSON, CSV."},
            status_code=400)
    request_hash = _ra.action_request_hash(
        source, "share_rotate", share_format=_rotate_fmt)
    # Finding 2: lock before the authoritative replay lookup (see
    # report_share_create).
    credits_helpers.lock_share_rate_bucket(db, str(user.id))
    prior, err = _share_action_replay(
        db, user, source, "share_rotate", idempotency_key, request_hash,
        share_format=_rotate_fmt)
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
    if _rotate_fmt is not None:
        sharing = _find_sharing(db, source.id, _rotate_fmt)
    else:
        # No format named: a single row (active OR revoked — rotate is
        # the reshare-after-revoke recovery) is unambiguous; with
        # several rows prefer the sole active one, then the txt one.
        _all_rows = db.execute(
            _select(models.ReportSharing).where(
                models.ReportSharing.result_id == source.id)
        ).scalars().all()
        actives = [row for row in _all_rows
                   if row.token_hash and row.revoked_at is None]
        sharing = None
        if len(_all_rows) == 1:
            sharing = _all_rows[0]
        elif len(actives) == 1:
            sharing = actives[0]
        elif _all_rows:
            sharing = next(
                (row for row in _all_rows
                 if _ra.share_format_of(row) == "txt"), None)
            if sharing is None:
                db.rollback()
                return JSONResponse(
                    {"error": "Specify which format's link to rotate."},
                    status_code=409)
    if sharing is not None:
        sharing = db.execute(
            _select(models.ReportSharing).where(
                models.ReportSharing.id == sharing.id)
            .with_for_update().execution_options(populate_existing=True)
        ).scalar_one_or_none()
    if sharing is None:
        db.commit()
        return JSONResponse(
            {"error": "This report has no share link to rotate"},
            status_code=409)
    raw_token = auth_helpers.generate_token()
    sharing.token_hash = auth_helpers.hash_token(raw_token)
    sharing.raw_token = raw_token
    sharing.generation += 1
    sharing.revoked_at = None
    db.flush()
    _record_share_action(db, user, source, "share_rotate", idempotency_key,
                         request_hash, sharing.generation)
    db.commit()
    return JSONResponse({
        "status": "rotated",
        "share_url": _share_url(request, raw_token),
        "format": _ra.share_format_of(sharing),
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
    # Issue #135: an explicit format revokes only that format's link;
    # without one, revoke kills EVERY active link for the report
    # (the pre-#135 single-link behaviour, and the safe default).
    _revoke_fmt_raw = form.get("format") or form.get("share_format")
    _revoke_fmt = _ra.normalize_share_format(_revoke_fmt_raw) \
        if _revoke_fmt_raw else None
    if _revoke_fmt_raw and _revoke_fmt is None:
        return JSONResponse(
            {"error": "Share format must be one of PDF, TXT, JSON, CSV."},
            status_code=400)
    request_hash = _ra.action_request_hash(
        source, "share_revoke", share_format=_revoke_fmt)
    # Finding 2: lock before the authoritative replay lookup (see
    # report_share_create).
    credits_helpers.lock_share_rate_bucket(db, str(user.id))
    prior, err = _share_action_replay(
        db, user, source, "share_revoke", idempotency_key, request_hash,
        share_format=_revoke_fmt)
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
    if _revoke_fmt is not None:
        _targets = []
        _row = _find_sharing(db, source.id, _revoke_fmt)
        if _row is not None:
            _targets = [_row]
    else:
        _targets = db.execute(
            _select(models.ReportSharing).where(
                models.ReportSharing.result_id == source.id)
        ).scalars().all()
    generation = 0
    for sharing in _targets:
        sharing = db.execute(
            _select(models.ReportSharing).where(
                models.ReportSharing.id == sharing.id)
            .with_for_update().execution_options(populate_existing=True)
        ).scalar_one_or_none()
        if sharing is None:
            continue
        if sharing.token_hash is not None or sharing.revoked_at is None:
            sharing.token_hash = None
            sharing.raw_token = None
            sharing.revoked_at = credits_helpers._utcnow()
            sharing.generation += 1
        generation = max(generation, sharing.generation)
    db.flush()
    _record_share_action(db, user, source, "share_revoke", idempotency_key,
                         request_hash, generation)
    db.commit()
    return JSONResponse({"status": "revoked"})


@app.post("/settings/report-access/{sharing_id}/revoke")
async def settings_report_access_revoke(request: Request, sharing_id: str,
                                        db=Depends(get_db)):
    """Revoke ONE share link from Settings -> Report Access (#135).

    Owner-only (session + CSRF), FREE, immediate: the row's token hash
    and raw token are cleared in this commit, so the very next public
    request for that token gets the identical unavailable response.
    Other formats' links for the same report are untouched."""
    import uuid as _uuid
    from fastapi.responses import JSONResponse
    from sqlalchemy import select as _select
    from app import auth as auth_helpers
    from app import credits as credits_helpers
    from app import models
    from app import report_access as _ra

    session = auth_helpers.get_session_from_cookie(db, request)
    if not session:
        return JSONResponse({"error": "Login required"}, status_code=401)
    user = session.user
    form, err = await _check_owner_csrf(request, session, db)
    if err is not None:
        return err
    try:
        sid = _uuid.UUID(sharing_id)
    except ValueError:
        return JSONResponse({"error": "Invalid link ID"}, status_code=400)
    # PR #138 remediation (finding 3): lock ORDER — acquire the
    # share rate bucket BEFORE locking the sharing row, exactly as
    # create/rotate/report-revoke do. Locking the row first inverted
    # that order and could deadlock on PostgreSQL against a
    # concurrent share action, aborting this revoke and leaving the
    # bearer token live.
    credits_helpers.lock_share_rate_bucket(db, str(user.id))
    sharing = db.execute(
        _select(models.ReportSharing).where(
            models.ReportSharing.id == sid,
            models.ReportSharing.owner_user_id == user.id)
        .with_for_update().execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if sharing is None:
        db.rollback()
        return JSONResponse({"error": "Share link not found"}, status_code=404)
    source = db.get(models.Result, sharing.result_id)
    if source is None:
        db.rollback()
        return JSONResponse({"error": "Share link not found"}, status_code=404)
    idempotency_key = str(form.get("idempotency_key") or _uuid.uuid4().hex)
    request_hash = _ra.action_request_hash(
        source, "share_revoke",
        share_format=_ra.share_format_of(sharing))
    prior, err = _share_action_replay(
        db, user, source, "share_revoke", idempotency_key, request_hash,
        share_format=_ra.share_format_of(sharing))
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
    if sharing.token_hash is not None or sharing.revoked_at is None:
        sharing.token_hash = None
        sharing.raw_token = None
        sharing.revoked_at = credits_helpers._utcnow()
        sharing.generation += 1
    db.flush()
    _record_share_action(db, user, source, "share_revoke", idempotency_key,
                         request_hash, sharing.generation)
    db.commit()
    return JSONResponse({"status": "revoked"})


def _share_file_response(db, token, sharing, result, payload, share_format):
    """Serve a shared report IN the link's format only (#135).

    Returns a Response, or None for the caller to render the identical
    unavailable 404. Content is generated from the validated source
    payload with the same generators the owner's export routes use,
    so the shared file's content is the report's exact content:
    txt = render_text_report, csv/json = structured_export, pdf =
    the paid-PDF artifact when one exists, else on-the-fly generation
    for an export-unlocked report with no PDF operation (the #129 §5
    path the old /pdf subroute used). The share route never charges.
    """
    from fastapi.responses import Response
    from app import report_access as _ra
    filename = payload.get("filename", "report")
    if share_format == "txt":
        text = render_text_report(payload)
        db.expire_all()
        if _ra.lookup_shared(db, token) is None:
            return None
        headers = _share_headers({
            "Content-Disposition": f'attachment; filename="stacksift-report-{_safe_download_filename(str(filename))}.txt"',
        })
        return Response(content=text, media_type="text/plain; charset=utf-8",
                        headers=headers)
    if share_format in ("csv", "json"):
        from app import structured_export as _se
        try:
            data = _se.generate_export(payload, share_format)
        except Exception:
            return None
        db.expire_all()
        if _ra.lookup_shared(db, token) is None:
            return None
        headers = _share_headers({
            "Content-Disposition": f'attachment; filename="{_se.safe_download_name(filename, result.id, share_format)}"',
        })
        return Response(content=data,
                        media_type=_se.MEDIA_TYPES[share_format],
                        headers=headers)
    if share_format == "pdf":
        pdf = _ra.find_shareable_pdf(db, result)
        if pdf is None:
            # #129 §5 / #107 T6, as in the old subroute: on-the-fly
            # generation ONLY when no PDF was ever generated but the
            # report is export-unlocked; an expired generated PDF
            # keeps the identical-404 outcome.
            if _ra.has_pdf_export_operation(db, result) \
                    or not _ra.is_export_unlocked(db, result):
                return None
            from app.pdf_export import generate_report_pdf as _gen_share_pdf
            try:
                pdf_bytes = _gen_share_pdf(
                    result.storage_manifest, payload.get("filename", "report"))
            except Exception:
                return None
            db.expire_all()
            if _ra.lookup_shared(db, token) is None:
                return None
            headers = _share_headers({
                "Content-Disposition": f'attachment; filename="stacksift-report-{_safe_download_filename(str(filename))}.pdf"',
            })
            return Response(content=pdf_bytes, media_type="application/pdf",
                            headers=headers)
        _pdf_result, pdf_bytes = pdf
        db.expire_all()
        if _ra.lookup_shared(db, token) is None:
            return None
        headers = _share_headers({
            "Content-Disposition": f'attachment; filename="stacksift-report-{_safe_download_filename(str(filename))}.pdf"',
        })
        return Response(content=pdf_bytes, media_type="application/pdf",
                        headers=headers)
    return None


@app.get("/s/{token}")
async def shared_report_view(request: Request, token: str, db=Depends(get_db)):
    """Public shared report FILE (#135, replacing the #107 web view).

    Bearer capability, not a session: sets no cookies, loads no owner
    identity, mutates nothing. The link serves ONLY its own format;
    unknown/malformed/revoked/expired tokens get the one identical
    unavailable response."""
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
    response = _share_file_response(
        db, token, sharing, result, payload, _ra.share_format_of(sharing))
    if response is None:
        return _share_unavailable()
    return response


@app.get("/s/{token}/pdf")
async def shared_report_pdf(request: Request, token: str, db=Depends(get_db)):
    """Legacy PDF subroute (#107 T3), kept under #135 ONLY for links
    whose own format is PDF: a pdf-format link serves the PDF here
    exactly as at /s/{token}; every other link format — and every
    invalid token — gets the same identical 404, because a link
    serves ONLY its chosen format."""
    from app import report_access as _ra
    limited = _share_rate_limited(request)
    if limited is not None:
        return limited
    found = _ra.lookup_shared(db, token)
    if found is None:
        return _share_unavailable()
    sharing, result, payload = found
    if _ra.share_format_of(sharing) != "pdf":
        return _share_unavailable()
    response = _share_file_response(db, token, sharing, result, payload, "pdf")
    if response is None:
        return _share_unavailable()
    return response

