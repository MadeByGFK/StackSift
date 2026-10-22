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
from app.service import analyze_upload, render_text_report

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




@app.get("/credits", response_class=HTMLResponse)
async def credits(request: Request):
    from app import auth as auth_helpers

    _user, _csrf = _get_current_user_optional(request)
    set_cookie_token = None
    if not _user:
        # Anonymous visitors need a CSRF token for the notify-me form
        # (issue #67). Mirrors the cookie pattern in auth_routes._render.
        _csrf = request.cookies.get(auth_helpers.CSRF_COOKIE) or auth_helpers.generate_token()
        if auth_helpers.CSRF_COOKIE not in request.cookies:
            set_cookie_token = _csrf
    response = templates.TemplateResponse(
        request, "pricing.html", {"current_user": _user, "csrf_token": _csrf}
    )
    if set_cookie_token:
        response.set_cookie(
            auth_helpers.CSRF_COOKIE, set_cookie_token,
            secure=True, httponly=True, samesite="lax", path="/",
        )
    return response


@app.get("/pricing", include_in_schema=False)
async def pricing_redirect():
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/credits", status_code=301)


# ISSUE-67 notify-me bridge: REMOVE this endpoint when checkout ships (#68).
# The collected addresses get exactly one launch email at that point; counts
# from notify_signups are intent only, never demand evidence (GFK-013 §5.12).
@app.post("/credits/notify")
async def credits_notify(
    request: Request,
    email: str = Form(...),
    csrf_token: str = Form(""),
    db=Depends(get_db),
):
    import hmac
    from fastapi import HTTPException
    from fastapi.responses import JSONResponse
    from sqlalchemy.exc import IntegrityError
    from app import auth as auth_helpers
    from app.models import NotifySignup

    # CSRF: mirrors auth_routes.require_csrf — session token when logged in,
    # CSRF cookie for anonymous visitors.
    session = auth_helpers.get_session_from_cookie(db, request)
    expected = session.csrf_token if session else request.cookies.get(auth_helpers.CSRF_COOKIE)
    if not expected or not isinstance(csrf_token, str) or not hmac.compare_digest(csrf_token, expected):
        raise HTTPException(403, "Invalid CSRF token. Reload the page and try again.")

    ip = _client_ip(request)
    auth_helpers.check_rate_limit("notify", ip)

    email_norm = auth_helpers.normalize_email(email)
    if len(email_norm) > 255 or email_norm.count("@") != 1 or any(c.isspace() for c in email_norm) or not all(email_norm.split("@")):
        return JSONResponse({"error": "Enter a valid email address."}, status_code=400)

    existing = db.query(NotifySignup).filter(NotifySignup.email == email_norm).first()
    if not existing:
        try:
            db.add(NotifySignup(email=email_norm, source="credits"))
            db.commit()
        except IntegrityError:
            # Race: another request captured this address first. Roll back and
            # treat as success — the address is on the list either way.
            db.rollback()
    return JSONResponse({"message": "You're on the list — we'll email you once when credit purchases open."})

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

    content = await file.read()
    if not content.strip():
        return error("That file is empty — nothing to analyze.")
    if len(content) > MAX_BYTES:
        return error("That file is over the 10 MB free-tier limit.")

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
_PAID_PENDING_DIR = os.environ.get("STACKSIFT_PAID_TMP", tempfile.gettempdir() + "/stacksift-paid")
_PAID_PENDING_TTL = 900  # 15 minutes


def _paid_pending_path(file_hash: str) -> str:
    os.makedirs(_PAID_PENDING_DIR, exist_ok=True)
    # Only server-generated consent IDs may select a file; filenames/digests cannot.
    token = uuid_module.UUID(file_hash).hex
    return os.path.join(_PAID_PENDING_DIR, f"pending-{token}.bin")


def _store_paid_pending(file_hash: str, filename: str, content: bytes) -> None:
    path = _paid_pending_path(file_hash)
    cleanup_pending_uploads()
    if sum(p.stat().st_size for p in Path(_PAID_PENDING_DIR).glob("pending-*.bin")) + len(content) > 64*1024*1024:
        raise RuntimeError("Pending upload capacity exhausted")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(json.dumps(filename).encode("utf-8") + b"\n")
        f.write(content)


def _load_paid_pending(file_hash: str) -> tuple[str, bytes] | None:
    path = _paid_pending_path(file_hash)
    try:
        stat = os.stat(path)
        age = datetime.now(timezone.utc).timestamp() - stat.st_mtime
        if age > _PAID_PENDING_TTL:
            os.unlink(path)
            return None
        with open(path, "rb") as f:
            raw = f.read()
        nl = raw.index(b"\n")
        filename = json.loads(raw[:nl].decode("utf-8"))
        content = raw[nl + 1:]
        return filename, content
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


def _delete_paid_pending(file_hash: str) -> None:
    try:
        os.unlink(_paid_pending_path(file_hash))
    except OSError:
        pass


def _paid_consent_page(request: Request, filename: str, content: bytes, user, csrf_token: str, ip: str):
    """Return a consent page offering 1-credit paid analysis. Raises on no DB."""
    import os as _os
    if not _os.environ.get("DATABASE_URL"):
        raise RuntimeError("no database")
    from app.db import SessionLocal
    from app import credits as credits_helpers

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
    except Exception:
        # GFD Finding 2: Fail closed. Never persist unredacted content.
        # If redaction fails, abort rather than writing raw logs to disk.
        from fastapi.responses import HTMLResponse
        return HTMLResponse(
            content="<h1>Upload processing error</h1><p>Could not securely process your file. Please try again.</p>",
            status_code=500,
        )
    file_hash = fingerprint(filename, content)
    db = SessionLocal()
    try:
        # Check eligible credits
        summary = credits_helpers.get_balance_summary(db, user.id)
        if summary["eligible"] < 1:
            # BR-01: raise the domain exception so _durable_analysis returns
            # HTTP 402 (credit limit), not a generic 503.
            raise credits_helpers.InsufficientCredits("insufficient credits")
        # Create server-bound consent
        consent = credits_helpers.create_consent(
            db, user.id, "additional_analysis", file_hash,
            credits_helpers.COST_ADDITIONAL_ANALYSIS,
        )
        db.commit()
        consent_id = str(consent.id)
    finally:
        db.close()

    # Store file for the paid endpoint (deleted after use)
    _store_paid_pending(consent_id, filename, content)

    return templates.TemplateResponse(
        request,
        "paid_consent.html",
        {
            "current_user": user,
            "csrf_token": csrf_token,
            "filename": filename,
            "file_hash": file_hash,
            "consent_id": consent_id,
            "cost": 1,
            "balance": summary["balance"],
            "eligible": summary["eligible"],
        },
        status_code=402,  # Payment Required
    )


def _analysis_response(request, status, data=None, message=None, *, output="html", filename="analysis.log", report_id=None):
    user, csrf = _get_current_user_optional(request)
    if data is None:
        return templates.TemplateResponse(request, "index.html", {
            "error": message, "remaining": limiter.remaining(_client_ip(request)),
            "current_user": user, "csrf_token": csrf}, status_code=status)
    if output == "txt":
        return PlainTextResponse(render_text_report(data), headers={
            "Content-Disposition": f'attachment; filename="{Path(filename).stem}-stacksift.txt"'})
    data = dict(data, current_user=user, csrf_token=csrf)
    if report_id is not None:
        data["report_id"] = report_id
    return templates.TemplateResponse(request, "report.html", data, status_code=status)


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
        try:
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
            return _analysis_response(request, 402, message="Insufficient Power-Up credits.")
        except C.AdmissionError as exc:
            db.rollback()
            return _analysis_response(request, 409 if '409' in str(exc) else 429, message=str(exc))
        except Exception:
            db.rollback()
            logging.getLogger(__name__).exception("Analysis admission failed")
            return _analysis_response(request, 503, message="Could not start analysis. Please retry this request.")
    result_id = None
    try:
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
    from app import auth
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
    return _durable_analysis(request, "", b"", idempotency_key, consent_id=consent_uuid, digest=file_hash)


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
    base_q = db.query(models.Result).filter(
        models.Result.user_id == _user.id,
        models.Result.type == "analysis",
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
    result = db.query(models.Result).filter(
        models.Result.id == rid,
        models.Result.user_id == _user.id,
        models.Result.type == "analysis",
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
    # Older manifests predate the elapsed field; the template requires it.
    data.setdefault("elapsed", 0.0)
    return templates.TemplateResponse(request, "report.html", data)


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

    result = db.query(models.Result).filter(
        models.Result.id == rid,
        models.Result.user_id == user.id,
        models.Result.type == "analysis",
        models.Result.deleted_at.is_(None),
    ).first()
    if not result:
        return JSONResponse({"error": "Report not found"}, status_code=404)
    if credits_helpers._as_aware(result.expires_at) < datetime.now(timezone.utc):
        return JSONResponse({"error": "Report has expired"}, status_code=410)

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
                        headers={"Content-Disposition": f'attachment; filename="stacksift-report-{filename}.pdf"'},
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
        return JSONResponse({"error": "Insufficient credits. PDF export costs 2 credits."}, status_code=402)
    except credits_helpers.AdmissionError as e:
        db.rollback()
        return JSONResponse({"error": str(e)}, status_code=409)

    from app.pdf_export import generate_report_pdf
    try:
        # Validate source analysis result integrity before generating PDF
        manifest_data = credits_helpers.result_payload(
            result, user_id=user.id,
            operation_id=result.operation_id,
            free_request_id=result.free_request_id,
        )
        filename = manifest_data.get("filename", "report")
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
        headers={"Content-Disposition": f'attachment; filename="stacksift-report-{filename}.pdf"'},
    )
