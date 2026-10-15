"""StackSift web — free log-file analyzer.

Thin slice: upload a log file, get an incident summary. No accounts or retained upload archive. Rate-limited free tier; auth + credits come later once usage proves
demand.

Phase 1: Accounts added — email/password auth, Google/GitHub OAuth, sessions.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.rate_limit import RateLimiter
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


app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")

# Phase 1: Auth routes (signup, login, OAuth, sessions, settings)
app.include_router(auth_router)

# Free tier: 10 analyses per hour per IP. Tune as usage data comes in.
limiter = RateLimiter(max_requests=10, window_seconds=3600)
burst_limiter = RateLimiter(max_requests=2, window_seconds=60)


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




@app.get("/pricing", response_class=HTMLResponse)
async def pricing(request: Request):
    _user, _csrf = _get_current_user_optional(request)
    return templates.TemplateResponse(
        request, "pricing.html", {"current_user": _user, "csrf_token": _csrf}
    )


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    _user, _csrf = _get_current_user_optional(request)
    return templates.TemplateResponse(
        request, "index.html", {"error": None, "remaining": limiter.remaining(_client_ip(request)), "current_user": _user, "csrf_token": _csrf}
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
    file: UploadFile = File(...),
    output: str = Form("html"),
):
    ip = _client_ip(request)

    def error(message: str, status: int = 400, headers: dict = None):
        _user, _csrf = _get_current_user_optional(request)
        return templates.TemplateResponse(
            request,
            "index.html",
            {"error": message, "remaining": limiter.remaining(ip), "current_user": _user, "csrf_token": _csrf},
            status_code=status,
            headers=headers or {},
        )

    if not file.filename:
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
    return os.path.join(_PAID_PENDING_DIR, f"pending-{file_hash}.bin")


def _store_paid_pending(file_hash: str, filename: str, content: bytes) -> None:
    path = _paid_pending_path(file_hash)
    with open(path, "wb") as f:
        f.write(filename.encode("utf-8") + b"\n")
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
        filename = raw[:nl].decode("utf-8")
        content = raw[nl + 1:]
        return filename, content
    except (OSError, ValueError):
        return None


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

    file_hash = hashlib.sha256(content).hexdigest()
    db = SessionLocal()
    try:
        # Check eligible credits
        summary = credits_helpers.get_balance_summary(db, user.id)
        if summary["eligible"] < 1:
            raise RuntimeError("insufficient credits")
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
    _store_paid_pending(file_hash, filename, content)

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


@app.post("/analyze/paid", response_class=HTMLResponse)
async def analyze_paid(
    request: Request,
    consent_id: str = Form(...),
    file_hash: str = Form(...),
    idempotency_key: str = Form(...),
    csrf_token: str = Form(""),
):
    """Execute a paid additional analysis (1 credit) with explicit consent.

    Free-first: re-checks free quota inside the admission transaction (T27).
    """
    from app.db import SessionLocal
    from app import credits as credits_helpers
    from app import auth as auth_helpers

    def error(message: str, status: int = 400):
        _user, _csrf = _get_current_user_optional(request)
        return templates.TemplateResponse(
            request, "index.html",
            {"error": message, "remaining": limiter.remaining(_client_ip(request)),
             "current_user": _user, "csrf_token": _csrf},
            status_code=status,
        )

    # Authenticate
    db = SessionLocal()
    try:
        session = auth_helpers.get_session_from_cookie(db, request)
        if not session:
            return error("Please log in to use Power-Up credits.", status=401)
        user = session.user
        # CSRF check
        if not csrf_token or csrf_token != session.csrf_token:
            return error("Invalid request. Please try again.", status=403)
    finally:
        db.close()

    # Retrieve pending file
    pending = _load_paid_pending(file_hash)
    if not pending:
        return error("Your analysis request expired. Please upload the file again.")
    filename, content = pending

    ip = _client_ip(request)

    # T27: re-check free quota BEFORE paid admission. If free is available now,
    # use it instead of charging (free-first).
    burst_ok = burst_limiter.check(ip)
    hourly_ok = limiter.check(ip)
    if burst_ok and hourly_ok:
        burst_limiter.record(ip)
        limiter.record(ip)
        _delete_paid_pending(file_hash)
        data = analyze_upload(filename, content)
        if isinstance(data, dict) and "error" in data:
            return error(data.get("message", "Analysis failed."), status=400)
        _user, _csrf = _get_current_user_optional(request)
        data["current_user"] = _user
        data["csrf_token"] = _csrf
        data["was_free"] = True  # UI note: free quota became available
        return templates.TemplateResponse(request, "report.html", data)

    # Paid admission (atomic per v11.1 Section 4.2)
    db = SessionLocal()
    worker_id = f"web-{uuid_module.uuid4().hex[:8]}"
    try:
        try:
            consent_uuid = uuid_module.UUID(consent_id)
        except ValueError:
            return error("Invalid consent. Please try again.")

        operation = credits_helpers.admit_paid_operation(
            db=db,
            user_id=user.id,
            operation_type="additional_analysis",
            idempotency_key=idempotency_key,
            request_hash=file_hash,
            cost=credits_helpers.COST_ADDITIONAL_ANALYSIS,
            consent_id=consent_uuid,
            worker_id=worker_id,
        )
        db.commit()
        op_id = operation.id

        # Idempotent replay: if operation already completed, return stored result
        if operation.status == "completed" and operation.result_id:
            # TODO Phase 2B: retrieve stored result. For 2A, re-render is acceptable
            # since analysis is deterministic; no new charge was made (A11).
            pass

    except credits_helpers.InsufficientCredits:
        db.rollback()
        return error("Insufficient Power-Up credits. Please purchase more or wait for free quota.", status=402)
    except credits_helpers.AdmissionError as e:
        db.rollback()
        # Idempotency conflict returns 409
        if "different input" in str(e):
            return error("This request conflicts with a previous one. Please start over.", status=409)
        return error(f"Could not start paid analysis: {e}", status=429)
    except Exception:
        db.rollback()
        return error("Could not start paid analysis. Please try again.", status=500)

    # Execute analysis (outside the admission transaction)
    try:
        data = analyze_upload(filename, content)
        if isinstance(data, dict) and "error" in data:
            # Analysis failed: RELEASE the reservation (refund)
            db2 = SessionLocal()
            try:
                credits_helpers.release_operation(db2, op_id, worker_id, "analysis_failed")
                db2.commit()
            finally:
                db2.close()
            return error(data.get("message", "Analysis failed."), status=400)

        # COMPLETE the operation
        db2 = SessionLocal()
        try:
            credits_helpers.complete_operation(db2, op_id, worker_id)
            db2.commit()
        finally:
            db2.close()

        _delete_paid_pending(file_hash)
        _user, _csrf = _get_current_user_optional(request)
        data["current_user"] = _user
        data["csrf_token"] = _csrf
        data["paid_credits_used"] = 1
        return templates.TemplateResponse(request, "report.html", data)

    except Exception:
        # Ensure release on unexpected failure
        try:
            db2 = SessionLocal()
            try:
                credits_helpers.release_operation(db2, op_id, worker_id, "worker_crash")
                db2.commit()
            finally:
                db2.close()
        except Exception:
            pass
        return error("Analysis failed unexpectedly. Your credit was refunded.", status=500)


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
