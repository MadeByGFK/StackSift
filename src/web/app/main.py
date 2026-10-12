"""StackSift web — free log-file analyzer.

Thin slice: upload a log file, get an incident summary. No accounts, no
storage. Rate-limited free tier; auth + credits come later once usage proves
demand.
"""

from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.rate_limit import RateLimiter
from app.sample_data import SAMPLE_FILENAME, SAMPLE_LOG
from app.service import analyze_upload, render_text_report

BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(title="StackSift", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")

logger = logging.getLogger("stacksift.diagnostic")

# Free tier: 10 analyses per hour per IP. Tune as usage data comes in.
limiter = RateLimiter(max_requests=10, window_seconds=3600)
burst_limiter = RateLimiter(max_requests=2, window_seconds=60)

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


def _client_ip(request: Request) -> str:
    """Proxy-aware client IP resolution for Railway."""
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        for part in forwarded.split(","):
            ip = part.strip()
            if ip and not ip.startswith(("10.", "192.168.", "127.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2")):
                try:
                    octets = ip.split(".")
                    if len(octets) == 4 and all(0 <= int(o) <= 255 for o in octets):
                        return ip
                except:
                    continue
    return request.client.host if request.client else "unknown"


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(
        request, "index.html", {"error": None, "remaining": limiter.remaining(_client_ip(request))}
    )


@app.get("/demo", response_class=HTMLResponse)
async def demo(request: Request):
    """One-click demo: analyze a canned incident log, no upload needed.

    Not rate-limited — the input is fixed and cheap to analyze, and this
    is the conversion path for new visitors.
    """
    data = analyze_upload(SAMPLE_FILENAME, SAMPLE_LOG.encode("utf-8"))
    data["is_demo"] = True
    return templates.TemplateResponse(request, "report.html", data)


@app.post("/analyze")
async def analyze(
    request: Request,
    file: UploadFile = File(...),
    output: str = Form("html"),
):
    ip = _client_ip(request)
    # TEMPORARY DIAGNOSTIC - REMOVE AFTER INVESTIGATION
    ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:16]
    logger.warning(
        f"DIAG pid={os.getpid()} ip_hash={ip_hash} "
        f"burst_id={id(burst_limiter)} hourly_id={id(limiter)} "
        f"burst_n={len(burst_limiter._hits.get(ip, []))} "
        f"hourly_n={len(limiter._hits.get(ip, []))}"
    )

    def error(message: str, status: int = 400, headers: dict = None):
        return templates.TemplateResponse(
            request,
            "index.html",
            {"error": message, "remaining": limiter.remaining(ip)},
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
        return error(
            "Free-tier limit reached (10 analyses/hour). Please try again later.",
            status=429,
            headers={"Retry-After": "3600"},
        )
    # Both pass: record in both limiters
    burst_limiter.record(ip)
    limiter.record(ip)

    # The upload is analyzed from a temp file and deleted immediately —
    # see app/service.py. Nothing is stored.
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

    return templates.TemplateResponse(request, "report.html", data)
