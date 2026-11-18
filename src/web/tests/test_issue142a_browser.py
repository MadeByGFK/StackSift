"""Issue #142a — executed-DOM/browser tests (RUN_AUTH_BROWSER=1).

Runtime interaction tests for the #142a polish (the standing rule:
page-contract tests alone do not satisfy stateful controls):

1. The purchase confirmation modal on the Report page renders with
   the shared modal treatment — the confirm button computes to the
   brand gold (it was an unstyled browser-default button before
   #142a, because .btn-small had no rule on this page) — Cancel
   closes it with NO deep-dive request fired, and a double-click on
   Confirm fires exactly one.
2. My Reports at 360px: no horizontal overflow, the long filename
   wraps fully visible, clicking a non-interactive part of the card
   navigates to the report, and clicking Export opens the dropdown
   WITHOUT navigating.
3. The Report page title at 360px wraps (overflow-wrap: anywhere,
   no break-all) with no horizontal overflow.

Serves the real app over local HTTPS (the test_issue164_s6s7_browser
pattern) and seeds one stored report by analyzing a log file whose
name is 84 characters long while logged in.
"""
import os
import socket
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_AUTH_BROWSER") != "1",
    reason="Set RUN_AUTH_BROWSER=1 and install Playwright Chromium",
)

MOBILE = {"width": 360, "height": 740}
DESKTOP = {"width": 1280, "height": 800}
LOG = "2024-01-01 10:00:00 ERROR database connection failed\n" * 5
LONG_NAME = "x" * 80 + ".log"
GOLD_RGB = "rgb(227, 167, 47)"  # #E3A72F


@contextmanager
def _serve(auth_env, tmp_path, monkeypatch):
    import uvicorn
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    import app.db as db_module

    monkeypatch.setenv("DATABASE_URL", "sqlite://")
    # product_ready gates the $9 upsell + modal opener on the Report
    # page (the test_issue164_s6s7_browser pattern).
    monkeypatch.setenv("STRIPE_PRICE_INVESTIGATION_REPORT", "price_test_ir")
    monkeypatch.setenv("STRIPE_PRICE_BATCH", "price_test_batch")
    monkeypatch.setenv("STRIPE_PRICE_COMPARE", "price_test_compare")
    monkeypatch.setenv("STRIPE_PRICE_LARGE_FILE", "price_test_large_file")
    monkeypatch.setattr(db_module, "SessionLocal", auth_env.sessions)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "a142.crt", tmp_path / "a142.key"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    base = f"https://localhost:{sock.getsockname()[1]}"
    server = uvicorn.Server(uvicorn.Config(
        auth_env.app, lifespan="off", access_log=False,
        ssl_keyfile=str(key_path), ssl_certfile=str(cert_path), log_level="error"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started and time.monotonic() < deadline:
            time.sleep(.05)
        assert server.started
        yield base
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        sock.close()


def _context(browser, base, viewport):
    context = browser.new_context(ignore_https_errors=True, viewport=viewport)
    context.route(
        "**/*",
        lambda route: route.continue_() if route.request.url.startswith(base + "/") else route.abort(),
    )
    return context


def _login(page, base, auth_env, email="a142@example.com"):
    from playwright.sync_api import expect
    page.goto(base + "/signup")
    page.get_by_label("Email", exact=True).fill(email)
    page.get_by_label("Password", exact=True).fill("SecurePass123!")
    page.locator('button[type="submit"]').click()
    expect(page.get_by_role("status")).to_contain_text("verification link")
    token = auth_env.sent[-1][2]
    page.goto(base + "/verify?token=" + token)
    page.get_by_role("button", name="Verify email").click()
    expect(page.get_by_role("status")).to_contain_text("Email verified")
    page.goto(base + "/login")
    page.get_by_label("Email", exact=True).fill(email)
    page.get_by_label("Password", exact=True).fill("SecurePass123!")
    page.get_by_role("button", name="Log in", exact=True).click()
    page.wait_for_url(base + "/")


def _seed_report(auth_env, email="a142@example.com"):
    """Insert a stored free report with the long filename for the
    browser-logged-in user. The manifest is built with the real
    analysis service (the test_phase2b_reports_pdf _create_result
    recipe) so the stored schema matches production exactly.
    Returns the report's URL path."""
    import hashlib
    import json
    import uuid
    from app import models
    from app.service import analyze_upload
    data = analyze_upload(LONG_NAME, LOG.encode())
    assert "error" not in data, f"fixture analysis failed: {data}"
    manifest = json.dumps(data, default=str)
    now = datetime.now(timezone.utc)
    db = auth_env.sessions()
    try:
        user = db.query(models.User).filter_by(email=email).one()
        result = models.Result(
            user_id=user.id, type="analysis",
            free_request_id=f"test-{uuid.uuid4().hex}",
            storage_manifest=manifest,
            integrity_digest=hashlib.sha256(manifest.encode()).hexdigest(),
            byte_count=len(manifest.encode()),
            ready_at=now, expires_at=now + timedelta(days=7),
        )
        db.add(result)
        db.commit()
        return f"/reports/{result.id}"
    finally:
        db.close()


def _no_overflow(page):
    return page.evaluate(
        "document.documentElement.scrollWidth <= window.innerWidth")


def test_142a_purchase_modal_styled_cancel_safe_and_single_fire(
        auth_env, tmp_path, monkeypatch):
    from playwright.sync_api import sync_playwright, expect
    with _serve(auth_env, tmp_path, monkeypatch) as base:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            context = _context(browser, base, DESKTOP)
            page = context.new_page()
            page.set_default_timeout(15000)
            _login(page, base, auth_env)
            report_url = base + _seed_report(auth_env)
            page.goto(report_url)
            page.wait_for_selector(".report-head h2")

            fired = []
            page.on("request", lambda r: fired.append(r.url)
                    if "/deep-dive" in r.url and r.method == "POST" else None)

            # Open the purchase confirmation modal.
            page.locator("#premium-upsell-btn").click()
            modal = page.locator("#analysis-modal")
            expect(modal).to_be_visible()
            confirm = page.locator("#analysis-confirm")
            # The confirm button is the gold primary now (pre-#142a it
            # computed to the browser-default button face).
            assert confirm.evaluate(
                "el => getComputedStyle(el).backgroundColor") == GOLD_RGB
            cancel = page.locator("#analysis-close")
            assert cancel.evaluate(
                "el => getComputedStyle(el).backgroundColor") == "rgba(0, 0, 0, 0)"

            # Cancel: closes, fires nothing, navigates nowhere.
            cancel.click()
            expect(modal).to_be_hidden()
            assert fired == []
            assert page.url == report_url

            # Double-click on Confirm fires exactly one request (the
            # handler disables the button synchronously).
            page.locator("#premium-upsell-btn").click()
            expect(modal).to_be_visible()
            page.evaluate(
                "document.getElementById('analysis-confirm').click();"
                "document.getElementById('analysis-confirm').click();")
            page.wait_for_timeout(800)
            assert len(fired) == 1, fired
            browser.close()


def test_142a_my_reports_mobile_layout_and_card_click(
        auth_env, tmp_path, monkeypatch):
    from playwright.sync_api import sync_playwright, expect
    with _serve(auth_env, tmp_path, monkeypatch) as base:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            context = _context(browser, base, MOBILE)
            page = context.new_page()
            page.set_default_timeout(15000)
            _login(page, base, auth_env)
            report_url = base + _seed_report(auth_env)
            page.goto(report_url)
            page.wait_for_selector(".report-head h2")

            page.goto(base + "/reports")
            page.wait_for_selector("tr.card.s3-row")
            assert _no_overflow(page)

            # The long filename is fully visible (wrapped, not
            # truncated): its scroll width fits its client width and
            # the full name is the element's text.
            name = page.locator(".s3-report-main .name").first
            assert name.inner_text() == LONG_NAME
            assert name.evaluate("el => el.scrollWidth <= el.clientWidth + 1")
            # No Open control remains in the actions row.
            assert page.locator('.s3-actions-row a:text-is("Open")').count() == 0

            # Clicking Export opens the dropdown and does NOT navigate.
            page.locator("[data-s3-export-btn]").first.click()
            expect(page.locator("[data-s3-export-menu]").first).to_be_visible()
            assert page.url == base + "/reports"

            # Clicking a non-interactive part of the card (the severity
            # cell) navigates to the report.
            page.locator("td.s3-severity-cell").first.click()
            page.wait_for_url(report_url)
            browser.close()


def test_142a_report_title_wraps_at_mobile(auth_env, tmp_path, monkeypatch):
    from playwright.sync_api import sync_playwright
    with _serve(auth_env, tmp_path, monkeypatch) as base:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            context = _context(browser, base, MOBILE)
            page = context.new_page()
            page.set_default_timeout(15000)
            _login(page, base, auth_env)
            page.goto(base + _seed_report(auth_env))
            page.wait_for_selector(".report-head h2")
            assert _no_overflow(page)
            h2 = page.locator(".report-head h2")
            assert h2.inner_text() == LONG_NAME
            assert h2.evaluate(
                "el => getComputedStyle(el).overflowWrap") == "anywhere"
            assert h2.evaluate(
                "el => getComputedStyle(el).wordBreak") == "normal"
            browser.close()
