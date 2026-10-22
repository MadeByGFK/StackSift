"""Real-browser header/nav test (issue #79). Enable with RUN_AUTH_BROWSER=1.

Serves the real app over local HTTPS (the pattern from
test_account_browser.py) and drives Chromium at a phone viewport and a
desktop viewport: the wordmark must compute to 20px/700 everywhere, the
nav must collapse behind the hamburger only at <=768px, the credits badge
must stay in the header bar on mobile, and Log out must work from inside
the mobile menu. Email delivery is captured by the auth_env fixture.
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

MOBILE = {"width": 390, "height": 844}
DESKTOP = {"width": 1280, "height": 800}


@contextmanager
def _serve(auth_env, tmp_path, monkeypatch):
    """Serve auth_env.app on a local HTTPS port (self-signed), as in
    test_account_browser.py. Page rendering resolves the current user via
    app.db.SessionLocal + DATABASE_URL, so point both at the test DB."""
    import uvicorn
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    import app.db as db_module

    monkeypatch.setenv("DATABASE_URL", "sqlite://")
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
    cert_path, key_path = tmp_path / "nav.crt", tmp_path / "nav.key"
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
    # Fail closed on any network request outside the local server (the
    # Google Fonts import falls back to system fonts; px sizes unaffected).
    context.route(
        "**/*",
        lambda route: route.continue_() if route.request.url.startswith(base + "/") else route.abort(),
    )
    return context


def _logo_size(page):
    return page.locator("a.logo").evaluate(
        "el => { const s = getComputedStyle(el); return s.fontSize + '/' + s.fontWeight; }"
    )


def test_header_nav_anonymous_mobile_and_desktop(auth_env, tmp_path, monkeypatch):
    from playwright.sync_api import sync_playwright, expect

    with _serve(auth_env, tmp_path, monkeypatch) as base:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            context = _context(browser, base, MOBILE)
            page = context.new_page()
            page.set_default_timeout(15000)

            page.goto(base + "/")
            assert _logo_size(page) == "20px/700"
            toggle = page.locator(".nav-toggle")
            nav = page.locator("#site-nav")
            expect(toggle).to_be_visible()
            expect(nav).to_be_hidden()
            # Collapsed menu holds the anonymous links.
            toggle.click()
            expect(nav).to_be_visible()
            assert toggle.get_attribute("aria-expanded") == "true"
            expect(nav.get_by_role("link", name="Credits")).to_be_visible()
            expect(nav.get_by_role("link", name="Sign up")).to_be_visible()
            # Escape closes and restores aria state.
            page.keyboard.press("Escape")
            expect(nav).to_be_hidden()
            assert toggle.get_attribute("aria-expanded") == "false"
            # Choosing a link navigates (and the menu closes with the page).
            toggle.click()
            nav.get_by_role("link", name="Log in").click()
            page.wait_for_url(base + "/login")
            assert _logo_size(page) == "20px/700"

            # Desktop: no hamburger, inline nav, same corrected wordmark.
            page.set_viewport_size(DESKTOP)
            page.goto(base + "/")
            expect(page.locator(".nav-toggle")).to_be_hidden()
            expect(page.locator("#site-nav")).to_be_visible()
            assert _logo_size(page) == "20px/700"
            browser.close()


def test_header_nav_logged_in_badge_menu_and_logout(auth_env, tmp_path, monkeypatch):
    from playwright.sync_api import sync_playwright, expect

    from app import auth

    with _serve(auth_env, tmp_path, monkeypatch) as base:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            context = _context(browser, base, MOBILE)
            page = context.new_page()
            page.set_default_timeout(15000)
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))

            # Sign up, verify, log in — the account browser test's flow.
            page.goto(base + "/signup")
            page.get_by_label("Email", exact=True).fill("nav79@example.com")
            page.get_by_label("Password", exact=True).fill("SecurePass123!")
            page.locator('button[type="submit"]').click()
            expect(page.get_by_role("status")).to_contain_text("verification link")
            token = auth_env.sent[-1][2]
            page.goto(base + "/verify?token=" + token)
            page.get_by_role("button", name="Verify email").click()
            expect(page.get_by_role("status")).to_contain_text("Email verified")
            page.goto(base + "/login")
            page.get_by_label("Email", exact=True).fill("nav79@example.com")
            page.get_by_label("Password", exact=True).fill("SecurePass123!")
            page.get_by_role("button", name="Log in", exact=True).click()
            page.wait_for_url(base + "/")

            # Mobile: the credits badge is in the header bar, NOT inside the
            # collapsed nav, and still opens the packs modal.
            badge = page.locator("#credit-badge")
            expect(badge).to_be_visible()
            expect(badge).to_contain_text("credits")
            assert page.evaluate(
                "document.getElementById('credit-badge').closest('nav') === null"
            ), "badge must live outside the collapsed nav on mobile"
            badge.click()
            expect(page.locator("#credit-modal")).to_be_visible()
            page.locator("#credit-modal-close").click()
            expect(page.locator("#credit-modal")).to_have_count(0)

            # Menu holds the logged-in links; the session is real.
            nav = page.locator("#site-nav")
            expect(nav).to_be_hidden()
            page.locator(".nav-toggle").click()
            expect(nav.get_by_role("link", name="My Reports")).to_be_visible()
            expect(nav.get_by_role("link", name="Settings")).to_be_visible()
            expect(nav.locator('form[action="/auth/logout"] button[type="submit"]')).to_be_visible()
            page.keyboard.press("Escape")

            # Desktop width: toggle gone, badge back inside the nav row.
            # (wait_for_function: the matchMedia change handler that moves
            # the badge fires asynchronously after a viewport resize.)
            page.set_viewport_size(DESKTOP)
            expect(page.locator(".nav-toggle")).to_be_hidden()
            page.wait_for_function(
                "document.getElementById('credit-badge').closest('nav') !== null"
            )
            page.set_viewport_size(MOBILE)

            # My Reports keeps its active-page marker inside the mobile menu.
            page.goto(base + "/reports")
            expect(page.locator("#site-nav a.active")).to_have_text("My Reports")
            assert page.evaluate(
                "document.getElementById('credit-badge').closest('nav') === null"
            ), "badge must stay in the bar on the reports header too"

            # Log out from inside the mobile menu completes to /.
            page.locator(".nav-toggle").click()
            page.locator('header form[action="/auth/logout"] button[type="submit"]').click()
            page.wait_for_url(base + "/")
            assert not any(c["name"] == auth.SESSION_COOKIE for c in context.cookies())
            page.locator(".nav-toggle").click()
            expect(page.locator("#site-nav .btn-login")).to_be_visible()

            # The only tolerated page error is the pre-existing homepage
            # upload-script one, also documented in test_account_browser.py.
            assert all(
                m == "Cannot read properties of null (reading 'addEventListener')" for m in errors
            ), errors
            browser.close()
