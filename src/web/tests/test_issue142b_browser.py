"""Issue #142b — executed-DOM/browser tests (RUN_AUTH_BROWSER=1).

Runtime tests for the Settings -> Branding port (spec: #142b runtime
tests 1-5): save persists and renders in the ported rows; clear
empties; the accent swatch and hex stay in sync both directions and an
invalid hex blocks the submit with a visible error and NO request;
the logo zone sets a file by browse and by drop, Remove logo clears;
layout gates at desktop and 360px (label column vs stacked, Save and
Clear on one row, no overflow).
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

DESKTOP = {"width": 1280, "height": 800}
MOBILE = {"width": 360, "height": 740}
PNG_1PX = bytes.fromhex(
    "89504e470d0a1a0a0000000d494844520000000100000001080600000"
    "01f15c4890000000d4944415478da6364f8cf500f00038601805a347d"
    "6b0000000049454e44ae426082")


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




def _open_settings(page, base):
    page.goto(base + "/settings")
    page.wait_for_selector("#branding-profile")


def _wait_settings(page, base):
    """After a Save/Clear click the app itself navigates (the auth-form
    flow assigns data-success-url); wait for that instead of goto,
    which races the in-flight navigation (ERR_ABORTED)."""
    page.wait_for_url(base + "/settings")
    page.wait_for_selector("#branding-profile")


def test_142b_save_clear_accent_and_logo(auth_env, tmp_path, monkeypatch):
    from playwright.sync_api import sync_playwright, expect
    logo = tmp_path / "logo.png"
    logo.write_bytes(PNG_1PX)
    with _serve(auth_env, tmp_path, monkeypatch) as base:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            context = _context(browser, base, DESKTOP)
            page = context.new_page()
            page.set_default_timeout(15000)
            _login(page, base, auth_env, email="b142@example.com")
            _open_settings(page, base)

            # 1. Save with changed fields -> values persist on reload.
            page.fill("#branding-business-name", "Acme Consulting")
            page.fill("#branding-report-title", "Monthly Health Check")
            page.fill("#branding-client-name", "Globex")
            page.fill("#branding-accent-hex", "#1a2b3c")
            with page.expect_navigation(url=base + "/settings"):
                page.get_by_role("button", name="Save branding").click()
            page.wait_for_selector("#branding-profile")
            assert page.input_value("#branding-business-name") == "Acme Consulting"
            assert page.input_value("#branding-accent-hex") == "#1a2b3c"
            # Swatch initialized from the saved hex.
            assert page.input_value("#branding-accent-swatch") == "#1a2b3c"

            # 3a. Swatch -> hex sync.
            page.evaluate(
                "document.querySelector('#branding-accent-swatch').focus()")
            page.locator("#branding-accent-swatch").evaluate(
                """el => { el.value = '#335577';
                           el.dispatchEvent(new Event('input', {bubbles: true})); }""")
            assert page.input_value("#branding-accent-hex") == "#335577"
            # 3b. Hex -> swatch sync.
            page.fill("#branding-accent-hex", "#aa5500")
            assert page.input_value("#branding-accent-swatch") == "#aa5500"

            # 3c. Invalid hex: blocked, visible error, no request fired.
            fired = []
            page.on("request", lambda r: fired.append(r.url)
                    if "/settings/branding" in r.url and r.method == "POST" else None)
            page.fill("#branding-accent-hex", "not-a-color")
            page.get_by_role("button", name="Save branding").click()
            page.wait_for_timeout(400)
            assert page.locator("#branding-accent-error").is_visible()
            assert not [u for u in fired if u.endswith("/settings/branding")], fired
            page.fill("#branding-accent-hex", "#aa5500")

            # 4a. Logo via the file input (browse path) -> set on reload.
            page.set_input_files("#branding-logo-input", str(logo))
            assert page.locator("#branding-file-name").inner_text() == "logo.png"
            with page.expect_navigation(url=base + "/settings"):
                page.get_by_role("button", name="Save branding").click()
            page.wait_for_selector("#branding-profile")
            page.wait_for_selector(".s4b-remove")

            # 4b. Remove logo -> cleared on reload.
            page.check(".s4b-remove input[type=checkbox]")
            with page.expect_navigation(url=base + "/settings"):
                page.get_by_role("button", name="Save branding").click()
            page.wait_for_selector("#branding-profile")
            assert page.locator(".s4b-remove").count() == 0

            # 2. Clear branding -> fields empty on reload.
            with page.expect_navigation(url=base + "/settings"):
                page.get_by_role("button", name="Clear branding").click()
            page.wait_for_selector("#branding-profile")
            assert page.input_value("#branding-business-name") == ""
            assert page.input_value("#branding-accent-hex") == ""
            browser.close()


def test_142b_drop_zone_sets_file(auth_env, tmp_path, monkeypatch):
    from playwright.sync_api import sync_playwright
    with _serve(auth_env, tmp_path, monkeypatch) as base:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            context = _context(browser, base, DESKTOP)
            page = context.new_page()
            page.set_default_timeout(15000)
            _login(page, base, auth_env, email="b142drop@example.com")
            _open_settings(page, base)
            page.evaluate(
                """() => {
                  const dt = new DataTransfer();
                  dt.items.add(new File([new Uint8Array([137, 80, 78, 71])],
                                        'dropped.png', {type: 'image/png'}));
                  const ev = new DragEvent('drop', {bubbles: true, dataTransfer: dt});
                  document.querySelector('#branding-drop').dispatchEvent(ev);
                }""")
            assert page.locator("#branding-file-name").inner_text() == "dropped.png"
            name = page.evaluate(
                "document.querySelector('#branding-logo-input').files[0].name")
            assert name == "dropped.png"
            browser.close()


def test_142b_long_filename_wraps_and_drop_zone_shows_keyboard_focus(
        auth_env, tmp_path, monkeypatch):
    """Codex P2 regression (PR #196): a long spaceless logo filename
    wraps inside the branding panel at 360px, and tabbing to the
    hidden file input shows a visible outline on the drop zone."""
    from playwright.sync_api import sync_playwright
    long_name = "a" * 72 + ".png"
    with _serve(auth_env, tmp_path, monkeypatch) as base:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            context = _context(browser, base, MOBILE)
            page = context.new_page()
            page.set_default_timeout(15000)
            _login(page, base, auth_env, email="b142codex@example.com")
            _open_settings(page, base)
            page.set_input_files("#branding-logo-input", {
                "name": long_name, "mimeType": "image/png",
                "buffer": PNG_1PX})
            assert page.locator("#branding-file-name").inner_text() == long_name
            geo = page.evaluate(
                """() => {
                  const panel = document.querySelector('#branding-profile');
                  const pr = panel.getBoundingClientRect();
                  const wide = [];
                  panel.querySelectorAll('*').forEach(el => {
                    const r = el.getBoundingClientRect();
                    if (r.right > pr.right + 1) wide.push(
                      el.tagName + '.' + el.className);
                  });
                  return { wide: wide.slice(0, 6) };
                }""")
            assert geo["wide"] == [], geo["wide"]
            # Keyboard-tab until the hidden file input holds focus,
            # then the drop zone must carry the visible outline.
            focused = False
            for _ in range(60):
                page.keyboard.press("Tab")
                page.wait_for_timeout(30)
                if page.evaluate(
                        "document.activeElement.id") == "branding-logo-input":
                    focused = True
                    break
            assert focused, "file input never received keyboard focus"
            outline = page.evaluate(
                """() => { const s = getComputedStyle(
                     document.querySelector('#branding-drop'));
                   return s.outlineStyle + ' ' + s.outlineWidth; }""")
            assert outline == "solid 3px", outline
            browser.close()


def test_142b_layout_desktop_and_mobile(auth_env, tmp_path, monkeypatch):
    from playwright.sync_api import sync_playwright
    with _serve(auth_env, tmp_path, monkeypatch) as base:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            context = _context(browser, base, DESKTOP)
            page = context.new_page()
            page.set_default_timeout(15000)
            _login(page, base, auth_env, email="b142layout@example.com")
            _open_settings(page, base)
            geo = page.evaluate(
                """() => {
                  const label = document.querySelector('.s4b-field-label')
                    .getBoundingClientRect();
                  const input = document.querySelector('#branding-business-name')
                    .getBoundingClientRect();
                  const save = document.querySelector('.s4b-save-row .btn-primary')
                    .getBoundingClientRect();
                  const clear = document.querySelector('.s4b-save-row .btn-ghost')
                    .getBoundingClientRect();
                  return { labelX: label.x, inputX: input.x, labelY: label.y,
                           inputY: input.y, saveY: save.y, clearY: clear.y,
                           saveBg: getComputedStyle(document.querySelector(
                             '.s4b-save-row .btn-primary')).backgroundColor };
                }""")
            # Desktop: label column left of the input, roughly same row.
            assert geo["labelX"] < geo["inputX"]
            assert abs(geo["labelY"] - geo["inputY"]) < 20
            # Save and Clear share one row; Save computes to brand gold.
            assert abs(geo["saveY"] - geo["clearY"]) < 4
            assert geo["saveBg"] == "rgb(227, 167, 47)"
            # Mobile: stacked, no overflow, both actions reachable.
            page.set_viewport_size(MOBILE)
            page.reload()
            page.wait_for_selector("#branding-profile")
            geo = page.evaluate(
                """() => {
                  const label = document.querySelector('.s4b-field-label')
                    .getBoundingClientRect();
                  const input = document.querySelector('#branding-business-name')
                    .getBoundingClientRect();
                  // Overflow gate scoped to the branding panel: the
                  // page-level remainder at 360px is group 01's
                  // .s4-field-value (pre-existing, 371px on the
                  // pre-port tree too) and belongs to the follow-up
                  // groups slice named on #142 — not this port.
                  const panel = document.querySelector('#branding-profile');
                  const wide = [];
                  panel.querySelectorAll('*').forEach(el => {
                    const r = el.getBoundingClientRect();
                    if (r.right > window.innerWidth + 1) wide.push(
                      el.tagName + '.' + el.className + ' right=' + Math.round(r.right));
                  });
                  return { labelY: label.y, inputY: input.y,
                           iw: window.innerWidth, wide: wide.slice(0, 6) };
                }""")
            assert geo["labelY"] < geo["inputY"]
            assert geo["wide"] == [], geo["wide"]
            page.get_by_role("button", name="Save branding").scroll_into_view_if_needed()
            assert page.get_by_role("button", name="Save branding").is_visible()
            assert page.get_by_role("button", name="Clear branding").is_visible()
            browser.close()
