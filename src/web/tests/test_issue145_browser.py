"""Issue #145 — executed-DOM/browser tests (RUN_AUTH_BROWSER=1).

Runtime sequences for sharing an Investigation Report (the #177
lesson — create/revoke state must sync across surfaces):

1. My Reports: the deep_dive row offers Share (it was suppressed
   pre-#145); the modal shows NO lock notes for the paid formats
   (they are included with the purchase); creating a PDF link shows
   the copyable URL in the modal.
2. The link serves the PDF to a logged-out visitor (download).
3. Settings -> Report Access lists the same link; revoking it there
   kills the public link AND the My Reports state line (on reload).

Seeding mirrors the API suite: signup via the HTTP helpers, a source
analysis row in the DB, the seeded $9 entitlement, and generation
through the real deep-dive route — all before the browser logs in.
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
EMAIL = "a145@example.com"
PASSWORD = "TestPass123!x"


@contextmanager
def _serve(auth_env, tmp_path, monkeypatch):
    import uvicorn
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    import app.db as db_module

    monkeypatch.setenv("DATABASE_URL", "sqlite://")
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
    cert_path, key_path = tmp_path / "a145.crt", tmp_path / "a145.key"
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


def _seed_deep_dive(auth_env):
    from test_phase2b_paid_e2e import _signup_verify_login
    from test_report_sharing import _make_report
    _email, uid, csrf = _signup_verify_login(auth_env, EMAIL)
    rid = _make_report(auth_env, uid)
    from product_seed import seed_entitlement_for_source
    seed_entitlement_for_source(auth_env.sessions, rid)
    gen = auth_env.client.post(f"/reports/{rid}/deep-dive",
                               data={"csrf_token": csrf})
    assert gen.status_code == 200, gen.text[:300]
    return gen.json()["analysis_result_id"]


def _login(page, base):
    from playwright.sync_api import expect
    page.goto(base + "/login")
    page.get_by_label("Email", exact=True).fill(EMAIL)
    page.get_by_label("Password", exact=True).fill(PASSWORD)
    page.get_by_role("button", name="Log in", exact=True).click()
    page.wait_for_url(base + "/")
    expect(page.locator("body")).to_be_visible()


def test_share_investigation_report_cross_surface(auth_env, tmp_path, monkeypatch):
    from playwright.sync_api import expect, sync_playwright

    dd_id = _seed_deep_dive(auth_env)
    with _serve(auth_env, tmp_path, monkeypatch) as base:
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            try:
                context = _context(browser, base, DESKTOP)
                page = context.new_page()
                _login(page, base)

                # 1. My Reports: Share exists on the deep_dive row and
                # the modal carries no lock notes for paid formats.
                page.goto(base + "/reports")
                share_btn = page.locator(
                    f'button.share-open[data-report="{dd_id}"]')
                expect(share_btn).to_have_count(1)
                share_btn.click()
                expect(page.locator("#share-modal")).to_be_visible()
                expect(page.locator(
                    '#share-modal .share-lock-note:visible')).to_have_count(0)
                page.locator(
                    'input[name="share-format"][value="pdf"]').check()
                page.locator("#share-create").click()
                expect(page.locator("#share-link-row")).to_be_visible()
                link = page.locator("#share-link").input_value()
                assert "/s/" in link, link
                page.locator("#share-close").click()

                # The row now reports sharing on (after reload).
                page.goto(base + "/reports")
                expect(page.locator(".s3-share-state")).to_contain_text(
                    "Link sharing on")

                # 2. A logged-out visitor gets the PDF.
                anon = _context(browser, base, DESKTOP)
                anon_page = anon.new_page()
                with anon_page.expect_download() as dl_info:
                    try:
                        anon_page.goto(link)
                    except Exception:
                        pass  # goto raises "Download is starting"; the
                        # expect_download context still captures it.
                download = dl_info.value
                path = download.path()
                with open(path, "rb") as fh:
                    assert fh.read(5) == b"%PDF-"
                anon.close()

                # 3. Settings lists the same link; revoke there.
                page.goto(base + "/settings")
                access_link = page.locator(".share-access-link")
                expect(access_link).to_have_count(1)
                # Settings stores the path form; the token must match.
                assert link.endswith(access_link.input_value())
                page.locator(".share-access-revoke").click()
                expect(page.locator(".share-access-link")).to_have_count(0)

                # The public link is dead and My Reports agrees.
                anon2 = _context(browser, base, DESKTOP)
                anon2_page = anon2.new_page()
                anon2_page.goto(link)
                expect(anon2_page.locator("body")).to_contain_text(
                    "unavailable")
                anon2.close()
                page.goto(base + "/reports")
                expect(page.locator(".s3-share-state")).to_have_count(0)
            finally:
                browser.close()
