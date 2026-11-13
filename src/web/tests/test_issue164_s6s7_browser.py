"""Issue #164 S6/S7 port: executed-DOM/browser tests (RUN_AUTH_BROWSER=1).

Covers the halves of the spec's runtime set that server tests cannot:
A1 badge suppression (executed JS: zero #credit-badge and zero
quick-buy controls after the shared script runs, at zero AND positive
balance, with the un-suppressed Analyze page as the in-harness
control), RT-7/RT-13 staged-list mutation sequences, RT-9 header as a
stateful control, RT-14 native validation, and the A6 long-filename
overflow rule. Serves the real app over local HTTPS, the
test_issue79_header_browser.py pattern, extended with the Phase B
product env (price envs + pending dir) so quotes render.
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

LOG = "2024-01-01 10:00:00 ERROR database connection failed\n"


@contextmanager
def _serve(auth_env, tmp_path, monkeypatch):
    import uvicorn
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    import app.db as db_module
    from app import main

    monkeypatch.setenv("DATABASE_URL", "sqlite://")
    monkeypatch.setenv("STRIPE_PRICE_BATCH", "price_test_batch")
    monkeypatch.setenv("STRIPE_PRICE_COMPARE", "price_test_compare")
    monkeypatch.setenv("STRIPE_PRICE_LARGE_FILE", "price_test_large_file")
    monkeypatch.setattr(db_module, "SessionLocal", auth_env.sessions)
    monkeypatch.setattr(main, "_PAID_PENDING_DIR", str(tmp_path / "pending"))

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "s6.crt", tmp_path / "s6.key"
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


def _login(page, base, auth_env, email="s6s7@example.com"):
    from playwright.sync_api import expect
    page.goto(base + "/signup")
    page.get_by_label("Email", exact=True).fill(email)
    page.get_by_label("Password", exact=True).fill("SecurePass123!")
    page.locator('button[type="submit"]').click()
    expect(page.get_by_role("status")).to_contain_text("verification link")
    # conftest auth_env sent tuples are ("verify", address, token) —
    # token is index 2 (the header-browser suite's pattern).
    token = auth_env.sent[-1][2]
    page.goto(base + "/verify?token=" + token)
    page.get_by_role("button", name="Verify email").click()
    expect(page.get_by_role("status")).to_contain_text("Email verified")
    page.goto(base + "/login")
    page.get_by_label("Email", exact=True).fill(email)
    page.get_by_label("Password", exact=True).fill("SecurePass123!")
    page.get_by_role("button", name="Log in", exact=True).click()
    page.wait_for_url(base + "/")


def _drop(page, zone_id, files):
    """Dispatch a real drop with a DataTransfer of synthetic Files.
    files: list of (name, content)."""
    page.evaluate(
        """([zoneId, files]) => {
          const dz = document.getElementById(zoneId);
          const dt = new DataTransfer();
          files.forEach(([name, content]) => {
            dt.items.add(new File([content], name, {type: 'text/plain'}));
          });
          dz.dispatchEvent(new DragEvent('drop',
            {dataTransfer: dt, bubbles: true, cancelable: true}));
        }""",
        [zone_id, files],
    )


def _staged_names(page, container_id):
    return page.evaluate(
        """(id) => Array.from(
             document.getElementById(id).querySelectorAll('.s6-file-name')
           ).map(el => el.textContent)""",
        container_id,
    )


def _input_names(page, input_id):
    return page.evaluate(
        "(id) => Array.from(document.getElementById(id).files).map(f => f.name)",
        input_id,
    )


def _write(tmp_path, name, content):
    p = tmp_path / name
    p.write_bytes(content if isinstance(content, bytes) else content.encode())
    return str(p)


def test_a1_badge_suppressed_on_ported_surfaces(auth_env, tmp_path, monkeypatch):
    """A1: after the shared script runs, each ported surface renders
    zero #credit-badge elements and exposes no quick-buy control, at
    positive AND zero balance; the un-suppressed home page is the
    control (badge appears there in the same harness); Log out from a
    ported surface still submits."""
    from playwright.sync_api import sync_playwright, expect

    with _serve(auth_env, tmp_path, monkeypatch) as base:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            context = _context(browser, base, DESKTOP)
            page = context.new_page()
            page.set_default_timeout(15000)
            _login(page, base, auth_env)

            # Control: home (un-suppressed include) DOES inject a badge.
            page.goto(base + "/")
            expect(page.locator("#credit-badge")).to_be_visible()
            expect(page.locator("#credit-badge")).to_contain_text("10 credits")

            def assert_suppressed(url):
                page.goto(url)
                # Give the (suppressed) script its chance to run/fetch.
                page.wait_for_timeout(800)
                assert page.locator("#credit-badge").count() == 0, url
                assert page.evaluate(
                    "typeof window.showCreditModal") == "undefined", url
                assert page.locator("#credit-modal").count() == 0, url

            assert_suppressed(base + "/batch")
            assert_suppressed(base + "/compare")
            assert_suppressed(
                base + "/products/return?product_checkout=cancelled&sku=batch")
            assert_suppressed(
                base + "/products/return?product_checkout=cancelled&sku=compare")
            # Consent render: stage two files and submit for a quote.
            f1 = _write(tmp_path, "one.log", LOG * 10)
            f2 = _write(tmp_path, "two.log", LOG * 5)
            page.goto(base + "/batch")
            page.set_input_files("#files", [f1, f2])
            page.get_by_role("button", name="Get batch quote").click()
            page.wait_for_selector(".s6-consent-panel")
            page.wait_for_timeout(800)
            assert page.locator("#credit-badge").count() == 0
            assert page.evaluate(
                "typeof window.showCreditModal") == "undefined"

            # Zero balance: the control still shows a badge on home
            # ("0 credits" — the base script's reproduced behaviour),
            # the ported surfaces still show none.
            from app.models import CreditAccount, User
            db = auth_env.sessions()
            user = db.query(User).filter(
                User.email == "s6s7@example.com").one()
            acct = db.query(CreditAccount).filter(
                CreditAccount.user_id == user.id).one()
            acct.balance = 0
            db.commit()
            db.close()
            page.goto(base + "/")
            expect(page.locator("#credit-badge")).to_contain_text("0 credits")
            assert_suppressed(base + "/batch")

            # Log out from a ported surface still submits (the shared
            # script's other duties are retained).
            page.goto(base + "/batch")
            page.locator(
                'header form[action="/auth/logout"] button[type="submit"]'
            ).click()
            page.wait_for_url(base + "/")
            from app import auth as auth_mod
            assert not any(c["name"] == auth_mod.SESSION_COOKIE
                           for c in context.cookies())
            browser.close()


def test_rt13_batch_staged_mutation_sequence(auth_env, tmp_path, monkeypatch):
    """RT-13/RT-7 (Batch): pick -> drop -> remove -> reselect; the
    visible rows, the input's FileList and the submitted consent all
    agree after EVERY mutation; filenames render as text."""
    from playwright.sync_api import sync_playwright, expect

    f1 = _write(tmp_path, "one.log", LOG * 10)
    f2 = _write(tmp_path, "two.log", LOG * 5)
    f3 = _write(tmp_path, "three.log", LOG * 3)
    with _serve(auth_env, tmp_path, monkeypatch) as base:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            context = _context(browser, base, DESKTOP)
            page = context.new_page()
            page.set_default_timeout(15000)
            _login(page, base, auth_env)
            page.goto(base + "/batch")

            page.set_input_files("#files", [f1, f2, f3])
            assert _staged_names(page, "batch-staged") == [
                "one.log", "two.log", "three.log"]
            assert _input_names(page, "files") == [
                "one.log", "two.log", "three.log"]
            # Real size is the staged meta (no invented format label).
            meta = page.locator("#batch-staged .s6-file-meta").first.text_content()
            assert meta.strip() == f"{len(LOG * 10)} B"

            # Drop appends a fourth file.
            _drop(page, "batch-dropzone", [("four.log", LOG * 2)])
            assert _staged_names(page, "batch-staged") == [
                "one.log", "two.log", "three.log", "four.log"]
            assert _input_names(page, "files") == [
                "one.log", "two.log", "three.log", "four.log"]

            # Remove the middle file via its x control.
            page.locator("#batch-staged .s6-file-row").nth(1).locator(
                ".s6-remove").click()
            assert _staged_names(page, "batch-staged") == [
                "one.log", "three.log", "four.log"]
            assert _input_names(page, "files") == [
                "one.log", "three.log", "four.log"]

            # Picker cancel leaves selection and staged list unchanged.
            page.evaluate(
                "document.getElementById('files')"
                ".dispatchEvent(new Event('cancel'))")
            assert _staged_names(page, "batch-staged") == [
                "one.log", "three.log", "four.log"]
            assert _input_names(page, "files") == [
                "one.log", "three.log", "four.log"]

            # A filename is rendered as TEXT, never HTML.
            _drop(page, "batch-dropzone", [("<b>evil</b>.log", LOG)])
            assert "<b>evil</b>.log" in _staged_names(page, "batch-staged")
            assert page.evaluate(
                "document.getElementById('batch-staged')"
                ".querySelectorAll('b').length") == 0
            page.locator("#batch-staged .s6-file-row").last.locator(
                ".s6-remove").click()

            # Reselecting the removed file stages it again (the picker
            # replaces the selection, natively).
            page.set_input_files("#files", [f2])
            assert _staged_names(page, "batch-staged") == ["two.log"]

            # Final sequence -> submission: pick two, drop a third;
            # the consent's file list follows the visible order.
            page.set_input_files("#files", [f1, f3])
            _drop(page, "batch-dropzone", [("two.log", LOG * 5)])
            assert _staged_names(page, "batch-staged") == [
                "one.log", "three.log", "two.log"]
            page.get_by_role("button", name="Get batch quote").click()
            page.wait_for_selector(".s6-consent-panel")
            chips = page.locator(".s6-consent-panel .s6-chip").all_text_contents()
            assert "1. one.log" in chips and "2. three.log" in chips \
                and "3. two.log" in chips
            assert chips.index("1. one.log") < chips.index("2. three.log") \
                < chips.index("3. two.log")
            assert "bytes across 3 files, in upload order" in page.content()
            browser.close()


def test_rt13_rt14_compare_zones(auth_env, tmp_path, monkeypatch):
    """RT-13 (Compare zones) + RT-14 (native validation): dropping
    several files into ONE zone keeps the last; a submit with only A
    staged is stopped by native required validation and sends NO
    POST; the final selection is what the consent lists."""
    from playwright.sync_api import sync_playwright, expect

    fa = _write(tmp_path, "a.log", LOG * 10)
    fb = _write(tmp_path, "b.log", LOG * 5)
    with _serve(auth_env, tmp_path, monkeypatch) as base:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            context = _context(browser, base, DESKTOP)
            page = context.new_page()
            page.set_default_timeout(15000)
            _login(page, base, auth_env)
            page.goto(base + "/compare")

            posts = []
            page.on("request", lambda r: posts.append(r.url)
                    if r.method == "POST" and r.url.endswith("/compare") else None)

            # Multi-file drop into zone A: last dropped wins, and the
            # row, the input and (below) the digest all agree.
            _drop(page, "zone-a", [("first.log", LOG * 2),
                                   ("second.log", LOG * 4)])
            assert _staged_names(page, "staged-a") == ["second.log"]
            assert _input_names(page, "file_a") == ["second.log"]

            # RT-14: only A staged -> native validation stops the
            # submit; no POST is sent.
            assert page.evaluate(
                "document.getElementById('file_b').checkValidity()") is False
            page.get_by_role("button", name="Compare ($5)").click()
            page.wait_for_timeout(500)
            assert posts == []
            assert page.url == base + "/compare"

            # Remove A, re-add a different A; stage B; submit.
            page.locator("#staged-a .s6-remove").click()
            assert _staged_names(page, "staged-a") == []
            assert _input_names(page, "file_a") == []
            page.set_input_files("#file_a", [fa])
            page.set_input_files("#file_b", [fb])
            assert _staged_names(page, "staged-a") == ["a.log"]
            assert _staged_names(page, "staged-b") == ["b.log"]
            page.get_by_role("button", name="Compare ($5)").click()
            page.wait_for_selector(".s6-consent-panel")
            chips = page.locator(".s6-consent-panel .s6-chip").all_text_contents()
            assert "A — a.log" in chips and "B — b.log" in chips
            browser.close()


def test_rt9_header_stateful_on_ported_screens(auth_env, tmp_path, monkeypatch):
    """RT-9: at mobile width the toggle opens the full signed-in nav
    (My Reports / Settings / Log out all reachable) on entry, consent
    and return renders; at desktop the nav is inline."""
    from playwright.sync_api import sync_playwright, expect

    f1 = _write(tmp_path, "one.log", LOG * 10)
    f2 = _write(tmp_path, "two.log", LOG * 5)
    with _serve(auth_env, tmp_path, monkeypatch) as base:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            context = _context(browser, base, MOBILE)
            page = context.new_page()
            page.set_default_timeout(15000)
            _login(page, base, auth_env)

            def check_header():
                toggle = page.locator(".nav-toggle")
                nav = page.locator("#site-nav")
                expect(toggle).to_be_visible()
                expect(nav).to_be_hidden()
                toggle.click()
                expect(nav.get_by_role("link", name="My Reports")).to_be_visible()
                expect(nav.get_by_role("link", name="Settings")).to_be_visible()
                expect(nav.locator(
                    'form[action="/auth/logout"] button[type="submit"]')).to_be_visible()
                page.keyboard.press("Escape")
                expect(nav).to_be_hidden()

            page.goto(base + "/batch")
            check_header()
            page.goto(base + "/compare")
            check_header()
            # Consent render (mobile).
            page.goto(base + "/batch")
            page.set_input_files("#files", [f1, f2])
            page.get_by_role("button", name="Get batch quote").click()
            page.wait_for_selector(".s6-consent-panel")
            check_header()
            # Return render (mobile).
            page.goto(base + "/products/return?product_checkout=cancelled&sku=compare")
            check_header()
            # Desktop: toggle gone, nav inline.
            page.set_viewport_size(DESKTOP)
            page.goto(base + "/batch")
            expect(page.locator(".nav-toggle")).to_be_hidden()
            expect(page.locator("#site-nav")).to_be_visible()
            browser.close()


def test_a6_long_filename_no_horizontal_overflow(auth_env, tmp_path, monkeypatch):
    """A6: an 80+ char unbroken filename renders as escaped text at
    390px with no horizontal page overflow — on the Batch entry
    staged list, the Batch consent chips, and the Compare entry."""
    from playwright.sync_api import sync_playwright, expect

    long_name = "x" * 84 + ".log"
    f1 = _write(tmp_path, "one.log", LOG * 10)
    with _serve(auth_env, tmp_path, monkeypatch) as base:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            context = _context(browser, base, MOBILE)
            page = context.new_page()
            page.set_default_timeout(15000)
            _login(page, base, auth_env)

            def no_overflow():
                return page.evaluate(
                    "document.documentElement.scrollWidth <= window.innerWidth")

            page.goto(base + "/batch")
            _drop(page, "batch-dropzone", [(long_name, LOG * 2)])
            assert _staged_names(page, "batch-staged") == [long_name]
            assert no_overflow()
            # Submit it (with a second file) -> consent chips.
            page.set_input_files("#files", [f1])
            _drop(page, "batch-dropzone", [(long_name, LOG * 2)])
            page.get_by_role("button", name="Get batch quote").click()
            page.wait_for_selector(".s6-consent-panel")
            chips = page.locator(".s6-consent-panel .s6-chip").all_text_contents()
            assert any(long_name in c for c in chips)
            assert no_overflow()
            chip = page.locator(".s6-consent-panel .s6-chip").nth(2)
            assert chip.evaluate(
                "el => getComputedStyle(el).wordBreak") == "break-all"
            # Compare entry staged list.
            page.goto(base + "/compare")
            _drop(page, "zone-a", [(long_name, LOG * 2)])
            assert _staged_names(page, "staged-a") == [long_name]
            assert no_overflow()
            browser.close()
