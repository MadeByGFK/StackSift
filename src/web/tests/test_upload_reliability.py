"""Upload submission reliability: duplicate-click prevention, output-format
preservation, and error retry. Real Chromium against a live local server.
Enable with RUN_AUTH_BROWSER=1.
"""
import os
import re
import socket
import threading
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("RUN_AUTH_BROWSER") != "1", reason="Set RUN_AUTH_BROWSER=1 and install Playwright Chromium")

SAMPLE_LOG = Path(__file__).resolve().parents[3] / "sample_logs" / "app.log"


@pytest.fixture
def live_app():
    from app.main import app, limiter, burst_limiter
    import uvicorn
    # Fresh quota per test: limiters are in-memory and shared process-wide.
    limiter._hits.clear()
    burst_limiter._hits.clear()
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    base = f"http://127.0.0.1:{sock.getsockname()[1]}"
    server = uvicorn.Server(uvicorn.Config(app, lifespan="off", access_log=False, log_level="error"))
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


def _browser_page(pw):
    browser = pw.chromium.launch()
    page = browser.new_page()
    page.set_default_timeout(15000)
    return browser, page


def _output_value(post_data: bytes) -> str:
    """First output= value from a multipart form body."""
    m = re.search(rb'name="output"\r\n\r\n(\w+)\r\n', post_data)
    assert m, "output field missing from submission"
    return m.group(1).decode()


def test_double_submit_sends_single_request(live_app):
    """Rapid repeated submissions while a request is pending send one request."""
    from playwright.sync_api import sync_playwright
    requests = []
    with sync_playwright() as pw:
        browser, page = _browser_page(pw)
        try:
            def handle(route):
                requests.append(route.request)
                route.fulfill(status=200, body="<html><body>ok</body></html>",
                              content_type="text/html")
            page.route("**/analyze", handle)
            page.goto(live_app + "/")
            # No script errors on load (the old head script threw on missing form).
            assert page.evaluate("document.getElementById('upload-form') !== null")
            page.set_input_files("#file-input", str(SAMPLE_LOG))
            # Two synchronous submissions. The in-flight state is asserted
            # synchronously (immune to navigation timing); the second submit
            # must be suppressed by the guard.
            state = page.eval_on_selector("#upload-form", """form => {
              form.requestSubmit();
              const s = {
                submitting: form.dataset.submitting,
                disabled: Array.from(form.querySelectorAll('button[type="submit"]')).every(b => b.disabled),
                loadingVisible: document.getElementById('loading').style.display === 'block',
                loadingRole: document.getElementById('loading').getAttribute('role'),
              };
              form.requestSubmit();
              return s;
            }""")
            assert state == {"submitting": "1", "disabled": True,
                             "loadingVisible": True, "loadingRole": "status"}, state
            # Allow any duplicate request time to arrive (first-request
            # interception can be slow), then assert exactly one was sent.
            page.wait_for_timeout(2500)
            assert len(requests) == 1, f"expected 1 request, got {len(requests)}"
        finally:
            browser.close()


def test_output_format_preserved_for_both_buttons(live_app):
    """The selected output (HTML or text report) survives the submit guard."""
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        for button_name, expected in [("Analyze my logs", "html"),
                                      ("Download .txt report", "txt")]:
            browser, page = _browser_page(pw)
            try:
                bodies = []
                def handle(route):
                    bodies.append(route.request.post_data_buffer or b"")
                    route.fulfill(status=200, body="<html><body>ok</body></html>",
                                  content_type="text/html")
                page.route("**/analyze", handle)
                page.goto(live_app + "/")
                page.set_input_files("#file-input", str(SAMPLE_LOG))
                page.get_by_role("button", name=button_name, exact=True).click()
                page.wait_for_timeout(1000)
                assert len(bodies) == 1
                assert _output_value(bodies[0]) == expected, button_name
            finally:
                browser.close()


def test_failed_submission_can_be_retried(live_app):
    """A validation error re-renders the form usable; a retry then succeeds."""
    from playwright.sync_api import sync_playwright, expect
    with sync_playwright() as pw:
        browser, page = _browser_page(pw)
        try:
            page.goto(live_app + "/")
            # Submit with no file: server re-renders the form with an error.
            page.get_by_role("button", name="Analyze my logs", exact=True).click()
            expect(page.locator(".error")).to_contain_text("choose a file")
            # The re-rendered form is fully usable again.
            assert page.locator("#upload-form button[type='submit']").first.is_enabled()
            page.set_input_files("#file-input", str(SAMPLE_LOG))
            page.get_by_role("button", name="Analyze my logs", exact=True).click()
            page.wait_for_url(live_app + "/analyze")
            expect(page.locator(".error")).to_have_count(0)
        finally:
            browser.close()
