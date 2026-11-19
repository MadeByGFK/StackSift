"""Home-page slice (founder decision 2026-11-18, sequenced after #142a):
the Analyze page must not overflow horizontally on phone widths, and
Privacy appears exactly once — the "Private by design" card was
consolidated into the Privacy notice, keeping every disclosed fact.

Two defects, both from the founder's staging screenshots 2026-11-18:
1. The page was wider than the viewport: the .info-grid children are
   grid items whose default min-width:auto refuses to shrink below the
   Supported-formats <pre> samples' intrinsic width. Fix: grid children
   get min-width:0 and pre.format caps at max-width:100% (it already
   scrolls internally via overflow-x:auto).
2. Privacy appeared twice (notice + "Private by design" card).
"""
import os
import re
from pathlib import Path

import pytest

APP = Path(__file__).resolve().parents[1] / "app"
INDEX = (APP / "templates" / "index.html").read_text(encoding="utf-8")
CSS = (APP / "static" / "style.css").read_text(encoding="utf-8")


# --- Contract ---------------------------------------------------------------

def test_grid_children_may_shrink_below_content():
    assert ".info-grid > * { min-width: 0; }" in CSS


def test_format_pre_capped_to_container():
    rule = re.search(r"pre\.format\s*\{([^}]+)\}", CSS).group(1)
    assert "max-width: 100%" in rule
    assert "overflow-x: auto" in rule  # the samples scroll inside the card


def test_privacy_appears_exactly_once():
    assert INDEX.count('class="privacy-notice s2-panel"') == 1
    assert "Private by design" not in INDEX
    headings = re.findall(r"<h3>([^<]+)</h3>", INDEX)
    privacy_headings = [h for h in headings if "rivacy" in h or "rivate" in h]
    assert privacy_headings == ["Privacy"], privacy_headings


def test_merged_notice_keeps_every_disclosed_fact():
    start = INDEX.index('<div class="privacy-notice s2-panel">')
    notice = " ".join(INDEX[start:INDEX.index("info-grid")].split())
    for fact in (
        "Uploads may be temporarily written to disk before redaction",
        "Redaction may miss sensitive data. Review your log before uploading.",
        "Analysis reports are <strong>stored for 7 days</strong>",
        "We keep no upload archive and don't use uploads for training.",
        "File contents are not logged or retained after processing",
        "<strong>session cookie</strong> to stay signed in",
    ):
        assert fact in notice, fact


def test_info_grid_keeps_three_cards():
    grid = INDEX[INDEX.index("info-grid"):INDEX.index("<footer>")]
    assert grid.count('class="card s2-panel"') == 3
    for heading in ("Supported formats", "What you get",
                    "Built by someone on-call"):
        assert f"<h3>{heading}</h3>" in grid


# --- Runtime (executed DOM) ---------------------------------------------------

pytestmark_browser = pytest.mark.skipif(
    os.environ.get("RUN_AUTH_BROWSER") != "1",
    reason="Set RUN_AUTH_BROWSER=1 and install Playwright Chromium")


@pytestmark_browser
def test_analyze_page_no_horizontal_overflow_on_phones(
        auth_env, tmp_path, monkeypatch):
    import socket
    import threading
    import time
    from contextlib import contextmanager
    from datetime import datetime, timedelta, timezone

    import uvicorn
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from playwright.sync_api import sync_playwright

    import app.db as db_module
    monkeypatch.setattr(db_module, "SessionLocal", auth_env.sessions)

    @contextmanager
    def serve():
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.now(timezone.utc)
        certificate = (
            x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(hours=1))
            .sign(key, hashes.SHA256()))
        cert_path, key_path = tmp_path / "hp.crt", tmp_path / "hp.key"
        cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        base = f"https://localhost:{sock.getsockname()[1]}"
        server = uvicorn.Server(uvicorn.Config(
            auth_env.app, lifespan="off", access_log=False,
            ssl_keyfile=str(key_path), ssl_certfile=str(cert_path),
            log_level="error"))
        thread = threading.Thread(
            target=server.run, kwargs={"sockets": [sock]}, daemon=True)
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

    with serve() as base:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            for width in (360, 390):
                context = browser.new_context(
                    ignore_https_errors=True,
                    viewport={"width": width, "height": 800})
                context.route(
                    "**/*",
                    lambda route: route.continue_()
                    if route.request.url.startswith(base + "/")
                    else route.abort())
                page = context.new_page()
                page.set_default_timeout(15000)
                page.goto(base + "/", wait_until="networkidle")
                metrics = page.evaluate(
                    """() => ({ sw: document.documentElement.scrollWidth,
                                iw: window.innerWidth })""")
                assert metrics["sw"] <= metrics["iw"], (width, metrics)
                pre = page.evaluate(
                    """() => { const el = document.querySelector('pre.format');
                        const r = el.getBoundingClientRect();
                        return { right: r.right, iw: window.innerWidth }; }""")
                assert pre["right"] <= pre["iw"] + 1, (width, pre)
                heads = page.evaluate(
                    """() => Array.from(document.querySelectorAll('h3'))
                        .map(h => h.textContent.trim())
                        .filter(t => /priv/i.test(t))""")
                assert heads == ["Privacy"], (width, heads)
                context.close()
            browser.close()
