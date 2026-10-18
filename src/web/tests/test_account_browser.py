"""Real HTTPS browser account-flow test. Enable with RUN_AUTH_BROWSER=1.

Provider exchange and mail delivery are mocked; browser forms/cookies/CSRF,
server handlers and persistence are real. Never targets a deployed service.
"""
import os
import socket
import threading
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse
from unittest.mock import AsyncMock

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("RUN_AUTH_BROWSER") != "1", reason="Set RUN_AUTH_BROWSER=1 and install Playwright Chromium")


def test_https_account_forms_end_to_end(auth_env, tmp_path, monkeypatch):
    import uvicorn
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from playwright.sync_api import sync_playwright, expect
    from app import auth, oauth
    from app.models import OAuthAccount

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(hours=1))
                   .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / "test.crt", tmp_path / "test.key"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    for name in ["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET"]:
        monkeypatch.setattr(oauth, name, "local-browser-test")
    monkeypatch.setattr(oauth, "exchange_google_code", AsyncMock(return_value={"id_token": "mock"}))
    monkeypatch.setattr(oauth, "get_google_identity", AsyncMock(return_value={"sub": "browser-google", "email": "browser@example.com", "email_verified": True}))
    monkeypatch.setattr(oauth, "exchange_github_code", AsyncMock(return_value="mock"))
    monkeypatch.setattr(oauth, "get_github_user", AsyncMock(return_value={"id": 999}))
    monkeypatch.setattr(oauth, "get_github_primary_verified_email", AsyncMock(return_value="browser@example.com"))
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    base = f"https://localhost:{sock.getsockname()[1]}"
    from fastapi import FastAPI
    from fastapi.responses import HTMLResponse
    harness = FastAPI()
    @harness.get("/mock-provider/{provider}")
    async def provider_page(provider: str):
        return HTMLResponse("Local mock provider authorization")
    harness.mount("/", auth_env.app)
    monkeypatch.setattr(oauth, "GOOGLE_AUTH_URL", base + "/mock-provider/google")
    monkeypatch.setattr(oauth, "GITHUB_AUTH_URL", base + "/mock-provider/github")
    server = uvicorn.Server(uvicorn.Config(harness, lifespan="off", access_log=False,
                            ssl_keyfile=str(key_path), ssl_certfile=str(cert_path), log_level="error"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started and time.monotonic() < deadline:
            time.sleep(.05)
        assert server.started
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            context = browser.new_context(ignore_https_errors=True)
            # Fail closed on any unexpected network request outside the local harness.
            context.route("**/*", lambda route: route.continue_() if route.request.url.startswith(base + "/") else route.abort())
            page = context.new_page()
            page.set_default_timeout(15000)
            errors = []
            page.on("pageerror", lambda error: errors.append((urlparse(page.url).path, str(error))))
            page.goto(base + "/signup")
            page.get_by_label("Email", exact=True).fill("browser@example.com")
            page.get_by_label("Password", exact=True).fill("SecurePass123!")
            page.locator('button[type="submit"]').click()
            expect(page.get_by_role("status")).to_contain_text("verification link")
            verify_token = auth_env.sent[-1][2]
            page.goto(base + "/verify?token=" + verify_token)
            page.get_by_role("button", name="Verify email").click()
            expect(page.get_by_role("status")).to_contain_text("Email verified")
            page.goto(base + "/login")
            page.get_by_label("Email", exact=True).fill("browser@example.com")
            page.get_by_label("Password", exact=True).fill("WrongPassword123!")
            page.get_by_role("button", name="Log in", exact=True).click()
            expect(page.get_by_role("status")).to_contain_text("Invalid email or password")
            page.get_by_label("Password", exact=True).fill("SecurePass123!")
            page.get_by_role("button", name="Log in", exact=True).click()
            page.wait_for_url(base + "/")
            cookie = next(c for c in context.cookies() if c["name"] == auth.SESSION_COOKIE)
            assert cookie["secure"] and cookie["httpOnly"] and cookie["sameSite"] == "Lax"
            page.goto(base + "/settings")
            for provider, label in [("google", "Google"), ("github", "GitHub")]:
                page.get_by_role("button", name=f"Link {label}", exact=True).click()
                page.wait_for_url(base + f"/mock-provider/{provider}?*")
                assert "state=" in page.url, page.url
                state = parse_qs(urlparse(page.url).query)["state"][0]
                page.goto(base + f"/auth/{provider}/callback?code=mock&state={state}")
                page.wait_for_url(base + "/settings")
            with auth_env.sessions() as db:
                assert db.query(OAuthAccount).count() == 2
            # The settings page has a single "Log out" button in the nav header.
            # It's a plain HTML form (no JS handler), so the server 303-redirects
            # to the homepage after clearing the session.
            page.wait_for_load_state()
            page.locator('header form[action="/auth/logout"] button[type="submit"]').click()
            page.wait_for_url(base + "/")
            assert not any(c["name"] == auth.SESSION_COOKIE for c in context.cookies())
            page.goto(base + "/settings")
            page.wait_for_url(base + "/login")
            page.goto(base + "/forgot")
            page.get_by_label("Email", exact=True).fill("browser@example.com")
            page.locator('button[type="submit"]').click()
            expect(page.get_by_role("status")).to_contain_text("reset link")
            reset_token = auth_env.sent[-1][2]
            page.goto(base + "/reset?token=" + reset_token)
            page.locator('input[name="new_password"]').fill("NewSecurePass123!")
            page.locator('button[type="submit"]').click()
            expect(page.get_by_role("status")).to_contain_text("Password reset")
            # Original homepage script references a missing upload-form element.
            # It is outside accounts scope and unchanged by this PR. Account pages
            # must have no script errors; do not suppress any other homepage error.
            assert all(path == "/" and message == "Cannot read properties of null (reading 'addEventListener')"
                       for path, message in errors), errors
            browser.close()
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        sock.close()
