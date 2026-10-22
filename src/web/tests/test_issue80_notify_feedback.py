"""Notify-me form submit feedback (issue #80).

The issue #67 endpoint was healthy, but a successful submit looked like
nothing happened: the email stayed in the box and the confirmation was one
small status line. The notify form now opts into richer feedback via
data-notify-feedback: on success the shared form handler clears the email
input and gives the status element an unmissable success state; on error
the typed address stays and the status element gets a distinct error
state. Auth forms (login/signup/forgot) do not carry the attribute and
behave exactly as before.
"""
import os
import re
import socket
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker


@pytest.fixture
def notify_env(tmp_path, monkeypatch):
    from app import auth
    from app.db import Base, get_db
    from app.main import app

    engine = create_engine(
        f"sqlite:///{tmp_path / 'notify80.db'}",
        connect_args={"check_same_thread": False, "timeout": 20},
    )

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, _):
        connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)

    def override():
        with sessions() as db:
            yield db

    monkeypatch.setitem(app.dependency_overrides, get_db, override)
    monkeypatch.setattr(auth, "auth_limiter", auth.AuthRateLimiter())
    try:
        with TestClient(app, base_url="https://testserver") as client:
            yield SimpleNamespace(client=client, sessions=sessions, engine=engine, app=app)
    finally:
        engine.dispose()


def _form_tag(html, action):
    for tag in re.findall(r"<form[^>]*>", html):
        if f'action="{action}"' in tag:
            return tag
    raise AssertionError(f"no form with action={action!r}")


def test_notify_form_opts_into_feedback_and_markers_survive(notify_env):
    resp = notify_env.client.get("/credits")
    assert resp.status_code == 200
    tag = _form_tag(resp.text, "/credits/notify")
    assert "data-auth-form" in tag
    assert "data-notify-feedback" in tag
    # The ISSUE-67 removal markers wrap the block (removed when #68 ships).
    assert "ISSUE-67 notify-me bridge" in resp.text
    assert "<!-- /ISSUE-67 -->" in resp.text
    # Feedback styles ship inside the same removable block's CSS.
    assert ".notify-success" in resp.text
    assert ".notify-error" in resp.text


def test_auth_forms_do_not_opt_into_notify_feedback(notify_env):
    for path, action in (("/login", "/auth/login"), ("/signup", "/auth/signup")):
        resp = notify_env.client.get(path)
        assert resp.status_code == 200
        tag = _form_tag(resp.text, action)
        assert "data-auth-form" in tag
        assert "data-notify-feedback" not in tag


def test_shared_handler_gates_feedback_on_the_attribute(notify_env):
    """The credits page ships the shared handler; its issue #80 branch must
    be gated on data-notify-feedback, with the generic status write (used
    by every auth form) unchanged ahead of it."""
    resp = notify_env.client.get("/credits")
    assert resp.status_code == 200
    script = resp.text
    assert "form.hasAttribute('data-notify-feedback')" in script
    assert "classList.toggle('notify-success', response.ok)" in script
    assert "classList.toggle('notify-error', !response.ok)" in script
    assert "form.querySelector('input[type=\"email\"]')" in script
    # Generic behavior every form relies on is still the first write.
    assert "output.textContent = result.error" in script
    # The gate is evaluated before any class is toggled.
    assert script.index("hasAttribute('data-notify-feedback')") < script.index(
        "classList.toggle('notify-success'"
    )


# --- Real-browser test (opt-in, same pattern as test_issue79) ---

pytestmark_browser = pytest.mark.skipif(
    os.environ.get("RUN_AUTH_BROWSER") != "1",
    reason="Set RUN_AUTH_BROWSER=1 and install Playwright Chromium",
)


@contextmanager
def _serve(auth_env, tmp_path, monkeypatch):
    """Serve auth_env.app on a local HTTPS port (self-signed), as in
    test_issue79_header_browser.py."""
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
    cert_path, key_path = tmp_path / "notify80.crt", tmp_path / "notify80.key"
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


@pytestmark_browser
def test_notify_feedback_in_browser(auth_env, tmp_path, monkeypatch):
    from playwright.sync_api import sync_playwright, expect

    with _serve(auth_env, tmp_path, monkeypatch) as base:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            context = browser.new_context(ignore_https_errors=True)
            # Fail closed on any network request outside the local server.
            context.route(
                "**/*",
                lambda route: route.continue_() if route.request.url.startswith(base + "/") else route.abort(),
            )
            page = context.new_page()
            page.set_default_timeout(15000)

            page.goto(base + "/credits")
            form = page.locator('form[action="/credits/notify"]')
            email = page.locator("#notify-email")
            status = page.locator('.notify-capture [role="status"]')
            submit = form.locator('button[type="submit"]')

            # Invalid email: native validation blocks the submit, the typed
            # address stays in the box (founder acceptance: forced error ->
            # email retained).
            email.fill("not-an-email")
            submit.click()
            assert email.input_value() == "not-an-email"
            assert page.evaluate(
                "document.getElementById('notify-email').validity.valid"
            ) is False

            # Success: box clears and the confirmation is an unmissable
            # styled state, not the old small plain line.
            email.fill("browser80@example.com")
            submit.click()
            expect(status).to_contain_text("on the list")
            expect(status).to_have_class(re.compile(r"notify-success"))
            expect(email).to_have_value("")
            style = status.evaluate(
                "el => { const s = getComputedStyle(el); "
                "return s.fontWeight + '|' + s.backgroundColor; }"
            )
            weight, background = style.split("|")
            assert weight == "700"
            assert background != "rgba(0, 0, 0, 0)"

            # Error (real 403 via a tampered CSRF field): the typed address
            # stays for correction and the status switches to the error
            # state with the server's message.
            email.fill("second80@example.com")
            page.evaluate(
                "document.querySelector('form[action=\"/credits/notify\"] "
                "input[name=\"csrf_token\"]').value = 'wrong'"
            )
            submit.click()
            expect(status).to_contain_text("Invalid CSRF")
            expect(status).to_have_class(re.compile(r"notify-error"))
            assert email.input_value() == "second80@example.com"

            # Auth forms are untouched by the feedback branch: a failed
            # login keeps the typed email and gets no notify classes.
            page.goto(base + "/login")
            login_form = page.locator('form[action="/auth/login"]')
            login_email = login_form.locator('input[type="email"]')
            login_email.fill("nobody80@example.com")
            login_form.locator('input[type="password"]').fill("WrongPass123!")
            login_form.locator('button[type="submit"]').click()
            login_status = login_form.locator('[role="status"]')
            expect(login_status).to_contain_text("Invalid email or password")
            assert login_email.input_value() == "nobody80@example.com"
            classes = login_status.evaluate("el => el.className")
            assert "notify-success" not in classes
            assert "notify-error" not in classes
            browser.close()
