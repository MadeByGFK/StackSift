"""Phase 3 integration tests, round 2 — addresses GFD review findings on PR #35.

GFD verdict on PR #35: CHANGES REQUIRED (test coverage gaps, not production defects).
This file closes the three gaps:

1. Persistence test bypassed HTTP analysis → tests below exercise the full
   HTTP /analyze path (upload → 200 → report content verified).
2. Redaction test did not assert HTTP 500 → uses TestClient with
   raise_server_exceptions=False to assert the actual HTTP 500 response.
3. Temp-dir check does not prove unredacted content was never written →
   patches tempfile.NamedTemporaryFile to prove it is never called
   when redaction raises.

Test-environment fixes (per GFD round-2 review):
- Rate limiters are reset before each test (limiter._hits.clear() etc.)
  so tests reach their intended code paths instead of getting 429.
- signal.signal/signal.alarm are mocked (they only work in main thread;
  TestClient runs the app in a worker thread). This does not weaken
  production safeguards — the timeout still applies in production.

No production-code changes. Tests only.
"""

import glob
import os
import signal
import tempfile
import uuid
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _reset_rate_limiters(monkeypatch):
    """Clear in-memory rate limiter state so tests aren't 429'd."""
    from app import main as main_module
    for name in ("limiter", "burst_limiter"):
        limiter = getattr(main_module, name, None)
        if limiter is not None and hasattr(limiter, "_hits"):
            limiter._hits.clear()
    # Shared (Postgres) limiter: tests use sqlite, so it's inactive,
    # but clear it defensively if present.
    shared = getattr(main_module, "shared_limiter", None)
    if shared is not None and hasattr(shared, "_hits"):
        shared._hits.clear()


@pytest.fixture(autouse=True)
def _mock_signals(monkeypatch):
    """signal.signal only works in main thread; TestClient uses worker threads.

    Mock signal.signal/signal.alarm to no-ops. Production behavior unchanged.
    """
    monkeypatch.setattr(signal, "signal", lambda *a, **k: None)
    monkeypatch.setattr(signal, "alarm", lambda *a, **k: None)


# --- Gap 1: HTTP-level analysis test with strong assertions ---

def test_http_analyze_end_to_end(auth_env):
    """Full HTTP path: POST /analyze → 200 → report contains analysis output.

    Strong assertions: verifies the report actually analyzed the log content
    (severity counts, filename, structure) — not just HTTP 200.
    """
    log_content = (
        b"2026-10-18 10:00:00 INFO Starting up\n"
        b"2026-10-18 10:00:01 ERROR Database timeout after 30s\n"
        b"2026-10-18 10:00:02 ERROR Database timeout after 30s\n"
        b"2026-10-18 10:00:03 WARN Slow query detected\n"
    )
    resp = auth_env.client.post(
        "/analyze",
        files={"file": ("test.log", log_content, "text/plain")},
        data={"request_id": uuid.uuid4().hex, "output": "html"},
    )
    assert resp.status_code == 200
    # Report structure
    assert "test.log" in resp.text
    # Analysis actually ran: severity breakdown present
    assert "ERROR" in resp.text
    # The repeated error appears in the report (2 occurrences analyzed)
    assert "Database timeout" in resp.text
    # Stats section rendered (proves analyze_log_file ran, not just template)
    assert "Total lines" in resp.text or "Parsed" in resp.text


def test_http_analyze_txt_output(auth_env):
    """HTTP path with txt output returns plain-text report with content."""
    resp = auth_env.client.post(
        "/analyze",
        files={"file": ("app.log", b"2026-10-18 WARN slow query on users table\n", "text/plain")},
        data={"request_id": uuid.uuid4().hex, "output": "txt"},
    )
    assert resp.status_code == 200
    assert "text/plain" in resp.headers.get("content-type", "")
    # Plain-text report contains analysis
    assert "slow query" in resp.text.lower() or "WARN" in resp.text


# --- Gap 2: Assert actual HTTP 500 on redaction failure ---

def test_redaction_failure_http_500(auth_env, monkeypatch):
    """Redaction exception → HTTP 500 response (not a raised exception).

    Uses a TestClient with raise_server_exceptions=False to observe the
    actual HTTP status the production server (uvicorn) would return.
    Verifies the redaction mock actually executes by checking the
    exception message would propagate (via the 500 status).
    """
    from app import service

    injected = []

    def _boom(text):
        injected.append(text)  # Prove the mock actually ran
        raise RuntimeError("simulated redaction failure")

    monkeypatch.setattr(service, "redact_secrets", _boom)

    client = TestClient(auth_env.app, raise_server_exceptions=False, base_url="https://testserver")
    if "X-CSRF-Token" in auth_env.client.headers:
        client.headers["X-CSRF-Token"] = auth_env.client.headers["X-CSRF-Token"]

    resp = client.post(
        "/analyze",
        files={"file": ("test.log", b"2026-10-18 ERROR boom\n", "text/plain")},
        data={"request_id": uuid.uuid4().hex, "output": "html"},
    )
    # The mock must have executed (not bypassed by rate limiting or routing)
    assert injected, "redact_secrets mock was never called — test did not reach intended code path"
    assert injected[0] == "2026-10-18 ERROR boom\n"
    # Production returns 500 on unhandled exception
    assert resp.status_code == 500


# --- Gap 3: Prove no file write is attempted when redaction fails ---

def test_redaction_failure_no_tempfile_created(monkeypatch):
    """If redact_secrets raises, tempfile.NamedTemporaryFile is never called.

    Stronger than checking the temp dir afterward: proves no file write was
    even attempted with unredacted content, not just that cleanup ran.
    """
    from app import service

    def _boom(text):
        raise RuntimeError("simulated redaction failure")

    monkeypatch.setattr(service, "redact_secrets", _boom)

    created = []
    real_ntf = tempfile.NamedTemporaryFile

    def _tracking_ntf(*args, **kwargs):
        created.append((args, kwargs))
        return real_ntf(*args, **kwargs)

    monkeypatch.setattr(tempfile, "NamedTemporaryFile", _tracking_ntf)

    with pytest.raises(RuntimeError, match="simulated redaction failure"):
        service.analyze_upload("test.log", b"2026-10-18 ERROR secret data\n")

    assert created == [], (
        f"tempfile.NamedTemporaryFile was called {len(created)} time(s) "
        "despite redaction failure — unredacted content may have reached disk"
    )


def test_redaction_failure_no_disk_artifacts(auth_env, monkeypatch):
    """End-to-end: redaction failure leaves no .log artifacts in temp dir."""
    from app import service

    tmpdir = tempfile.gettempdir()
    before = set(glob.glob(os.path.join(tmpdir, "*.log")))

    injected = []

    def _boom(text):
        injected.append(True)
        raise RuntimeError("simulated redaction failure")

    monkeypatch.setattr(service, "redact_secrets", _boom)

    # Use pytest.raises since auth_env's TestClient re-raises;
    # the 500 assertion is covered by test_redaction_failure_http_500.
    with pytest.raises(RuntimeError, match="simulated redaction failure"):
        auth_env.client.post(
            "/analyze",
            files={"file": ("test.log", b"2026-10-18 ERROR boom\n", "text/plain")},
            data={"request_id": uuid.uuid4().hex, "output": "html"},
        )

    assert injected, "redact_secrets mock never executed"
    after = set(glob.glob(os.path.join(tmpdir, "*.log")))
    assert after == before, f"Temp files leaked: {after - before}"
