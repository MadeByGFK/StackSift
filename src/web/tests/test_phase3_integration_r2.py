"""Phase 3 integration tests, round 2 — addresses GFD review findings on PR #35.

GFD verdict on PR #35: CHANGES REQUIRED (test coverage gaps, not production defects).
This file closes the three gaps:

1. Persistence test bypassed HTTP analysis → new test exercises the full
   HTTP /analyze path (upload → 200 → report content).
2. Redaction test did not assert HTTP 500 → new test uses a TestClient with
   raise_server_exceptions=False to assert the actual HTTP 500 response.
3. Temp-dir check does not prove unredacted content was never written →
   new test patches tempfile.NamedTemporaryFile to prove it is never called
   when redaction raises (i.e., no file write is even attempted).

No production-code changes. Tests only.
"""

import glob
import os
import tempfile
import uuid
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient


# --- Gap 1: HTTP-level analysis test ---

def test_http_analyze_end_to_end(auth_env):
    """Full HTTP path: POST /analyze → 200 → report contains analysis output.

    Unlike the module-level persistence tests, this exercises the real HTTP
    stack: multipart parsing, redaction, analysis, template rendering.
    """
    resp = auth_env.client.post(
        "/analyze",
        files={"file": ("test.log", b"2026-10-18 10:00:00 ERROR Database timeout\n", "text/plain")},
        data={"request_id": uuid.uuid4().hex, "output": "html"},
    )
    assert resp.status_code == 200
    # Report renders with analysis content
    assert "Database timeout" in resp.text or "ERROR" in resp.text
    assert "test.log" in resp.text


def test_http_analyze_txt_output(auth_env):
    """HTTP path with txt output returns plain-text report."""
    resp = auth_env.client.post(
        "/analyze",
        files={"file": ("app.log", b"2026-10-18 WARN slow query\n", "text/plain")},
        data={"request_id": uuid.uuid4().hex, "output": "txt"},
    )
    assert resp.status_code == 200
    assert "text/plain" in resp.headers.get("content-type", "")


# --- Gap 2: Assert actual HTTP 500 on redaction failure ---

def test_redaction_failure_http_500(auth_env, monkeypatch):
    """Redaction exception → HTTP 500 response (not a raised exception).

    Uses a TestClient with raise_server_exceptions=False to observe the
    actual HTTP status the production server (uvicorn) would return.
    """
    from app import service

    def _boom(text):
        raise RuntimeError("simulated redaction failure")

    monkeypatch.setattr(service, "redact_secrets", _boom)

    # Build a non-raising client on the same app
    client = TestClient(auth_env.app, raise_server_exceptions=False, base_url="https://testserver")
    # Carry over CSRF header (not strictly needed for /analyze, but harmless)
    if "X-CSRF-Token" in auth_env.client.headers:
        client.headers["X-CSRF-Token"] = auth_env.client.headers["X-CSRF-Token"]

    resp = client.post(
        "/analyze",
        files={"file": ("test.log", b"2026-10-18 ERROR boom\n", "text/plain")},
        data={"request_id": uuid.uuid4().hex, "output": "html"},
    )
    assert resp.status_code == 500


# --- Gap 3: Prove no file write is attempted when redaction fails ---

def test_redaction_failure_no_tempfile_created(monkeypatch):
    """If redact_secrets raises, tempfile.NamedTemporaryFile is never called.

    This is stronger than checking the temp dir afterward: it proves no file
    write was even attempted with unredacted content, not just that cleanup
    ran.
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


def test_redaction_failure_no_disk_artifacts(auth_env, monkeypatch, tmp_path):
    """End-to-end: redaction failure leaves no .log artifacts in temp dir.

    Complements the NamedTemporaryFile assertion with a filesystem-level check.
    """
    from app import service

    tmpdir = tempfile.gettempdir()
    before = set(glob.glob(os.path.join(tmpdir, "*.log")))

    def _boom(text):
        raise RuntimeError("simulated redaction failure")

    monkeypatch.setattr(service, "redact_secrets", _boom)

    with pytest.raises(RuntimeError, match="simulated redaction failure"):
        auth_env.client.post(
            "/analyze",
            files={"file": ("test.log", b"2026-10-18 ERROR boom\n", "text/plain")},
            data={"request_id": uuid.uuid4().hex, "output": "html"},
        )

    after = set(glob.glob(os.path.join(tmpdir, "*.log")))
    assert after == before, f"Temp files leaked: {after - before}"
