"""Issue #107: public share-route abuse limiting + log redaction (draft §6/§7).

The public limiter is a distinct PostgresRateLimiter instance
(30/min, 300/hr per trusted IP) called WITHOUT request_id (no replay
bypass), keyed by an isolated ``s:`` namespace fitting
RateLimitBucket.trusted_ip String(45), failing closed with 503.
``/s/*`` token paths must be redacted in application logs.
"""

import logging
import re
import uuid

import pytest
from fastapi.testclient import TestClient
from test_account_migrations import migrated_engine  # noqa: F401  (fixture)
from test_phase2b_paid_e2e import paid_env, _signup_verify_login  # noqa: F401
from test_report_sharing import _make_report, _create_share, _token_from, _anon_client

from app import main
from app.rate_limit import BurstLimited, HourlyLimited, PostgresRateLimiter, RateLimitUnavailable


def _setup(env):
    _, uid, csrf = _signup_verify_login(env)
    rid = _make_report(env, uid)
    resp = _create_share(env, rid, csrf)
    assert resp.status_code == 200, resp.text[:300]
    return rid, _token_from(resp)


def test_share_limit_key_namespace_and_length():
    from app.report_access import share_limit_key
    k1 = share_limit_key("127.0.0.1")
    assert k1.startswith("s:") and len(k1) == 42
    assert share_limit_key("127.0.0.1") == k1
    assert share_limit_key("10.0.0.9") != k1
    k6 = share_limit_key("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
    assert k6.startswith("s:") and len(k6) == 42


def test_public_limiter_enforces_on_hits_and_misses(paid_env, monkeypatch):
    env = paid_env
    rid, token = _setup(env)
    monkeypatch.setattr(main, "share_limiter",
                        PostgresRateLimiter(burst_max=2, burst_window=60,
                                            hourly_max=1000, hourly_window=3600))
    anon = _anon_client()
    assert anon.get(f"/s/{token}").status_code == 200
    assert anon.get(f"/s/{'0' * 64}").status_code == 404  # misses count too
    third = anon.get(f"/s/{token}")
    assert third.status_code == 429
    assert third.headers.get("retry-after")


def test_public_limiter_fails_closed_503(paid_env, monkeypatch):
    env = paid_env
    rid, token = _setup(env)

    class Down:
        def admit(self, db, ip, request_id=None):
            raise RateLimitUnavailable("down")

    monkeypatch.setattr(main, "share_limiter", Down())
    anon = _anon_client()
    r = anon.get(f"/s/{token}")
    assert r.status_code == 503


def test_public_limiter_has_no_replay_bypass(paid_env, monkeypatch):
    """admit() must be called without request_id for share traffic."""
    env = paid_env
    rid, token = _setup(env)
    seen = {}
    real = main.share_limiter

    class Spy:
        def admit(self, db, ip, request_id=None):
            seen["request_id"] = request_id
            seen["ip"] = ip
            return real.admit(db, ip, request_id=request_id)

    monkeypatch.setattr(main, "share_limiter", Spy())
    anon = _anon_client()
    assert anon.get(f"/s/{token}").status_code == 200
    assert seen["request_id"] is None
    assert seen["ip"].startswith("s:")


def test_share_path_log_redaction_filter():
    from app.report_access import SharePathRedactionFilter
    token = "a" * 64
    record = logging.LogRecord(
        "uvicorn.access", logging.INFO, __file__, 1,
        '127.0.0.1 - "GET /s/%s HTTP/1.1" 200', (token,), None)
    # uvicorn.access formats args into the message; emulate by rendering.
    rendered = record.getMessage()
    assert token in rendered  # sanity: the raw record really carries it
    filt = SharePathRedactionFilter()
    filt.filter(record)
    assert token not in record.getMessage()
    assert "[redacted]" in record.getMessage()


def test_share_tokens_not_in_app_logs_during_request(paid_env, caplog):
    env = paid_env
    rid, token = _setup(env)
    anon = _anon_client()
    with caplog.at_level(logging.DEBUG):
        assert anon.get(f"/s/{token}").status_code == 200
    for record in caplog.records:
        # The httpx logger is the TEST CLIENT's own request log (it
        # necessarily knows the URL it requested); the requirement is
        # that no APPLICATION logger emits the raw token.
        if record.name.startswith("httpx"):
            continue
        assert token not in record.getMessage()
