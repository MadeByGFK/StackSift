"""Shared Postgres-backed rate limiter: atomicity, multi-worker, idempotency.

Postgres tests require TEST_POSTGRES_URL (provided by CI). Each test gets
a unique schema upgraded to Alembic head, then dropped.
"""
import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from multiprocessing import get_context
from pathlib import Path
from threading import Barrier

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from app.rate_limit import (
    BurstLimited,
    HourlyLimited,
    PostgresRateLimiter,
    RateLimitUnavailable,
)

pytestmark = pytest.mark.skipif(
    not os.environ.get("TEST_POSTGRES_URL"),
    reason="TEST_POSTGRES_URL is required for shared-limiter tests",
)


@pytest.fixture
def pg_schema():
    """Unique Postgres schema, migrated to head. Yields (url, schema)."""
    url = os.environ["TEST_POSTGRES_URL"]
    schema = "rl_test_" + uuid.uuid4().hex
    admin = create_engine(url, poolclass=NullPool)
    with admin.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_engine(
        url, connect_args={"options": f"-csearch_path={schema}"}, poolclass=NullPool
    )
    config = Config()
    config.set_main_option(
        "script_location", str(Path(__file__).parents[1] / "alembic")
    )
    try:
        with engine.begin() as conn:
            config.attributes["connection"] = conn
            command.upgrade(config, "head")
        yield url, schema
    finally:
        engine.dispose()
        with admin.begin() as conn:
            conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


def _factory(url, schema):
    engine = create_engine(
        url, connect_args={"options": f"-csearch_path={schema}"}, poolclass=NullPool
    )
    return sessionmaker(bind=engine), engine


def _worker_admit(payload):
    """Module-level worker: fresh engine per process (fork-safe)."""
    url, schema, ip, attempts, burst_max, burst_window, hourly_max, hourly_window = payload
    factory, engine = _factory(url, schema)
    try:
        limiter = PostgresRateLimiter(
            burst_max=burst_max,
            burst_window=burst_window,
            hourly_max=hourly_max,
            hourly_window=hourly_window,
        )
        ok = 0
        for _ in range(attempts):
            with factory() as db:
                try:
                    limiter.admit(db, ip)
                    ok += 1
                except (BurstLimited, HourlyLimited):
                    pass
        return ok
    finally:
        engine.dispose()


def test_burst_limit_across_processes(pg_schema):
    """The regression test: 4 processes x 3 rapid admits -> exactly 2 admitted.

    Fails on the old in-memory limiter (each process would admit its own 2).
    """
    url, schema = pg_schema
    ip = "203.0.113.7"
    payload = (url, schema, ip, 3, 2, 60, 10, 3600)
    ctx = get_context("fork")
    with ctx.Pool(4) as pool:
        results = pool.map(_worker_admit, [payload] * 4)
    assert sum(results) == 2


def test_hourly_limit_across_processes(pg_schema):
    url, schema = pg_schema
    ip = "203.0.113.8"
    payload = (url, schema, ip, 2, 100, 60, 3, 3600)
    ctx = get_context("fork")
    with ctx.Pool(3) as pool:
        results = pool.map(_worker_admit, [payload] * 3)
    assert sum(results) == 3


def test_simultaneous_admissions_never_exceed(pg_schema):
    """Barrier-synchronized threads: admitted + rejected == attempted, admitted <= limit."""
    url, schema = pg_schema
    factory, engine = _factory(url, schema)
    try:
        limiter = PostgresRateLimiter(burst_max=2, burst_window=60, hourly_max=10, hourly_window=3600)
        ip = "203.0.113.9"
        barrier = Barrier(8)

        def attempt(_):
            with factory() as db:
                barrier.wait(timeout=15)
                try:
                    limiter.admit(db, ip)
                    return True
                except (BurstLimited, HourlyLimited):
                    return False

        with ThreadPoolExecutor(8) as ex:
            results = list(ex.map(attempt, range(8)))
        assert sum(results) == 2
        assert len(results) == 8
        with factory() as db:
            assert limiter.remaining(db, ip) == 8
    finally:
        engine.dispose()


def test_remaining_reflects_shared_state(pg_schema):
    url, schema = pg_schema
    factory, engine = _factory(url, schema)
    try:
        limiter = PostgresRateLimiter()
        ip = "203.0.113.10"
        with factory() as db:
            assert limiter.remaining(db, ip) == 10
            limiter.admit(db, ip)
        # A different session/process sees the same shared count.
        with factory() as db:
            assert limiter.remaining(db, ip) == 9
    finally:
        engine.dispose()


def test_db_failure_fails_closed(pg_schema):
    """If the limiter's tables are gone, admit() raises — never allows."""
    url, schema = pg_schema
    factory, engine = _factory(url, schema)
    try:
        with engine.begin() as conn:
            conn.execute(text("DROP TABLE rate_limit_hits"))
            conn.execute(text("DROP TABLE rate_limit_buckets"))
        limiter = PostgresRateLimiter()
        with factory() as db:
            with pytest.raises(RateLimitUnavailable):
                limiter.admit(db, "203.0.113.11")
    finally:
        engine.dispose()


def _create_free_requests(engine):
    """Ensure free_requests exists (PR #17's migrations create it here)."""
    with engine.begin() as conn:
        conn.execute(
            text(
                "CREATE TABLE IF NOT EXISTS free_requests ("
                "request_id VARCHAR(255) PRIMARY KEY, "
                "status VARCHAR(20) NOT NULL, "
                "quota_bucket_trusted_ip VARCHAR(45), "
                "fingerprint VARCHAR(64), "
                "deadline TIMESTAMPTZ)"
            )
        )


def _insert_request(engine, rid, status, ip):
    """Insert a free_requests row satisfying PR #17's schema.

    The check constraint requires exactly one owner (user XOR anonymous),
    and created_at/updated_at have Python-side defaults only, so raw SQL
    must supply them.
    """
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO free_requests "
                "(request_id, status, quota_bucket_trusted_ip, fingerprint, deadline, "
                " anonymous_session_hash, created_at, updated_at) "
                "VALUES (:rid, :status, :ip, 'fp', now() + interval '1 hour', "
                "        'testhash', now(), now())"
            ),
            {"rid": rid, "status": status, "ip": ip},
        )

def test_replay_consumes_no_quota(pg_schema):
    """A completed request_id retried from the same IP is a replay: no quota burned."""
    url, schema = pg_schema
    factory, engine = _factory(url, schema)
    try:
        _create_free_requests(engine)
        _insert_request(engine, 'req-1', 'completed', '127.0.0.1')
        limiter = PostgresRateLimiter()
        with factory() as db:
            assert limiter.admit(db, "203.0.113.12", request_id="req-1") == "replay"
            assert limiter.remaining(db, "203.0.113.12") == 10
    finally:
        engine.dispose()


def test_replay_different_ip_consumes_quota(pg_schema):
    """Same request_id from another IP is treated as new (conservative)."""
    url, schema = pg_schema
    factory, engine = _factory(url, schema)
    try:
        _create_free_requests(engine)
        _insert_request(engine, 'req-2', 'completed', '127.0.0.1')
        limiter = PostgresRateLimiter()
        with factory() as db:
            assert limiter.admit(db, "203.0.113.13", request_id="req-2") == "ok"
            assert limiter.remaining(db, "203.0.113.13") == 9
    finally:
        engine.dispose()


def test_incomplete_request_consumes_quota(pg_schema):
    """An in-progress (not completed) request_id still consumes quota."""
    url, schema = pg_schema
    factory, engine = _factory(url, schema)
    try:
        _create_free_requests(engine)
        _insert_request(engine, 'req-3', 'in_progress', '127.0.0.1')
        limiter = PostgresRateLimiter()
        with factory() as db:
            assert limiter.admit(db, "127.0.0.1", request_id="req-3") == "ok"
            assert limiter.remaining(db, "127.0.0.1") == 9
    finally:
        engine.dispose()


def test_expired_hits_are_cleaned(pg_schema):
    url, schema = pg_schema
    factory, engine = _factory(url, schema)
    try:
        limiter = PostgresRateLimiter(burst_max=2, burst_window=60, hourly_max=10, hourly_window=3600)
        ip = "203.0.113.16"
        old = datetime.now(timezone.utc) - timedelta(hours=2)
        with engine.begin() as conn:
            conn.execute(text("INSERT INTO rate_limit_buckets (trusted_ip) VALUES (:ip)"), {"ip": ip})
            conn.execute(
                text("INSERT INTO rate_limit_hits (trusted_ip, hit_at) VALUES (:ip, :ts)"),
                {"ip": ip, "ts": old},
            )
        with factory() as db:
            assert limiter.remaining(db, ip) == 10  # expired hit not counted
            assert limiter.admit(db, ip) == "ok"
        with engine.begin() as conn:
            n = conn.execute(
                text("SELECT COUNT(*) FROM rate_limit_hits WHERE trusted_ip = :ip"), {"ip": ip}
            ).scalar()
            assert n == 1  # the expired row was deleted on write
    finally:
        engine.dispose()


def test_http_429_shapes(monkeypatch, pg_schema):
    """End-to-end wiring: 3 rapid POSTs -> 200, 200, 429 with Retry-After: 60."""
    import asyncio
    import httpx
    from app import main

    url, schema = pg_schema
    factory, engine = _factory(url, schema)
    try:
        monkeypatch.setattr(main, "_use_shared_limiter", lambda: True)
        monkeypatch.setattr(main, "_db_session", lambda: factory())
        import app.db as db_module
        monkeypatch.setattr(db_module, "SessionLocal", factory)
        monkeypatch.setattr(main, "analyze_upload", lambda *args: {})
        monkeypatch.setattr(main, "render_text_report", lambda data: "report")

        async def run():
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=main.app), base_url="http://test"
            ) as c:
                async def post():
                    return await c.post(
                        "/analyze",
                        files={"file": ("test.log", b"ERROR synthetic")},
                        data={"output": "txt"},
                    )

                responses = [await post() for _ in range(3)]
                assert [r.status_code for r in responses] == [200, 200, 429]
                assert responses[2].headers["retry-after"] == "60"

        asyncio.run(run())
    finally:
        engine.dispose()


def _post_analyze(c, request_id=None):
    data = {"output": "txt"}
    if request_id:
        data["request_id"] = request_id
    return c.post(
        "/analyze",
        files={"file": ("test.log", b"ERROR synthetic")},
        data=data,
    )


def test_replay_serves_stored_result_not_rerun(monkeypatch, pg_schema):
    """Finding 1: a completed request_id hands off to the durable path.

    analyze_upload must NOT run again, quota must NOT be consumed, and the
    stored result is served.
    """
    import asyncio
    import httpx
    from fastapi.responses import PlainTextResponse
    from app import main

    url, schema = pg_schema
    factory, engine = _factory(url, schema)
    try:
        _create_free_requests(engine)
        _insert_request(engine, 'req-replay', 'completed', '127.0.0.1')
        monkeypatch.setattr(main, "_use_shared_limiter", lambda: True)
        monkeypatch.setattr(main, "_db_session", lambda: factory())
        calls = {"analyzed": 0, "durable": 0}

        def fake_analyze(*args):
            calls["analyzed"] += 1
            return {}

        def fake_durable(request, filename, content, request_id, output):
            calls["durable"] += 1
            assert request_id == "req-replay"
            return PlainTextResponse("stored-result")

        monkeypatch.setattr(main, "analyze_upload", fake_analyze)
        monkeypatch.setattr(main, "_durable_analysis", fake_durable, raising=False)

        async def run():
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=main.app), base_url="http://test"
            ) as c:
                r = await _post_analyze(c, request_id="req-replay")
                assert r.status_code == 200
                assert r.text == "stored-result"

        asyncio.run(run())
        assert calls == {"analyzed": 0, "durable": 1}
        with factory() as db:
            assert main.shared_limiter.remaining(db, "127.0.0.1") == 10
    finally:
        engine.dispose()


def test_session_creation_failure_fails_closed(monkeypatch, pg_schema):
    """Finding 2: if even session creation fails, /analyze 503s (never bypasses)."""
    import asyncio
    import httpx
    from sqlalchemy.exc import OperationalError
    from app import main

    url, schema = pg_schema
    _, engine = _factory(url, schema)
    try:
        monkeypatch.setattr(main, "_use_shared_limiter", lambda: True)

        def broken_session():
            raise OperationalError("connection failed", None, None)

        monkeypatch.setattr(main, "_db_session", broken_session)
        calls = {"analyzed": 0}
        monkeypatch.setattr(main, "analyze_upload", lambda *a: calls.__setitem__("analyzed", 1) or {})

        async def run():
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=main.app), base_url="http://test"
            ) as c:
                r = await _post_analyze(c)
                assert r.status_code == 503
                assert r.headers["retry-after"] == "60"

        asyncio.run(run())
        assert calls == {"analyzed": 0}
    finally:
        engine.dispose()


def test_remaining_display_failure_shows_zero(monkeypatch, pg_schema):
    """Finding 2: quota-display DB failure -> '0 of 10', page still renders 200."""
    import asyncio
    import httpx
    from sqlalchemy.exc import OperationalError
    from app import main

    url, schema = pg_schema
    _, engine = _factory(url, schema)
    try:
        monkeypatch.setattr(main, "_use_shared_limiter", lambda: True)

        def broken_session():
            raise OperationalError("connection failed", None, None)

        monkeypatch.setattr(main, "_db_session", broken_session)

        async def run():
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=main.app), base_url="http://test"
            ) as c:
                r = await c.get("/")
                assert r.status_code == 200
                assert "0 of 10 analyses left" in r.text

        asyncio.run(run())
    finally:
        engine.dispose()
