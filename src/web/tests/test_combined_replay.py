"""Combined PR #17 + PR #28 replay behavior (real code, no mocks of the durable path).

When PR #17 (durable request identities) and PR #28 (shared rate limiting)
are both present, retrying a completed analysis must:
  1. serve the STORED result (via PR #17's lookup/replay),
  2. NOT rerun the analysis,
  3. NOT consume additional quota in either limiter.

Requires TEST_POSTGRES_URL (provided by CI).
"""
import os
import re
import uuid
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

pytestmark = pytest.mark.skipif(
    not os.environ.get("TEST_POSTGRES_URL"),
    reason="TEST_POSTGRES_URL is required for the combined replay test",
)


@pytest.fixture
def pg_schema():
    url = os.environ["TEST_POSTGRES_URL"]
    schema = "replay_test_" + uuid.uuid4().hex
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


def _anon_cookie(response):
    m = re.search(r"__Host-stacksift_analysis=([0-9a-f]{64})", response.headers.get("set-cookie", ""))
    assert m, "expected the anonymous analysis cookie"
    return m.group(1)


def test_combined_replay_serves_stored_result(monkeypatch, pg_schema):
    import asyncio
    import httpx
    from app import main
    import app.db as db_module

    url, schema = pg_schema
    engine = create_engine(
        url, connect_args={"options": f"-csearch_path={schema}"}, poolclass=NullPool
    )
    factory = sessionmaker(bind=engine)
    try:
        # Route ALL database access (PR #28's limiter + PR #17's durable
        # path) to the test database.
        monkeypatch.setattr(db_module, "SessionLocal", factory)
        monkeypatch.setattr(main, "_use_shared_limiter", lambda: True)

        calls = {"analyzed": 0}

        def fake_analyze(filename, content):
            calls["analyzed"] += 1
            return {"incidents": [{"title": "synthetic", "severity": "high"}]}

        monkeypatch.setattr(main, "analyze_upload", fake_analyze)
        monkeypatch.setattr(
            main, "render_text_report", lambda data: f"REPORT:{data['incidents'][0]['title']}"
        )

        async def run():
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=main.app), base_url="http://test"
            ) as c:
                rid = "replay-" + uuid.uuid4().hex
                payload = {"output": "txt", "request_id": rid}
                files = lambda: {"file": ("app.log", b"ERROR boom\nINFO ok\n")}
                r1 = await c.post("/analyze", files=files(), data=payload)
                assert r1.status_code == 200, r1.text[:300]
                cookie = _anon_cookie(r1)
                # Retry the SAME completed request: same id, content, cookie.
                r2 = await c.post(
                    "/analyze",
                    files=files(),
                    data=payload,
                    cookies={"__Host-stacksift_analysis": cookie},
                )
                return r1, r2

        r1, r2 = asyncio.run(run())

        assert r2.status_code == 200, r2.text[:300]
        assert calls["analyzed"] == 1, "retry must not rerun the analysis"
        assert r2.text == r1.text, "retry must serve the stored result"
        # Quota consumed exactly once, in both limiters.
        with factory() as db:
            assert db.execute(text("SELECT COUNT(*) FROM rate_limit_hits")).scalar() == 1
            assert db.execute(text("SELECT COUNT(*) FROM free_requests")).scalar() == 1
            assert main.shared_limiter.remaining(db, "127.0.0.1") == 9
    finally:
        engine.dispose()
