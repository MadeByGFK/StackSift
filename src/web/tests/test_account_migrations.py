"""SQLite and real PostgreSQL migrations/constraints/atomic redemption.

Set TEST_POSTGRES_URL to a disposable UTF-8 PostgreSQL database. Each test uses a unique
schema; no existing schemas or application database configuration are changed.
"""
import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier

import pytest
from alembic import command
from alembic.config import Config
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.models import User, OAuthAccount, Session, EmailVerification, PasswordReset
from app.auth import generate_token, hash_token
from app.account_tokens import redeem


@pytest.fixture(params=["sqlite", "postgresql", "postgresql+psycopg2", "postgresql+psycopg"])
def migrated_engine(request, tmp_path):
    schema = None
    admin = None
    if request.param != "sqlite":
        url = os.environ.get("TEST_POSTGRES_URL")
        if not url:
            pytest.skip("TEST_POSTGRES_URL is required for actual PostgreSQL tests")
        url = make_url(url).set(drivername=request.param)
        schema = "auth_test_" + uuid.uuid4().hex
        admin = create_engine(url)
        with admin.begin() as conn:
            conn.execute(text(f'CREATE SCHEMA "{schema}"'))
        engine = create_engine(url, connect_args={"options": f"-csearch_path={schema}"})
    else:
        engine = create_engine(f"sqlite:///{tmp_path / 'migration.db'}", connect_args={"check_same_thread": False, "timeout": 30})
    config = Config()
    config.set_main_option("script_location", str(Path(__file__).parents[1] / "alembic"))
    try:
        with engine.begin() as conn:
            config.attributes["connection"] = conn
            command.upgrade(config, "head")
        yield engine, config
    finally:
        engine.dispose()
        if admin:
            with admin.begin() as conn:
                conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
            admin.dispose()


def test_upgrade_models_constraints_and_downgrade(migrated_engine):
    engine, config = migrated_engine
    with engine.connect() as conn:
        assert compare_metadata(MigrationContext.configure(conn), Base.metadata) == []
    factory = sessionmaker(bind=engine)
    with factory() as db:
        user = User(email="roundtrip@example.com", email_verified=True)
        db.add(user)
        db.commit()
        ident = user.id
        assert isinstance(ident, uuid.UUID)
        assert db.get(User, str(ident)).id == ident
        db.add(User(email="roundtrip@example.com"))
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()
        db.add(OAuthAccount(user_id=ident, provider="github", provider_user_id="123"))
        db.commit()
        db.add(OAuthAccount(user_id=ident, provider="github", provider_user_id="123"))
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()
    if engine.dialect.name == "postgresql":
        assert str(inspect(engine).get_columns("users")[0]["type"]) == "UUID"
        with factory() as db:
            db.add(OAuthAccount(user_id=uuid.uuid4(), provider="github", provider_user_id="bad"))
            with pytest.raises(IntegrityError):
                db.commit()
    with engine.begin() as conn:
        config.attributes["connection"] = conn
        command.downgrade(config, "base")
        assert set(inspect(conn).get_table_names()) == {"alembic_version"}
        command.upgrade(config, "head")
        assert compare_metadata(MigrationContext.configure(conn), Base.metadata) == []


@pytest.mark.parametrize("model", [EmailVerification, PasswordReset])
@pytest.mark.parametrize("same_token", [True, False])
def test_concurrent_redemption_and_sibling_invalidation(migrated_engine, model, same_token):
    engine, _ = migrated_engine
    factory = sessionmaker(bind=engine)
    now = datetime.now(timezone.utc)
    tokens = [generate_token(), generate_token()]
    with factory() as db:
        user = User(email="race@example.com", password_hash="old")
        db.add(user)
        db.flush()
        ident = user.id
        for token in tokens:
            db.add(model(user_id=ident, token_hash=hash_token(token), expires_at=now + timedelta(hours=1)))
        db.add(Session(user_id=ident, token_hash=hash_token(generate_token()), csrf_token=generate_token(), expires_at=now+timedelta(days=1)))
        db.commit()
    barrier = Barrier(2)
    def consume(token):
        with factory() as db:
            barrier.wait(timeout=10)
            return redeem(db, model, token, "new" if model is PasswordReset else None)
    with ThreadPoolExecutor(2) as executor:
        results = list(executor.map(consume, [tokens[0], tokens[0] if same_token else tokens[1]]))
    assert sorted(results) == [False, True]
    with factory() as db:
        assert all(t.used_at is not None for t in db.query(model))
        if model is PasswordReset:
            assert db.get(User, ident).password_hash == "new"
            assert all(s.revoked_at is not None for s in db.query(Session))
        else:
            assert db.get(User, ident).email_verified is True


@pytest.mark.parametrize("model", [EmailVerification, PasswordReset])
def test_expired_tokens_leave_account_unchanged(migrated_engine, model):
    engine, _ = migrated_engine
    factory = sessionmaker(bind=engine)
    token = generate_token()
    with factory() as db:
        user = User(email="expired@example.com", password_hash="unchanged")
        db.add(user)
        db.flush()
        ident = user.id
        db.add(model(user_id=ident, token_hash=hash_token(token), expires_at=datetime.now(timezone.utc)-timedelta(seconds=1)))
        db.commit()
        assert not redeem(db, model, token, "changed")
        db.expire_all()
        assert db.get(User, ident).password_hash == "unchanged"
        assert db.get(User, ident).email_verified is False


@pytest.mark.parametrize("driver", ["postgresql", "postgresql+psycopg2", "postgresql+psycopg"])
def test_app_imports_with_postgres_url_without_connecting(driver):
    """Catch missing drivers at the same import boundary as deployed Uvicorn."""
    import subprocess
    import sys
    env = {**os.environ, "DATABASE_URL": f"{driver}://test:test@localhost:1/test",
           "PYTHONPATH": str(Path(__file__).parents[1])}
    result = subprocess.run([sys.executable, "-c", "from app.main import app; assert app"],
                            env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr



def test_startup_migrates_configured_engine_from_any_directory(migrated_engine, monkeypatch, tmp_path):
    import asyncio
    from app import db as database
    from app.main import run_migrations
    engine, config = migrated_engine
    with engine.begin() as conn:
        config.attributes["connection"] = conn
        command.downgrade(config, "base")
    # Deliberately invalid raw URL proves startup uses the already configured engine.
    monkeypatch.setenv("DATABASE_URL", "must-not-be-reparsed://")
    monkeypatch.setattr(database, "engine", engine)
    monkeypatch.chdir(tmp_path)
    asyncio.run(run_migrations())
    assert set(Base.metadata.tables).issubset(inspect(engine).get_table_names())
    with sessionmaker(bind=engine)() as db:
        db.add(User(email="startup@example.com"))
        db.commit()
    asyncio.run(run_migrations())
    with sessionmaker(bind=engine)() as db:
        assert db.query(User).filter_by(email="startup@example.com").count() == 1


def test_startup_skips_without_database_url(monkeypatch):
    import asyncio
    from unittest.mock import Mock
    from app import db as database
    from app.main import run_migrations
    engine = Mock()
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setattr(database, "engine", engine)
    asyncio.run(run_migrations())
    engine.begin.assert_not_called()


def test_startup_failure_does_not_log_credentials(monkeypatch, caplog):
    import asyncio
    from unittest.mock import Mock
    from app import db as database
    from app.main import run_migrations
    engine = Mock()
    engine.begin.side_effect = RuntimeError("database-password-secret")
    monkeypatch.setenv("DATABASE_URL", "configured")
    monkeypatch.setattr(database, "engine", engine)
    asyncio.run(run_migrations())
    assert "Account migrations failed (RuntimeError)" in caplog.text
    assert "database-password-secret" not in caplog.text
