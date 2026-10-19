"""Opt-in account fixtures; collection never changes database configuration."""
from types import SimpleNamespace
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker


@pytest.fixture
def auth_env(tmp_path, monkeypatch):
    from app import auth, email
    from app.db import Base, get_db
    from app.main import app
    engine = create_engine(f"sqlite:///{tmp_path / 'accounts.db'}", connect_args={"check_same_thread": False, "timeout": 20})
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
    monkeypatch.setattr(auth, "check_password_breached", lambda _: False)
    sent = []
    monkeypatch.setattr(email, "send_verification_email", lambda address, token: sent.append(("verify", address, token)))
    monkeypatch.setattr(email, "send_password_reset_email", lambda address, token: sent.append(("reset", address, token)))
    try:
        with TestClient(app, base_url="https://testserver") as client:
            client.headers["X-CSRF-Token"] = client.get("/auth/csrf").json()["csrf_token"]
            yield SimpleNamespace(client=client, sessions=sessions, sent=sent, engine=engine, app=app)
    finally:
        engine.dispose()
