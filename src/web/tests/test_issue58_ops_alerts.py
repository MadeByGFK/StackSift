"""Operations alerting for paid-launch readiness (issue #58).

Acceptance criterion under test (non-founder parts):
- Maintenance jobs that fail repeatedly alert the founder instead of dying
  silently; a single transient failure stays a log line.
- Stuck credit reservations (paid operations past their lease, free requests
  past their deadline — recovery needs human-supplied executor evidence)
  alert the founder.
- Sustained analysis failures (threshold failed analyses in a trailing
  window) alert the founder.

Alerts go to OPS_ALERT_EMAIL via Resend; the email send is monkeypatched so
no test touches the network. The "named owner" half of the criterion (the
actual address) is founder configuration, not code.

Evidence database: TEST_POSTGRES_URL (Postgres 16, the CI service) when set,
otherwise a local SQLite file.
"""
import os
import uuid
from datetime import timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool


def _engine_for(tmp_path):
    pg_url = os.environ.get("TEST_POSTGRES_URL")
    if pg_url:
        schema = "fp58_" + uuid.uuid4().hex
        admin = create_engine(pg_url, poolclass=NullPool)
        with admin.begin() as conn:
            conn.execute(text(f'CREATE SCHEMA "{schema}"'))
        admin.dispose()
        engine = create_engine(
            pg_url,
            connect_args={"options": f"-csearch_path={schema}"},
            poolclass=NullPool,
        )
        return engine, schema
    path = tmp_path / f"opsalert58_{uuid.uuid4().hex[:8]}.db"
    engine = create_engine(
        f"sqlite:///{path}",
        connect_args={"check_same_thread": False, "timeout": 20},
    )

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, _):
        connection.execute("PRAGMA foreign_keys=ON")

    return engine, None


@pytest.fixture
def ops_env(tmp_path, monkeypatch):
    from app.db import Base
    import app.models  # noqa: F401 -- register tables before create_all
    from app import credit_maintenance as cm, ops_alerts

    engine, schema = _engine_for(tmp_path)
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)
    monkeypatch.delenv("OPS_ALERT_EMAIL", raising=False)
    cm.reset_job_state()
    ops_alerts.reset_alert_state()

    sent = []

    def fake_send(to, subject, html):
        sent.append({"to": to, "subject": subject, "html": html})
        return True

    monkeypatch.setattr("app.email.send_email", fake_send)
    try:
        yield SimpleNamespace(sessions=sessions, sent=sent, cm=cm, alerts=ops_alerts)
    finally:
        cm.reset_job_state()
        ops_alerts.reset_alert_state()
        engine.dispose()
        if schema:
            admin = create_engine(os.environ["TEST_POSTGRES_URL"], poolclass=NullPool)
            with admin.begin() as conn:
                conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
            admin.dispose()


def _make_user(db, models):
    uid = uuid.uuid4()
    db.add(models.User(id=uid, email=f"{uid.hex[:8]}@test.com", email_verified=True))
    db.commit()
    return uid


def _make_operation(db, models, uid, *, status="reserved", lease_delta=None, failure=False):
    from app import credits as C
    lease = C._utcnow() + (lease_delta if lease_delta is not None else timedelta(hours=1))
    op = models.Operation(
        user_id=uid,
        type="additional_analysis",
        idempotency_key=f"key-{uuid.uuid4().hex[:8]}",
        request_hash="0" * 64,
        cost=2,
        worker_id="worker-test",
        lease_expires_at=lease,
        status=status,
    )
    if failure:
        op.failure_code = "executor_crashed"
    db.add(op)
    db.commit()
    return op


def _make_free_request(db, models, uid, *, status="in_progress", deadline_delta=None):
    from app import credits as C
    deadline = C._utcnow() + (deadline_delta if deadline_delta is not None else timedelta(hours=1))
    fr = models.FreeRequest(
        request_id=f"fr-{uuid.uuid4().hex[:12]}",
        user_id=uid,
        fingerprint="1" * 64,
        status=status,
        deadline=deadline,
    )
    db.add(fr)
    db.commit()
    return fr


# --- ops_alerts unit behavior ---------------------------------------------

def test_alert_dropped_without_recipient(ops_env):
    assert ops_env.alerts.send_ops_alert("subject", "<p>x</p>") is False
    assert ops_env.sent == []


def test_alert_sent_when_configured(ops_env, monkeypatch):
    monkeypatch.setenv("OPS_ALERT_EMAIL", "owner@example.com")
    assert ops_env.alerts.send_ops_alert("Stuck things", "<p>detail</p>") is True
    assert len(ops_env.sent) == 1
    assert ops_env.sent[0]["to"] == "owner@example.com"
    assert ops_env.sent[0]["subject"].startswith("[StackSift]")


def test_alert_throttled_per_dedupe_key(ops_env, monkeypatch):
    monkeypatch.setenv("OPS_ALERT_EMAIL", "owner@example.com")
    assert ops_env.alerts.send_ops_alert("s", "<p>1</p>", dedupe_key="k1") is True
    assert ops_env.alerts.send_ops_alert("s", "<p>2</p>", dedupe_key="k1") is False
    assert ops_env.alerts.send_ops_alert("s", "<p>3</p>", dedupe_key="k2") is True
    assert len(ops_env.sent) == 2


# --- maintenance job failure counting --------------------------------------

def _boom(_db):
    raise RuntimeError("job exploded")


def test_job_alert_fires_on_third_consecutive_failure(ops_env, monkeypatch):
    monkeypatch.setenv("OPS_ALERT_EMAIL", "owner@example.com")
    cm = ops_env.cm
    db = ops_env.sessions()
    try:
        assert cm._run_job(db, "demo-job", _boom) is None
        assert cm._run_job(db, "demo-job", _boom) is None
        assert ops_env.sent == []  # transient failures stay log lines
        assert cm._run_job(db, "demo-job", _boom) is None
        assert len(ops_env.sent) == 1
        assert "demo-job" in ops_env.sent[0]["subject"]
        assert cm._job_failures["demo-job"] == 3
    finally:
        db.close()


def test_job_failure_count_resets_on_success(ops_env):
    cm = ops_env.cm
    db = ops_env.sessions()
    try:
        cm._run_job(db, "flaky-job", _boom)
        cm._run_job(db, "flaky-job", _boom)
        assert cm._job_failures["flaky-job"] == 2
        assert cm._run_job(db, "flaky-job", lambda _d: "ok") == "ok"
        assert cm._job_failures["flaky-job"] == 0
    finally:
        db.close()


def test_job_exception_does_not_raise_and_session_recovers(ops_env):
    import app.models as models
    cm = ops_env.cm
    db = ops_env.sessions()
    try:
        assert cm._run_job(db, "bad-job", _boom) is None
        # Session is still usable afterwards (rolled back, not poisoned).
        assert db.scalar(__import__("sqlalchemy").select(models.User.id).limit(1)) is None
    finally:
        db.close()


# --- stuck reservations ----------------------------------------------------

def test_stuck_reservations_alert(ops_env, monkeypatch):
    import app.models as models
    monkeypatch.setenv("OPS_ALERT_EMAIL", "owner@example.com")
    cm = ops_env.cm
    db = ops_env.sessions()
    try:
        uid = _make_user(db, models)
        _make_operation(db, models, uid, status="reserved", lease_delta=timedelta(hours=-2))
        _make_free_request(db, models, uid, status="in_progress", deadline_delta=timedelta(hours=-1))
        signals = cm.check_ops_signals(db)
        assert signals["stuck_reservations"] == {"operations": 1, "free_requests": 1}
        assert len(ops_env.sent) == 1
        assert "reservation" in ops_env.sent[0]["subject"].lower()
        # Second pass is throttled: one alert per incident per hour.
        cm.check_ops_signals(db)
        assert len(ops_env.sent) == 1
    finally:
        db.close()


def test_no_stuck_alert_when_nothing_stuck(ops_env, monkeypatch):
    import app.models as models
    monkeypatch.setenv("OPS_ALERT_EMAIL", "owner@example.com")
    cm = ops_env.cm
    db = ops_env.sessions()
    try:
        uid = _make_user(db, models)
        _make_operation(db, models, uid, status="reserved", lease_delta=timedelta(hours=2))
        signals = cm.check_ops_signals(db)
        assert signals["stuck_reservations"] == {"operations": 0, "free_requests": 0}
        assert ops_env.sent == []
    finally:
        db.close()


# --- sustained failures -----------------------------------------------------

def test_sustained_failures_alert_at_threshold(ops_env, monkeypatch):
    import app.models as models
    monkeypatch.setenv("OPS_ALERT_EMAIL", "owner@example.com")
    cm = ops_env.cm
    db = ops_env.sessions()
    try:
        uid = _make_user(db, models)
        for _ in range(4):
            _make_operation(db, models, uid, status="failed", failure=True)
        _make_free_request(db, models, uid, status="failed")
        signals = cm.check_ops_signals(db)
        assert signals["recent_failures"] == {"operations": 4, "free_requests": 1}
        assert len(ops_env.sent) == 1
        assert "failure" in ops_env.sent[0]["subject"].lower()
    finally:
        db.close()


def test_no_sustained_alert_below_threshold(ops_env, monkeypatch):
    import app.models as models
    monkeypatch.setenv("OPS_ALERT_EMAIL", "owner@example.com")
    cm = ops_env.cm
    db = ops_env.sessions()
    try:
        uid = _make_user(db, models)
        for _ in range(3):
            _make_operation(db, models, uid, status="failed", failure=True)
        signals = cm.check_ops_signals(db)
        assert signals["recent_failures"]["operations"] == 3
        assert ops_env.sent == []
    finally:
        db.close()
