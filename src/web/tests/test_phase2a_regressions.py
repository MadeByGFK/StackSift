"""Route regressions and real PostgreSQL interleavings for the review blockers."""
import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, func
from sqlalchemy.orm import sessionmaker

from test_account_migrations import migrated_engine
from app import auth, credits as C, models as M, main, db as DB, analysis_admission as A
from app.sample_data import SAMPLE_LOG


@pytest.fixture
def env(migrated_engine, monkeypatch, tmp_path):
    engine, _ = migrated_engine
    sessions = sessionmaker(bind=engine, autoflush=False)
    with sessions() as db:
        user = M.User(email=f'{uuid.uuid4()}@example.com', email_verified=True)
        db.add(user); db.commit(); uid = user.id
        C.grant_credits(db, uid, 'admin', 'test', 20)
        session, token = auth.create_session(db, uid)
        db.commit(); csrf = session.csrf_token
    monkeypatch.setenv('DATABASE_URL', str(engine.url))
    monkeypatch.setattr(DB, 'SessionLocal', sessions)
    monkeypatch.setattr(main, '_PAID_PENDING_DIR', str(tmp_path / 'pending'))
    client = TestClient(main.app, base_url='https://testserver', raise_server_exceptions=False, client=('127.0.0.1', 50000))
    client.cookies.set(auth.SESSION_COOKIE, token)
    calls = []
    # The existing diagnostic service uses SIGALRM (main thread only).
    # Generate a real report here, then exercise the HTTP execution boundary.
    import copy
    report = main.analyze_upload('test.log', SAMPLE_LOG.encode())
    def analyze(*args):
        calls.append(args)
        return copy.deepcopy(report)
    monkeypatch.setattr(main, 'analyze_upload', analyze)
    yield SimpleNamespace(engine=engine, sessions=sessions, uid=uid, csrf=csrf, client=client, calls=calls)
    client.close()


def quota(env, n=10):
    with env.sessions() as db:
        for _ in range(n):
            db.add(M.FreeRequest(request_id=uuid.uuid4().hex, user_id=env.uid, fingerprint='old',
                status='failed', quota_bucket_trusted_ip='127.0.0.1',
                created_at=C._utcnow()-timedelta(minutes=2), deadline=C._utcnow()))
        db.commit()


def quote(env):
    content = SAMPLE_LOG.encode(); filename = 'test.log'; digest = A.fingerprint(filename, content)
    with env.sessions() as db:
        c = C.create_consent(db, env.uid, 'additional_analysis', digest, 1)
        db.commit(); cid = str(c.id)
    main._store_paid_pending(cid, filename, content)
    return dict(consent_id=cid, file_hash=digest, idempotency_key=cid, csrf_token=env.csrf)


def balance(env):
    with env.sessions() as db:
        return C.get_balance_summary(db, env.uid)['balance']


def test_new_paid_executes_and_replays_without_upload(env):
    quota(env); form = quote(env)
    first = env.client.post('/analyze/paid', data=form)
    assert first.status_code == 200, first.text
    assert len(env.calls) == 1 and balance(env) == 19
    assert main._load_paid_pending(form['consent_id']) is None
    # Free quota now available must not change the saved paid outcome.
    with env.sessions() as db:
        for fr in db.scalars(select(M.FreeRequest)):
            fr.created_at = C._utcnow()-timedelta(hours=2)
        db.commit()
    retry = env.client.post('/analyze/paid', data=form)
    assert retry.status_code == 200
    assert len(env.calls) == 1 and balance(env) == 19
    with env.sessions() as db:
        result = db.scalars(select(M.Result)).one()
        result.expires_at = C._utcnow()-timedelta(seconds=1); db.commit()
    assert env.client.post('/analyze/paid', data=form).status_code == 410
    assert len(env.calls) == 1 and balance(env) == 19


def test_failed_paid_retry_cannot_execute_again(env, monkeypatch):
    quota(env); form = quote(env)
    calls = []
    monkeypatch.setattr(main, 'analyze_upload', lambda *a: calls.append(a) or {'error': True, 'message': 'bad log'})
    assert env.client.post('/analyze/paid', data=form).status_code == 400
    for _ in range(3):
        assert env.client.post('/analyze/paid', data=form).status_code == 409
    assert len(calls) == 1 and balance(env) == 20
    with env.sessions() as db:
        assert db.scalar(select(M.RateBucket.attempts)) == 1


def test_inflight_retry_and_conflicting_input(env):
    quota(env); form = quote(env)
    with env.sessions() as db:
        C.admit_paid_operation(db, env.uid, 'additional_analysis', form['idempotency_key'], form['file_hash'],
            1, uuid.UUID(form['consent_id']), 'original-worker')
        db.commit()
    main._delete_paid_pending(form['consent_id'])
    assert env.client.post('/analyze/paid', data=form).status_code == 202
    assert env.client.post('/analyze/paid', data=dict(form, file_hash='other')).status_code == 409
    assert not env.calls and balance(env) == 19


def test_free_first_retry_is_durable_and_never_turns_paid(env):
    form = quote(env)
    assert env.client.post('/analyze/paid', data=form).status_code == 200
    quota(env)
    assert env.client.post('/analyze/paid', data=form).status_code == 200
    assert len(env.calls) == 1 and balance(env) == 20
    with env.sessions() as db:
        assert db.scalar(select(func.count()).select_from(M.Operation)) == 0


def test_burst_does_not_fall_through_to_paid(env):
    quota(env, 2)
    with env.sessions() as db:
        for fr in db.scalars(select(M.FreeRequest)):
            fr.created_at = C._utcnow()
        db.commit()
    form = quote(env)
    assert env.client.post('/analyze/paid', data=form).status_code == 429
    assert not env.calls and balance(env) == 20


def test_free_failed_upload_replay(env, monkeypatch):
    calls = []
    monkeypatch.setattr(main, 'analyze_upload', lambda *a: calls.append(a) or {'error': True, 'message': 'bad'})
    args = dict(files={'file': ('a.log', b'content')}, data={'request_id': 'free-failure'})
    assert env.client.post('/analyze', **args).status_code == 400
    assert env.client.post('/analyze', **args).status_code == 409
    assert len(calls) == 1


def operation(env, key='op'):
    with env.sessions() as db:
        consent = C.create_consent(db, env.uid, 'additional_analysis', key, 1)
        db.commit()
        op = C.admit_paid_operation(db, env.uid, 'additional_analysis', key, key, 1, consent.id, 'worker')
        db.commit(); return op.id


def test_recovery_ready_unlinked_result_and_unknown_executor(env):
    oid = operation(env)
    with env.sessions() as db:
        C.store_result(db, env.uid, oid, {'report': 'ready'})
        db.get(M.Operation, oid).lease_expires_at = C._utcnow()-timedelta(seconds=1)
        db.commit()
        assert C.recover_expired_operations(db) == 1
        assert db.get(M.Operation, oid).status == 'completed'
    oid2 = operation(env, 'unknown')
    with env.sessions() as db:
        db.get(M.Operation, oid2).lease_expires_at = C._utcnow()-timedelta(seconds=1); db.commit()
        assert C.recover_expired_operations(db) == 0
        assert db.get(M.Operation, oid2).status == 'reserved'
        assert C.recover_expired_operations(db, executor_stopped=lambda *args: args[0] == oid2) == 1
        assert db.get(M.Operation, oid2).status == 'expired'
        assert not C.verify_account_invariants(db, env.uid)
        assert not C.verify_capacity_invariants(db)


def test_completion_rejects_missing_foreign_and_corrupt_result(env):
    first, second = operation(env), operation(env, 'second')
    with env.sessions() as db:
        with pytest.raises(C.AdmissionError):
            C.complete_operation(db, first, 'worker')
        db.rollback()
        r = C.store_result(db, env.uid, second, {'ok': True}); db.commit(); rid = r.id
        with pytest.raises(C.AdmissionError):
            C.complete_operation(db, first, 'worker', rid)
        db.rollback()
        db.get(M.Result, rid).storage_manifest = '{}'; db.commit()
        with pytest.raises(C.AdmissionError, match='integrity'):
            C.complete_operation(db, second, 'worker', rid)
        db.rollback()


def test_invariants_find_allocation_cost_corruption(env):
    oid = operation(env)
    with env.sessions() as db:
        db.get(M.Operation, oid).cost = 2; db.commit()
        assert any(v.startswith('A4:') for v in C.verify_account_invariants(db, env.uid))
        assert C.reconcile_account(db, env.uid)
        assert C.has_active_restriction(db, env.uid, 'spend')


def test_postgres_last_free_slot_race(env):
    if env.engine.dialect.name != 'postgresql':
        pytest.skip('Row-lock interleaving requires PostgreSQL')
    quota(env, 9)
    barrier = Barrier(2)
    def attempt(i):
        with env.sessions() as db:
            barrier.wait(timeout=10)
            item, created = A.admit(db, env.uid, None, f'free-{i}', str(i), '127.0.0.1', str(i))
            db.commit()
            return created
    with ThreadPoolExecutor(2) as pool:
        assert sorted(pool.map(attempt, range(2))) == [False, True]


def test_postgres_duplicate_admission_and_completion_recovery_race(env):
    if env.engine.dialect.name != 'postgresql':
        pytest.skip('Row-lock interleaving requires PostgreSQL')
    with env.sessions() as db:
        consent = C.create_consent(db, env.uid, 'additional_analysis', 'same', 1)
        db.commit(); cid = consent.id
    barrier = Barrier(2)
    def admit(i):
        with env.sessions() as db:
            barrier.wait(timeout=10)
            op = C.admit_paid_operation(db, env.uid, 'additional_analysis', 'same', 'same', 1, cid, f'w{i}')
            db.commit(); return op.id
    with ThreadPoolExecutor(2) as pool:
        ids = list(pool.map(admit, range(2)))
    assert ids[0] == ids[1] and balance(env) == 19
    with env.sessions() as db:
        C.store_result(db, env.uid, ids[0], {'ok': True})
        db.get(M.Operation, ids[0]).lease_expires_at = C._utcnow()-timedelta(seconds=1)
        db.commit()
    barrier = Barrier(2)
    def recover(_):
        with env.sessions() as db:
            barrier.wait(timeout=10)
            return C.recover_expired_operations(db)
    with ThreadPoolExecutor(2) as pool:
        assert sum(pool.map(recover, range(2))) == 1
    with env.sessions() as db:
        assert not C.verify_account_invariants(db, env.uid)
        assert not C.verify_capacity_invariants(db)


def test_free_consent_cannot_authorize_later_paid_request(env):
    form = quote(env)
    assert env.client.post('/analyze/paid', data=form).status_code == 200
    quota(env)
    other = dict(form, idempotency_key='another-key')
    assert env.client.post('/analyze/paid', data=other).status_code != 200
    assert len(env.calls) == 1 and balance(env) == 20


def test_retention_removes_payload_but_keeps_identity(env):
    from app.credit_maintenance import cleanup_results
    oid = operation(env)
    with env.sessions() as db:
        r = C.store_result(db, env.uid, oid, {'sensitive': 'report'})
        C.complete_operation(db, oid, 'worker', r.id); db.commit()
        r.expires_at = C._utcnow()-timedelta(seconds=1); db.commit()
        cleanup_results(db)
        db.expire_all()
        assert db.get(M.Result, r.id).storage_manifest == '{}'
        assert db.get(M.Operation, oid).status == 'completed'
        assert not C.verify_account_invariants(db, env.uid)


def test_lost_http_response_does_not_refund_or_reexecute(env, monkeypatch):
    quota(env); form = quote(env)
    original = main._analysis_response
    def lost_response(request, status, data=None, *args, **kwargs):
        if data is not None:
            raise RuntimeError('simulated response loss after commit')
        return original(request, status, data, *args, **kwargs)
    monkeypatch.setattr(main, '_analysis_response', lost_response)
    assert env.client.post('/analyze/paid', data=form).status_code == 500
    assert len(env.calls) == 1 and balance(env) == 19
    monkeypatch.setattr(main, '_analysis_response', original)
    assert env.client.post('/analyze/paid', data=form).status_code == 200
    assert len(env.calls) == 1 and balance(env) == 19


def test_postgres_snapshot_during_concurrent_grant(env):
    if env.engine.dialect.name != 'postgresql':
        pytest.skip('Snapshot isolation requires PostgreSQL')
    from sqlalchemy import event
    from threading import Event, current_thread
    read_account, committed = Event(), Event()
    def after_read(conn, cursor, statement, params, context, many):
        if current_thread().name == 'snapshot-writer':
            return
        if statement.lstrip().startswith('SELECT credit_accounts.') and not read_account.is_set():
            read_account.set()
            assert committed.wait(10)
    def grant():
        assert read_account.wait(10)
        try:
            with env.sessions() as db:
                C.grant_credits(db, env.uid, 'admin', 'concurrent', 5); db.commit()
        finally:
            committed.set()
    from threading import Thread
    worker = Thread(target=grant, name='snapshot-writer')
    event.listen(env.engine, 'after_cursor_execute', after_read)
    try:
        worker.start()
        with env.sessions() as db:
            assert C.verify_account_invariants(db, env.uid) == []
    finally:
        event.remove(env.engine, 'after_cursor_execute', after_read)
        worker.join(10)
    assert balance(env) == 25


def test_postgres_recovery_vs_admission_and_settlement(env):
    if env.engine.dialect.name != 'postgresql':
        pytest.skip('Lock races require PostgreSQL')
    oid = operation(env)
    with env.sessions() as db:
        C.store_result(db, env.uid, oid, {'ready': True})
        db.get(M.Operation, oid).lease_expires_at = C._utcnow()-timedelta(seconds=1); db.commit()
        consent = C.create_consent(db, env.uid, 'additional_analysis', 'new', 1); db.commit(); cid = consent.id
    barrier = Barrier(2)
    def recovery():
        with env.sessions() as db:
            barrier.wait(10)
            return C.recover_expired_operations(db)
    def admission():
        with env.sessions() as db:
            barrier.wait(10)
            op = C.admit_paid_operation(db, env.uid, 'additional_analysis', 'new', 'new', 1, cid, 'new-worker')
            db.commit(); opid = op.id
            C.release_operation(db, opid, 'new-worker', 'test'); db.commit()
    with ThreadPoolExecutor(2) as pool:
        first, second = pool.submit(recovery), pool.submit(admission)
        assert first.result(timeout=15) == 1
        second.result(timeout=15)
    with env.sessions() as db:
        assert not C.verify_account_invariants(db, env.uid)
        assert not C.verify_capacity_invariants(db)


def test_recovery_rechecks_renewed_lease(env):
    oid = operation(env)
    with env.sessions() as db:
        db.get(M.Operation, oid).lease_expires_at = C._utcnow()-timedelta(seconds=1); db.commit()
    def supervisor(*args):
        with env.sessions() as other:
            other.get(M.Operation, oid).lease_expires_at = C._utcnow()+timedelta(minutes=5); other.commit()
        return True
    with env.sessions() as db:
        assert C.recover_expired_operations(db, executor_stopped=supervisor) == 0
        assert db.get(M.Operation, oid).status == 'reserved'
