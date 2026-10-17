"""Durable standard-analysis admission. PostgreSQL serializes all admission
on the shared capacity row before checking identities or rolling IP quotas.
The no-database demo retains its existing in-process limiter in main.py.
"""
import json
import uuid
from datetime import datetime, timedelta, timezone
from sqlalchemy import select, func
from app import credits as C, models as M


def fingerprint(filename, content):
    return C.hash_input(filename.encode() + b'\0' + content)


def lookup(db, user_id, anonymous_hash, key, digest):
    if user_id:
        op = C.find_operation(db, user_id, 'additional_analysis', key, digest)
        if op:
            return op
    fr = db.get(M.FreeRequest, key, populate_existing=True)
    if fr and (fr.user_id != user_id or fr.anonymous_session_hash != anonymous_hash or fr.fingerprint != digest):
        raise C.AdmissionError('request identity conflict (409)')
    return fr


def admit(db, user_id, anonymous_hash, key, digest, ip, worker, consent_id=None):
    scope = C._ensure_capacity_scope(db, 'global:paid', C.DEFAULT_GLOBAL_CONCURRENT_LIMIT)
    existing = lookup(db, user_id, anonymous_hash, key, digest)
    if existing:
        return existing, False
    consent = C.validate_consent(db, consent_id, user_id, "additional_analysis", digest, 1) if consent_id else None
    now = C._utcnow()
    # Keep the existing rolling hour and two-per-minute policy, including failed attempts.
    def count_free(since):
        return db.scalar(select(func.count()).select_from(M.FreeRequest).where(
            M.FreeRequest.quota_bucket_trusted_ip == ip, M.FreeRequest.created_at > since))
    burst = count_free(now - timedelta(minutes=1)) + db.scalar(select(func.count()).select_from(M.Operation).where(
        M.Operation.type == 'additional_analysis', M.Operation.input_manifest == ip,
        M.Operation.created_at > now - timedelta(minutes=1)))
    if burst >= 2:
        raise C.AdmissionError('Too many requests. Please wait a minute and try again.')
    if count_free(now - timedelta(hours=1)) >= 10:
        if consent_id is None:
            return None, False
        op = C.admit_paid_operation(db, user_id, 'additional_analysis', key, digest, 1, consent_id, worker,
            input_manifest=ip)
        return op, op.worker_id == worker
    active_free = db.scalar(select(func.count()).select_from(M.FreeRequest).where(M.FreeRequest.status == 'in_progress'))
    if scope.used + active_free >= scope.max_limit:
        raise C.AdmissionError('Analysis capacity exhausted. Please try again later.')
    # A stable bucket, with rolling-window membership in retained request timestamps.
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    from sqlalchemy.dialects.sqlite import insert as sqlite_insert
    insert = pg_insert if db.bind.dialect.name == 'postgresql' else sqlite_insert
    db.execute(insert(M.FreeBucket).values(trusted_ip=ip, window_start=epoch, policy_version=1, attempts=0)
        .on_conflict_do_nothing())
    bucket = db.execute(select(M.FreeBucket).where(M.FreeBucket.trusted_ip == ip,
        M.FreeBucket.window_start == epoch, M.FreeBucket.policy_version == 1).with_for_update()
        .execution_options(populate_existing=True)).scalar_one()
    bucket.attempts += 1
    fr = M.FreeRequest(request_id=key, user_id=user_id, anonymous_session_hash=anonymous_hash,
        fingerprint=digest, quota_bucket_trusted_ip=ip, quota_bucket_window_start=epoch,
        deadline=now+C.LEASE_TTL, created_at=now)
    db.add(fr)
    db.flush()
    if consent is not None:
        consent.consumed_by_free_request_id = key
        db.flush()
    return fr, True


def replay(db, item, user_id):
    if item.status in ('reserved', 'in_progress'):
        return 202, None, 'This analysis is in progress. Please retry this request later.'
    if item.status in ('failed', 'expired'):
        return 409, None, 'This request failed. Start a new request to run another analysis.'
    result = db.get(M.Result, item.result_id) if item.result_id else None
    try:
        data = C.result_payload(result, user_id=user_id,
            operation_id=item.id if isinstance(item, M.Operation) else None,
            free_request_id=item.request_id if isinstance(item, M.FreeRequest) else None)
        if isinstance(item, M.FreeRequest) and result.anonymous_owner_hash != item.anonymous_session_hash:
            raise C.AdmissionError('result owner mismatch')
        return 200, data, None
    except (C.AdmissionError, ValueError):
        return 410, None, 'This result has expired or is unavailable. Start a new request to regenerate it.'


def finish_free(db, key, data=None, failure=None):
    C._ensure_capacity_scope(db, 'global:paid', C.DEFAULT_GLOBAL_CONCURRENT_LIMIT)
    fr = db.execute(select(M.FreeRequest).where(M.FreeRequest.request_id == key).with_for_update()
        .execution_options(populate_existing=True)).scalar_one()
    if fr.status != 'in_progress':
        raise C.AdmissionError('request already settled')
    if failure:
        fr.status, fr.failure_code = 'failed', failure
        fr.execution_generation += 1
    else:
        raw = json.dumps(data, default=str)
        result = M.Result(user_id=fr.user_id, anonymous_owner_hash=fr.anonymous_session_hash,
            free_request_id=key, type='analysis', storage_manifest=raw,
            integrity_digest=C.hash_input(raw.encode()), byte_count=len(raw.encode()),
            ready_at=C._utcnow(), expires_at=C._utcnow()+timedelta(days=7))
        db.add(result)
        db.flush()
        fr.status, fr.result_id = 'completed', result.id
    db.flush()
