"""Issue #107: retention extension (+90 days / 1 credit, stackable, capped).

APPROVED spec trims T2/T5/T6: COST_RETENTION_EXTENSION = 1 per +90-day
unit added to the report's CURRENT expires_at, lifetime ceiling
ready_at + 365 days, full-unit only (409, no debit, past the ceiling),
atomic reserve -> extend -> receipt -> complete, exactly -1 on success
and 0 on failure, 402 + /credits on insufficient credits.

Uses the paid_env HTTP fixture (migrated DB) plus direct Result inserts
with a realistic analysis payload, so expiry arithmetic is exact.
"""

import copy
import json
import uuid
from datetime import timedelta

import pytest
from test_account_migrations import migrated_engine  # noqa: F401  (fixture)
from test_phase2b_paid_e2e import paid_env, _signup_verify_login, _http_balance  # noqa: F401

from app import credits as C, models as M
from app.sample_data import SAMPLE_LOG


def _payload(env, filename="test.log"):
    data = env.client  # placeholder to keep linters quiet about env use
    from app import main
    payload = main.analyze_upload("test.log", SAMPLE_LOG.encode())
    payload = copy.deepcopy(payload)
    payload["filename"] = filename
    payload.pop("current_user", None)
    payload.pop("csrf_token", None)
    return payload


def _make_report(env, uid, *, filename="test.log", payload=None,
                 ready_age_days=0, expires_in_days=7, result_type="analysis"):
    if payload is None:
        payload = _payload(env, filename)
    raw = json.dumps(payload, default=str)
    now = C._utcnow()
    with env.sessions() as db:
        r = M.Result(
            user_id=uid, free_request_id=uuid.uuid4().hex, type=result_type,
            storage_manifest=raw, integrity_digest=C.hash_input(raw.encode()),
            byte_count=len(raw.encode()),
            ready_at=now - timedelta(days=ready_age_days),
            expires_at=now + timedelta(days=expires_in_days),
        )
        db.add(r)
        db.commit()
        db.refresh(r)
        return r.id, C._as_aware(r.expires_at), C._as_aware(r.ready_at)


def _expiry(env, rid):
    with env.sessions() as db:
        r = db.get(M.Result, rid)
        return C._as_aware(r.expires_at)


def _extend(env, rid, csrf, key):
    return env.client.post(
        f"/reports/{rid}/retention",
        data={"csrf_token": csrf, "idempotency_key": key},
    )


def test_extend_success_charges_exactly_one_and_adds_90_days(paid_env):
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    assert _http_balance(env) == 3
    rid, original_expiry, _ = _make_report(env, uid)

    r = _extend(env, rid, csrf, "ext-1")
    assert r.status_code == 200, r.text[:400]
    assert _http_balance(env) == 2
    delta = _expiry(env, rid) - original_expiry
    assert abs(delta.total_seconds() - 90 * 86400) < 2

    with env.sessions() as db:
        ops = db.query(M.Operation).filter(
            M.Operation.user_id == uid,
            M.Operation.type == "retention_extension").all()
        assert len(ops) == 1 and ops[0].status == "completed" and ops[0].cost == 1
        receipt = db.get(M.Result, ops[0].result_id)
        assert receipt is not None and receipt.type == "report_action"
        manifest = json.loads(receipt.storage_manifest)
        assert manifest["action_kind"] == "retention_extension"
        assert manifest["target_result_id"] == str(rid)
        assert C.verify_account_invariants(db, uid) == []
        assert C.verify_capacity_invariants(db) == []


def test_extend_replay_same_key_no_second_charge_or_extension(paid_env):
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    rid, original_expiry, _ = _make_report(env, uid)
    assert _extend(env, rid, csrf, "ext-dup").status_code == 200
    after_first = _expiry(env, rid)
    r = _extend(env, rid, csrf, "ext-dup")
    assert r.status_code == 200, r.text[:400]
    assert _http_balance(env) == 2
    assert _expiry(env, rid) == after_first


def test_extend_distinct_keys_stack(paid_env):
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    rid, original_expiry, _ = _make_report(env, uid)
    assert _extend(env, rid, csrf, "ext-a").status_code == 200
    assert _extend(env, rid, csrf, "ext-b").status_code == 200
    assert _http_balance(env) == 1
    delta = _expiry(env, rid) - original_expiry
    assert abs(delta.total_seconds() - 180 * 86400) < 2


def test_extend_cap_rejects_full_unit_without_debit(paid_env):
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    # ready 300 days ago -> ceiling is 65 days from now; +90 overshoots.
    rid, original_expiry, _ = _make_report(env, uid, ready_age_days=300)
    r = _extend(env, rid, csrf, "ext-cap")
    assert r.status_code == 409, r.text[:400]
    assert _http_balance(env) == 3
    assert _expiry(env, rid) == original_expiry
    with env.sessions() as db:
        assert db.query(M.Operation).filter(
            M.Operation.user_id == uid,
            M.Operation.type == "retention_extension").count() == 0


def test_extend_exactly_to_ceiling_is_allowed(paid_env):
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    # ceiling = ready + 365d = now + 165d; expiry set so +90 lands on it.
    rid, _, ready = _make_report(env, uid, ready_age_days=200)
    ceiling = ready + timedelta(days=365)
    with env.sessions() as db:
        r0 = db.get(M.Result, rid)
        r0.expires_at = ceiling - timedelta(days=90)
        db.commit()
    r = _extend(env, rid, csrf, "ext-edge")
    assert r.status_code == 200, r.text[:400]
    assert abs((_expiry(env, rid) - ceiling).total_seconds()) < 2


def test_extend_insufficient_credits_402_with_purchase_url(paid_env):
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    rid, _, _ = _make_report(env, uid)
    for i in range(3):  # spend the 3 signup credits on extensions
        assert _extend(env, rid, csrf, f"ext-spend-{i}").status_code == 200
    assert _http_balance(env) == 0
    before = _expiry(env, rid)
    r = _extend(env, rid, csrf, "ext-broke")
    assert r.status_code == 402, r.text[:400]
    assert r.json().get("purchase_url") == "/credits"
    assert _expiry(env, rid) == before


def test_extend_expired_report_410_no_charge(paid_env):
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    rid, _, _ = _make_report(env, uid, expires_in_days=-1)
    r = _extend(env, rid, csrf, "ext-dead")
    assert r.status_code == 410, r.text[:400]
    assert _http_balance(env) == 3


def test_extend_foreign_report_404_and_anonymous_401(paid_env):
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    rid, _, _ = _make_report(env, uid)
    _, uid2, csrf2 = _signup_verify_login(env)
    r = _extend(env, rid, csrf2, "ext-foreign")
    assert r.status_code == 404, r.text[:400]
    with env.sessions() as db:
        assert C.get_balance_summary(db, uid)["balance"] == 3
        assert C.get_balance_summary(db, uid2)["balance"] == 3


def test_extend_requires_csrf(paid_env):
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    rid, _, _ = _make_report(env, uid)
    r = env.client.post(f"/reports/{rid}/retention",
                        data={"csrf_token": "wrong", "idempotency_key": "ext-csrf"})
    assert r.status_code == 403
    assert _http_balance(env) == 3


def test_extend_comparison_report_allowed(paid_env):
    """T4: retention applies to any owned analysis Result regardless of kind."""
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    rid, original_expiry, _ = _make_report(env, uid, result_type="comparison")
    r = _extend(env, rid, csrf, "ext-compare")
    assert r.status_code == 200, r.text[:400]
    delta = _expiry(env, rid) - original_expiry
    assert abs(delta.total_seconds() - 90 * 86400) < 2


def test_extend_does_not_extend_pdf_artifact(paid_env):
    """T6: source extension leaves the PDF Result's own expiry untouched."""
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    rid, _, _ = _make_report(env, uid)
    pdf = env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert pdf.status_code == 200, pdf.text[:300]
    with env.sessions() as db:
        pdf_result = db.query(M.Result).filter(
            M.Result.user_id == uid, M.Result.type == "pdf").one()
        pdf_expiry = C._as_aware(pdf_result.expires_at)
    assert _extend(env, rid, csrf, "ext-pdf-independent").status_code == 200
    with env.sessions() as db:
        pdf_result = db.query(M.Result).filter(
            M.Result.user_id == uid, M.Result.type == "pdf").one()
        assert C._as_aware(pdf_result.expires_at) == pdf_expiry


def test_extend_settlement_failure_rolls_back_everything(paid_env, monkeypatch):
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    rid, original_expiry, _ = _make_report(env, uid)

    def boom(*args, **kwargs):
        raise RuntimeError("forced receipt failure")

    monkeypatch.setattr(C, "store_report_action_receipt", boom)
    r = _extend(env, rid, csrf, "ext-fail")
    assert r.status_code == 500, r.text[:400]
    assert _http_balance(env) == 3
    assert _expiry(env, rid) == original_expiry
    with env.sessions() as db:
        assert C.verify_account_invariants(db, uid) == []
        assert C.verify_capacity_invariants(db) == []


def test_cleanup_spares_extended_and_clears_control(paid_env):
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    rid_ext, _, _ = _make_report(env, uid)
    rid_ctl, _, _ = _make_report(env, uid, filename="control.log")
    assert _extend(env, rid_ext, csrf, "ext-cleanup").status_code == 200
    # Move both source expiries to the past on the CONTROL only by ageing
    # the control past its (unextended) expiry; the extended report keeps
    # its new +90d expiry in the future.
    with env.sessions() as db:
        ctl = db.get(M.Result, rid_ctl)
        ctl.expires_at = C._utcnow() - timedelta(days=1)
        db.commit()
    from app import credit_maintenance
    with env.sessions() as db:
        credit_maintenance.cleanup_results(db)
    with env.sessions() as db:
        assert db.get(M.Result, rid_ctl).deleted_at is not None
        ext = db.get(M.Result, rid_ext)
        assert ext.deleted_at is None
        assert ext.storage_manifest != "{}"
    # At the new expiry the extended report is cleaned up too.
    with env.sessions() as db:
        ext = db.get(M.Result, rid_ext)
        ext.expires_at = C._utcnow() - timedelta(minutes=1)
        db.commit()
    with env.sessions() as db:
        credit_maintenance.cleanup_results(db)
    with env.sessions() as db:
        assert db.get(M.Result, rid_ext).deleted_at is not None


def test_extend_replay_after_receipt_cleanup_never_recharges(paid_env):
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    rid, _, _ = _make_report(env, uid)
    assert _extend(env, rid, csrf, "ext-replay-clean").status_code == 200
    after = _expiry(env, rid)
    # Simulate receipt payload cleanup (receipt Results expire in 7 days).
    with env.sessions() as db:
        receipt = db.query(M.Result).filter(
            M.Result.user_id == uid, M.Result.type == "report_action").one()
        receipt.expires_at = C._utcnow() - timedelta(days=1)
        db.commit()
    from app import credit_maintenance
    with env.sessions() as db:
        credit_maintenance.cleanup_results(db)
    r = _extend(env, rid, csrf, "ext-replay-clean")
    assert r.status_code == 200, r.text[:400]
    assert _http_balance(env) == 2
    assert _expiry(env, rid) == after
