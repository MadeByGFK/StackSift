"""Issue #107: retention extension (+90 days / 1 credit, stackable, capped).

APPROVED spec trims T2/T5/T6: COST_RETENTION_EXTENSION = 1 per +90-day
unit added to the report's CURRENT expires_at, lifetime ceiling
ready_at + 365 days, full-unit only (409, no debit, past the ceiling),
atomic reserve -> extend -> receipt -> complete, exactly -1 on success
and 0 on failure, 402 + /credits on insufficient credits.

Uses the paid_env HTTP fixture (migrated DB) plus direct Result inserts
with a realistic analysis payload, so expiry arithmetic is exact.

PREMISE CHANGED (#164 Phase C, Decision 5 / C5): retention extensions
are NO LONGER SOLD. A new extension POST refuses 410 ("Retention
extensions are no longer sold; paid reports include 90 days of
retention.") AFTER the ReportAction replay fence and after the
Phase B product-paid 409 — so a COMPLETED pre-cutover extension still
REPLAYS its recorded response (no second charge/extension), while
every new admission (any balance, any report kind, at/past the old
ceiling, expired or not) refuses with no charge and no date change.
Expiries already in force are untouched. Fixtures therefore seed the
legacy balance and completed extensions directly (never via the
retired signup grant or a live extension POST).
"""

import copy
import json
import uuid
from datetime import timedelta

import pytest
from test_account_migrations import migrated_engine  # noqa: F401  (fixture)
from test_phase2b_paid_e2e import paid_env, _signup_verify_login, _http_balance, _drain_signup  # noqa: F401

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


RETIREMENT_ERROR = (
    "Retention extensions are no longer sold; paid reports include "
    "90 days of retention.")


def _seed_balance(env, uid, qty=10):
    """Seed a legacy credit balance directly (Phase C: never via the
    retired signup grant)."""
    with env.sessions() as db:
        C.grant_credits(db, uid, "purchase",
                        f"seed-{uuid.uuid4().hex}", qty)
        db.commit()


def _seed_completed_extension(env, uid, rid, key):
    """Record a COMPLETED pre-cutover extension on its original terms,
    directly in the fixture (mirrors the old route's one transaction:
    consent -> admit -> extend -> receipt -> ReportAction -> complete;
    exactly one 1-credit charge). Returns the new expiry."""
    from app import report_access as RA
    with env.sessions() as db:
        source = db.get(M.Result, rid)
        request_hash = RA.action_request_hash(source, "retention_extension")
        previous_expiry = C._as_aware(source.expires_at)
        new_expiry = previous_expiry + timedelta(
            days=C.RETENTION_EXTENSION_DAYS)
        consent = C.create_consent(
            db, uid, "retention_extension", request_hash,
            C.COST_RETENTION_EXTENSION)
        db.flush()
        op = C.admit_paid_operation(
            db, uid, "retention_extension", key, request_hash,
            C.COST_RETENTION_EXTENSION, consent.id, "seed-worker")
        source.expires_at = new_expiry
        db.flush()
        receipt = C.store_report_action_receipt(db, uid, op.id, {
            "action_kind": "retention_extension",
            "target_result_id": str(rid),
            "previous_expiry": previous_expiry.isoformat(),
            "new_expiry": new_expiry.isoformat(),
        })
        db.add(M.ReportAction(
            owner_user_id=uid, result_id=rid,
            action_kind="retention_extension", idempotency_key=key,
            request_hash=request_hash, resulting_expiry=new_expiry,
            operation_id=op.id))
        db.flush()
        C.complete_operation(db, op.id, "seed-worker",
                             result_id=receipt.id,
                             lease_generation=op.lease_generation)
        db.commit()
        return new_expiry


def _retention_ops(env, uid):
    with env.sessions() as db:
        return db.query(M.Operation).filter(
            M.Operation.user_id == uid,
            M.Operation.type == "retention_extension").all()


def test_extend_new_admission_refused_410_no_charge_no_extension(paid_env):
    # Was test_extend_success_charges_exactly_one_and_adds_90_days.
    # PREMISE CHANGED (#164 Phase C): a new extension admission is
    # refused 410 — even with a funded legacy balance — with the
    # retirement message, no charge, no operation, no ReportAction,
    # and no date change (the old success assertions, at the same
    # strength, on the refusal).
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    _seed_balance(env, uid, 10)
    assert _http_balance(env) == 10
    rid, original_expiry, _ = _make_report(env, uid)

    r = _extend(env, rid, csrf, "ext-1")
    assert r.status_code == 410, r.text[:400]
    assert r.json()["error"] == RETIREMENT_ERROR
    assert _http_balance(env) == 10  # no charge
    assert _expiry(env, rid) == original_expiry  # no extension

    with env.sessions() as db:
        assert _retention_ops(env, uid) == []
        assert db.query(M.ReportAction).filter(
            M.ReportAction.result_id == rid).count() == 0
        assert db.query(M.Result).filter(
            M.Result.user_id == uid,
            M.Result.type == "report_action").count() == 0
        assert C.verify_account_invariants(db, uid) == []
        assert C.verify_capacity_invariants(db) == []


def test_extend_replay_same_key_no_second_charge_or_extension(paid_env):
    # Subject PRESERVED (C5): a completed pre-cutover extension
    # replays its recorded response post-cutover. The completed
    # extension is seeded on its original terms (one 1-credit
    # charge, +90 days, receipt + ReportAction), so the replay is
    # measured against a real recorded outcome.
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    _seed_balance(env, uid, 10)
    rid, original_expiry, _ = _make_report(env, uid)
    new_expiry = _seed_completed_extension(env, uid, rid, "ext-dup")
    assert _http_balance(env) == 9  # one 1-credit charge total
    assert _expiry(env, rid) == new_expiry
    delta = new_expiry - original_expiry
    assert abs(delta.total_seconds() - 90 * 86400) < 2
    with env.sessions() as db:
        ops = _retention_ops(env, uid)
        assert len(ops) == 1 and ops[0].status == "completed" and ops[0].cost == 1
        receipt = db.get(M.Result, ops[0].result_id)
        assert receipt is not None and receipt.type == "report_action"
        manifest = json.loads(receipt.storage_manifest)
        assert manifest["action_kind"] == "retention_extension"
        assert manifest["target_result_id"] == str(rid)

    r = _extend(env, rid, csrf, "ext-dup")
    assert r.status_code == 200, r.text[:400]
    body = r.json()
    assert body["replayed"] is True
    assert body["expires_at"].startswith(
        new_expiry.strftime("%Y-%m-%dT%H:%M"))
    assert _http_balance(env) == 9  # replay charges nothing more
    assert _expiry(env, rid) == new_expiry  # and extends nothing more
    assert len(_retention_ops(env, uid)) == 1


def test_extend_distinct_keys_each_refused_no_stacking(paid_env):
    # Was test_extend_distinct_keys_stack. PREMISE CHANGED (#164
    # Phase C): distinct NEW keys no longer stack extensions — each
    # is its own new admission and refuses 410, so the expiry and
    # balance are exactly where they started after both attempts.
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    _seed_balance(env, uid, 10)
    rid, original_expiry, _ = _make_report(env, uid)
    for key in ("ext-a", "ext-b"):
        r = _extend(env, rid, csrf, key)
        assert r.status_code == 410, r.text[:400]
        assert r.json()["error"] == RETIREMENT_ERROR
    assert _http_balance(env) == 10  # neither attempt charged
    assert _expiry(env, rid) == original_expiry  # nothing stacked
    assert _retention_ops(env, uid) == []


def test_extend_beyond_ceiling_refused_410_without_debit(paid_env):
    # Was test_extend_cap_rejects_full_unit_without_debit. PREMISE
    # CHANGED (#164 Phase C): the 410 retirement refusal precedes the
    # old 409 ceiling check (which is now unreachable), so a report
    # whose +90 would overshoot the ceiling refuses 410 — still with
    # no debit, no date change, and no operation.
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    _seed_balance(env, uid, 10)
    # ready 300 days ago -> ceiling is 65 days from now; +90 overshoots.
    rid, original_expiry, _ = _make_report(env, uid, ready_age_days=300)
    r = _extend(env, rid, csrf, "ext-cap")
    assert r.status_code == 410, r.text[:400]
    assert r.json()["error"] == RETIREMENT_ERROR
    assert _http_balance(env) == 10
    assert _expiry(env, rid) == original_expiry
    assert _retention_ops(env, uid) == []


def test_extend_exactly_to_ceiling_refused_410_after_cutover(paid_env):
    # Was test_extend_exactly_to_ceiling_is_allowed. PREMISE CHANGED
    # (#164 Phase C): even an extension that would land exactly on
    # the old ceiling is a new admission and refuses 410 — the
    # expiry stays at ceiling - 90 days and nothing is charged.
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    _seed_balance(env, uid, 10)
    # ceiling = ready + 365d = now + 165d; expiry set so +90 lands on it.
    rid, _, ready = _make_report(env, uid, ready_age_days=200)
    ceiling = ready + timedelta(days=365)
    with env.sessions() as db:
        r0 = db.get(M.Result, rid)
        r0.expires_at = ceiling - timedelta(days=90)
        db.commit()
    before = _expiry(env, rid)
    r = _extend(env, rid, csrf, "ext-edge")
    assert r.status_code == 410, r.text[:400]
    assert r.json()["error"] == RETIREMENT_ERROR
    assert _http_balance(env) == 10
    assert _expiry(env, rid) == before
    assert abs((_expiry(env, rid) - ceiling).total_seconds()
               + 90 * 86400) < 2  # still 90 days SHORT of the ceiling


def test_extend_zero_balance_refused_410_not_402_no_purchase_url(paid_env):
    # Was test_extend_insufficient_credits_402_with_purchase_url.
    # PREMISE CHANGED (#164 Phase C): with the signup grant removed
    # the user genuinely has 0 credits, and a new admission refuses
    # 410 (retirement) — not the old 402 — with no purchase_url, no
    # charge, and no date change.
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    assert _http_balance(env) == 0  # Phase C: no signup grant
    rid, _, _ = _make_report(env, uid)
    before = _expiry(env, rid)
    r = _extend(env, rid, csrf, "ext-broke")
    assert r.status_code == 410, r.text[:400]
    assert r.json()["error"] == RETIREMENT_ERROR
    assert "purchase_url" not in r.json()
    assert _http_balance(env) == 0
    assert _expiry(env, rid) == before
    assert _retention_ops(env, uid) == []


def test_extend_expired_report_410_no_charge(paid_env):
    # Name/premise retained, mechanism changed (#164 Phase C): the
    # 410 is now the retirement refusal, which precedes the old
    # expiry handling — an expired report's new admission refuses
    # with the retirement message and charges nothing.
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    _seed_balance(env, uid, 10)
    rid, _, _ = _make_report(env, uid, expires_in_days=-1)
    r = _extend(env, rid, csrf, "ext-dead")
    assert r.status_code == 410, r.text[:400]
    assert r.json()["error"] == RETIREMENT_ERROR
    assert _http_balance(env) == 10
    assert _retention_ops(env, uid) == []


def test_extend_foreign_report_404_and_anonymous_401(paid_env):
    # Premise preserved: ownership/auth fences precede the Phase C
    # refusal — a foreign report is still 404 and an anonymous
    # caller still 401, and neither balance moves. Balances are
    # seeded directly (no signup grant under Phase C).
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    _seed_balance(env, uid, 10)
    rid, _, _ = _make_report(env, uid)
    _, uid2, csrf2 = _signup_verify_login(env)
    _seed_balance(env, uid2, 10)
    r = _extend(env, rid, csrf2, "ext-foreign")
    assert r.status_code == 404, r.text[:400]
    with env.sessions() as db:
        assert C.get_balance_summary(db, uid)["balance"] == 10
        assert C.get_balance_summary(db, uid2)["balance"] == 10
    env.client.post("/auth/logout")
    r = _extend(env, rid, csrf2, "ext-anon")
    assert r.status_code == 401, r.text[:400]


def test_extend_requires_csrf(paid_env):
    # Premise preserved: the CSRF fence precedes the Phase C refusal.
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    _seed_balance(env, uid, 10)
    rid, original_expiry, _ = _make_report(env, uid)
    r = env.client.post(f"/reports/{rid}/retention",
                        data={"csrf_token": "wrong", "idempotency_key": "ext-csrf"})
    assert r.status_code == 403
    assert _http_balance(env) == 10
    assert _expiry(env, rid) == original_expiry


def test_extend_comparison_report_refused_410_after_cutover(paid_env):
    """Was test_extend_comparison_report_allowed (T4). PREMISE
    CHANGED (#164 Phase C): the retirement refusal applies to every
    owned report kind — a comparison report's new extension refuses
    410 with no charge and no date change, exactly like analysis."""
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    _seed_balance(env, uid, 10)
    rid, original_expiry, _ = _make_report(env, uid, result_type="comparison")
    r = _extend(env, rid, csrf, "ext-compare")
    assert r.status_code == 410, r.text[:400]
    assert r.json()["error"] == RETIREMENT_ERROR
    assert _http_balance(env) == 10
    assert _expiry(env, rid) == original_expiry
    assert _retention_ops(env, uid) == []


def test_extend_does_not_extend_pdf_artifact(paid_env):
    """T6, PREMISE CHANGED (#164 Phase C): the PDF export is FREE
    (balance untouched), and the extension attempt refuses 410 — so
    neither the source expiry nor the PDF Result's own expiry moves."""
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    _seed_balance(env, uid, 10)
    rid, original_expiry, _ = _make_report(env, uid)
    pdf = env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert pdf.status_code == 200, pdf.text[:300]
    assert _http_balance(env) == 10  # exports are free (Phase C)
    # Phase C's free path generates on the fly and stores no
    # artifact, so the stored PDF artifact whose independent expiry
    # T6 guards is seeded directly (a pre-cutover stored artifact).
    raw = json.dumps({"pdf_base64": "AAAA", "filename": "test.log"})
    now = C._utcnow()
    with env.sessions() as db:
        db.add(M.Result(
            user_id=uid, free_request_id=uuid.uuid4().hex, type="pdf",
            storage_manifest=raw,
            integrity_digest=C.hash_input(raw.encode()),
            byte_count=len(raw.encode()), ready_at=now,
            expires_at=now + timedelta(days=7)))
        db.commit()
    with env.sessions() as db:
        pdf_result = db.query(M.Result).filter(
            M.Result.user_id == uid, M.Result.type == "pdf").one()
        pdf_expiry = C._as_aware(pdf_result.expires_at)
    r = _extend(env, rid, csrf, "ext-pdf-independent")
    assert r.status_code == 410, r.text[:400]
    assert _http_balance(env) == 10
    assert _expiry(env, rid) == original_expiry
    with env.sessions() as db:
        pdf_result = db.query(M.Result).filter(
            M.Result.user_id == uid, M.Result.type == "pdf").one()
        assert C._as_aware(pdf_result.expires_at) == pdf_expiry


def test_extend_refusal_never_reaches_settlement_and_changes_nothing(paid_env, monkeypatch):
    # Was test_extend_settlement_failure_rolls_back_everything.
    # PREMISE CHANGED (#164 Phase C): there is no settlement to roll
    # back — the 410 refusal precedes the (now unreachable) charge
    # tail, so the receipt store is never even called, and balance,
    # expiry, and invariants are exactly as before the attempt.
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    _seed_balance(env, uid, 10)
    rid, original_expiry, _ = _make_report(env, uid)

    calls = []

    def boom(*args, **kwargs):
        calls.append((args, kwargs))
        raise RuntimeError("forced receipt failure")

    monkeypatch.setattr(C, "store_report_action_receipt", boom)
    r = _extend(env, rid, csrf, "ext-fail")
    assert r.status_code == 410, r.text[:400]
    assert r.json()["error"] == RETIREMENT_ERROR
    assert calls == []  # settlement machinery never reached
    assert _http_balance(env) == 10
    assert _expiry(env, rid) == original_expiry
    with env.sessions() as db:
        assert C.verify_account_invariants(db, uid) == []
        assert C.verify_capacity_invariants(db) == []


def test_cleanup_spares_extended_and_clears_control(paid_env):
    # Subject PRESERVED (#164 Phase C, Decision 5): expiries already
    # in force keep running to their recorded dates. The extended
    # report's +90-day expiry is seeded as a completed pre-cutover
    # extension; cleanup still spares it until that date and clears
    # it afterwards, exactly as before.
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    _seed_balance(env, uid, 10)
    rid_ext, _, _ = _make_report(env, uid)
    rid_ctl, _, _ = _make_report(env, uid, filename="control.log")
    _seed_completed_extension(env, uid, rid_ext, "ext-cleanup")
    assert _http_balance(env) == 9  # the one pre-cutover charge
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
    # Subject PRESERVED (C5): the completed extension is seeded on
    # its original terms; after its receipt payload is cleaned up,
    # the ReportAction replay still returns the recorded success
    # and never recharges.
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    _seed_balance(env, uid, 10)
    rid, _, _ = _make_report(env, uid)
    _seed_completed_extension(env, uid, rid, "ext-replay-clean")
    assert _http_balance(env) == 9  # one 1-credit charge total
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
    assert _http_balance(env) == 9  # one 1-credit charge total
    assert _expiry(env, rid) == after
