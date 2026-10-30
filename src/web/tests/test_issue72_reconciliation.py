"""Daily Stripe-to-ledger reconciliation (issue #72).

Acceptance criteria:
- Job compares Stripe totals and ledger grants per day and per pack, to the cent.
- A clean day produces a recorded clean result; a mismatch produces a
  founder-visible alert with the differing records identified.
- Reconciliation covers refunds/disputes as negative entries.

Stripe is faked at the injection boundary: reconcile_day takes a
``stripe_get(kind, day)`` callable, so no test touches the network.
Money values below are cents; pack amounts are $5/10/25 -> 10/25/75.

Evidence database: TEST_POSTGRES_URL (Postgres 16, the CI service) when
set, otherwise a local SQLite file::
"""
import os
import uuid
from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, event, select, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

PACK_AMOUNTS = {"starter": 500, "growth": 1000, "power": 2500}
PACK_CREDITS = {"starter": 10, "growth": 25, "power": 75}


def _engine_for(tmp_path):
    pg_url = os.environ.get("TEST_POSTGRES_URL")
    if pg_url:
        schema = "fp72_" + uuid.uuid4().hex
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
    path = tmp_path / f"recon72_{uuid.uuid4().hex[:8]}.db"
    engine = create_engine(
        f"sqlite:///{path}",
        connect_args={"check_same_thread": False, "timeout": 20},
    )

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, _):
        connection.execute("PRAGMA foreign_keys=ON")

    return engine, None


@pytest.fixture
def recon_env(tmp_path, monkeypatch):
    from app.db import Base
    import app.models  # noqa: F401 -- register tables before create_all

    engine, schema = _engine_for(tmp_path)
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)
    monkeypatch.setenv("STRIPE_PRICE_STARTER", "price_test_starter")
    monkeypatch.setenv("STRIPE_PRICE_GROWTH", "price_test_growth")
    monkeypatch.setenv("STRIPE_PRICE_POWER", "price_test_power")
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_cycle_fixture")
    monkeypatch.delenv("RECON_ALERT_EMAIL", raising=False)
    try:
        yield SimpleNamespace(sessions=sessions)
    finally:
        engine.dispose()
        if schema:
            admin = create_engine(os.environ["TEST_POSTGRES_URL"], poolclass=NullPool)
            with admin.begin() as conn:
                conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
            admin.dispose()


def _user_id(db):
    from app.models import User
    u = User(id=uuid.uuid4(), email=f"recon72-{uuid.uuid4().hex[:8]}@example.com",
             email_verified=True)
    db.add(u)
    db.commit()
    return u.id


def _purchase(db, user_id, day, pack_id="starter", session_id=None,
              amount_cents=None, completed_hour=12):
    from app.models import CreditPurchase
    completed_at = datetime(day.year, day.month, day.day, completed_hour, 0,
                            tzinfo=timezone.utc)
    p = CreditPurchase(
        id=uuid.uuid4(), user_id=user_id,
        stripe_session_id=session_id or f"cs_test_{uuid.uuid4().hex[:8]}",
        stripe_payment_intent_id=f"pi_test_{uuid.uuid4().hex[:8]}",
        pack_id=pack_id, credits=PACK_CREDITS[pack_id],
        amount_cents=amount_cents if amount_cents is not None
        else PACK_AMOUNTS[pack_id],
        currency="usd", pricing_version=1, status="completed",
        stripe_event_id=f"evt_test_{uuid.uuid4().hex[:8]}",
        completed_at=completed_at,
    )
    db.add(p)
    db.commit()
    return p


def _session(sid, pack_id="starter", amount=None, pi="pi_1"):
    return {
        "id": sid,
        "amount_total": amount if amount is not None else PACK_AMOUNTS[pack_id],
        "currency": "usd",
        "payment_status": "paid",
        "status": "complete",
        "metadata": {"pack_id": pack_id},
        "payment_intent": pi,
    }


def _charge(cid, amount, pi="pi_1", refunded=0, disputed=False, pack_meta=None,
            dispute=None):
    charge = {
        "id": cid,
        "amount": amount,
        "amount_refunded": refunded,
        "refunded": refunded > 0,
        "disputed": disputed,
        "payment_intent": pi,
        "created": 0,
        "metadata": {"pack_id": pack_meta} if pack_meta else {},
    }
    if dispute is not None:
        # Mirrors the expanded dispute object (fetch_day_charges passes
        # expand[]=data.dispute); omitted means the fallback path.
        charge["dispute"] = dispute
    return charge


def _fake(sessions=(), charges=(), wide=()):
    def get(kind, day):
        if kind == "sessions":
            return list(sessions)
        if kind == "charges":
            return list(charges)
        return list(wide)
    return get


def _run(db, day):
    from app.models import PaymentReconciliation
    return db.execute(
        select(PaymentReconciliation).where(
            PaymentReconciliation.recon_date == day)
    ).scalar_one_or_none()


def test_clean_day_recorded(recon_env):
    from app import payment_reconcile as pr
    day = date(2026, 10, 20)
    with recon_env.sessions() as db:
        uid = _user_id(db)
        _purchase(db, uid, day, session_id="cs_clean_1")
        run = pr.reconcile_day(db, day, stripe_get=_fake(
            sessions=[_session("cs_clean_1")]))
        assert run.status == "clean"
        assert run.stripe_gross_cents == 500
        assert run.ledger_gross_cents == 500
        assert run.per_pack["starter"]["diff_cents"] == 0
        assert run.differences == []
        assert run.alert_pending is False
        # Recorded: a second run returns the same row, no duplicate.
        run2 = pr.reconcile_day(db, day, stripe_get=_fake())
        assert run2.id == run.id
        from app.models import PaymentReconciliation
        rows = db.execute(select(PaymentReconciliation)).scalars().all()
        assert len(rows) == 1


def test_cent_precision_mismatch(recon_env):
    from app import payment_reconcile as pr
    day = date(2026, 10, 20)
    with recon_env.sessions() as db:
        uid = _user_id(db)
        # Ledger says 499¢, Stripe says 500¢ — one cent is a mismatch.
        _purchase(db, uid, day, session_id="cs_cent_1", amount_cents=499)
        run = pr.reconcile_day(db, day, stripe_get=_fake(
            sessions=[_session("cs_cent_1", amount=500)]))
        assert run.status == "mismatch"
        assert run.per_pack["starter"]["diff_cents"] == 1
        kinds = [d["kind"] for d in run.differences]
        assert "pack_total_mismatch" in kinds
        assert run.alert_pending is True  # RECON_ALERT_EMAIL unset
        assert run.alert_sent is False


def test_stripe_session_without_purchase_identified(recon_env):
    from app import payment_reconcile as pr
    day = date(2026, 10, 20)
    with recon_env.sessions() as db:
        run = pr.reconcile_day(db, day, stripe_get=_fake(
            sessions=[_session("cs_orphan_1", pack_id="growth")]))
        assert run.status == "mismatch"
        orphan = [d for d in run.differences
                  if d["kind"] == "stripe_session_without_purchase"]
        assert len(orphan) == 1
        assert orphan[0]["stripe_session_id"] == "cs_orphan_1"
        assert orphan[0]["amount_cents"] == 1000
        assert orphan[0]["pack"] == "growth"


def test_purchase_without_stripe_session_identified(recon_env):
    from app import payment_reconcile as pr
    day = date(2026, 10, 20)
    with recon_env.sessions() as db:
        uid = _user_id(db)
        p = _purchase(db, uid, day, session_id="cs_missing_1")
        run = pr.reconcile_day(db, day, stripe_get=_fake(sessions=[]))
        assert run.status == "mismatch"
        missing = [d for d in run.differences
                   if d["kind"] == "purchase_without_stripe_session"]
        assert len(missing) == 1
        assert missing[0]["purchase_id"] == str(p.id)


def test_refund_is_negative_entry(recon_env):
    from app import payment_reconcile as pr
    day = date(2026, 10, 20)
    with recon_env.sessions() as db:
        uid = _user_id(db)
        _purchase(db, uid, day, session_id="cs_ref_1")
        run = pr.reconcile_day(db, day, stripe_get=_fake(
            sessions=[_session("cs_ref_1", pi="pi_ref")],
            charges=[_charge("ch_ref_1", 500, pi="pi_ref", refunded=500)]))
        assert run.status == "mismatch"
        pp = run.per_pack["starter"]
        assert pp["stripe_refund_cents"] == 500
        assert pp["stripe_net_cents"] == 0
        assert pp["ledger_net_cents"] == 500
        assert pp["diff_cents"] == -500
        kinds = [d["kind"] for d in run.differences]
        assert "stripe_refund" in kinds
        refund = [d for d in run.differences if d["kind"] == "stripe_refund"][0]
        assert refund["charge_id"] == "ch_ref_1"
        assert refund["refunded_cents"] == 500


def test_dispute_is_negative_entry(recon_env):
    from app import payment_reconcile as pr
    day = date(2026, 10, 20)
    with recon_env.sessions() as db:
        uid = _user_id(db)
        _purchase(db, uid, day, session_id="cs_disp_1")
        run = pr.reconcile_day(db, day, stripe_get=_fake(
            sessions=[_session("cs_disp_1", pi="pi_disp")],
            charges=[_charge("ch_disp_1", 500, pi="pi_disp", disputed=True)]))
        assert run.status == "mismatch"
        pp = run.per_pack["starter"]
        assert pp["stripe_dispute_cents"] == 500
        assert pp["stripe_net_cents"] == 0
        dispute = [d for d in run.differences if d["kind"] == "stripe_dispute"][0]
        assert dispute["charge_id"] == "ch_disp_1"
        assert dispute["disputed_cents"] == 500


def test_refund_attributed_via_charge_metadata(recon_env):
    """Charges created after PI metadata shipped carry pack_id directly."""
    from app import payment_reconcile as pr
    day = date(2026, 10, 20)
    with recon_env.sessions() as db:
        uid = _user_id(db)
        _purchase(db, uid, day, session_id="cs_rm_1", pack_id="power")
        run = pr.reconcile_day(db, day, stripe_get=_fake(
            sessions=[_session("cs_rm_1", pack_id="power", pi="pi_rm")],
            charges=[_charge("ch_rm_1", 2500, pi="pi_unknown",
                             refunded=2500, pack_meta="power")]))
        pp = run.per_pack["power"]
        assert pp["stripe_refund_cents"] == 2500
        assert "unknown" not in run.per_pack or \
            run.per_pack["unknown"]["stripe_refund_cents"] == 0


def test_ledger_refund_nets_against_stripe_refund(recon_env):
    """A ledger cash_refund (valued at the purchase's cents) offsets the
    Stripe refund so a properly recorded refund reconciles clean."""
    from app import models, payment_reconcile as pr
    day = date(2026, 10, 20)
    with recon_env.sessions() as db:
        uid = _user_id(db)
        purchase = _purchase(db, uid, day, session_id="cs_lr_1")
        # Grant linked to the purchase, then a cash_refund ledger entry
        # reversing it through the ledger_grants chain.
        grant = models.CreditGrant(
            id=uuid.uuid4(), user_id=uid, source="purchase",
            source_key=str(purchase.id), issued=10, remaining=10,
            purchase_id=purchase.id)
        db.add(grant)
        db.flush()
        entry = models.CreditLedger(
            id=uuid.uuid4(), user_id=uid, account_sequence=1,
            event_key=f"cash_refund:{grant.id}", delta=-10,
            balance_after=0, reason="cash_refund",
            created_at=datetime(2026, 10, 20, 15, 0, tzinfo=timezone.utc))
        db.add(entry)
        db.flush()
        db.add(models.LedgerGrant(
            ledger_entry_id=entry.id, grant_id=grant.id, signed_delta=-10))
        db.commit()
        run = pr.reconcile_day(db, day, stripe_get=_fake(
            sessions=[_session("cs_lr_1", pi="pi_lr")],
            charges=[_charge("ch_lr_1", 500, pi="pi_lr", refunded=500)]))
        pp = run.per_pack["starter"]
        assert pp["ledger_refund_cents"] == 500
        assert pp["stripe_net_cents"] == 0
        assert pp["ledger_net_cents"] == 0
        assert pp["diff_cents"] == 0


def test_skipped_when_checkout_not_configured(recon_env, monkeypatch):
    from app import payment_reconcile as pr
    monkeypatch.delenv("STRIPE_PRICE_STARTER")
    monkeypatch.delenv("STRIPE_PRICE_GROWTH")
    monkeypatch.delenv("STRIPE_PRICE_POWER")
    day = date(2026, 10, 20)
    with recon_env.sessions() as db:
        run = pr.reconcile_day(db, day, stripe_get=_fake())
        assert run.status == "skipped"
        assert "not configured" in (run.error_note or "")


def test_error_day_failing_twice_keeps_single_row(recon_env):
    """Review finding on PR #95: deleting the error row upfront, then
    rolling back on a second failure, resurrected it — and re-inserting
    violated recon_date's uniqueness. A still-failing day must update
    its error row in place, never raise, never duplicate."""
    from app import models, payment_reconcile as pr
    day = date(2026, 10, 20)
    with recon_env.sessions() as db:
        def boom(kind, day):
            raise pr.ReconcileError("stripe down")
        run1 = pr.reconcile_day(db, day, stripe_get=boom)
        assert run1.status == "error"
        run2 = pr.reconcile_day(db, day, stripe_get=boom)
        assert run2.status == "error"
        assert "stripe down" in (run2.error_note or "")
        rows = db.execute(
            select(models.PaymentReconciliation).where(
                models.PaymentReconciliation.recon_date == day)
        ).scalars().all()
        assert len(rows) == 1
        assert rows[0].id == run1.id


def test_missing_days_job_survives_still_failing_error_day(recon_env):
    """Job level of the same finding: an error day that keeps failing
    must not abort the scan — later days still reconcile and the
    alert-pending retry still runs."""
    from app import models, payment_reconcile as pr
    err_day = date(2026, 10, 20)
    later_day = date(2026, 10, 21)
    with recon_env.sessions() as db:
        uid = _user_id(db)
        _purchase(db, uid, later_day, session_id="cs_surv_1")

        def boom(kind, day):
            raise pr.ReconcileError("stripe down")
        # The error row already exists from an earlier tick (as in the
        # real Oct 24 case); the job must retry it, not start after it.
        assert pr.reconcile_day(db, err_day, stripe_get=boom).status == "error"

        def get(kind, day):
            if day == err_day:
                raise pr.ReconcileError("stripe down")
            return {
                "sessions": [_session("cs_surv_1")] if day == later_day else [],
                "charges": [],
                "wide_sessions": [],
                "prior_sessions": [],
            }[kind]
        runs = pr.reconcile_missing_days(db, stripe_get=get,
                                         today=date(2026, 10, 23))
        assert [str(r.recon_date) for r in runs] == \
            ["2026-10-20", "2026-10-21", "2026-10-22"]
        assert runs[0].status == "error"
        assert runs[1].status == "clean"  # later day reconciled despite it
        err_rows = db.execute(
            select(models.PaymentReconciliation).where(
                models.PaymentReconciliation.recon_date == err_day)
        ).scalars().all()
        assert len(err_rows) == 1
        # And a second job tick with the same outage still completes.
        runs2 = pr.reconcile_missing_days(db, stripe_get=get,
                                          today=date(2026, 10, 23))
        assert runs2[0].status == "error"
        assert runs2[1].status == "clean"
        err_rows2 = db.execute(
            select(models.PaymentReconciliation).where(
                models.PaymentReconciliation.recon_date == err_day)
        ).scalars().all()
        assert len(err_rows2) == 1


def test_error_day_is_retried(recon_env):
    from app import payment_reconcile as pr
    day = date(2026, 10, 20)
    with recon_env.sessions() as db:
        def boom(kind, day):
            raise pr.ReconcileError("stripe down")
        run = pr.reconcile_day(db, day, stripe_get=boom)
        assert run.status == "error"
        assert "stripe down" in (run.error_note or "")
        # Next cycle retries the error day instead of skipping it.
        uid = _user_id(db)
        _purchase(db, uid, day, session_id="cs_retry_1")
        run2 = pr.reconcile_day(db, day, stripe_get=_fake(
            sessions=[_session("cs_retry_1")]))
        assert run2.status == "clean"
        from app.models import PaymentReconciliation
        rows = db.execute(select(PaymentReconciliation)).scalars().all()
        assert len(rows) == 1


def test_missing_days_job_retries_error_day_after_later_days(recon_env):
    """Regression: the job's watermark was latest-recorded-day + 1, so an
    error day was abandoned once a later day had a row (the 2026-10-24
    run errored on Stripe and never re-ran). The job must rescan from
    the earliest error day; settled days are returned untouched."""
    from app import models, payment_reconcile as pr
    err_day = date(2026, 10, 20)
    later_day = date(2026, 10, 21)
    with recon_env.sessions() as db:
        uid = _user_id(db)
        _purchase(db, uid, err_day, session_id="cs_err_1")
        _purchase(db, uid, later_day, session_id="cs_lat_1")

        def boom(kind, day):
            raise pr.ReconcileError("midnight stripe 400")
        assert pr.reconcile_day(db, err_day, stripe_get=boom).status == "error"
        # The loop advanced past the error day and settled the next one.
        assert pr.reconcile_day(db, later_day, stripe_get=_fake(
            sessions=[_session("cs_lat_1")])).status == "clean"

        runs = pr.reconcile_missing_days(
            db,
            stripe_get=lambda kind, day: {
                "sessions": [_session("cs_err_1")] if day == err_day else
                ([_session("cs_lat_1")] if day == later_day else []),
                "charges": [],
                "wide_sessions": [],
                "prior_sessions": [],
            }[kind],
            today=date(2026, 10, 23),
        )
        assert [str(r.recon_date) for r in runs] == \
            ["2026-10-20", "2026-10-21", "2026-10-22"]
        assert runs[0].status == "clean"  # the error day, retried
        assert runs[1].status == "clean"  # settled day, untouched
        rows = db.execute(
            select(models.PaymentReconciliation).where(
                models.PaymentReconciliation.recon_date == err_day)
        ).scalars().all()
        assert len(rows) == 1
        assert rows[0].status == "clean"


def test_missing_days_job_retries_error_day_as_latest_row(recon_env):
    """Same watermark bug, no later days: an error row as the latest
    recorded day must still be retried by the next job run."""
    from app import models, payment_reconcile as pr
    err_day = date(2026, 10, 20)
    with recon_env.sessions() as db:
        uid = _user_id(db)
        _purchase(db, uid, err_day, session_id="cs_err2_1")

        def boom(kind, day):
            raise pr.ReconcileError("stripe down")
        assert pr.reconcile_day(db, err_day, stripe_get=boom).status == "error"
        runs = pr.reconcile_missing_days(
            db,
            stripe_get=lambda kind, day: {
                "sessions": [_session("cs_err2_1")] if day == err_day else [],
                "charges": [],
                "wide_sessions": [],
                "prior_sessions": [],
            }[kind],
            today=date(2026, 10, 22),
        )
        assert [str(r.recon_date) for r in runs] == ["2026-10-20", "2026-10-21"]
        assert runs[0].status == "clean"
        assert runs[1].status == "clean"  # empty day after the retried one
        rows = db.execute(
            select(models.PaymentReconciliation).where(
                models.PaymentReconciliation.recon_date == err_day)
        ).scalars().all()
        assert len(rows) == 1


def test_mismatch_alert_sent_and_pending_retry(recon_env, monkeypatch):
    from app import models, payment_reconcile as pr
    from app import email as email_module
    sent = []
    monkeypatch.setattr(email_module, "send_email",
                        lambda to, subject, html: sent.append((to, subject)) or True)
    day = date(2026, 10, 20)
    with recon_env.sessions() as db:
        uid = _user_id(db)
        _purchase(db, uid, day, session_id="cs_al_1")
        # No alert address configured: mismatch recorded, alert pending.
        run = pr.reconcile_day(db, day, stripe_get=_fake(sessions=[]))
        assert run.status == "mismatch"
        assert run.alert_pending is True
        assert run.alert_sent is False
        assert sent == []
        # Address configured later: the next cycle delivers the pending alert.
        monkeypatch.setenv("RECON_ALERT_EMAIL", "ops@example.com")
        pr.reconcile_missing_days(db, stripe_get=_fake(sessions=[]),
                                  today=date(2026, 10, 22))
        assert len(sent) == 1
        assert sent[0][0] == "ops@example.com"
        assert "2026-10-20" in sent[0][1]
        run = db.execute(select(models.PaymentReconciliation).where(
            models.PaymentReconciliation.recon_date == day)).scalar_one()
        assert run.alert_pending is False
        assert run.alert_sent is True


def test_missing_days_backfill_from_first_purchase(recon_env):
    from app import models, payment_reconcile as pr
    with recon_env.sessions() as db:
        uid = _user_id(db)
        _purchase(db, uid, date(2026, 10, 18), session_id="cs_bf_1")
        _purchase(db, uid, date(2026, 10, 19), session_id="cs_bf_2")
        runs = pr.reconcile_missing_days(
            db,
            stripe_get=lambda kind, day: {
                "sessions": [_session(f"cs_bf_1")] if day == date(2026, 10, 18)
                else ([_session(f"cs_bf_2")] if day == date(2026, 10, 19) else []),
                "charges": [],
                "wide_sessions": [],
                "prior_sessions": [],
            }[kind],
            today=date(2026, 10, 21),
        )
        assert [str(r.recon_date) for r in runs] == \
            ["2026-10-18", "2026-10-19", "2026-10-20"]
        assert all(r.status == "clean" for r in runs[:2])
        assert runs[2].status == "clean"  # empty day, configured Stripe
        rows = db.execute(select(models.PaymentReconciliation)).scalars().all()
        assert len(rows) == 3


def test_checkout_session_carries_pi_metadata(monkeypatch):
    """Issue #72 join keys: the payment intent carries purchase/pack so
    refund/dispute charges attribute to a pack."""
    from app import stripe_billing as sb
    monkeypatch.setenv("STRIPE_PRICE_STARTER", "price_test_starter")
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_cycle_fixture")
    posted = {}

    class FakeResp:
        status_code = 200

        def json(self):
            return {"url": "https://checkout.stripe.com/pay/cs_x",
                    "id": "cs_x"}

    import httpx
    monkeypatch.setattr(httpx, "post",
                        lambda url, data=None, auth=None, headers=None,
                        timeout=None: posted.update(data) or FakeResp())
    sb.create_checkout_session(
        user_id="user-1", pack_id="starter", purchase_id="purchase-1",
        success_url="https://x/s", cancel_url="https://x/c",
    )
    assert posted["payment_intent_data[metadata][purchase_id]"] == "purchase-1"
    assert posted["payment_intent_data[metadata][pack_id]"] == "starter"
    assert posted["payment_intent_data[metadata][pricing_version]"] == "1"
    # Issue #71 fix: receipt_email is never sent — Managed Payments
    # rejects payment_intent_data[receipt_email]; Stripe sends receipts.
    assert "payment_intent_data[receipt_email]" not in posted


def test_stripe_session_list_sends_no_payment_status_param(monkeypatch):
    """Issue #72 follow-up: payment_status is a Checkout Session response
    field, NOT a list parameter for GET /v1/checkout/sessions — Stripe
    rejects it with 400. fetch_day_sessions must send only valid list
    parameters; the paid+complete filter stays client-side (line 116)."""
    from app import payment_reconcile as pr
    import httpx
    captured = []

    class FakeResp:
        status_code = 200

        def json(self):
            return {"data": [
                _session("cs_paid", "starter"),
                {"id": "cs_unpaid", "amount_total": 500, "currency": "usd",
                 "payment_status": "unpaid", "status": "complete",
                 "metadata": {"pack_id": "starter"}, "payment_intent": "pi_9"},
                {"id": "cs_open", "amount_total": 500, "currency": "usd",
                 "payment_status": "paid", "status": "open",
                 "metadata": {"pack_id": "starter"}, "payment_intent": "pi_8"},
            ], "has_more": False}

    def fake_get(url, params=None, auth=None, timeout=None):
        captured.append((url, dict(params or {})))
        return FakeResp()

    monkeypatch.setattr(httpx, "get", fake_get)
    sessions = pr.fetch_day_sessions("sk_test_cycle_fixture", date(2026, 10, 24))
    assert [s["id"] for s in sessions] == ["cs_paid"]
    assert len(captured) == 1
    url, params = captured[0]
    assert url.endswith("/checkout/sessions")
    assert "payment_status" not in params
    assert params["limit"] == 100
    assert "created[gte]" in params and "created[lte]" in params


def test_wide_session_list_sends_no_payment_status_param(recon_env, monkeypatch):
    """Issue #72 follow-up: the refund-attribution wide fetch in
    reconcile_day sends the same invalid parameter. Drive reconcile_day
    with stripe_get=None and a faked httpx.get so all session list
    calls (day + prior + wide) are captured; none may carry
    payment_status. The prior call covers the settlement-lookback window
    [day - 4, day - 1] (Finding 1a)."""
    from app import payment_reconcile as pr
    import httpx
    captured = []

    class FakeResp:
        status_code = 200

        def __init__(self, data):
            self._data = data

        def json(self):
            return {"data": self._data, "has_more": False}

    def fake_get(url, params=None, auth=None, timeout=None):
        captured.append((url, dict(params or {})))
        if url.endswith("/charges"):
            return FakeResp([_charge("ch_1", 500, refunded=500,
                                      pack_meta="starter")])
        return FakeResp([])

    monkeypatch.setattr(httpx, "get", fake_get)
    with recon_env.sessions() as db:
        pr.reconcile_day(db, date(2026, 10, 24), stripe_get=None)
    session_calls = [p for u, p in captured if u.endswith("/checkout/sessions")]
    # Day fetch + prior settlement-lookback fetch + wide
    # refund-attribution fetch.
    assert len(session_calls) == 3
    for params in session_calls:
        assert "payment_status" not in params
    day_start = datetime(2026, 10, 24, tzinfo=timezone.utc)
    prior_start = datetime(2026, 10, 20, tzinfo=timezone.utc)
    assert session_calls[1]["created[gte]"] == int(prior_start.timestamp())
    assert session_calls[1]["created[lte]"] == int(day_start.timestamp()) - 1
    # PR #108 Finding 1 resolution: charges are listed WITHOUT an
    # expand[] (the Charges reference lists no `dispute` attribute and
    # the code pins no Stripe-Version, so an unsupported expansion
    # would 400 the whole charges fetch). Dispute status comes from
    # the separate /v1/disputes fetch instead.
    charge_calls = [p for u, p in captured if u.endswith("/charges")]
    assert "expand[]" not in charge_calls[0]


def test_disputes_fetched_separately_from_charges(recon_env, monkeypatch):
    """PR #108 Finding 1 resolution: a disputed charge with no
    expanded dispute object gets its status from a separate
    /v1/disputes list call (joined by dispute.charge), and the
    charges call itself carries no expand[]. A won dispute found
    this way subtracts nothing, so the paired day stays clean."""
    from app import payment_reconcile as pr
    import httpx
    captured = []

    class FakeResp:
        status_code = 200

        def __init__(self, data):
            self._data = data

        def json(self):
            return {"data": self._data, "has_more": False}

    def fake_get(url, params=None, auth=None, timeout=None):
        captured.append((url, dict(params or {})))
        if url.endswith("/charges"):
            return FakeResp([_charge("ch_sep_1", 500, pi="pi_sep",
                                     disputed=True)])
        if url.endswith("/disputes"):
            return FakeResp([{"id": "dp_sep_1", "charge": "ch_sep_1",
                              "status": "won", "amount": 500}])
        if url.endswith("/checkout/sessions"):
            return FakeResp([_session("cs_sep_1", pi="pi_sep")])
        return FakeResp([])

    monkeypatch.setattr(httpx, "get", fake_get)
    with recon_env.sessions() as db:
        uid = _user_id(db)
        _purchase(db, uid, date(2026, 10, 20), session_id="cs_sep_1")
        run = pr.reconcile_day(db, date(2026, 10, 20), stripe_get=None)
        # Won dispute found via the separate fetch: subtracts nothing.
        assert run.status == "clean"
        assert run.per_pack["starter"]["stripe_dispute_cents"] == 0
        assert run.differences == []
        charge_calls = [p for u, p in captured if u.endswith("/charges")]
        assert "expand[]" not in charge_calls[0]
        dispute_calls = [p for u, p in captured if u.endswith("/disputes")]
        assert len(dispute_calls) == 1
        day_start = datetime(2026, 10, 20, tzinfo=timezone.utc)
        assert dispute_calls[0]["created[gte]"] == int(day_start.timestamp())
        assert dispute_calls[0]["created[lte]"] >= \
            dispute_calls[0]["created[gte]"]


def _dispute_fake(monkeypatch, disputes):
    """httpx.get fake for the disputes-fetch path: one paired session,
    one disputed charge, and the given disputes list (newest first,
    as Stripe lists return). Returns captured (url, params) pairs."""
    from app import payment_reconcile as pr  # noqa: F401 -- documents path
    import httpx
    captured = []

    class FakeResp:
        status_code = 200

        def __init__(self, data):
            self._data = data

        def json(self):
            return {"data": self._data, "has_more": False}

    def fake_get(url, params=None, auth=None, timeout=None):
        captured.append((url, dict(params or {})))
        if url.endswith("/charges"):
            return FakeResp([_charge("ch_multi_1", 500, pi="pi_multi",
                                     disputed=True)])
        if url.endswith("/disputes"):
            return FakeResp(disputes)
        if url.endswith("/checkout/sessions"):
            return FakeResp([_session("cs_multi_1", pi="pi_multi")])
        return FakeResp([])

    monkeypatch.setattr(httpx, "get", fake_get)
    return captured


def test_multiple_disputes_grouped_not_last_wins(recon_env, monkeypatch):
    """PR #108 Codex P2 regression: a charge with a newer lost dispute
    and an older won dispute must NOT attach only the won object
    (the old last-wins join kept the oldest, since Stripe lists are
    reverse chronological, and recorded the day clean despite lost
    funds). The grouped result subtracts the lost 500."""
    from app import payment_reconcile as pr
    _dispute_fake(monkeypatch, [
        {"id": "dp_new", "charge": "ch_multi_1", "status": "lost",
         "amount": 500},
        {"id": "dp_old", "charge": "ch_multi_1", "status": "won",
         "amount": 500},
    ])
    with recon_env.sessions() as db:
        uid = _user_id(db)
        _purchase(db, uid, date(2026, 10, 20), session_id="cs_multi_1")
        run = pr.reconcile_day(db, date(2026, 10, 20), stripe_get=None)
        assert run.per_pack["starter"]["stripe_dispute_cents"] == 500
        assert run.per_pack["starter"]["stripe_net_cents"] == 0
        dispute = [d for d in run.differences
                   if d["kind"] == "stripe_dispute"][0]
        assert dispute["disputed_cents"] == 500
        assert dispute["status"] == "lost"


def test_multiple_disputes_capped_at_charge(recon_env, monkeypatch):
    """PR #108 Codex P2 follow-up: two lost 500 disputes on one 500
    charge sum to 1000 but the per-charge cap holds the subtraction
    at the unrefunded remainder (500), never double-counting beyond
    the charge."""
    from app import payment_reconcile as pr
    _dispute_fake(monkeypatch, [
        {"id": "dp_a", "charge": "ch_multi_1", "status": "lost",
         "amount": 500},
        {"id": "dp_b", "charge": "ch_multi_1", "status": "lost",
         "amount": 500},
    ])
    with recon_env.sessions() as db:
        uid = _user_id(db)
        _purchase(db, uid, date(2026, 10, 20), session_id="cs_multi_1")
        run = pr.reconcile_day(db, date(2026, 10, 20), stripe_get=None)
        assert run.per_pack["starter"]["stripe_dispute_cents"] == 500
        assert run.per_pack["starter"]["stripe_net_cents"] == 0


def test_error_recovery_preserves_alert_history(recon_env, monkeypatch):
    """PR #108 Codex Finding 2 regression: a mismatch row whose alert
    was already delivered, then failed by a window re-run (Stripe
    down), keeps its id AND alert_sent=True through the error row,
    and its non-force recovery sends no second alert."""
    from app import models, payment_reconcile as pr
    from app import email as email_module
    sent = []
    monkeypatch.setattr(email_module, "send_email",
                        lambda to, subject, html: sent.append((to, subject)) or True)
    monkeypatch.setenv("RECON_ALERT_EMAIL", "ops@example.com")
    day = date(2026, 10, 20)
    sess = _session("cs_recover_1")
    failing = {"fail": False}

    def get(kind, day):
        if failing["fail"] and day == date(2026, 10, 20):
            raise pr.ReconcileError("stripe down")
        return {"sessions": [sess] if day == date(2026, 10, 20) else [],
                "charges": [], "wide_sessions": [],
                "prior_sessions": []}[kind]

    with recon_env.sessions() as db:
        run = pr.reconcile_day(db, day, stripe_get=get)
        assert run.status == "mismatch"
        assert run.alert_sent is True
        assert len(sent) == 1
        row_id, created_at = run.id, run.created_at
        # Window re-run fails: the row becomes 'error' in place.
        failing["fail"] = True
        pr.reconcile_missing_days(db, stripe_get=get, today=date(2026, 10, 23))
        db.expire_all()
        row = _run(db, day)
        assert row.status == "error"
        assert row.id == row_id
        assert row.created_at == created_at
        assert row.alert_sent is True
        assert len(sent) == 1
        # Recovery: non-force retry of the error row, same id, no
        # second alert, exactly one row for the day.
        failing["fail"] = False
        pr.reconcile_missing_days(db, stripe_get=get, today=date(2026, 10, 23))
        db.expire_all()
        row = _run(db, day)
        assert row.status == "mismatch"
        assert row.id == row_id
        assert row.created_at == created_at
        assert row.alert_sent is True
        assert row.alert_pending is False
        assert len(sent) == 1
        rows = db.execute(select(models.PaymentReconciliation).where(
            models.PaymentReconciliation.recon_date == day)).scalars().all()
        assert len(rows) == 1


# --- Issue #101: #72 pre-activation reconciliation fixes ---

def test_cross_midnight_session_settles_next_day(recon_env):
    """Finding 1a: a session created day D settling (webhook) on day D+1
    is clean on both days — excluded on D (matched, completed
    elsewhere), included via prior_sessions on D+1 and paired with the
    purchase. Old code mismatched both days, permanently."""
    from app import payment_reconcile as pr
    day_d = date(2026, 10, 20)
    day_d1 = date(2026, 10, 21)
    sess = _session("cs_xmid_1")
    table = {
        day_d: {"sessions": [sess], "charges": [], "wide_sessions": [],
                "prior_sessions": []},
        day_d1: {"sessions": [], "charges": [], "wide_sessions": [],
                 "prior_sessions": [sess]},
    }

    def get(kind, day):
        return list(table[day][kind])

    with recon_env.sessions() as db:
        uid = _user_id(db)
        _purchase(db, uid, day_d1, session_id="cs_xmid_1")
        run_d = pr.reconcile_day(db, day_d, stripe_get=get)
        assert run_d.status == "clean"
        assert run_d.differences == []
        run_d1 = pr.reconcile_day(db, day_d1, stripe_get=get)
        assert run_d1.status == "clean"
        assert run_d1.stripe_gross_cents == 500
        assert run_d1.ledger_gross_cents == 500
        assert run_d1.differences == []


def test_late_webhook_healed_by_window_rerun(recon_env):
    """Finding 1b: a row computed as mismatch before a late webhook
    lands flips to clean on the window re-run, keeping its id, and the
    window pass does not appear in the scan's returned runs list."""
    from app import models, payment_reconcile as pr
    day = date(2026, 10, 20)
    sess = _session("cs_late_1")

    def get(kind, day):
        return {"sessions": [sess] if day == date(2026, 10, 20) else [],
                "charges": [], "wide_sessions": [],
                "prior_sessions": []}[kind]

    with recon_env.sessions() as db:
        uid = _user_id(db)
        first = pr.reconcile_day(db, day, stripe_get=get)
        assert first.status == "mismatch"
        first_id = first.id
        # Late webhook lands: the purchase settles on the same day.
        _purchase(db, uid, day, session_id="cs_late_1")
        runs = pr.reconcile_missing_days(db, stripe_get=get,
                                         today=date(2026, 10, 23))
        assert "2026-10-20" not in [str(r.recon_date) for r in runs]
        row = _run(db, day)
        assert row.id == first_id
        assert row.status == "clean"
        assert row.differences == []
        rows = db.execute(select(models.PaymentReconciliation).where(
            models.PaymentReconciliation.recon_date == day)).scalars().all()
        assert len(rows) == 1


def test_window_rerun_does_not_resend_alert(recon_env, monkeypatch):
    """Finding 1b alert rule: a mismatch row with alert_sent=True that
    flips to clean and back to mismatch sends exactly one email total."""
    from app import payment_reconcile as pr
    from app import email as email_module
    sent = []
    monkeypatch.setattr(email_module, "send_email",
                        lambda to, subject, html: sent.append((to, subject)) or True)
    monkeypatch.setenv("RECON_ALERT_EMAIL", "ops@example.com")
    day = date(2026, 10, 20)
    sess = _session("cs_alert_1")
    fixture = {"sessions": [sess]}

    def get(kind, day):
        if day == date(2026, 10, 20):
            return {"sessions": list(fixture["sessions"]), "charges": [],
                    "wide_sessions": [], "prior_sessions": []}[kind]
        return {"sessions": [], "charges": [], "wide_sessions": [],
                "prior_sessions": []}[kind]

    with recon_env.sessions() as db:
        uid = _user_id(db)
        # Mismatch with the alert delivered.
        run = pr.reconcile_day(db, day, stripe_get=get)
        assert run.status == "mismatch"
        assert run.alert_sent is True
        assert len(sent) == 1
        # Webhook lands; the window re-run heals the row to clean.
        _purchase(db, uid, day, session_id="cs_alert_1")
        pr.reconcile_missing_days(db, stripe_get=get, today=date(2026, 10, 23))
        row = _run(db, day)
        assert row.status == "clean"
        assert len(sent) == 1
        # Fixture changes: the session disappears while the purchase
        # remains — back to mismatch, but no second email.
        fixture["sessions"] = []
        pr.reconcile_missing_days(db, stripe_get=get, today=date(2026, 10, 23))
        row = _run(db, day)
        assert row.status == "mismatch"
        assert row.alert_sent is True
        assert row.alert_pending is False
        assert len(sent) == 1


def test_window_rerun_heals_final_row_after_persistent_error_day(recon_env):
    """Follow-up fix to Finding 1b: a final mismatch row later in the
    window than a persistent error day must still heal on the window
    re-run. The main loop starts at the earliest error day and merely
    visits the later final row (reconcile_day without force returns it
    untouched), so the old `wday < start_day` window filter skipped it
    too — the late-webhook row never healed until the error day
    cleared. The window pass must force-re-run pre-scan final rows
    inside the window, not just rows before start_day."""
    from app import payment_reconcile as pr
    err_day = date(2026, 10, 20)
    later_day = date(2026, 10, 21)
    sess = _session("cs_errlate_1")

    def boom(kind, day):
        raise pr.ReconcileError("stripe down")

    def get(kind, day):
        if day == err_day:
            raise pr.ReconcileError("stripe down")
        return {
            "sessions": [sess] if day == later_day else [],
            "charges": [],
            "wide_sessions": [],
            "prior_sessions": [],
        }[kind]

    with recon_env.sessions() as db:
        uid = _user_id(db)
        assert pr.reconcile_day(db, err_day, stripe_get=boom).status == "error"
        # Later day first computed as mismatch (session, no purchase yet).
        first = pr.reconcile_day(db, later_day, stripe_get=get)
        assert first.status == "mismatch"
        first_id = first.id
        # Late webhook lands for the later day.
        _purchase(db, uid, later_day, session_id="cs_errlate_1")
        runs = pr.reconcile_missing_days(db, stripe_get=get,
                                         today=date(2026, 10, 23))
        assert runs[0].status == "error"  # the outage persists
        db.expire_all()
        row = _run(db, later_day)
        assert row.id == first_id
        assert row.status == "clean"
        assert row.differences == []


def test_force_rerun_preserves_row_identity(recon_env):
    """Finding 1b: a force re-run updates the row in place — same id
    and created_at, exactly one row for the day afterward."""
    from app import models, payment_reconcile as pr
    day = date(2026, 10, 20)
    with recon_env.sessions() as db:
        uid = _user_id(db)
        _purchase(db, uid, day, session_id="cs_ident_1")
        run = pr.reconcile_day(db, day, stripe_get=_fake(
            sessions=[_session("cs_ident_1")]))
        assert run.status == "clean"
        row_id, created_at = run.id, run.created_at
        rerun = pr.reconcile_day(db, day, stripe_get=_fake(
            sessions=[_session("cs_ident_1")]), force=True)
        assert rerun.id == row_id
        db.expire_all()
        row = _run(db, day)
        assert row.id == row_id
        assert row.created_at == created_at
        rows = db.execute(select(models.PaymentReconciliation).where(
            models.PaymentReconciliation.recon_date == day)).scalars().all()
        assert len(rows) == 1


def test_won_dispute_subtracts_nothing(recon_env):
    """Finding 2: a won dispute subtracts nothing and appends no
    difference entry, so a fully paired day stays clean."""
    from app import payment_reconcile as pr
    day = date(2026, 10, 20)
    with recon_env.sessions() as db:
        uid = _user_id(db)
        _purchase(db, uid, day, session_id="cs_won_1")
        run = pr.reconcile_day(db, day, stripe_get=_fake(
            sessions=[_session("cs_won_1", pi="pi_won")],
            charges=[_charge("ch_won_1", 500, pi="pi_won", disputed=True,
                             dispute={"status": "won", "amount": 500})]))
        assert run.status == "clean"
        pp = run.per_pack["starter"]
        assert pp["stripe_dispute_cents"] == 0
        assert pp["stripe_net_cents"] == 500
        assert run.differences == []


def test_lost_dispute_plus_full_refund_counts_once(recon_env):
    """Finding 2: a fully refunded + lost-disputed charge counts once —
    old code subtracted refund 500 + dispute 500 for a net of -500."""
    from app import payment_reconcile as pr
    day = date(2026, 10, 20)
    with recon_env.sessions() as db:
        uid = _user_id(db)
        _purchase(db, uid, day, session_id="cs_lfr_1")
        run = pr.reconcile_day(db, day, stripe_get=_fake(
            sessions=[_session("cs_lfr_1", pi="pi_lfr")],
            charges=[_charge("ch_lfr_1", 500, pi="pi_lfr", refunded=500,
                             disputed=True,
                             dispute={"status": "lost", "amount": 500})]))
        pp = run.per_pack["starter"]
        assert pp["stripe_refund_cents"] == 500
        assert pp["stripe_dispute_cents"] == 0
        assert pp["stripe_net_cents"] == 0


def test_partial_refund_plus_lost_dispute(recon_env):
    """Finding 2: partial refund 400 + lost dispute 600 on a 1000
    charge nets to 0 against a 1000 gross (portion capped at the
    unrefunded remainder)."""
    from app import payment_reconcile as pr
    day = date(2026, 10, 20)
    with recon_env.sessions() as db:
        uid = _user_id(db)
        _purchase(db, uid, day, session_id="cs_prd_1", pack_id="growth")
        run = pr.reconcile_day(db, day, stripe_get=_fake(
            sessions=[_session("cs_prd_1", pack_id="growth", pi="pi_prd")],
            charges=[_charge("ch_prd_1", 1000, pi="pi_prd", refunded=400,
                             disputed=True,
                             dispute={"status": "lost", "amount": 600})]))
        pp = run.per_pack["growth"]
        assert pp["stripe_gross_cents"] == 1000
        assert pp["stripe_refund_cents"] == 400
        assert pp["stripe_dispute_cents"] == 600
        assert pp["stripe_net_cents"] == 0


def test_open_dispute_counts_but_notes_status(recon_env):
    """Finding 2: an open dispute subtracts (funds held) and its
    difference entry carries the open status note."""
    from app import payment_reconcile as pr
    day = date(2026, 10, 20)
    with recon_env.sessions() as db:
        uid = _user_id(db)
        _purchase(db, uid, day, session_id="cs_open_1")
        run = pr.reconcile_day(db, day, stripe_get=_fake(
            sessions=[_session("cs_open_1", pi="pi_open")],
            charges=[_charge("ch_open_1", 500, pi="pi_open", disputed=True,
                             dispute={"status": "needs_response",
                                      "amount": 500})]))
        pp = run.per_pack["starter"]
        assert pp["stripe_dispute_cents"] == 500
        dispute = [d for d in run.differences
                   if d["kind"] == "stripe_dispute"][0]
        assert dispute["disputed_cents"] == 500
        assert "needs_response" in dispute["note"]
        assert "may reverse" in dispute["note"]


def test_disputed_without_expanded_object_falls_back(recon_env):
    """Finding 2 fallback pin: disputed=True with no expanded dispute
    object keeps the old conservative behavior (full amount subtracted,
    entry present, status unknown)."""
    from app import payment_reconcile as pr
    day = date(2026, 10, 20)
    with recon_env.sessions() as db:
        uid = _user_id(db)
        _purchase(db, uid, day, session_id="cs_fb_1")
        run = pr.reconcile_day(db, day, stripe_get=_fake(
            sessions=[_session("cs_fb_1", pi="pi_fb")],
            charges=[_charge("ch_fb_1", 500, pi="pi_fb", disputed=True)]))
        pp = run.per_pack["starter"]
        assert pp["stripe_dispute_cents"] == 500
        assert pp["stripe_net_cents"] == 0
        dispute = [d for d in run.differences
                   if d["kind"] == "stripe_dispute"][0]
        assert dispute["disputed_cents"] == 500
        assert "unknown" in dispute["note"]


def _paginated(monkeypatch, pages):
    """Fake httpx.get serving one page per call, capturing params."""
    import httpx
    captured = []

    class FakeResp:
        status_code = 200

        def __init__(self, body):
            self._body = body

        def json(self):
            return self._body

    def fake_get(url, params=None, auth=None, timeout=None):
        captured.append(dict(params or {}))
        return FakeResp(pages[len(captured) - 1])

    monkeypatch.setattr(httpx, "get", fake_get)
    return captured


def test_pagination_merges_two_pages_in_order(monkeypatch):
    """Finding 3: _stripe_list merges pages in order and advances
    starting_after to the last id of each page."""
    from app import payment_reconcile as pr
    captured = _paginated(monkeypatch, [
        {"data": [{"id": "a"}, {"id": "b"}], "has_more": True},
        {"data": [{"id": "c"}], "has_more": False},
    ])
    result = pr._stripe_list("sk_test_paginate", "/charges", 0, 1000)
    assert [item["id"] for item in result] == ["a", "b", "c"]
    assert len(captured) == 2
    assert "starting_after" not in captured[0]
    assert captured[1]["starting_after"] == "b"
    assert all(params["limit"] == 100 for params in captured)


def test_pagination_advances_starting_after_each_page(monkeypatch):
    """Finding 3: three single-item pages advance starting_after
    through absent, "a", "b" in order."""
    from app import payment_reconcile as pr
    captured = _paginated(monkeypatch, [
        {"data": [{"id": "a"}], "has_more": True},
        {"data": [{"id": "b"}], "has_more": True},
        {"data": [{"id": "c"}], "has_more": False},
    ])
    result = pr._stripe_list("sk_test_paginate", "/charges", 0, 1000)
    assert [item["id"] for item in result] == ["a", "b", "c"]
    assert len(captured) == 3
    assert "starting_after" not in captured[0]
    assert captured[1]["starting_after"] == "a"
    assert captured[2]["starting_after"] == "b"
    assert all(params["limit"] == 100 for params in captured)


def test_pagination_stops_on_empty_page(monkeypatch):
    """Finding 3: the `or not items` guard terminates the loop even
    when has_more lies."""
    from app import payment_reconcile as pr
    captured = _paginated(monkeypatch, [
        {"data": [{"id": "a"}], "has_more": True},
        {"data": [], "has_more": True},
    ])
    result = pr._stripe_list("sk_test_paginate", "/charges", 0, 1000)
    assert [item["id"] for item in result] == ["a"]
    assert len(captured) == 2
