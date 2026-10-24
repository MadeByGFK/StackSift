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


def _charge(cid, amount, pi="pi_1", refunded=0, disputed=False, pack_meta=None):
    return {
        "id": cid,
        "amount": amount,
        "amount_refunded": refunded,
        "refunded": refunded > 0,
        "disputed": disputed,
        "payment_intent": pi,
        "created": 0,
        "metadata": {"pack_id": pack_meta} if pack_meta else {},
    }


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
